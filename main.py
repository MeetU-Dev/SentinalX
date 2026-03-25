import logging
import signal
import sys
import time

from monitor import collect_process_snapshot
from detector import detect_new_processes, detect_cpu_spikes, build_process_tree, calculate_parent_cpu_stats, detect_correlated_activity
from logger import log_event
from notifier import send_notification

LOG_FILE = 'events.log'
CPU_SPIKE_THRESHOLD = 50.0
last_alert_time = {}
ALERT_COOLDOWN = 5
spawn_history = {}  # parent -> list of child creation timestamps
TIME_WINDOW = 5  # seconds
burst_alerted = {}  # parent -> last burst alert timestamp
cpu_history = {}  # pid -> consecutive high CPU count
cpu_alerted = {}  # pid -> alert state (True/False)
CPU_CONFIRMATION = 3  # cycles
parent_signals = {}  # parent -> {"burst": bool, "cpu": bool, "file": bool}
ALERT_THRESHOLD = 5

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
LOGGER = logging.getLogger('sentinelx_lite')


def should_alert(pid):
    """Check if enough time has passed since last alert for this PID."""
    now = time.time()

    if pid not in last_alert_time:
        last_alert_time[pid] = now
        return True

    if now - last_alert_time[pid] > ALERT_COOLDOWN:
        last_alert_time[pid] = now
        return True

    return False


def calculate_score(signals):
    """Calculate threat score from signal combination."""
    score = 0

    if signals["burst"]:
        score += 3

    if signals["cpu"]:
        score += 3

    if signals["file"]:
        score += 4

    return score


def update_spawn_history(parent, new_children):
    """Update spawn history with timestamps for new children."""
    global spawn_history
    now = time.time()

    if parent not in spawn_history:
        spawn_history[parent] = []

    # Add timestamp for each new child
    for _ in new_children:
        spawn_history[parent].append(now)

    # Remove old entries outside time window
    spawn_history[parent] = [
        t for t in spawn_history[parent]
        if now - t <= TIME_WINDOW
    ]


def detect_spawn_burst_with_time(parent):
    """Check if parent has spawned too many children within time window and hasn't been alerted recently."""
    global spawn_history, burst_alerted
    now = time.time()
    events = spawn_history.get(parent, [])
    
    # Only alert if we have enough events AND haven't alerted in the last TIME_WINDOW
    if len(events) >= 5:
        last_alert = burst_alerted.get(parent, 0)
        if now - last_alert > TIME_WINDOW:
            burst_alerted[parent] = now
            return True
    
    return False


def signal_handler(signum, frame):
    LOGGER.info('Signal %s received, shutting down.', signum)
    sys.exit(0)


def print_alert(event):
    if event['type'] == 'new_process':
        message = f"New process PID={event['pid']} NAME={event['name']} CPU={event['cpu_percent']:.2f} RSS={event['rss']}"
    elif event['type'] == 'cpu_spike':
        message = f"CPU spike PID={event['pid']} NAME={event['name']} CPU={event['cpu']:.2f}%"
    elif event['type'] == 'process_burst':
        count = event.get('count', len(event.get('new_children', [])))
        message = f"[BURST] PID {event['parent']} spawned {count} NEW processes rapidly"
    elif event['type'] == 'correlated_activity':
        count = event.get('count', 0)
        total_cpu = event.get('total_cpu', 0.0)
        max_cpu = event.get('max_cpu', 0.0)
        message = (
            f"[CORRELATED] PID {event['parent']} spawned {count} processes | "
            f"max CPU: {max_cpu:.1f}% | total CPU: {total_cpu:.1f}%"
        )
    else:
        message = f"Unknown event: {event}"

    LOGGER.warning(message)
    print(message)
    send_notification('SentinelX-Lite Alert', message)


def run_monitor():
    previous_snapshot = collect_process_snapshot()
    prev_tree = build_process_tree(previous_snapshot)
    LOGGER.info('Initial snapshot collected with %d processes.', len(previous_snapshot))

    while True:
        try:
            current_snapshot = collect_process_snapshot()

            events = []
            events.extend(detect_new_processes(previous_snapshot, current_snapshot))
            events.extend(detect_cpu_spikes(current_snapshot, CPU_SPIKE_THRESHOLD))

            curr_tree = build_process_tree(current_snapshot)
            
            # Detect new children and update spawn history
            burst_alerts = []
            for parent, curr_children in curr_tree.items():
                prev_children = prev_tree.get(parent, [])
                new_children = list(set(curr_children) - set(prev_children))
                
                if new_children:
                    update_spawn_history(parent, new_children)
                    
                    # Check if this triggers time-window burst
                    if detect_spawn_burst_with_time(parent):
                        burst_alerts.append({
                            'type': 'process_burst',
                            'parent': parent,
                            'new_children': new_children,
                            'count': len(new_children),
                        })
            
            events.extend(burst_alerts)

            parent_cpu = calculate_parent_cpu_stats(curr_tree, current_snapshot)
            
            # Filter out low-CPU burst alerts before correlation
            filtered_burst_alerts = []
            for alert in burst_alerts:
                parent = alert['parent']
                stats = parent_cpu.get(parent, {})
                max_cpu = stats.get('max', 0)
                total_cpu = stats.get('total', 0)
                
                # Skip if low CPU activity
                if max_cpu < 5 and total_cpu < 20:
                    continue
                    
                filtered_burst_alerts.append(alert)
            
            correlated_alerts = detect_correlated_activity(filtered_burst_alerts, parent_cpu)
            events.extend(correlated_alerts)

            for evt in events:
                should_emit = False
                
                # Track signals for scoring
                if evt['type'] == 'process_burst':
                    parent = evt.get('parent')
                    if parent not in parent_signals:
                        parent_signals[parent] = {"burst": False, "cpu": False, "file": False}
                    parent_signals[parent]["burst"] = True
                    should_emit = True
                    
                elif evt['type'] == 'cpu_spike':
                    # For CPU spikes, track signal on the parent process
                    pid = evt.get('pid')
                    if pid in current_snapshot:
                        parent = current_snapshot[pid].get('ppid', 0)
                        if parent not in parent_signals:
                            parent_signals[parent] = {"burst": False, "cpu": False, "file": False}
                        parent_signals[parent]["cpu"] = True
                    should_emit = True
                    
                elif evt['type'] == 'new_process':
                    # Only alert new processes with high CPU or that are part of bursts
                    cpu = evt.get('cpu_percent', 0.0)
                    if cpu > 20:
                        should_emit = True
                    # Note: burst-related new processes are handled separately via correlated_activity
                    
                elif evt['type'] == 'correlated_activity':
                    should_emit = True
                
                if should_emit:
                    pid = evt.get('pid') or evt.get('parent')
                    if should_alert(pid):
                        print_alert(evt)
                        log_event(evt['type'], evt, LOG_FILE)

            # Final threat scoring and alerting
            for parent, signals in list(parent_signals.items()):
                score = calculate_score(signals)
                
                if score >= ALERT_THRESHOLD:
                    msg = (
                        f"[THREAT] PID {parent} | score={score} | "
                        f"signals={signals}"
                    )
                    
                    if should_alert(parent):
                        print(msg)
                        log_event("THREAT", {
                            "parent": parent,
                            "score": score,
                            "signals": signals
                        }, LOG_FILE)
                        send_notification("SentinelX Alert", msg)

            previous_snapshot = current_snapshot
            prev_tree = curr_tree

            time.sleep(1.0)

        except KeyboardInterrupt:
            LOGGER.info('KeyboardInterrupt received, exiting.')
            break
        except Exception as exc:
            LOGGER.exception('Unexpected error in monitoring loop: %s', exc)
            time.sleep(1.0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    LOGGER.info('SentinelX-Lite starting...')
    run_monitor()
