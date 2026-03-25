import argparse
import logging
import os
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
threat_active = {}  # parent -> True/False (threat state tracking)
ALERT_THRESHOLD = 5
FILE_SPIKE_THRESHOLD = 30
MONITORED_DIR = 'test_dir'
file_events = []  # (event_type, path, timestamp)
file_snapshot = {}  # path -> last modified time
signal_history = {}  # parent -> {"burst": ts, "cpu": ts, "file": ts}
SIGNAL_WINDOW = 5  # seconds
last_file_spike_time = 0.0
RUN_MODE = 'live'
QUIET_MODE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
LOGGER = logging.getLogger('sentinelx_lite')


def parse_args():
    parser = argparse.ArgumentParser(description="SentinelX Behavioral Detection Engine")
    parser.add_argument("--mode", choices=["live", "background"], default="live")
    parser.add_argument("--log", default="events.log")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def emit_console(message, flush=False):
    if RUN_MODE == 'live':
        print(message, flush=flush)


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
        score += 2

    if signals["cpu"]:
        score += 3

    if signals["file"]:
        score += 4

    return score


def classify_threat(signals):
    """Classify threat type based on signal combination."""
    if signals["burst"] and signals["cpu"] and signals["file"]:
        return "MULTI_VECTOR_BEHAVIOR"

    if signals["burst"] and signals["cpu"]:
        return "PROCESS_SPAWN_ABUSE"

    if signals["cpu"]:
        return "CPU_INTENSIVE_PROCESS"

    if signals["file"]:
        return "FILE_ACTIVITY_SPIKE"

    if signals["burst"]:
        return "PROCESS_SPAWN_BURST"

    return "UNKNOWN"


def explain_threat(category):
    """Return a human-readable reason for the classified threat category."""
    if category == "PROCESS_SPAWN_ABUSE":
        return "Process spawned multiple child processes with sustained high CPU usage"

    if category == "MULTI_VECTOR_BEHAVIOR":
        return "Process shows combined abnormal behavior: spawning, high CPU, and file activity"

    if category == "CPU_INTENSIVE_PROCESS":
        return "Process consuming sustained high CPU over time"

    if category == "FILE_ACTIVITY_SPIKE":
        return "High rate of file operations detected in short time window"

    if category == "PROCESS_SPAWN_BURST":
        return "Process rapidly spawned multiple child processes"

    return "Unclassified behavior detected"


def get_severity(score):
    """Map numeric score to severity level."""
    if score >= 8:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


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


def collect_file_events(directory=MONITORED_DIR):
    """Track file write/create activity in monitored directory."""
    global file_snapshot, file_events
    now = time.time()

    if not os.path.isdir(directory):
        file_snapshot = {}
        return

    current_snapshot = {}

    for root, _, files in os.walk(directory):
        for filename in files:
            path = os.path.join(root, filename)
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue

            current_snapshot[path] = mtime

            if path not in file_snapshot or mtime > file_snapshot[path]:
                file_events.append(("write", path, now))

    file_snapshot = current_snapshot


def detect_file_spike(time_window=5, threshold=30):
    now = time.time()

    recent = [
        e for e in file_events
        if now - e[2] <= time_window
    ]

    return len(recent), recent


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
    emit_console(message)
    if RUN_MODE == 'live':
        send_notification('SentinelX-Lite Alert', message)


def run_monitor():
    previous_snapshot = collect_process_snapshot()
    prev_tree = build_process_tree(previous_snapshot)
    LOGGER.info('Initial snapshot collected with %d processes.', len(previous_snapshot))

    while True:
        try:
            current_snapshot = collect_process_snapshot()
            collect_file_events()

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
                    # Skip kernel processes
                    if parent in {0, 1, 2}:
                        continue
                    
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

            file_count, _ = detect_file_spike(time_window=TIME_WINDOW, threshold=FILE_SPIKE_THRESHOLD)
            if file_count >= FILE_SPIKE_THRESHOLD and should_alert('file_spike'):
                now = time.time()
                file_message = f"[FILE SPIKE] {file_count} file operations in {TIME_WINDOW}s"
                LOGGER.warning(file_message)
                emit_console(file_message, flush=True)
                log_event("FILE_SPIKE", {
                    "count": file_count
                }, LOG_FILE)

                global last_file_spike_time
                last_file_spike_time = now

                for parent in signal_history:
                    signal_history[parent]["file"] = now

            file_events[:] = [
                e for e in file_events
                if time.time() - e[2] <= TIME_WINDOW
            ]

            for evt in events:
                should_emit = False
                
                # Track signals for scoring
                if evt['type'] == 'process_burst':
                    parent = evt.get('parent')
                    if parent is not None:
                        now = time.time()
                        if parent not in signal_history:
                            signal_history[parent] = {}
                        signal_history[parent]["burst"] = now
                        stats = parent_cpu.get(parent, {})
                        max_cpu = stats.get('max', 0)
                        total_cpu = stats.get('total', 0)
                        if max_cpu > 20 or total_cpu > 50:
                            signal_history[parent]["cpu"] = now
                        if now - last_file_spike_time <= SIGNAL_WINDOW:
                            signal_history[parent]["file"] = last_file_spike_time
                    should_emit = True
                    
                elif evt['type'] == 'cpu_spike':
                    # For CPU spikes, track signal on the parent process
                    pid = evt.get('pid')
                    if pid in current_snapshot:
                        parent = current_snapshot[pid].get('ppid', 0)
                        now = time.time()
                        if parent not in signal_history:
                            signal_history[parent] = {}
                        signal_history[parent]["cpu"] = now
                        if now - last_file_spike_time <= SIGNAL_WINDOW:
                            signal_history[parent]["file"] = last_file_spike_time
                    should_emit = True
                    
                elif evt['type'] == 'new_process':
                    # Only alert new processes with high CPU or that are part of bursts
                    cpu = evt.get('cpu_percent', 0.0)
                    if cpu > 20:
                        should_emit = True
                    # Note: burst-related new processes are handled separately via correlated_activity
                    
                elif evt['type'] == 'correlated_activity':
                    parent = evt.get('parent')
                    if parent is not None:
                        now = time.time()
                        if parent not in signal_history:
                            signal_history[parent] = {}
                        signal_history[parent]["cpu"] = now
                    should_emit = True
                
                if should_emit:
                    pid = evt.get('pid') or evt.get('parent')
                    if should_alert(pid):
                        print_alert(evt)
                        log_event(evt['type'], evt, LOG_FILE)

            # Final threat scoring and alerting (state machine + temporal correlation)
            now = time.time()
            candidate_parents = set(signal_history.keys()) | set(threat_active.keys())
            for parent in list(candidate_parents):
                history = signal_history.get(parent, {})
                signals = {
                    "burst": False,
                    "cpu": False,
                    "file": False,
                }

                for key in signals:
                    if key in history and now - history[key] <= SIGNAL_WINDOW:
                        signals[key] = True

                score = calculate_score(signals)
                
                # Initialize threat state if not exists
                if parent not in threat_active:
                    threat_active[parent] = False
                
                # State transition: entering threat state (only alert on transition)
                if score >= ALERT_THRESHOLD and not threat_active[parent]:
                    # Delay burst+file-only entry to allow temporal CPU correlation in the signal window.
                    if signals["burst"] and signals["file"] and not signals["cpu"]:
                        continue

                    threat_active[parent] = True
                    
                    category = classify_threat(signals)
                    severity = get_severity(score)
                    reason = explain_threat(category)
                    active_signals = [k for k, v in signals.items() if v]
                    proc = current_snapshot.get(parent, {})
                    name = proc.get("name", "unknown")
                    ppid = proc.get("ppid")
                    parent_name = "unknown"

                    if ppid is not None and ppid in current_snapshot:
                        parent_name = current_snapshot[ppid].get("name", "unknown")

                    ppid_display = ppid if ppid is not None else "unknown"
                    signals_text = ", ".join(active_signals)
                    msg = (
                        f"[THREAT - {category} | {severity}]\n\n"
                        f"Process : {name} (PID {parent})\n"
                        f"Parent  : {parent_name} (PID {ppid_display})\n\n"
                        f"Signals : {signals_text}\n"
                        f"Score   : {score}\n\n"
                        f"Reason  : {reason}"
                    )

                    emit_console(msg, flush=True)
                    log_event("THREAT", {
                        "parent": parent,
                        "score": score,
                        "signals": signals,
                        "category": category,
                        "severity": severity
                    }, LOG_FILE)
                    if RUN_MODE == 'live':
                        send_notification("SentinelX Alert", msg)
                
                # State transition: exiting threat state (reset when behavior calms)
                elif score < ALERT_THRESHOLD and threat_active[parent]:
                    threat_active[parent] = False

            # Cleanup old signal history
            now = time.time()
            for parent in list(signal_history.keys()):
                signal_history[parent] = {
                    k: t for k, t in signal_history[parent].items()
                    if now - t <= SIGNAL_WINDOW
                }

                if not signal_history[parent]:
                    del signal_history[parent]

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
    args = parse_args()

    LOG_FILE = args.log
    RUN_MODE = args.mode
    QUIET_MODE = args.quiet

    if QUIET_MODE:
        logging.getLogger().setLevel(logging.WARNING)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    LOGGER.info('SentinelX-Lite starting...')
    run_monitor()
