import argparse
import logging
import os
import re
import signal
import sys
import time

from monitor import collect_process_snapshot
from detector import detect_new_processes, detect_cpu_spikes, build_process_tree, calculate_parent_cpu_stats, detect_correlated_activity
from logger import log_event
from notifier import send_notification
from context import get_process_context

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


def analyze_children(parent_pid, snapshot, tree):
    """
    Analyze child processes of given parent.
    
    Returns dict with 'summary' containing list of child groups sorted by CPU descending.
    Each group: {"name": "...", "count": ..., "cpu_total": ...}
    """
    child_pids = tree.get(parent_pid, [])
    
    if not child_pids:
        return {"summary": []}
    
    # Group children by process name
    groups = {}
    for pid in child_pids:
        if pid not in snapshot:
            continue
        
        name = snapshot[pid].get("name", "unknown")
        cpu = snapshot[pid].get("cpu_percent", 0.0)
        
        if name not in groups:
            groups[name] = {"count": 0, "cpu_total": 0.0}
        
        groups[name]["count"] += 1
        groups[name]["cpu_total"] += cpu
    
    # Convert to list and sort by CPU descending
    summary = [
        {"name": name, "count": data["count"], "cpu_total": data["cpu_total"]}
        for name, data in groups.items()
    ]
    summary.sort(key=lambda x: x["cpu_total"], reverse=True)
    
    return {"summary": summary}


def analyze_file_activity(file_events, parent_pid, current_time):
    """
    Analyze file activity within signal window for temporal correlation.
    
    Returns dict with directory, operations, and pattern, or None if no relevant activity.
    """
    if not file_events:
        return None
    
    # Filter events within signal window
    window_start = current_time - SIGNAL_WINDOW
    recent_events = [
        e for e in file_events
        if e[2] >= window_start
    ]
    
    if not recent_events:
        return None
    
    # Group by directory
    dir_counts = {}
    operations = []
    filenames = []
    
    for op, path, timestamp in recent_events:
        directory = os.path.dirname(path)
        if not directory:
            directory = "."
        
        if directory not in dir_counts:
            dir_counts[directory] = 0
        dir_counts[directory] += 1
        
        operations.append(op)
        filenames.append(os.path.basename(path))
    
    # Pick directory with most activity
    if not dir_counts:
        return None
    
    primary_dir = max(dir_counts, key=dir_counts.get)
    
    # Determine operation type
    write_count = operations.count("write")
    create_count = operations.count("create")
    total_ops = len(operations)
    
    if total_ops == 0:
        return None
    elif write_count == total_ops:
        op_type = "write"
    elif create_count == total_ops:
        op_type = "create"
    else:
        op_type = "mixed"
    
    # Detect pattern
    pattern = "burst"  # Default
    
    # Check for sequential pattern (incrementing numbers or common prefix)
    if len(filenames) > 1:
        # Look for numeric patterns or common prefixes
        numeric_files = []
        for fname in filenames:
            # Extract base name without extension
            base = fname.rsplit('.', 1)[0]
            numeric_files.append(base)
        
        # Check if names share prefix and have numeric suffixes
        if len(set(numeric_files)) < len(numeric_files):
            # Some repetition in naming (same prefix)
            pattern = "sequential"
        else:
            # Check for numeric increments
            numbers = []
            for fname in numeric_files:
                # Try to find trailing numbers
                match = re.search(r'(\d+)$', fname)
                if match:
                    numbers.append(int(match.group(1)))
            
            if len(numbers) > 1:
                # Check if numbers are sequential or close
                numbers.sort()
                diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]
                if all(d == 1 for d in diffs):
                    pattern = "sequential"
    
    # Ensure proper directory format
    if not primary_dir.endswith('/'):
        primary_dir = primary_dir + '/'
    
    return {
        "directory": primary_dir,
        "operations": op_type,
        "pattern": pattern
    }


def build_explanation(threat_data):
    """
    Build a human-readable explanation from threat data.
    
    Returns dict with process, behavior list, reasoning, and conclusion.
    """
    # Extract components from threat_data
    context = threat_data.get("context", {})
    signals = threat_data.get("signals", {})
    children_data = threat_data.get("children", {})
    file_activity = threat_data.get("file_activity")
    category = threat_data.get("category", "UNKNOWN")
    severity = threat_data.get("severity", "UNKNOWN")
    parent_pid = threat_data.get("parent", "unknown")
    process_name = threat_data.get("process_name", "unknown")
    
    # === PROCESS SECTION ===
    exe = context.get("exe", "unknown")
    cmdline = context.get("cmdline", [])
    
    # Extract just the executable name from full path
    exe_name = os.path.basename(exe) if exe != "unknown" else "unknown"
    if exe_name == "unknown" and process_name != "unknown":
        exe_name = process_name
    
    main_script = None
    if cmdline and isinstance(cmdline, list):
        for arg in cmdline[1:]:
            arg_text = str(arg)
            if arg_text and not arg_text.startswith("-"):
                main_script = os.path.basename(arg_text)
                break
        if not main_script and cmdline:
            main_script = os.path.basename(str(cmdline[0]))
    
    if main_script:
        process = f"{exe_name} ({main_script})"
    else:
        process = f"{exe_name} (PID {parent_pid})"
    
    # === BEHAVIOR SECTION (LIST) ===
    behavior = []
    children_summary = children_data.get("summary", [])
    
    if signals.get("cpu") and signals.get("burst"):
        if children_summary:
            top_child = children_summary[0]
            child_name = top_child.get("name", "unknown")
            child_count = top_child.get("count", 0)
            behavior.append(
                f"Spawned {child_count} {child_name} child processes, with one consuming high CPU"
            )
        else:
            behavior.append("Concurrent process spawning and sustained high CPU usage detected")
    elif signals.get("cpu"):
        if children_summary:
            top_child = children_summary[0]
            child_name = top_child.get("name", "unknown")
            behavior.append(f"High CPU driven by {child_name} child processes")
        else:
            behavior.append("Sustained high CPU usage detected")
    
    if signals.get("burst") and not signals.get("cpu"):
        if children_summary:
            top_child = children_summary[0]
            child_name = top_child.get("name", "unknown")
            child_count = top_child.get("count", 0)
            behavior.append(f"Spawned {child_count} {child_name} child processes rapidly")
        else:
            behavior.append("Spawned multiple child processes rapidly")
    
    if file_activity:
        directory = file_activity.get("directory", "unknown")
        pattern = file_activity.get("pattern", "unknown")
        operations = file_activity.get("operations", "unknown")
        if operations == "write":
            op_text = "file writes"
        elif operations == "create":
            op_text = "file creations"
        else:
            op_text = "file operations"
        behavior.append(f"Performed rapid {pattern} {op_text} in {directory}")
    
    # === REASONING SECTION ===
    burst = signals.get("burst", False)
    cpu = signals.get("cpu", False)
    file_ops = signals.get("file", False) or bool(file_activity)
    
    if burst and cpu and file_ops:
        reasoning = "Concurrent process spawning, sustained CPU usage, and file operations indicate automated execution behavior."
    elif burst and cpu:
        reasoning = "Concurrent process spawning and sustained CPU usage indicate automated execution behavior."
    elif cpu and file_ops:
        reasoning = "Sustained CPU usage with file activity suggests intensive file processing."
    elif burst and file_ops:
        reasoning = "Process spawning with file activity suggests automated file manipulation."
    elif burst:
        reasoning = "Rapid process spawning suggests automation or abuse."
    elif cpu:
        reasoning = "Sustained high CPU usage suggests resource-intensive execution."
    elif file_ops:
        reasoning = "File activity within the signal window suggests rapid file operations."
    else:
        reasoning = "Suspicious behavior detected."
    
    # === CONFIDENCE SECTION ===
    if burst and cpu and file_ops:
        confidence = 0.92
    elif burst and cpu:
        confidence = 0.82
    elif cpu and file_ops:
        confidence = 0.78
    elif burst and file_ops:
        confidence = 0.72
    elif burst or cpu or file_ops:
        confidence = 0.55
    else:
        confidence = 0.5
    
    # === CONCLUSION SECTION ===
    conclusion = f"{category} ({severity})"
    
    return {
        "process": process,
        "behavior": behavior,
        "reasoning": reasoning,
        "conclusion": conclusion,
        "confidence": confidence
    }
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
                    context = get_process_context(parent)
                    children_data = analyze_children(parent, current_snapshot, curr_tree)
                    file_data = analyze_file_activity(file_events, parent, now)
                    cmdline_value = context.get("cmdline")
                    cmdline_text = " ".join(cmdline_value) if cmdline_value else "unknown"
                    msg = (
                        f"[THREAT - {category} | {severity}]\n\n"
                        f"Process : {name} (PID {parent})\n"
                        f"Parent  : {parent_name} (PID {ppid_display})\n\n"
                        f"Signals : {signals_text}\n"
                        f"Score   : {score}\n\n"
                        f"Reason  : {reason}\n\n"
                        f"Context :\n"
                        f"  exe     : {context.get('exe') or 'unknown'}\n"
                        f"  cmdline : {cmdline_text}\n"
                        f"  cwd     : {context.get('cwd') or 'unknown'}"
                    )

                    emit_console(msg, flush=True)
                    threat_data = {
                        "parent": parent,
                        "score": score,
                        "signals": signals,
                        "category": category,
                        "severity": severity,
                        "context": context,
                        "children": children_data,
                        "process_name": name
                    }
                    if file_data is not None:
                        threat_data["file_activity"] = file_data
                    
                    # Build explanation (Phase 4)
                    explanation = build_explanation(threat_data)
                    threat_data.pop("process_name", None)
                    threat_data["explanation"] = explanation
                    
                    log_event("THREAT", threat_data, LOG_FILE)
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
