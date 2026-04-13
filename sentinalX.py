import argparse
import json
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
from controller import decide_action, execute_action, log_action
from event_stream import get_events_since
from ebpf_collector import start_ebpf_collector

LOG_FILE = 'events.log'
CPU_SPIKE_THRESHOLD = 50.0
last_alert_time = {}
ALERT_COOLDOWN = 5
spawn_history = {}  # parent -> list of child creation timestamps
TIME_WINDOW = 5  # seconds
BURST_THRESHOLD = 5
burst_alerted = {}  # parent -> last burst alert timestamp
cpu_history = {}  # (pid, create_time) -> consecutive high CPU count
cpu_alerted = {}  # (pid, create_time) -> alert state (True/False)
CPU_CONFIRMATION = 3  # cycles
threat_active = {}  # (pid, create_time) -> True/False (threat state tracking)
ALERT_THRESHOLD = 5
FILE_SPIKE_THRESHOLD = 50
MONITORED_DIR = 'test_dir'
TEST_TMP_PREFIX = '/tmp/test_'
file_events = []  # (event_type, path, timestamp)
file_snapshot = {}  # path -> last modified time
dir_mtime_snapshot = {}  # directory -> last modified time
signal_history = {}  # (pid, create_time) -> {"burst": ts, "cpu_sustained": ts, "cpu_instant": ts, "file": ts}
SIGNAL_WINDOW = 5  # seconds
SIGNAL_HISTORY_RETENTION = 20  # seconds; validator-facing retention only
pid_identity_cache = {}
# structure:
# pid -> {
#     "create_time": float | None,
#     "last_seen": float
# }
last_file_spike_time = 0.0
last_file_alert_time = 0.0
RUN_MODE = 'live'
QUIET_MODE = False
SIGNAL_HISTORY_SNAPSHOT_FILE = 'signal_history_snapshot.json'

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


def write_signal_history_snapshot():
    """Export current signal_history for validator-only introspection."""
    rows = []
    for (pid, create_time), signals in signal_history.items():
        rows.append({
            "pid": pid,
            "create_time": create_time,
            "signals": signals,
        })

    tmp_path = SIGNAL_HISTORY_SNAPSHOT_FILE + '.tmp'
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(rows, f)
        os.replace(tmp_path, SIGNAL_HISTORY_SNAPSHOT_FILE)
    except Exception:
        pass


def make_proc_key(proc):
    return (proc["pid"], proc["create_time"])


def get_proc_key(snapshot, pid):
    proc = snapshot.get(pid)
    if proc is None:
        return (pid, 0)
    return make_proc_key(proc)


def should_alert(entity_key):
    """Check if enough time has passed since last alert for this process key."""
    now = time.time()

    if entity_key not in last_alert_time:
        last_alert_time[entity_key] = now
        return True

    if now - last_alert_time[entity_key] > ALERT_COOLDOWN:
        last_alert_time[entity_key] = now
        return True

    return False


def calculate_score(signals):
    """Calculate threat score from signal combination."""
    score = 0

    if signals["burst"]:
        score += 2

    if signals["cpu_sustained"]:
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
    global file_snapshot, file_events, dir_mtime_snapshot
    now = time.time()

    if not os.path.isdir(directory):
        file_snapshot = {}
        dir_mtime_snapshot = {}
        return

    # Capture rapid create/delete churn via directory mtime transitions.
    # This preserves polling architecture while reducing blind spots for short-lived files.
    try:
        dir_mtime = os.path.getmtime(directory)
        prev_dir_mtime = dir_mtime_snapshot.get(directory)
        if prev_dir_mtime is not None and dir_mtime > prev_dir_mtime:
            file_events.append(("write", directory, now))
        dir_mtime_snapshot[directory] = dir_mtime
    except OSError:
        pass

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
    global last_file_spike_time, last_file_alert_time
    ebpf_active = start_ebpf_collector()
    self_pid = os.getpid()
    self_ppid = os.getppid()
    previous_snapshot = collect_process_snapshot()
    prev_tree = build_process_tree(previous_snapshot)
    LOGGER.info('Initial snapshot collected with %d processes.', len(previous_snapshot))

    while True:
        try:
            current_snapshot = collect_process_snapshot()
            collect_file_events()
            cycle_now = time.time()
            effective_signal_window = max(SIGNAL_WINDOW, 5)

            for pid, proc in current_snapshot.items():
                pid_identity_cache[pid] = {
                    "create_time": proc.get("create_time", 0),
                    "last_seen": cycle_now,
                }

            window_events = get_events_since(cycle_now - effective_signal_window)
            import psutil

            def resolve_event_pid(raw_event):
                raw_pid = raw_event.get("pid")
                if isinstance(raw_pid, int):
                    return raw_pid
                return None

            for event in window_events:
                if event.get("type") != "exec":
                    continue

                pid = resolve_event_pid(event)

                if pid is None:
                    continue

                try:
                    p = psutil.Process(pid)
                    create_time = p.create_time()
                except Exception:
                    create_time = None

                pid_identity_cache[pid] = {
                    "create_time": create_time,
                    "last_seen": cycle_now
                }

            exec_counts = {}
            file_events_by_pid = {}
            for ll_event in window_events:
                evt_type = ll_event.get("type")
                evt_pid = resolve_event_pid(ll_event)
                if evt_type == "file_write":
                    print(f"[FILE RAW PID] {ll_event.get('pid')} -> {evt_pid}")
                if evt_type == "exec":
                    exec_counts[evt_pid] = exec_counts.get(evt_pid, 0) + 1
                elif evt_type == "file_write":
                    if isinstance(evt_pid, int):
                        file_events_by_pid.setdefault(evt_pid, []).append(ll_event)

            ebpf_burst_candidates = {
                pid: count for pid, count in exec_counts.items()
                if count >= BURST_THRESHOLD
            }
            if ebpf_burst_candidates:
                LOGGER.debug("eBPF burst candidates: %s", ebpf_burst_candidates)

            events = []
            events.extend(detect_new_processes(previous_snapshot, current_snapshot))
            events.extend(detect_cpu_spikes(current_snapshot, CPU_SPIKE_THRESHOLD))

            curr_tree = build_process_tree(current_snapshot)
            
            # Detect new children and update spawn history
            burst_alerts = []
            new_children_map = {}
            for parent, curr_children in curr_tree.items():
                prev_children = prev_tree.get(parent, [])
                new_children = list(set(curr_children) - set(prev_children))
                
                if new_children:
                    # Skip kernel processes
                    if parent in {0, 1, 2}:
                        continue

                    new_children_map[parent] = new_children
                    
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

            parent_cpu = calculate_parent_cpu_stats(curr_tree, current_snapshot, new_children_map)
            
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

            now = time.time()
            has_recent_file_activity = False
            if not ebpf_active:
                file_count, _ = detect_file_spike(time_window=TIME_WINDOW, threshold=FILE_SPIKE_THRESHOLD)
                has_recent_file_activity = file_count > 0
                if file_count >= FILE_SPIKE_THRESHOLD and now - last_file_alert_time > ALERT_COOLDOWN:
                    now = time.time()
                    file_message = f"[FILE SPIKE] {file_count} file operations in {TIME_WINDOW}s"
                    LOGGER.warning(file_message)
                    emit_console(file_message, flush=True)
                    log_event("FILE_SPIKE", {
                        "count": file_count
                    }, LOG_FILE)

                    last_file_alert_time = now
                    last_file_spike_time = now

            file_events[:] = [
                e for e in file_events
                if time.time() - e[2] <= TIME_WINDOW
            ]

            for evt in events:
                should_emit = False
                alert_key = None
                
                # Track signals for scoring
                if evt['type'] == 'process_burst':
                    parent = evt.get('parent')
                    if parent is not None:
                        now = time.time()
                        parent_key = get_proc_key(current_snapshot, parent)
                        if parent_key not in signal_history:
                            signal_history[parent_key] = {}
                        signal_history[parent_key]["burst"] = now
                        parent_cpu_now = current_snapshot.get(parent, {}).get("cpu_percent", 0.0)
                        if parent_cpu_now > 20:
                            signal_history[parent_key]["cpu_sustained"] = now
                        stats = parent_cpu.get(parent, {})
                        max_cpu = stats.get('max', 0)
                        total_cpu = stats.get('total', 0)
                        if max_cpu > 20 or total_cpu > 50:
                            signal_history[parent_key]["cpu_instant"] = now
                        alert_key = parent_key
                    should_emit = True
                    
                elif evt['type'] == 'cpu_spike':
                    # For CPU spikes, keep signal ownership on the process that generated CPU
                    pid = evt.get('pid')
                    if pid in current_snapshot:
                        now = time.time()
                        proc_key = make_proc_key(current_snapshot[pid])
                        if proc_key not in signal_history:
                            signal_history[proc_key] = {}
                        signal_history[proc_key]["cpu_sustained"] = now
                        alert_key = proc_key
                    should_emit = True
                    
                elif evt['type'] == 'new_process':
                    # Only alert new processes with high CPU or that are part of bursts
                    cpu = evt.get('cpu_percent', 0.0)
                    if cpu > 20:
                        should_emit = True
                        pid = evt.get('pid')
                        if pid in current_snapshot:
                            alert_key = make_proc_key(current_snapshot[pid])
                    # Note: burst-related new processes are handled separately via correlated_activity
                    
                elif evt['type'] == 'correlated_activity':
                    parent = evt.get('parent')
                    if parent is not None:
                        now = time.time()
                        parent_key = get_proc_key(current_snapshot, parent)
                        if parent_key not in signal_history:
                            signal_history[parent_key] = {}
                        signal_history[parent_key]["cpu_instant"] = now
                        parent_cpu_now = current_snapshot.get(parent, {}).get("cpu_percent", 0.0)
                        if parent_cpu_now > 20:
                            signal_history[parent_key]["cpu_sustained"] = now
                        alert_key = parent_key
                    should_emit = True
                
                if should_emit and alert_key is not None:
                    if should_alert(alert_key):
                        print_alert(evt)
                        log_event(evt['type'], evt, LOG_FILE)

            # V4 Phase 2 bridge: assign file signal strictly from eBPF PID event buckets.
            if ebpf_active:
                now = time.time()
                for pid, events in file_events_by_pid.items():
                    count = len(events)
                    if count < FILE_SPIKE_THRESHOLD:
                        continue

                    # Prefer event-time identity from eBPF metadata for short-lived writers.
                    event_create_time = None
                    for evt in events:
                        meta = evt.get("meta") or {}
                        ct = meta.get("create_time")
                        if ct is not None:
                            event_create_time = ct
                            break

                    if event_create_time is not None:
                        proc_key = (pid, event_create_time)
                        pid_identity_cache[pid] = {
                            "create_time": event_create_time,
                            "last_seen": now,
                        }
                    elif pid in current_snapshot:
                        proc = current_snapshot[pid]
                        proc_key = make_proc_key(proc)
                        pid_identity_cache[pid] = {
                            "create_time": proc.get("create_time", 0),
                            "last_seen": now,
                        }
                    elif pid in pid_identity_cache:
                        cached = pid_identity_cache[pid]
                        proc_key = (pid, cached.get("create_time", 0))
                    else:
                        continue

                    signal_history.setdefault(proc_key, {})
                    signal_history[proc_key]["file"] = now
                    print(f"[FILE SIGNAL SET] pid={pid} count={count}")

            # Final threat scoring and alerting (state machine + temporal correlation)
            now = time.time()
            candidate_entities = set(signal_history.keys()) | set(threat_active.keys())
            for entity in list(candidate_entities):
                history = signal_history.get(entity, {})
                signals = {
                    "burst": False,
                    "cpu_sustained": False,
                    "cpu_instant": False,
                    "file": False,
                }

                for key in signals:
                    if key in history and now - history[key] <= SIGNAL_WINDOW:
                        signals[key] = True

                score = calculate_score(signals)
                score_signals = {
                    "burst": signals["burst"],
                    "cpu": signals["cpu_sustained"],
                    "file": signals["file"],
                }
                
                # Initialize threat state if not exists
                if entity not in threat_active:
                    threat_active[entity] = False
                
                # State transition: entering threat state (only alert on transition)
                if score >= ALERT_THRESHOLD and not threat_active[entity]:
                    # Hold burst+cpu-only entries so file activity can still join the same entity
                    # within the correlation window. This keeps multi-vector alignment intact.
                    if score_signals["burst"] and score_signals["cpu"] and not score_signals["file"]:
                        continue

                    # Delay burst+file-only entry to allow temporal CPU correlation in the signal window.
                    if score_signals["burst"] and score_signals["file"] and not score_signals["cpu"]:
                        continue

                    threat_active[entity] = True
                    entity_pid = entity[0]
                    
                    category = classify_threat(score_signals)
                    severity = get_severity(score)
                    reason = explain_threat(category)
                    active_signals = [k for k, v in score_signals.items() if v]
                    proc = current_snapshot.get(entity_pid, {})
                    name = proc.get("name", "unknown")
                    ppid = proc.get("ppid")
                    parent_name = "unknown"

                    if ppid is not None and ppid in current_snapshot:
                        parent_name = current_snapshot[ppid].get("name", "unknown")

                    ppid_display = ppid if ppid is not None else "unknown"
                    signals_text = ", ".join(active_signals)
                    context = get_process_context(entity_pid)
                    children_data = analyze_children(entity_pid, current_snapshot, curr_tree)
                    file_data = analyze_file_activity(file_events, entity_pid, now)
                    cmdline_value = context.get("cmdline")
                    cmdline_text = " ".join(cmdline_value) if cmdline_value else "unknown"
                    msg = (
                        f"[THREAT - {category} | {severity}]\n\n"
                        f"Process : {name} (PID {entity_pid})\n"
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
                        "parent": entity_pid,
                        "score": score,
                        "signals": score_signals,
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

                    # V3 Control Layer: deterministic post-THREAT action.
                    decision = decide_action(threat_data)
                    action = decision["action"]
                    action_reason = decision["reason"]
                    action_status = "success"
                    action_key = ("action", entity_pid, entity[1])

                    # Cooldown guard for control actions, reusing existing alert cooldown state.
                    action_allowed = True
                    if action_key in last_alert_time and now - last_alert_time[action_key] <= ALERT_COOLDOWN:
                        action_allowed = False
                        action_reason = f"{action_reason} (cooldown_guard)"
                        action_status = "skipped"

                    # Stale PID guard: act only if process identity still matches current snapshot.
                    proc_still_valid = (
                        entity_pid in current_snapshot
                        and current_snapshot[entity_pid].get("create_time", 0) == entity[1]
                    )

                    if not proc_still_valid:
                        action_status = "failed"
                        action_reason = f"{action_reason} (stale_pid_guard)"
                    elif action_allowed:
                        action_status = execute_action(action, entity_pid, context)
                        last_alert_time[action_key] = time.time()

                    log_action(
                        LOGGER,
                        {
                            "action": action,
                            "target": entity_pid,
                            "severity": severity,
                            "category": category,
                            "reason": action_reason,
                            "status": action_status,
                        },
                        LOG_FILE,
                    )

                    if RUN_MODE == 'live':
                        send_notification("SentinelX Alert", msg)
                
                # State transition: exiting threat state (reset when behavior calms)
                elif score < ALERT_THRESHOLD and threat_active[entity]:
                    threat_active[entity] = False

            # Cleanup state for dead processes using PID+create_time keys
            active_keys = set(
                (pid, proc.get("create_time", 0))
                for pid, proc in current_snapshot.items()
            )
            cache_keys = set(
                (pid, meta.get("create_time", 0))
                for pid, meta in pid_identity_cache.items()
            )
            tracked_keys = active_keys | cache_keys

            now = time.time()
            for pid in list(pid_identity_cache.keys()):
                cached = pid_identity_cache[pid]

                if now - cached["last_seen"] > SIGNAL_WINDOW:
                    del pid_identity_cache[pid]

            for state_dict in [cpu_history, cpu_alerted, threat_active, signal_history]:
                for key in list(state_dict.keys()):
                    if key in tracked_keys:
                        continue
                    if state_dict is signal_history and key[1] == 0:
                        history = state_dict.get(key, {})
                        if any(now - t <= SIGNAL_WINDOW for t in history.values()):
                            continue
                    del state_dict[key]

            for key in list(last_alert_time.keys()):
                if isinstance(key, tuple) and len(key) == 3 and key[0] == "action":
                    entity_key = (key[1], key[2])
                    if entity_key not in tracked_keys:
                        del last_alert_time[key]
                elif key not in tracked_keys:
                    del last_alert_time[key]

            # Cleanup old signal history timestamps
            now = time.time()
            for entity in list(signal_history.keys()):
                signal_history[entity] = {
                    k: t for k, t in signal_history[entity].items()
                    if now - t <= SIGNAL_HISTORY_RETENTION
                }

                if not signal_history[entity]:
                    del signal_history[entity]

            write_signal_history_snapshot()

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
