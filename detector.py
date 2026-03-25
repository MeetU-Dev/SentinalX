import logging

LOGGER = logging.getLogger(__name__)


def detect_new_processes(prev_snapshot, curr_snapshot):
    """Detect new processes with filtering for noise reduction."""
    new = []
    IGNORED_NAMES = {"sleep", "kworker", "cpuUsage.sh"}

    prev_pids = set(prev_snapshot.keys())

    for pid, info in curr_snapshot.items():
        if pid not in prev_pids:
            name = info.get('name', '')
            ppid = info.get('ppid', 0)
            mem = info.get('rss', 0)

            # Filter kernel/system noise
            if ppid in {0, 1, 2}:
                continue
            if mem == 0:
                continue

            # Filter useless process names
            if any(name.startswith(ignored) for ignored in IGNORED_NAMES):
                continue

            new.append({
                'type': 'new_process',
                'pid': pid,
                'name': name,
                'cpu_percent': info.get('cpu_percent'),
                'rss': mem,
                'ppid': ppid,
            })

    LOGGER.debug('New processes detected: %d', len(new))
    return new


def detect_cpu_spikes(curr_snapshot, threshold=50.0):
    """Detect sustained CPU spikes with state machine - alert only on transitions."""
    from sentinalX import cpu_history, CPU_CONFIRMATION, cpu_alerted
    spikes = []

    for pid, proc in curr_snapshot.items():
        cpu = proc.get('cpu_percent', 0.0)

        # Initialize state for new PIDs
        if pid not in cpu_history:
            cpu_history[pid] = 0
            cpu_alerted[pid] = False

        # Update consecutive high CPU count
        if cpu > threshold:
            cpu_history[pid] = cpu_history[pid] + 1
        else:
            cpu_history[pid] = 0

        # Alert only when crossing threshold (not already alerted)
        if cpu_history[pid] >= CPU_CONFIRMATION and not cpu_alerted[pid]:
            spikes.append({
                'type': 'cpu_spike',
                'pid': pid,
                'name': proc.get('name'),
                'cpu': cpu,
            })
            cpu_alerted[pid] = True

        # Reset alert state when CPU drops significantly
        if cpu < 30:
            cpu_alerted[pid] = False

    LOGGER.debug('CPU spike events detected: %d', len(spikes))
    return spikes


def build_process_tree(snapshot):
    """Build parent->children mapping from process snapshot."""
    tree = {}

    for pid, data in snapshot.items():
        ppid = data.get('ppid')

        if ppid not in tree:
            tree[ppid] = []

        tree[ppid].append(pid)

    LOGGER.debug('Process tree built with %d parent nodes', len(tree))
    return tree


def detect_spawn_burst(prev_tree, curr_tree, threshold=5):
    """Detect parents spawning too many NEW children within time window."""
    bursts = []

    for parent, curr_children in curr_tree.items():
        prev_children = prev_tree.get(parent, [])
        new_children = list(set(curr_children) - set(prev_children))

        if len(new_children) >= threshold:
            bursts.append({
                'type': 'process_burst',
                'parent': parent,
                'new_children': new_children,
                'count': len(new_children),
            })

    LOGGER.debug('Process burst events detected: %d', len(bursts))
    return bursts


def calculate_parent_cpu_stats(tree, snapshot):
    """Calculate comprehensive CPU statistics for all children of each parent."""
    stats = {}

    for parent, children in tree.items():
        cpu_values = [
            snapshot[child].get('cpu_percent', 0.0)
            for child in children
            if child in snapshot
        ]

        if cpu_values:
            total_cpu = sum(cpu_values)
            max_cpu = max(cpu_values)
            avg_cpu = total_cpu / len(cpu_values)
            count = len(cpu_values)
        else:
            total_cpu = max_cpu = avg_cpu = 0.0
            count = 0

        stats[parent] = {
            "total": total_cpu,
            "max": max_cpu,
            "avg": avg_cpu,
            "count": count
        }

    LOGGER.debug('Calculated CPU stats for %d parents', len(stats))
    return stats


def detect_correlated_activity(burst_alerts, cpu_stats):
    """Correlate spawn bursts with high child CPU usage using quality + intensity metrics."""
    alerts = []
    IGNORED_PARENTS = {0, 1, 2}  # kernel, init, kthreadd

    for alert in burst_alerts:
        parent = alert['parent']

        # Skip known system parents
        if parent in IGNORED_PARENTS:
            continue

        stats = cpu_stats.get(parent, {})
        total = stats.get("total", 0)
        max_cpu = stats.get("max", 0)
        count = stats.get("count", 0)

        # Improved correlation logic: structure + intensity
        # Requires: 3+ children AND (high max CPU OR high total CPU)
        if count >= 3 and (max_cpu > 50 or total > 120):
            alerts.append({
                'type': 'correlated_activity',
                'parent': parent,
                'new_children': alert['new_children'],
                'count': count,
                'total_cpu': total,
                'max_cpu': max_cpu,
            })

    LOGGER.debug('Correlated activity events detected: %d', len(alerts))
    return alerts


def classify_threat(signals):
    if signals.get("burst") and signals.get("cpu") and signals.get("file"):
        return "MULTI_VECTOR_BEHAVIOR"

    if signals.get("burst") and signals.get("cpu"):
        return "PROCESS_SPAWN_ABUSE"

    if signals.get("cpu"):
        return "CPU_INTENSIVE_PROCESS"

    if signals.get("file"):
        return "FILE_ACTIVITY_SPIKE"

    if signals.get("burst"):
        return "PROCESS_SPAWN_BURST"

    return "UNKNOWN"
