import logging
import time
import psutil

from utils import safe_int


LOGGER = logging.getLogger(__name__)
_PREV_CPU_TIMES = {}
_PREV_CPU_SAMPLE_TS = None


def collect_process_snapshot():
    """Return a map pid->process_info for all accessible processes."""
    snapshot = {}
    global _PREV_CPU_TIMES, _PREV_CPU_SAMPLE_TS
    now = time.time()

    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            pid = proc.pid
            name = proc.info.get('name') or '<unknown>'
            rss = getattr(proc.info.get('memory_info'), 'rss', 0)
            try:
                cpu_times = proc.cpu_times()
                cpu_total = float(cpu_times.user) + float(cpu_times.system)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu_total = 0.0

            cpu = 0.0
            prev = _PREV_CPU_TIMES.get(pid)
            if prev is not None and _PREV_CPU_SAMPLE_TS is not None:
                prev_total, prev_ts = prev
                delta_wall = max(now - prev_ts, 1e-6)
                delta_cpu = max(cpu_total - prev_total, 0.0)
                cpu = (delta_cpu / delta_wall) * 100.0
            else:
                cpu = proc.cpu_percent(interval=0.0)
            
            try:
                create_time = proc.create_time()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                create_time = 0

            try:
                ppid = proc.ppid()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                ppid = 0

            snapshot[pid] = {
                'pid': pid,
                'name': name,
                'cpu_percent': float(cpu),
                'rss': safe_int(rss),
                'create_time': create_time,
                'ppid': ppid,
            }
            _PREV_CPU_TIMES[pid] = (cpu_total, now)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            LOGGER.debug('Skipping process pid=%s: %s', getattr(proc, 'pid', '?'), exc)
            continue
        except Exception as exc:
            LOGGER.exception('Unexpected error while collecting process info for pid=%s', getattr(proc, 'pid', '?'))
            continue

    _PREV_CPU_SAMPLE_TS = now

    return snapshot
