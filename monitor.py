import logging
import psutil

from utils import safe_int


LOGGER = logging.getLogger(__name__)


def collect_process_snapshot():
    """Return a map pid->process_info for all accessible processes."""
    snapshot = {}

    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            pid = proc.pid
            name = proc.info.get('name') or '<unknown>'
            rss = getattr(proc.info.get('memory_info'), 'rss', 0)
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

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            LOGGER.debug('Skipping process pid=%s: %s', getattr(proc, 'pid', '?'), exc)
            continue
        except Exception as exc:
            LOGGER.exception('Unexpected error while collecting process info for pid=%s', getattr(proc, 'pid', '?'))
            continue

    return snapshot
