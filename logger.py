import json
import logging

from utils import current_timestamp

LOGGER = logging.getLogger(__name__)


def log_event(event_type, data, log_file='events.log'):
    """Append-only JSON line logging."""
    entry = {
        'time': current_timestamp(),
        'type': event_type,
        'data': data,
    }

    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception as exc:
        LOGGER.exception('Failed to write event to log file: %s', exc)
