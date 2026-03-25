from datetime import datetime


def current_timestamp():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
