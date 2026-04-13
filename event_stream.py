from collections import defaultdict, deque


event_queue = defaultdict(lambda: deque(maxlen=200))


VALID_TYPES = {"exec", "file_write"}


def push_event(event: dict):
    """Push a low-level event into the bounded in-memory queue."""
    if not isinstance(event, dict):
        return

    required = {"type", "pid", "timestamp", "meta"}
    if not required.issubset(event.keys()):
        return

    if event["type"] not in VALID_TYPES:
        return

    if not isinstance(event["pid"], int):
        return

    if not isinstance(event["timestamp"], (int, float)):
        return

    if not isinstance(event["meta"], dict):
        return

    pid = event["pid"]
    event_queue[pid].append(event)


def get_events_since(ts: float):
    """Return all buffered events with timestamp >= ts across all PID queues."""
    events = []

    for pid_queue in event_queue.values():
        for event in pid_queue:
            if event["timestamp"] >= ts:
                events.append(event)

    return events
