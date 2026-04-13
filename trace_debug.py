import json
import time
from collections import defaultdict

from event_stream import get_events_since

TRACE_PID = None  # will be filled dynamically


def log(stage, data):
    print(json.dumps({
        "ts": time.time(),
        "stage": stage,
        **data,
    }))


def run_trace(signal_history, SIGNAL_WINDOW):
    global TRACE_PID

    now = time.time()
    events = get_events_since(now - SIGNAL_WINDOW)

    # STEP 1 - capture candidate PIDs
    file_events = defaultdict(list)

    for e in events:
        if e["type"] == "file_write":
            file_events[e["pid"]].append(e)

    # pick highest activity PID if not set
    if TRACE_PID is None and file_events:
        TRACE_PID = max(file_events, key=lambda p: len(file_events[p]))

    log("trace_pid_selected", {"pid": TRACE_PID})

    for pid, evs in file_events.items():
        count = len(evs)

        log("aggregation", {
            "pid": pid,
            "count": count,
            "is_target": pid == TRACE_PID,
        })

        if count >= 5:
            e = evs[-1]

            create_time = e["meta"].get("create_time")

            if create_time:
                proc_key = (pid, create_time)
                source = "meta"
            else:
                proc_key = (pid, -1)
                source = "fallback"

            log("mapping", {
                "pid": pid,
                "proc_key": proc_key,
                "source": source,
            })

            signal_history.setdefault(proc_key, {})
            signal_history[proc_key]["file"] = now

            log("assignment", {
                "pid": pid,
                "assigned": True,
            })
        else:
            log("assignment", {
                "pid": pid,
                "assigned": False,
                "reason": "count_below_threshold",
            })
