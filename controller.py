import json
import logging
import os

import psutil

from utils import current_timestamp


def decide_action(threat_data):
    """Deterministically map threat severity to control action."""
    severity = threat_data.get("severity", "LOW")

    if severity == "HIGH":
        return {
            "action": "TERMINATE",
            "reason": "Severity HIGH maps to TERMINATE",
        }

    if severity == "MEDIUM":
        return {
            "action": "THROTTLE",
            "reason": "Severity MEDIUM maps to THROTTLE",
        }

    return {
        "action": "NONE",
        "reason": "Severity LOW maps to NONE",
    }


def get_process_tree(pid):
    """Collect all descendants of PID recursively."""
    descendants = []

    try:
        root = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return descendants

    stack = []
    try:
        stack.extend(root.children(recursive=False))
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return descendants

    seen = set()
    while stack:
        proc = stack.pop()
        if proc.pid in seen:
            continue
        seen.add(proc.pid)
        descendants.append(proc)

        try:
            children = proc.children(recursive=False)
            stack.extend(children)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return descendants


def execute_action(action, target_pid, context):
    """Execute deterministic control action for a threat target."""
    if action == "NONE":
        return "success"

    if action == "THROTTLE":
        try:
            current = os.getpriority(os.PRIO_PROCESS, target_pid)
            target_nice = min(current + 10, 19)
            os.setpriority(os.PRIO_PROCESS, target_pid, target_nice)
            return "success"
        except PermissionError:
            return "failed"
        except ProcessLookupError:
            return "failed"
        except OSError:
            return "failed"

    if action == "TERMINATE":
        try:
            descendants = get_process_tree(target_pid)
            descendants.sort(key=lambda p: p.pid)

            for proc in descendants:
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            try:
                psutil.Process(target_pid).kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            return "success"
        except Exception:
            return "failed"

    return "failed"


def log_action(logger, action_data, log_file="events.log"):
    """Append ACTION control event in JSONL format."""
    entry = {
        "timestamp": current_timestamp(),
        "type": "ACTION",
        "data": action_data,
    }

    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        if isinstance(logger, logging.Logger):
            logger.exception("Failed to write ACTION event: %s", exc)
