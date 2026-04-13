import ctypes as ct
import importlib
import logging
import threading
import time

from event_stream import push_event

LOGGER = logging.getLogger(__name__)

_COLLECTOR_STARTED = False
_COLLECTOR_LOCK = threading.Lock()
pid_counts = {}

BPF_PROGRAM = """
typedef unsigned int u32;

struct data_t {
    u32 pid;
};

BPF_PERF_OUTPUT(events);

int trace_write(void *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint)]

def start_ebpf_collector():
    global _COLLECTOR_STARTED

    with _COLLECTOR_LOCK:
        if _COLLECTOR_STARTED:
            return True

    try:
        bcc_mod = importlib.import_module("bcc")
        BPF = getattr(bcc_mod, "BPF")
    except Exception as exc:
        LOGGER.warning("eBPF collector unavailable; fallback active: %s", exc)
        return False

    try:
        bpf = BPF(text=BPF_PROGRAM)
        print("[eBPF] Compile success")
    except Exception as e:
        print("[eBPF ERROR] Compile failed:", e)
        return False

    attach_points = [
        "__x64_sys_write",
        "sys_write",
        "ksys_write",
    ]

    attached = False
    for sym in attach_points:
        try:
            bpf.attach_kprobe(event=sym, fn_name="trace_write")
            print(f"[eBPF] Attached to: {sym}")
            attached = True
            break
        except Exception as e:
            print(f"[eBPF] Failed attach: {sym} -> {e}")

    if not attached:
        print("[eBPF ERROR] No valid write probe found")
        return False

    print("[eBPF] write probe active")

    def handle_event(cpu, data, size):
        global pid_counts
        try:
            event = ct.cast(data, ct.POINTER(Data)).contents
            pid = int(event.pid)
            prev_count = pid_counts.get(pid, 0)
            pid_counts[pid] = prev_count + 1

            # Optional kernel/system noise filter.
            if pid < 300:
                return

            # Prioritize first events from new PIDs; rate-limit sustained noisy PIDs.
            if prev_count > 0 and pid_counts[pid] > 1000:
                return

            if pid_counts[pid] % 100 == 0:
                print(f"[eBPF EVENT] pid={pid} count={pid_counts[pid]}")

            try:
                import psutil
                p = psutil.Process(event.pid)

                meta = {
                    "create_time": p.create_time(),
                    "name": p.name(),
                    "cmdline": p.cmdline(),
                }

            except Exception:
                meta = {
                    "create_time": None,
                    "name": None,
                    "cmdline": None,
                }

            push_event({
                "type": "file_write",
                "pid": int(event.pid),
                "timestamp": time.time(),
                "meta": meta,
            })
        except Exception:
            return

    try:
        bpf["events"].open_perf_buffer(handle_event)
    except Exception as exc:
        print("[eBPF ERROR] Failed to open perf buffer:", exc)
        return False

    running = True

    def run_loop():
        nonlocal running
        while running:
            try:
                bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                running = False
                break
            except Exception as e:
                print("[eBPF ERROR] Poll failed:", e)

    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()

    with _COLLECTOR_LOCK:
        _COLLECTOR_STARTED = True

    LOGGER.info("eBPF collector started")
    return True
