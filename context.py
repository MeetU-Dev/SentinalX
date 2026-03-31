import psutil


def get_process_context(pid: int) -> dict:
    """Return executable path, cmdline, and cwd for a process in a failure-safe way."""
    fallback = {
        "exe": None,
        "cmdline": None,
        "cwd": None,
    }

    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return fallback
    except Exception:
        return fallback

    context = {
        "exe": None,
        "cmdline": None,
        "cwd": None,
    }

    try:
        context["exe"] = proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    except Exception:
        pass

    try:
        context["cmdline"] = proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    except Exception:
        pass

    try:
        context["cwd"] = proc.cwd()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    except Exception:
        pass

    return context
