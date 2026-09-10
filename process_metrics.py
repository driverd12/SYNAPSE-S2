"""Cheap current-process memory observations, independent of topology estimates.

Darwin layout follows sys/resource.h rusage_info_v0 (RUSAGE_INFO_V0) and
libproc.h proc_pid_rusage. No subprocess, backend lane, or memory-store read.
Unsupported platforms report unavailable values rather than fabricated zeros.
"""
from __future__ import annotations

import ctypes
import os
import sys
import time
from functools import lru_cache


class _RUsageInfoV0(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
        (name, ctypes.c_uint64) for name in (
            "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups",
            "pageins", "wired_size", "resident_size", "phys_footprint",
            "proc_start_abstime", "proc_exit_abstime",
        )
    ]


@lru_cache(maxsize=1)
def _darwin_rusage_function():
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_pid_rusage
    function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    function.restype = ctypes.c_int
    return function


def observe_process_memory() -> dict:
    """Observe this authoritative process; a metric failure is not core failure."""
    result = {
        "pid": os.getpid(),
        "resident_bytes": None,
        "footprint_bytes": None,
        "measured_at_unix_ms": int(time.time() * 1000),
        "source": "unavailable",
        "available": False,
    }
    if sys.platform != "darwin":
        return result
    try:
        usage = _RUsageInfoV0()
        if _darwin_rusage_function()(os.getpid(), 0, ctypes.byref(usage)) != 0:
            return result
        result.update(
            resident_bytes=int(usage.resident_size),
            footprint_bytes=int(usage.phys_footprint),
            source="darwin-proc_pid_rusage-v0",
            available=True,
        )
    except (AttributeError, OSError, TypeError, ValueError):
        pass
    return result
