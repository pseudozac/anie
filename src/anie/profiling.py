"""Cross-platform memory and process profiling utilities for ANIE.

Measures true Operating System Resident Set Size (RSS) and peak working set,
distinguishing total process footprint from local Python tracemalloc heap allocations.
Essential for constrained runtime environments such as the 1 GiB Oracle Linux VM.
"""
from __future__ import annotations

import os
import sys
import time
import tracemalloc
from typing import Any, Callable


def get_process_rss() -> dict[str, int]:
    """Return current and peak Resident Set Size (RSS) in bytes for current process."""
    current_rss = 0
    peak_rss = 0

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
        ctypes.windll.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
            current_rss = int(pmc.WorkingSetSize)
            peak_rss = int(pmc.PeakWorkingSetSize)
    else:
        try:
            import resource
            peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # On Linux ru_maxrss is in KiB; on Darwin it is in bytes
            peak_rss = peak_kb * 1024 if sys.platform.startswith("linux") else peak_kb
        except Exception:
            pass

        try:
            with open("/proc/self/statm", "r", encoding="ascii") as f:
                pages = int(f.read().split()[1])
                current_rss = pages * os.sysconf("SC_PAGE_SIZE")
        except Exception:
            current_rss = peak_rss

    if peak_rss < current_rss:
        peak_rss = current_rss

    return {
        "current_rss_bytes": current_rss,
        "peak_rss_bytes": peak_rss,
    }


def profile_execution(func: Callable[[], Any]) -> tuple[Any, dict[str, Any]]:
    """Execute a function while measuring wall time, CPU time, heap allocations, and true RSS."""
    start_rss = get_process_rss()
    tracemalloc.start()
    t0_wall = time.perf_counter()
    t0_cpu = time.process_time()

    try:
        result = func()
    finally:
        t1_wall = time.perf_counter()
        t1_cpu = time.process_time()
        _, peak_heap = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        end_rss = get_process_rss()

    elapsed_wall_ms = round((t1_wall - t0_wall) * 1000.0, 3)
    elapsed_cpu_ms = round((t1_cpu - t0_cpu) * 1000.0, 3)
    peak_rss_mb = round(end_rss["peak_rss_bytes"] / (1024.0 * 1024.0), 3)
    current_rss_mb = round(end_rss["current_rss_bytes"] / (1024.0 * 1024.0), 3)

    profile_metrics = {
        "elapsed_wall_ms": elapsed_wall_ms,
        "elapsed_cpu_ms": elapsed_cpu_ms,
        "peak_heap_bytes": peak_heap,
        "peak_heap_mb": round(peak_heap / (1024.0 * 1024.0), 3),
        "start_rss_bytes": start_rss["current_rss_bytes"],
        "end_rss_bytes": end_rss["current_rss_bytes"],
        "peak_rss_bytes": end_rss["peak_rss_bytes"],
        "peak_rss_mb": peak_rss_mb,
        "current_rss_mb": current_rss_mb,
        "os_name": os.name,
    }

    return result, profile_metrics
