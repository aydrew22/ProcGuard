"""Formatting helpers."""
from __future__ import annotations

import time
from typing import Optional


def fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_age(create_time: Optional[float]) -> str:
    if not create_time:
        return "unknown"
    secs = max(0, int(time.time() - create_time))
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {mins}m"
    if mins:
        return f"{mins}m {secs}s"
    return f"{secs}s"


def fmt_time(ts: Optional[float]) -> str:
    if not ts:
        return "unknown"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
