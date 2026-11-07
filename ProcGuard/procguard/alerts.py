"""Decides WHEN to alert, and sends native desktop notifications (best effort)."""
from __future__ import annotations

import shutil
import subprocess
import sys
import threading
from typing import List, Set, Tuple

from .models import Assessed, Level


class AlertManager:
    """Reports high-risk processes the first time they are seen.

    The very first scan is treated as a baseline: instead of one alert per
    pre-existing process, the caller gets `is_first_scan=True` and can show a
    single summary.
    """

    def __init__(self) -> None:
        self._seen: Set[tuple] = set()
        self._primed = False

    def update(self, assessed: List[Assessed]) -> Tuple[List[Assessed], bool]:
        alive = {a.info.key for a in assessed}
        high = [a for a in assessed if a.risk.level is Level.HIGH]
        new = [a for a in high if a.info.key not in self._seen]
        first = not self._primed
        self._seen = {k for k in self._seen if k in alive} | {a.info.key for a in high}
        self._primed = True
        return new, first


def notify(title: str, message: str) -> None:
    """Fire a native notification without blocking the UI. Never raises."""
    threading.Thread(target=_notify_blocking, args=(title, message), daemon=True).start()


def _notify_blocking(title: str, message: str) -> None:
    try:
        if sys.platform == "darwin":
            # Pass text as argv so process names can't inject AppleScript.
            subprocess.run(
                ["osascript",
                 "-e", "on run argv",
                 "-e", "display notification (item 1 of argv) with title (item 2 of argv)",
                 "-e", "end run", message, title],
                timeout=5, capture_output=True)
        elif sys.platform.startswith("linux"):
            exe = shutil.which("notify-send")
            if exe:
                subprocess.run([exe, "--", title, message], timeout=5, capture_output=True)
        elif sys.platform == "win32":
            try:
                from plyer import notification  # optional dependency
                notification.notify(title=title, message=message, timeout=8)
            except ImportError:
                pass  # in-app alerts still work
    except Exception:
        pass
