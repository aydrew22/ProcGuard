"""Local performance advice, independent of security risk and AI opinions."""
from __future__ import annotations

import os
import sys
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .models import ProcessInfo

MIB = 1024 * 1024
CRITICAL_NAMES = {
    "kernel_task", "launchd", "windowserver", "loginwindow", "finder", "dock",
    "systemuiserver", "securityd", "trustd", "mds", "mds_stores", "configd",
    "notifyd", "syslogd", "opendirectoryd", "logd", "fseventsd", "coreaudiod",
    "system", "registry", "secure system", "memory compression", "system idle process",
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "dwm.exe", "taskhostw.exe",
    "systemd", "init", "sshd", "cron", "dbus-daemon", "polkitd", "networkmanager",
    "gnome-shell", "plasmashell", "xorg", "xwayland", "sddm", "gdm", "gdm3",
    "msmpeng.exe", "mssense.exe", "securityhealthservice.exe", "windefend",
    "clamd", "clamscan", "sophos", "falcond", "sentineld", "endpointsecurityd",
}


def protection_reason(info: ProcessInfo, own_pid: int, owner: str,
                      ancestors: Iterable[int] = (), platform: str = sys.platform) -> str:
    """Conservative local veto. AI can never override this decision."""
    name = info.name.casefold()
    path = (info.exe or "").replace("\\", "/").casefold()
    if info.simulated or "(simulated)" in name:
        return "Simulated entry: no real process exists to terminate."
    if info.pid <= 1 or info.pid == own_pid or info.pid in ancestors:
        return "ProcGuard, its launcher, or an essential operating-system process."
    if not info.create_time:
        return "Process identity is incomplete; termination is disabled."
    if not owner or not info.username or info.username.casefold() != owner.casefold():
        return "Owned by the system, another user, or an unknown account."
    if name in CRITICAL_NAMES or name.startswith(("systemd-", "kworker/", "ksoftirqd/")):
        return "Essential desktop, operating-system, or security service."
    if any(word in name for word in ("antivirus", "crowdstrike", "sentinelone", "sophos", "defender")):
        return "Security software: keep protection running."
    if platform == "darwin" and path.startswith(("/system/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/library/apple/")):
        return "macOS system service."
    if platform == "win32":
        windows = os.environ.get("SystemRoot", "C:/Windows").replace("\\", "/").casefold().rstrip("/")
        if path.startswith(windows + "/"):
            return "Windows system component."
    if platform.startswith("linux") and path.startswith(("/usr/lib/systemd/", "/lib/systemd/", "/usr/libexec/")):
        return "Linux system service."
    if info.status in ("zombie", "dead"):
        return "Already exited; its parent must collect its exit status."
    return ""


@dataclass
class Finding:
    info: ProcessInfo
    average_cpu: float
    samples: int
    sample_seconds: float
    impact: str
    reasons: List[str]
    advice: str
    protected: str
    rank: float

    @property
    def flagged(self) -> bool:
        return bool(self.reasons)

    @property
    def can_terminate(self) -> bool:
        return not self.protected


class PerformanceEngine:
    def __init__(self, own_pid: int, owner: str, ancestors: Iterable[int] = ()):
        self.own_pid = own_pid
        self.owner = owner
        self.ancestors = set(ancestors)
        self._history: Dict[tuple, deque] = {}

    def assess(self, infos: Iterable[ProcessInfo], now: Optional[float] = None) -> List[Finding]:
        now = time.monotonic() if now is None else now
        infos = list(infos)
        live = {i.key for i in infos}
        self._history = {k: v for k, v in self._history.items() if k in live}
        out = []
        for info in infos:
            hist = self._history.setdefault(info.key, deque(maxlen=5))
            # A long pause is not evidence of sustained CPU load.
            if hist and now - hist[-1][0] > 30:
                hist.clear()
            hist.append((now, max(0.0, info.cpu_percent)))
            avg = sum(cpu for _, cpu in hist) / len(hist)
            seconds = max(0.0, now - hist[0][0])
            ready = len(hist) >= 3 and seconds >= 4
            reasons = []
            impact = "Low measured impact"
            if ready and avg >= 10 and sum(cpu >= 10 for _, cpu in hist) >= 3:
                reasons.append(f"Averaged {avg:.1f}% of total machine CPU over {seconds:.0f} seconds.")
                impact = "Sustained CPU use"
            if info.mem_rss >= 500 * MIB or (info.mem_percent >= 5 and info.mem_rss >= 128 * MIB):
                reasons.append(f"Uses {info.mem_rss / MIB:.0f} MiB resident memory ({info.mem_percent:.1f}% of RAM).")
                impact = "CPU + memory" if reasons[:-1] else "Memory heavy"
            if not ready and info.cpu_percent >= 10 and not reasons:
                impact = "Measuring CPU…"
            name = info.name.casefold()
            if any(x in name for x in ("chrome", "firefox", "safari", "edge", "webkit", "browser")):
                advice = "Close unused browser tabs or quit the browser normally first. A helper may serve several tabs; ending it can crash a tab or interrupt work."
            elif any(x in name for x in ("dropbox", "onedrive", "syncthing", "backup", "update", "installer")):
                advice = "This may be syncing, backing up, or updating. Check progress and pause it inside the app instead of terminating active work."
            else:
                advice = "If you recognize this app and are not using it, save your work and quit it normally. Terminate only if it will not close."
            if not reasons:
                advice = "No strong CPU or memory signal yet. Closing this process may make little difference. " + advice
            protected = protection_reason(info, self.own_pid, self.owner, self.ancestors)
            if protected:
                advice = protected + " Check its owning application or system settings instead."
            rank = (avg if ready else 0) + min(60, info.mem_rss / (128 * MIB))
            out.append(Finding(info, avg, len(hist), seconds, impact, reasons, advice, protected, rank))
        return sorted(out, key=lambda f: (f.flagged, f.rank), reverse=True)
