"""Collects process + network information in a cross-platform way via psutil."""
from __future__ import annotations

import sys
from typing import Dict, List, Tuple

import psutil

from .models import ProcessInfo

_ATTRS = [
    "pid", "ppid", "name", "exe", "cmdline", "username", "create_time",
    "status", "num_threads", "cpu_percent", "memory_percent", "memory_info",
]

_ConnStore = Dict[int, Tuple[list, list]]


class Collector:
    """Call snapshot() repeatedly. The first call reports 0% CPU for everything
    (psutil needs two samples to compute a rate); later calls are accurate."""

    def __init__(self, connection_every: int = 3):
        self._ncpu = psutil.cpu_count(logical=True) or 1
        self._tick = 0
        self._connection_every = max(1, connection_every)
        self._conns: _ConnStore = {}
        # Remember whether the fast system-wide socket listing works. On macOS it
        # needs root, so we fall back to asking each process individually.
        self._global_conns_ok = True

    # ------------------------------------------------------------------ public
    def snapshot(self) -> List[ProcessInfo]:
        refresh_conns = self._tick % self._connection_every == 0
        self._tick += 1

        raw = []
        objs = {}
        for p in psutil.process_iter(_ATTRS, ad_value=None):
            d = p.info
            pid = d.get("pid")
            if pid is None:
                continue
            if sys.platform == "win32" and pid == 0:  # "System Idle Process"
                continue
            raw.append(d)
            objs[pid] = p

        if refresh_conns:
            self._conns = self._collect_connections(objs)

        names = {d["pid"]: (d.get("name") or "") for d in raw}
        out: List[ProcessInfo] = []
        for d in raw:
            pid = d["pid"]
            mem = d.get("memory_info")
            remote, listening = self._conns.get(pid, ([], []))
            cpu = (d.get("cpu_percent") or 0.0) / self._ncpu
            out.append(
                ProcessInfo(
                    pid=pid,
                    ppid=d.get("ppid"),
                    name=d.get("name") or f"pid {pid}",
                    exe=d.get("exe") or None,
                    cmdline=list(d.get("cmdline") or []),
                    username=d.get("username"),
                    create_time=d.get("create_time"),
                    status=d.get("status"),
                    num_threads=d.get("num_threads") or 0,
                    cpu_percent=min(100.0, max(0.0, cpu)),
                    mem_percent=d.get("memory_percent") or 0.0,
                    mem_rss=getattr(mem, "rss", 0) if mem else 0,
                    parent_name=names.get(d.get("ppid") or -1) or None,
                    remote=list(remote),
                    listening=list(listening),
                )
            )
        return out

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _add(store: _ConnStore, pid: int, c) -> None:
        remote, listening = store.setdefault(pid, ([], []))
        if c.status == psutil.CONN_LISTEN and c.laddr:
            listening.append((c.laddr.ip, c.laddr.port))
        elif c.status == psutil.CONN_ESTABLISHED and c.raddr:
            remote.append((c.raddr.ip, c.raddr.port))

    def _collect_connections(self, objs: Dict[int, psutil.Process]) -> _ConnStore:
        store: _ConnStore = {}
        if self._global_conns_ok:
            try:
                for c in psutil.net_connections(kind="inet"):
                    if c.pid is not None:
                        self._add(store, c.pid, c)
                return store
            except (psutil.AccessDenied, PermissionError, OSError):
                self._global_conns_ok = False
        # Fallback: per-process lookup (works for your own processes without root).
        for pid, p in objs.items():
            fn = getattr(p, "net_connections", None) or getattr(p, "connections", None)
            if fn is None:
                break
            try:
                for c in fn(kind="inet"):
                    self._add(store, pid, c)
            except (psutil.AccessDenied, psutil.NoSuchProcess,
                    psutil.ZombieProcess, OSError):
                continue
        return store
