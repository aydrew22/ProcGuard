"""Rule-based risk scoring.

Every rule is a small function: ProcessInfo -> list[Reason]. Scores are summed and
mapped to HIGH / MEDIUM / LOW. Because each point comes from a named Reason, the UI
can always explain *why* something was flagged.

To add a detection: write a function, decorate it with @rule. That's it.

IMPORTANT: these are heuristics, not a virus scanner. Expect false positives
(e.g. a developer running a script out of /tmp) and false negatives.
"""
from __future__ import annotations

import ipaddress
import math
import os
import re
import sys
from collections import Counter
from typing import Callable, Iterable, List, Optional, Set

from .knowledge import KNOWN
from .models import Assessed, Level, ProcessInfo, Reason, RiskResult
from .util import fmt_age, fmt_bytes

HIGH_THRESHOLD = 50
MEDIUM_THRESHOLD = 20

PLATFORM = sys.platform  # 'darwin', 'win32', 'linux', ...


def _norm(path: Optional[str]) -> str:
    """Lower-case, forward-slash version of a path for platform-neutral matching."""
    return path.replace("\\", "/").lower() if path else ""


def _with_slash(p: str) -> str:
    n = _norm(p)
    return n if n.endswith("/") else n + "/"


# ---------------------------------------------------------------- trusted dirs
def _trusted_dirs() -> tuple:
    if PLATFORM == "win32":
        vars_ = ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")
        dirs = [_with_slash(os.environ[v]) for v in vars_ if os.environ.get(v)]
        return tuple(dirs or ["c:/windows/", "c:/program files/", "c:/program files (x86)/"])
    if PLATFORM == "darwin":
        return ("/system/", "/usr/", "/bin/", "/sbin/", "/library/apple/",
                "/applications/", "/opt/homebrew/")
    return ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/")


def _os_dirs() -> tuple:
    """Where *operating-system* binaries are allowed to live."""
    if PLATFORM == "win32":
        root = os.environ.get("SystemRoot", "C:\\Windows")
        return (_with_slash(root),)
    if PLATFORM == "darwin":
        return ("/system/", "/usr/", "/bin/", "/sbin/", "/library/apple/")
    return ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/")


TRUSTED_DIRS = _trusted_dirs()
OS_DIRS = _os_dirs()

# Names that attackers like to impersonate, per platform (lower-case).
CORE_NAMES = {
    "win32": {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
              "smss.exe", "wininit.exe", "taskhostw.exe", "explorer.exe", "dwm.exe",
              "spoolsv.exe", "runtimebroker.exe", "fontdrvhost.exe", "ctfmon.exe"},
    "darwin": {"launchd", "windowserver", "loginwindow", "finder", "dock", "systemuiserver",
               "mds", "mds_stores", "cfprefsd", "configd", "notifyd", "securityd", "trustd",
               "syslogd", "opendirectoryd", "logd", "fseventsd", "coreaudiod", "bluetoothd"},
    "linux": {"systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "sshd",
              "cron", "dbus-daemon", "rsyslogd", "polkitd", "networkmanager", "udisksd"},
}.get(PLATFORM, set())

TEMP_MARKERS = ("/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/folders/", "/var/folders/",
                "/dev/shm/", "/appdata/local/temp/", "/windows/temp/", "/$recycle.bin/")
DOWNLOAD_MARKERS = ("/downloads/",)

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 6697, 5555, 9001, 9050, 3333, 14444}

KNOWN_BAD = {"mimikatz", "xmrig", "minerd", "cpuminer", "meterpreter", "lazagne", "pwdump",
             "njrat", "darkcomet", "quasar", "cobaltstrike", "keylogger"}
DUAL_USE = {"nc", "ncat", "netcat", "nmap", "masscan", "tcpdump", "tshark", "ettercap",
            "hydra", "hashcat", "sqlmap", "socat", "chisel", "frpc", "ngrok", "psexec"}
REMOTE_ACCESS = {"anydesk", "teamviewer", "rustdesk", "ultraviewer", "vncserver", "x11vnc"}

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe",
                  "acrobat.exe", "foxitreader.exe", "microsoft word", "microsoft excel",
                  "microsoft powerpoint", "microsoft outlook"}
SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                  "mshta.exe", "sh", "bash", "zsh", "osascript"}

# (regex, points, explanation)
CMD_PATTERNS = [
    (re.compile(r"(powershell|pwsh)[^|]*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{30,}", re.I), 35,
     "PowerShell is running an encoded (base64) command. Attackers use this to hide what a script does."),
    (re.compile(r"(curl|wget)\s[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I), 40,
     "It downloads something and pipes it straight into a shell, running remote code without inspection."),
    (re.compile(r"/dev/tcp/|\b(nc|ncat|netcat)\b[^|;]*\s-(e|c)\s|bash\s+-i\s*>&", re.I), 50,
     "The command line matches a classic reverse-shell pattern (it hands a remote machine a shell on this one)."),
    (re.compile(r"(mshta|regsvr32|rundll32)[^|;]*(https?://|javascript:)", re.I), 40,
     "A Windows built-in tool is being pointed at remote or script content, a common way to run malware "
     "while looking like a trusted program."),
    (re.compile(r"certutil[^|;]*-urlcache", re.I), 35,
     "certutil is being used to download a file, which is not its normal job."),
    (re.compile(r"stratum\+(tcp|ssl)://|--donate-level", re.I), 50,
     "The command line contains cryptocurrency-mining pool settings."),
    (re.compile(r"base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh", re.I), 40,
     "It decodes hidden base64 content and executes it."),
    (re.compile(r"\b(python3?|perl|ruby)\b\s+-[ce]\s.*(socket|exec\(|b64decode|base64)", re.I), 25,
     "A one-line script uses sockets/exec/base64 together, a pattern common in quick-and-dirty backdoors."),
    (re.compile(r"osascript.*(do shell script|keystroke)", re.I), 15,
     "AppleScript is running shell commands or sending keystrokes, which is sometimes abused for automation attacks."),
]

Rule = Callable[[ProcessInfo], Iterable[Reason]]
RULES: List[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


# --------------------------------------------------------------------- helpers
def _stem(name: str) -> str:
    n = name.lower()
    return n[:-4] if n.endswith(".exe") else n


def _is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_unspecified)


is_external = _is_external  # public alias used by the GUI and AI payload builder


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in c.values())


def in_trusted_dir(exe: Optional[str]) -> bool:
    p = _norm(exe)
    return bool(p) and p.startswith(TRUSTED_DIRS)


def trust_key(info: ProcessInfo) -> str:
    return info.exe or info.name


# ----------------------------------------------------------------------- rules
@rule
def rule_location(info: ProcessInfo):
    p = _norm(info.exe)
    if not p:
        return
    if any(m in p for m in TEMP_MARKERS):
        yield Reason(35, f"The program file lives in a temporary folder ({info.exe}). Real software is "
                         "almost never installed there, but malware and droppers often run from temp "
                         "folders because any user can write to them.", "location")
    elif any(m in p for m in DOWNLOAD_MARKERS):
        yield Reason(20, f"It is running straight from a Downloads folder ({info.exe}). It may be "
                         "something you just downloaded and have not installed or vetted.", "location")
    elif PLATFORM == "win32" and "/appdata/roaming/" in p:
        yield Reason(15, "It runs from the AppData\\Roaming folder, a user-writable spot that some "
                         "malware uses to persist (though many legitimate apps do too).", "location")


@rule
def rule_deleted_binary(info: ProcessInfo):
    """Linux only: the kernel marks a running binary whose file was deleted (or that
    never had one, e.g. memfd) with ' (deleted)'. psutil hides that suffix, so we
    read the link ourselves. Needs permission to read /proc/<pid>/exe (own processes
    or root); silently skipped otherwise."""
    if PLATFORM != "linux":
        return
    try:
        target = os.readlink(f"/proc/{info.pid}/exe")
    except OSError:
        return
    if target.endswith(" (deleted)"):
        yield Reason(45, "The program file was deleted from disk (or never existed on disk) while "
                         "the process kept running. Malware does this to hide its tracks.", "location")


@rule
def rule_masquerade(info: ProcessInfo):
    if info.name.lower() in CORE_NAMES and info.exe:
        if not _norm(info.exe).startswith(OS_DIRS):
            yield Reason(50, f"Its name matches a core operating-system process, but the file is at "
                             f"{info.exe}, not in a system folder. Malware commonly impersonates "
                             "system processes this way.", "identity")


@rule
def rule_name(info: ProcessInfo):
    stem = _stem(info.name)
    if stem in KNOWN_BAD:
        yield Reason(60, f"'{info.name}' is the name of a well-known attack, credential-stealing or "
                         "crypto-mining tool.", "identity")
    elif stem in DUAL_USE:
        yield Reason(20, f"'{info.name}' is a dual-use network/security tool. Admins and security "
                         "researchers use it legitimately, but so do attackers.", "identity")
    elif stem in REMOTE_ACCESS:
        yield Reason(12, f"'{info.name}' is remote-access software: it lets someone else view or "
                         "control this computer. Fine if you installed it, concerning if not.",
                     "identity")
    if re.fullmatch(r"[a-z0-9]{10,}", stem) and re.search(r"\d", stem) and re.search(r"[a-z]", stem) \
            and _entropy(stem) >= 3.3:
        yield Reason(15, f"The name '{info.name}' looks randomly generated. Malware often uses "
                         "random names to avoid detection.", "identity")


@rule
def rule_cmdline(info: ProcessInfo):
    cmd = info.cmd
    if not cmd or len(cmd) > 8000:
        return
    for rx, pts, text in CMD_PATTERNS:
        if rx.search(cmd):
            yield Reason(pts, text, "behavior")


@rule
def rule_parent_child(info: ProcessInfo):
    if info.parent_name and info.parent_name.lower() in OFFICE_PARENTS \
            and info.name.lower() in SHELL_CHILDREN:
        yield Reason(45, f"It was launched by '{info.parent_name}'. Documents and office apps "
                         "starting a command shell is a classic sign of a malicious macro or exploit.",
                     "behavior")


@rule
def rule_network(info: ProcessInfo):
    ext = [(ip, port) for ip, port in info.remote if _is_external(ip)]
    bad = sorted({port for _, port in ext if port in SUSPICIOUS_PORTS})
    if bad:
        yield Reason(25, f"It is connected to an internet host on port(s) {', '.join(map(str, bad))}, "
                         "ports commonly used by backdoors, IRC botnets, Tor or mining pools.", "network")
    if len(ext) > 25:
        yield Reason(10, f"It has {len(ext)} simultaneous connections to internet hosts, which is "
                         "unusually many (could be scanning, a botnet or a busy server).", "network")
    wide = [port for ip, port in info.listening if ip in ("0.0.0.0", "::", "*")]
    if wide and not in_trusted_dir(info.exe):
        yield Reason(8, f"It is accepting connections from other machines on port(s) "
                        f"{', '.join(map(str, sorted(set(wide))[:5]))}, and it does not live in a "
                        "standard application folder.", "network")


@rule
def rule_resources(info: ProcessInfo):
    if info.cpu_percent >= 85:
        yield Reason(15, f"It is using {info.cpu_percent:.0f}% of the machine's total CPU. Sustained "
                         "load like this can mean a runaway task or a crypto-miner.", "resource")
    elif info.cpu_percent >= 50:
        yield Reason(8, f"It is using {info.cpu_percent:.0f}% of the machine's total CPU.", "resource")
    if info.mem_percent >= 25:
        yield Reason(12, f"It is holding {info.mem_percent:.0f}% of all RAM "
                         f"({fmt_bytes(info.mem_rss)}).", "resource")


# ---------------------------------------------------------------- descriptions
def describe(info: ProcessInfo) -> str:
    lookup = re.sub(r"\s*\(.*\)$", "", info.name).lower()
    base = KNOWN.get(lookup) or KNOWN.get(_stem(lookup))
    if not base:
        m = re.search(r"/([^/]+)\.app(/|$)", (info.exe or "").replace("\\", "/"), re.I)
        p = _norm(info.exe)
        home = _norm(os.path.expanduser("~")) + "/"
        if m:
            base = f"Part of the application \u201c{m.group(1)}\u201d."
        elif p.startswith(OS_DIRS):
            base = "A component of the operating system or a command-line tool installed on this machine."
        elif p.startswith(TRUSTED_DIRS):
            base = "A program installed in a standard application folder."
        elif p.startswith(home):
            base = "A program living in a user folder rather than being installed system-wide."
        elif not p:
            base = ("Its file location is hidden from this app (usually a permissions limit), so it "
                    "cannot be identified from the path.")
        else:
            base = "No description is known for this program. Judge it by where it lives and what it does."

    bits = [base]
    bits.append(f"Right now it is using {info.cpu_percent:.1f}% of total CPU and "
                f"{fmt_bytes(info.mem_rss)} of memory across {info.num_threads} thread(s).")
    ext = sum(1 for ip, _ in info.remote if _is_external(ip))
    if info.remote:
        bits.append(f"It has {len(info.remote)} open network connection(s), {ext} to the internet.")
    if info.listening:
        ports = ", ".join(str(p) for p in sorted({p for _, p in info.listening})[:6])
        bits.append(f"It is listening for incoming connections on port(s) {ports}.")
    who = f" by {info.username}" if info.username else ""
    parent = f", launched by {info.parent_name}" if info.parent_name else ""
    bits.append(f"It started {fmt_age(info.create_time)} ago{who}{parent}.")
    return " ".join(bits)


# ---------------------------------------------------------------------- engine
class RiskEngine:
    def __init__(self, trusted: Optional[Set[str]] = None):
        self.trusted: Set[str] = trusted if trusted is not None else set()

    def assess(self, info: ProcessInfo) -> RiskResult:
        reasons: List[Reason] = []
        if info.pid == os.getpid():
            reasons.append(Reason(0, "This is ProcGuard itself.", "info"))
        elif trust_key(info) in self.trusted:
            reasons.append(Reason(0, "You marked this program as trusted, so it is not scored.", "info"))
        else:
            for fn in RULES:
                try:
                    reasons.extend(fn(info) or [])
                except Exception:  # a buggy rule must never break the scan
                    continue
            if not reasons and in_trusted_dir(info.exe):
                reasons.append(Reason(0, "It runs from a standard system/application folder and "
                                         "nothing unusual was observed.", "info"))
        score = sum(r.points for r in reasons)
        level = (Level.HIGH if score >= HIGH_THRESHOLD
                 else Level.MEDIUM if score >= MEDIUM_THRESHOLD else Level.LOW)
        return RiskResult(score, level, reasons, describe(info))

    def assess_all(self, infos: Iterable[ProcessInfo]) -> List[Assessed]:
        return [Assessed(i, self.assess(i)) for i in infos]
