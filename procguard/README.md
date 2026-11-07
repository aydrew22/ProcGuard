# ProcGuard

A cross-platform (macOS / Windows / Linux) process monitor in the spirit of Task Manager or
Activity Monitor, but every process is sorted into **High / Medium / Low risk**, and every
flag comes with a plain-English explanation of *why* and *what the process is probably doing*.

## Run it

Needs Python 3.9+ with Tkinter (included with Python on Windows and with the python.org macOS
installer; Linux: `sudo apt install python3-tk`; Homebrew: `brew install python-tk`).

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt    # just psutil
python -m procguard
```

Run the tests: `python -m unittest discover -s tests -v`

See alerts without waiting for real malware: `python -m procguard --demo-alerts` (after ~5 s a
*simulated* high-risk process appears and triggers the banner, alert log and notification).

## Using it

* Processes are grouped into **High**, **Medium** and **Low** (Low is collapsed by default).
  Click any column header to sort; type in *Search* to filter by name, PID, path, user or command.
* Click a process to open the **Inspector**: the score broken down into reasons (`+40 It downloads
  something and pipes it into a shell...`), a description of what it is doing, and full details
  (path, command line, parent, user, connections, listening ports).
* **Mark as trusted** silences a program you know is fine (stored in `~/.procguard/trusted.json`).
* **Terminate process** asks for confirmation and checks the PID still refers to the same process.
* **Alerts**: when a *new* process reaches High risk you get an in-app banner, an entry in the
  *Alert log* tab, and a native notification (macOS and Linux built in; Windows needs `pip install plyer`).
  The first scan after launch is a baseline and produces one summary, not a flood.

## How the scoring works

`procguard/risk_engine.py`. Each rule returns zero or more `Reason(points, text)` objects. Points
are summed: **>= 50 High, >= 20 Medium, otherwise Low**.

| Signal | Points |
|---|---|
| Name of a known attack/mining tool (mimikatz, xmrig...) | 60 |
| Name matches a core OS process but file is outside system folders (masquerading) | 50 |
| Reverse-shell / mining-pool command lines | 50 |
| Linux binary deleted from disk or run from memory (`memfd`) | 45 |
| Office/PDF app spawning a shell | 45 |
| `curl ... \| sh`, encoded PowerShell, LOLBin fetching remote content | 35-40 |
| Runs from a temp folder | 35 |
| Connected to an internet host on a backdoor/IRC/Tor/miner port | 25 |
| Runs from Downloads; dual-use tool (nmap, nc...) | 20 |
| Random-looking name; AppData\Roaming (Windows); high CPU/RAM; remote-access software | 8-15 |

To add a detection, write a function and decorate it with `@rule`:

```python
@rule
def rule_my_check(info):
    if info.name == "weird.exe" and info.cpu_percent > 30:
        yield Reason(20, "Explain to the user WHY this matters.", "behavior")
```

Descriptions for well-known processes live in `procguard/knowledge.py`; add your own there.

## AI monitoring (optional, off by default)

```bash
pip install google-genai
export GEMINI_API_KEY="your-key"        # Windows: setx GEMINI_API_KEY "your-key"
export GEMINI_MODEL="gemini-3.7-flash"  # optional; this is the default, check Google's docs for current names
python -m procguard
```

* **Ask AI about this**: sends one process for a second opinion (benign / suspicious / malicious + explanation).
* **AI auto-review**: continuously reviews *new* Medium/High processes in the background, at most one
  call every 6 seconds, de-duplicated by name + path + command line. If the AI says suspicious or
  malicious you get an alert. Low-risk processes are never sent.
* The AI **never changes the score**; it adds an opinion next to the heuristics.
* **Privacy**: only a redacted summary is sent (name, path, command line, parent name, internet IP:ports,
  heuristic reasons). Home folder and username are masked and password/token-looking values are
  stripped, but redaction is best-effort. The app asks for consent before the first send.
  The prompt also tells the model to treat process data as untrusted, since command lines are
  attacker-controlled and could contain prompt-injection text.
* To use another provider, subclass `Analyzer` in `ai_analyzer.py` and return it from `default_analyzer()`.

## Platform notes and limits

* **This is a heuristic tool, not antivirus.** Expect false positives (a developer running a script from
  `/tmp`, a shell whose command line merely *contains* `curl | sh`) and false negatives (anything
  that looks normal). Use *Mark as trusted* to tune it.
* **Permissions**: without admin/root, macOS and Windows hide the path, command line and network
  connections of other users' and protected system processes. ProcGuard says so instead of guessing.
  On Linux, reading `/proc/<pid>/exe` (needed for the deleted-binary check) also needs root for other users' processes.
* CPU % is share of *total* machine CPU, like Task Manager (not per-core like `top`).
* Network connections are refreshed every 3rd scan to keep scans cheap.

## Ideas for next steps

Code-signature checks (`codesign` on macOS, Authenticode on Windows), SHA-256 lookups against
VirusTotal, autostart/persistence inspection (LaunchAgents, Run keys, cron/systemd), a history
database with a timeline, a system-tray icon, and packaging with PyInstaller into a double-click app.
