# ProcGuard

A cross-platform (macOS / Windows / Linux) process monitor in the spirit of Task Manager or
Activity Monitor, but every process is sorted into **High / Medium / Low risk**, and every
flag comes with a plain-English explanation of *why* and *what the process is probably doing*.

## Updated interface

The GUI uses a navy and teal theme with your ProcGuard icon, clickable process and
risk summary cards, and a resizable side-by-side process list and inspector.
Click a risk card or filter to narrow the process list. Counts on the summary cards
always describe the full scan; the list header shows the filtered count.
Search matches names, PIDs, paths, users and command lines. Use Ctrl+F (Cmd+F on
macOS) to focus search and Escape to clear it. Scroll horizontally for additional
process columns or drag the divider to give the table or inspector more space.

Pause suspends periodic scans; Refresh now still requests a scan. AI review,
trust management, risk scoring and termination confirmation use the existing
project logic. AI auto-review is disabled until an AI provider is configured.

To update your existing project, replace `procguard/gui.py` and copy the
`procguard/assets` directory beside it. This package also includes the full
source and a launcher so you can run it separately. Existing trust settings are
still loaded from the same user configuration folder.

Validation: 49 automated tests passed, including performance sampling, Gemini
response handling, privacy, and guarded termination. Python source compilation passed. The desktop window could not be visually checked in the
build environment; verify layout on your operating system before distributing.

## Junk finder with Gemini performance advice

Open the **Junk finder** tab while monitoring is running. It automatically updates
from the same process snapshots as the security monitor. Performance analysis is
separate from malware risk: a legitimate app can be resource-heavy.

- **CPU:** considers up to five recent scans. Sustained CPU advice needs at least
  three samples at or above 10% of total machine CPU, a recent average of at
  least 10%, and at least four seconds of observation. Long sampling gaps reset
  the history. A first-scan zero or brief spike is not a sustained-load verdict.
- **Memory:** flags at least 500 MiB of resident memory, or at least 5% of RAM
  with at least 128 MiB resident. RSS may include shared pages; it is not a
  promise of reclaimable RAM. No system memory-pressure measurement is made.
- Sort by impact, CPU, or memory. The search field filters both tabs. Enable
  **Show all processes** to inspect smaller apps too.
- The details explain local guidance and recommend quitting normally, closing
  browser tabs, or using pause controls for syncing and updates.
- Essential desktop/system services, recognised security software, other-user
  processes, ProcGuard and its launcher, incomplete identities, and simulated
  entries have termination disabled in the Junk finder. This is a conservative
  safeguard, not proof that every other process is safe to close.
- **Terminate selected** asks for confirmation and rechecks identity and ownership.
  It sends a termination request and checks for exit in the background. A process
  that ignores the request stays listed with a message; no force-kill is sent.

### Turn on Gemini

Create a key in [Google AI Studio](https://aistudio.google.com/apikey). On macOS
or Linux, run these commands from the extracted project directory:

```bash
python -m pip install -r requirements.txt
python -m pip install google-genai
read -s -p "Gemini API key: " GEMINI_API_KEY; echo
export GEMINI_API_KEY
python -m procguard
```

The `read` form above is for bash. In macOS's default zsh shell, use:

```zsh
read -s "GEMINI_API_KEY?Gemini API key: "; echo
export GEMINI_API_KEY
python -m procguard
```

Keys are read from the environment; they are never saved inside the project.
You can also use an existing `GEMINI_API_KEY` or `GOOGLE_API_KEY`. The default
model is `gemini-flash-latest`; set `GEMINI_MODEL` to use a model your account
supports. Restart the app after changing its environment or installing the SDK.

1. Select a row and choose **Gemini: review selected**, or choose
   **Gemini: review top 5** for the leading visible resource-heavy candidates.
2. Approve the performance-summary prompt once for the session.
3. Read **Keep running**, **Review first**, or **Consider closing**, with an
   explanation and caution. Gemini cannot determine whether you need an app.
4. Save your work and quit through the app where possible. ProcGuard never
   closes anything based solely on the AI opinion.

Only process/parent names, OS type, CPU/RAM observations and protection status
are sent. Names receive best-effort redaction. Paths, command lines, usernames,
PIDs, IP addresses and file contents are omitted from performance requests.
Names can still reveal the apps you use. Security AI review retains its own
separate consent and payload described below.

Performance reviews are manual: up to five per batch, a bounded queue, and at
least six seconds between calls. Pending duplicates are skipped. Advice is
attached to the sampled process identity and resource bucket; when these change
materially, a fresh review is required. Completed opinions remain for that
workload until you explicitly retry a selected process. API charges may apply.
Invalid responses fall back to manual review. Errors show a retry message without
echoing raw provider errors. Local protections always override AI advice.

### Safe demo

```bash
python -m procguard --demo-alerts
```

After the third scan, a simulated high-risk dropper and a simulated medium-risk,
resource-heavy browser helper appear. Open **Junk finder** to inspect the helper.
These are records only: they start no programs, use no extra CPU/RAM and cannot
be terminated. A selected demo row can be reviewed by Gemini using your API key;
**review top 5** excludes protected and simulated entries. Close and restart
normally to remove the demo records.

### Scope and validation

This finder reviews running processes only; it does not delete junk files,
uninstall apps, change startup settings, or identify every cause of slowness.
Automated tests use synthetic process data and mocked process-control and API
calls. Live Gemini requests were not tested without your credentials. The GUI
still needs a visual check on your desktop operating system.

Gemini integration follows the [Google Gen AI Python SDK](https://googleapis.github.io/python-genai/)
using structured JSON output and a separate system instruction for process data.

## Run it

Needs Python 3.9+ with Tkinter (included with Python on Windows and with the python.org macOS
installer; Linux: `sudo apt install python3-tk`; Homebrew: `brew install python-tk`).

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-ai.txt    # just psutil
python -m procguard
```

Run the tests: `python -m unittest discover -s tests -v`

See alerts without waiting for real malware: `python -m procguard --demo-alerts` (after ~5 s
*simulated* high- and medium-risk processes appear; the high-risk entry triggers the banner, alert log and notification).

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
export GEMINI_MODEL="gemini-flash-latest"  # optional; this is the default, check Google's docs for current names
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
