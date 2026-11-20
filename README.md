# Heat Doctor

**Find out why your computer runs hot and slow, and fix it in one click.**

Heat Doctor is a lightweight monitor and diagnostics tool for Windows (with basic macOS/Linux support). It watches
temperature, disk activity, CPU, RAM and storage, works out *which programs* are causing the heat, explains them in
plain English, and gives you safe fixes. It also runs a lightweight malware check and can ask Claude for
personalised advice.

- **Heat & disk**: drive temperature, live disk/CPU charts, and a ranked list of the processes heating the machine
  (Windows Search, Defender, cloud sync, updates, browsers, WSL/Docker…), each with an explanation and fix.
- **Memory**: what's using your RAM, and whether Windows is paging to disk (a classic hidden cause of SSD heat).
- **Storage**: finds space hogs (temp files, Windows.old, update cache, Recycle Bin, browser/dev caches, Docker/WSL
  images) and the largest folders in your profile.
- **Security**: lightweight heuristics for fake system processes, crypto-miners, hidden/encoded PowerShell,
  programs running from Temp/Downloads, suspicious startup items and scheduled tasks, and hosts-file tampering.
  It also checks that your antivirus is on and up to date. One click sends any file to Microsoft Defender.
- **One-click fixes**: clean temp files, end a runaway process, run a Defender scan, or jump straight to the right
  Windows setting (Startup apps, Indexing Options, Storage Sense, Delivery Optimization…). Anything that changes
  your system asks first.
- **Ask Claude** (optional): sends a privacy-trimmed summary of the dashboard to Claude and streams back prioritised
  recommendations.

## Built to stay light

A monitor that heats your computer would defeat the point. Heat Doctor:

- uses about **0.1% CPU and ~40 MB of RAM** while running;
- reads every process's CPU, memory and I/O in **one native Windows call** (`NtQuerySystemInformation`, about 20 ms)
  instead of querying hundreds of processes one by one;
- reads performance counters directly through PDH, with no PowerShell process each tick;
- slows its sampling from every 2 s to every 6 s when the dashboard isn't open;
- has **one required dependency** (`psutil`); the Claude SDK is optional and only loaded when you ask a question;
- uses a standard-library web server and a dependency-free UI: no Electron, no Node, no frameworks.

## Install and run

Requires **Python 3.9+** ([python.org](https://www.python.org/downloads/); on Windows, tick "Add python.exe to PATH").

```bash
git clone https://github.com/NoahA6624/heat-doctor.git
cd heat-doctor
pip install -r requirements.txt
python -m heat_doctor
```

Or on Windows, double-click **`start.bat`** (it installs what's needed the first time). On macOS/Linux run `./start.sh`.

Heat Doctor opens as its own app window in Chrome, Edge or Brave if one is installed, and otherwise in your
default browser (Firefox and Safari work too). It runs only on your computer at `http://127.0.0.1:8765`.

Closing the window leaves monitoring running quietly in the background, so the history is there the next time the
machine gets hot. Run the launcher again to reopen it, or press **Quit** in the top bar to stop it completely.

| Option | What it does |
| --- | --- |
| `--open browser` | open in a normal browser tab instead of an app window |
| `--open none` | just run the monitor; open the URL yourself |
| `--port 9000` | use another port |
| `--report 60` | no UI: sample for 60 s and print a diagnosis in the terminal |

### Drive temperature needs administrator rights

Windows only shares the SSD/HDD's own temperature sensor with administrator programs. Everything else works as a
normal user. For the temperature reading, start Heat Doctor with **`run_as_admin.bat`**. If you have
[smartmontools](https://www.smartmontools.org/) installed, Heat Doctor uses `smartctl` as a fallback.

### Ask Claude (optional)

```bash
pip install anthropic
```

Then paste an [Anthropic API key](https://console.anthropic.com/settings/keys) on the *Ask Claude* tab, or set the
`ANTHROPIC_API_KEY` environment variable. Usage is billed to your Anthropic account. The default model is
`claude-opus-5-5`; set `HEAT_DOCTOR_MODEL` to use another.

**What gets sent:** process names, usage numbers, temperatures, storage sizes and security findings, with your
username removed from paths. File contents are never sent, and nothing is sent until you press *Ask*.
If you tick "Remember on this computer", the key is saved in plain text at
`%APPDATA%\HeatDoctor\config.json`, readable by your user account.

## Privacy and security

- All monitoring stays on your machine. Heat Doctor makes no network requests except to the Claude API when you
  use *Ask Claude*.
- The local server listens on `127.0.0.1` only, rejects requests with a foreign `Host` header (DNS rebinding), and
  requires a random per-launch token on every API call, so other websites can't use it through your browser.
- The UI is served with a strict Content-Security-Policy, and all data is HTML-escaped before display.

## Limitations

- The malware check is a **heuristic second opinion, not an antivirus**. It has no signature database and never
  deletes anything by itself. Keep Microsoft Defender (or another antivirus) switched on.
- Per-process "disk" numbers come from Windows I/O counters, which also count some network and device I/O.
- The "heat share" is an estimate that combines disk throughput and CPU time. It ranks suspects well but isn't a
  measurement of watts.
- Some laptops report a fixed value for the ACPI "system sensor"; the drive sensor (admin) is the reliable one.
- macOS and Linux get the monitoring, RAM, storage and diagnosis features; Windows-specific tools (Defender, Startup
  apps, services) are hidden there.

## Project layout

```
heat_doctor/
  collector.py   background sampler (ring buffers, bounded memory)
  winproc.py     one-call process snapshot via NtQuerySystemInformation
  pdh.py         Windows performance counters without PowerShell
  sensors.py     drive temperature / health, thermal zones, power plan
  diagnose.py    rules that turn samples into ranked findings
  knowledge.py   what common processes are and how to tame them
  storage.py     time-boxed storage scan
  security.py    lightweight malware heuristics
  actions.py     one-click fixes
  assistant.py   Ask Claude (Anthropic SDK)
  server.py      local web server + API
  static/        dashboard (plain HTML/CSS/JS)
```

Contributions are welcome, especially new entries for `knowledge.py`.

## License

MIT
