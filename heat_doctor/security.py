"""Lightweight malware heuristics.

This is NOT an antivirus: there are no signatures and nothing is quarantined
automatically. It looks for the behaviours that commonly give malware away and
that also make machines run hot (crypto-miners), and it checks that the real
antivirus is switched on. Everything it flags comes with an explanation and the
user decides what to do.
"""
from __future__ import annotations

import os
import re
import threading
import time

import psutil

from .util import IS_WINDOWS, as_list, powershell_json

WINDIR = os.environ.get("WINDIR", r"C:\Windows").lower()
SYSTEM32 = os.path.join(WINDIR, "system32")
SYSWOW64 = os.path.join(WINDIR, "syswow64")

# Core Windows processes that malware likes to impersonate, with where they must live.
CORE_PROCESSES = {
    "svchost.exe": {SYSTEM32, SYSWOW64}, "lsass.exe": {SYSTEM32}, "csrss.exe": {SYSTEM32},
    "winlogon.exe": {SYSTEM32}, "services.exe": {SYSTEM32}, "smss.exe": {SYSTEM32},
    "wininit.exe": {SYSTEM32}, "dwm.exe": {SYSTEM32}, "taskhostw.exe": {SYSTEM32},
    "runtimebroker.exe": {SYSTEM32}, "spoolsv.exe": {SYSTEM32}, "conhost.exe": {SYSTEM32},
    "dllhost.exe": {SYSTEM32, SYSWOW64}, "lsm.exe": {SYSTEM32}, "explorer.exe": {WINDIR},
    "ctfmon.exe": {SYSTEM32, SYSWOW64}, "sihost.exe": {SYSTEM32}, "fontdrvhost.exe": {SYSTEM32},
}
# Common typo-squats of the above.
LOOKALIKES = {"scvhost.exe", "svch0st.exe", "svhost.exe", "svchosts.exe", "lsas.exe", "lsasss.exe",
              "csrsss.exe", "expl0rer.exe", "explore.exe", "winlogin.exe", "taskhost32.exe", "rundII32.exe"}

MINER_NAMES = {"xmrig", "xmr-stak", "nicehash", "minerd", "cpuminer", "ethminer", "nbminer", "t-rex",
               "phoenixminer", "lolminer", "gminer", "teamredminer", "nanominer", "srbminer", "ccminer", "bfgminer"}
MINER_ARGS = re.compile(r"stratum\+(tcp|ssl)://|--donate-level|cryptonight|randomx|\bpool\.(minexmr|supportxmr|hashvault)", re.I)

SUSPICIOUS_CMD = [
    (re.compile(r"powershell.*\s-(e|en|enc|encodedcommand)\s", re.I), "PowerShell running an encoded (hidden) command"),
    (re.compile(r"powershell.*(-w|-windowstyle)\s+hidden", re.I), "PowerShell running in a hidden window"),
    (re.compile(r"(iex|invoke-expression).*(downloadstring|net\.webclient|invoke-webrequest|iwr)", re.I), "PowerShell downloading and running code"),
    (re.compile(r"mshta(\.exe)?\s+[\"']?(https?:|javascript:|vbscript:)", re.I), "mshta running remote/inline script"),
    (re.compile(r"regsvr32.*/i:\s*https?:", re.I), "regsvr32 loading a remote script"),
    (re.compile(r"certutil.*-urlcache.*-f", re.I), "certutil being used to download files"),
    (re.compile(r"bitsadmin.*/transfer", re.I), "bitsadmin being used to download files"),
    (re.compile(r"(wscript|cscript)(\.exe)?\s+.*\\(temp|appdata\\roaming|downloads|users\\public)\\.*\.(js|jse|vbs|vbe|wsf)", re.I), "Script host running a script from a user-writable folder"),
    (re.compile(r"rundll32(\.exe)?\s+[\"']?.*\\(temp|appdata\\roaming|users\\public)\\", re.I), "rundll32 loading a DLL from a user-writable folder"),
]

_RISKY_DIR = re.compile(
    r"\\(appdata\\local\\temp|windows\\temp|users\\public|\$recycle\.bin|downloads|appdata\\roaming)\\", re.I)
# Very common legitimate apps that live under AppData\Roaming (so we don't cry wolf).
_ROAMING_OK = re.compile(r"\\appdata\\roaming\\(zoom|spotify|microsoft|mozilla|npm|python|discord|"
                         r"telegram desktop|signal|code|jetbrains|obsidian|notion)", re.I)


def _risky_location(path: str) -> str | None:
    p = path.lower()
    if not _RISKY_DIR.search(p):
        return None
    if "\\appdata\\roaming\\" in p and _ROAMING_OK.search(p):
        return None
    for label, needle in (("Temp folder", "\\temp\\"), ("Public user folder", "\\users\\public\\"),
                          ("Recycle Bin", "$recycle.bin"), ("Downloads folder", "\\downloads\\"),
                          ("AppData\\Roaming", "\\appdata\\roaming\\")):
        if needle in p:
            return label
    return "user-writable folder"





def _signatures(paths: list[str]) -> dict[str, dict]:
    # Paths come from untrusted processes. They're passed to the script as data on stdin, one per line,
    # so only absolute single-line paths are accepted.
    paths = [p for p in paths if p and os.path.isabs(p) and re.match(r"^[A-Za-z]:\\", p)
             and "\n" not in p and "\r" not in p]
    if not IS_WINDOWS or not paths:
        return {}
    data = powershell_json("signature_check.ps1", stdin="\n".join(paths[:40]), timeout=40)
    out = {}
    for d in as_list(data):
        signer = d.get("signer") or ""
        m = re.search(r"CN=\"?([^,\"]+)", signer)
        out[(d.get("path") or "").lower()] = {"status": d.get("status"), "signer": m.group(1) if m else ""}
    return out


def _startup_entries() -> list[dict]:
    entries = []
    if not IS_WINDOWS:
        return entries
    import winreg
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"),
    ]
    for hive, path, label in keys:
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    entries.append({"name": name, "command": str(value), "where": label})
                    i += 1
        except OSError:
            continue
    for folder, label in ((os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "Startup folder"),
                          (os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp"), "All-users Startup folder")):
        try:
            for f in os.listdir(folder):
                if f.lower() != "desktop.ini":
                    entries.append({"name": f, "command": os.path.join(folder, f), "where": label})
        except OSError:
            pass
    return entries


def _cmd_flags(cmd: str) -> list[str]:
    return [why for rx, why in SUSPICIOUS_CMD if rx.search(cmd)]


def _exe_from_command(cmd: str) -> str:
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith('"'):
        return cmd[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|bat|cmd|vbs|js|ps1|lnk|com|scr))\b", cmd, re.I)
    return m.group(1) if m else cmd.split(" ")[0]


class SecurityScanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.state = {"status": "idle", "finished": None, "findings": [], "startup": [], "defender": None,
                      "av": [], "counts": {}, "scanned_processes": 0}

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self.state)

    def start(self) -> bool:
        with self.lock:
            if self.state["status"] == "running":
                return False
            self.state["status"] = "running"
        threading.Thread(target=self._run, daemon=True).start()
        return True

    # ------------------------------------------------------------------ scan
    def _run(self):
        findings: list[dict] = []
        # Skip Heat Doctor itself and the helper scripts it launches, so it never flags its own checks.
        mine = {os.getpid()}
        try:
            mine |= {c.pid for c in psutil.Process().children(recursive=True)}
        except psutil.Error:
            pass
        procs = []
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
            if p.info["pid"] in (0, 4) or p.info["pid"] in mine:
                continue
            procs.append(p.info)

        flagged_paths: set[str] = set()
        for info in procs:
            name = (info.get("name") or "").lower()
            exe = info.get("exe") or ""
            cmd = " ".join(info.get("cmdline") or [])
            pid = info["pid"]
            exe_dir = os.path.dirname(exe).lower()

            if name in CORE_PROCESSES and exe and exe_dir not in CORE_PROCESSES[name]:
                findings.append(self._f("critical", "masquerade", f"Fake system process: {info['name']}",
                    f"{info['name']} is a core Windows process that only ever runs from {sorted(CORE_PROCESSES[name])[0]}, "
                    f"but this copy is running from somewhere else. Malware does this to hide.",
                    [f"Path: {exe}", f"PID {pid}"], pid=pid, path=exe))
                flagged_paths.add(exe)
            elif name in LOOKALIKES:
                findings.append(self._f("critical", "lookalike", f"Look-alike process name: {info['name']}",
                    "The name is a misspelling of a real Windows process, a classic malware trick.",
                    [f"Path: {exe or 'unknown'}", f"PID {pid}"], pid=pid, path=exe))
                if exe:
                    flagged_paths.add(exe)

            base = os.path.splitext(name)[0]
            if any(m in base for m in MINER_NAMES) or MINER_ARGS.search(cmd):
                findings.append(self._f("critical", "miner", f"Possible crypto-miner: {info['name']}",
                    "This looks like cryptocurrency mining software. Hidden miners max out the CPU/GPU, which makes "
                    "the machine run hot all the time. If you didn't install it on purpose, treat it as malware.",
                    [f"Path: {exe or 'unknown'}", f"Command: {cmd[:200]}"], pid=pid, path=exe))
                if exe:
                    flagged_paths.add(exe)

            for why in _cmd_flags(cmd):
                findings.append(self._f("serious", "cmdline", f"Suspicious command: {info['name']}",
                    why + ". Legitimate software rarely does this; malware and attack tools often do.",
                    [f"Command: {cmd[:240]}", f"PID {pid}"], pid=pid, path=exe))
                if exe:
                    flagged_paths.add(exe)

            loc = _risky_location(exe) if exe else None
            if loc:
                findings.append(self._f("warning", "location", f"Program running from {loc}: {info['name']}",
                    f"Real installed programs normally live in Program Files. Software running from the {loc} "
                    "is often an installer, but it can also be malware that dropped itself there.",
                    [f"Path: {exe}", f"PID {pid}"], pid=pid, path=exe))
                flagged_paths.add(exe)

        # Startup entries (registry + Startup folder)
        startup = _startup_entries()
        for e in startup:
            target = _exe_from_command(e["command"])
            reasons = _cmd_flags(e["command"])
            loc = _risky_location(target)
            if loc:
                reasons.append(f"starts a program from the {loc}")
            if target and os.path.isabs(target) and not os.path.exists(target):
                e["missing"] = True
            e["target"] = target
            if reasons:
                e["suspicious"] = True
                findings.append(self._f("serious" if _cmd_flags(e["command"]) else "warning", "startup",
                    f"Suspicious startup entry: {e['name']}",
                    "This runs automatically at sign-in and " + "; ".join(reasons) + ".",
                    [f"{e['where']}: {e['command'][:240]}"], path=target, actions=["open_startup_apps"]))
                if target and os.path.exists(target):
                    flagged_paths.add(target)

        defender, av, tasks = None, [], []
        if IS_WINDOWS:
            data = powershell_json("security_status.ps1", timeout=60) or {}
            defender = data.get("defender")
            av = [a.get("name") for a in as_list(data.get("av")) if a.get("name")]
            for t in as_list(data.get("threats")):
                findings.append(self._f("critical", "defender", "Microsoft Defender has detected a threat",
                    "Defender recorded a detection on this PC. Open Windows Security > Protection history to review it.",
                    [f"Detected {t.get('time')}", (t.get("resources") or "")[:240]], actions=["open_defender"]))
            for t in as_list(data.get("tasks")):
                full = f"{t.get('exec', '')} {t.get('args', '')}"
                reasons = _cmd_flags(full)
                loc = _risky_location(os.path.expandvars(t.get("exec", "")))
                if loc:
                    reasons.append(f"runs a program from the {loc}")
                if reasons:
                    findings.append(self._f("serious" if _cmd_flags(full) else "warning", "task",
                        f"Suspicious scheduled task: {t.get('name')}",
                        "This scheduled task " + "; ".join(reasons) + ".",
                        [f"{t.get('path', '')}{t.get('name', '')}: {full[:240]}", f"Author: {t.get('author') or 'unknown'}"],
                        actions=["open_task_scheduler"]))

            third_party = [a for a in av if "defender" not in a.lower()]
            if defender:
                if not defender.get("realtime") and not third_party:
                    findings.append(self._f("critical", "av", "Real-time antivirus protection is OFF",
                        "Nothing is checking files as they arrive. Turn Microsoft Defender's real-time protection back on.",
                        [], actions=["open_defender"]))
                sig = defender.get("sig_age")
                if isinstance(sig, int) and sig > 7 and defender.get("realtime"):
                    findings.append(self._f("warning", "av", f"Antivirus definitions are {sig} days old",
                        "Defender can't recognise new threats until it updates. Run Windows Update or 'Check for updates' in Windows Security.",
                        [], actions=["open_defender"]))
                qa = defender.get("quick_age")
                if isinstance(qa, int) and qa > 14 and defender.get("realtime"):
                    findings.append(self._f("info", "av", f"No antivirus scan in {qa} days",
                        "Run a quick scan to double-check anything the heuristics above can't see.",
                        [], actions=["defender_quick_scan"]))
            if len(third_party) > 1:
                findings.append(self._f("warning", "av", "More than one antivirus product installed",
                    "Running several antivirus products at once wastes CPU and disk and can cause conflicts.",
                    [", ".join(third_party)]))

            # Hosts file tampering
            findings += self._hosts_check()

        # Signature check on everything flagged; signed-by-known-vendor lowers severity.
        sigs = _signatures(sorted(flagged_paths))
        for f in findings:
            s = sigs.get((f.get("path") or "").lower())
            if not s:
                continue
            f["signature"] = s
            if s["status"] == "Valid":
                f["evidence"].append(f"Digitally signed by {s['signer']}")
                if f["kind"] in ("location", "startup", "task"):
                    f["severity"] = "info"
            else:
                f["evidence"].append(f"Not validly signed ({s['status'] or 'unknown'})")

        # Network context for flagged processes
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []
        remote_by_pid: dict[int, int] = {}
        for c in conns:
            if c.raddr and c.pid:
                remote_by_pid[c.pid] = remote_by_pid.get(c.pid, 0) + 1
        for f in findings:
            n = remote_by_pid.get(f.get("pid") or -1)
            if n:
                f["evidence"].append(f"{n} open internet connection(s)")

        order = {"critical": 4, "serious": 3, "warning": 2, "info": 1, "good": 0}
        findings.sort(key=lambda f: order.get(f["severity"], 0), reverse=True)
        counts = {k: sum(1 for f in findings if f["severity"] == k) for k in order}
        with self.lock:
            self.state = {"status": "done", "finished": time.time(), "findings": findings,
                          "startup": startup, "defender": defender, "av": av, "counts": counts,
                          "scanned_processes": len(procs)}

    @staticmethod
    def _f(severity, kind, title, detail, evidence, pid=None, path=None, actions=None):
        acts = list(actions or [])
        if pid:
            acts.append("end_process")
        if path:
            acts += ["open_file_location", "defender_scan_file"]
        return {"severity": severity, "kind": kind, "title": title, "detail": detail,
                "evidence": list(evidence), "pid": pid, "path": path, "actions": acts}

    def _hosts_check(self) -> list[dict]:
        path = os.path.join(WINDIR, "system32", "drivers", "etc", "hosts")
        out = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return out
        important = re.compile(r"(google|microsoft|windowsupdate|live\.com|office|bing|apple|amazon|paypal|bank|"
                               r"facebook|github|defender|symantec|norton|mcafee|kaspersky|malwarebytes|avast)", re.I)
        odd = []
        for ln in lines:
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            parts = ln.split()
            if len(parts) < 2 or parts[1].lower() in ("localhost", "localhost.localdomain"):
                continue
            ip, hosts = parts[0], parts[1:]
            for h in hosts:
                if important.search(h) and ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                    out.append(self._f("critical", "hosts", f"Hosts file redirects {h}",
                        f"Your hosts file sends {h} to {ip}. That can send you to a fake site or block security updates.",
                        [f"{path}: {ip} {h}"]))
                elif important.search(h) and any(k in h.lower() for k in ("update", "defender", "norton", "mcafee",
                                                                         "kaspersky", "malwarebytes", "avast", "symantec")):
                    out.append(self._f("serious", "hosts", f"Hosts file blocks {h}",
                        "Blocking security or update sites is a common malware trick.", [f"{ip} {h}"]))
                else:
                    odd.append(f"{ip} {h}")
        if odd:
            out.append(self._f("info", "hosts", f"{len(odd)} custom hosts-file entr{'y' if len(odd) == 1 else 'ies'}",
                "Usually ad-blockers or dev tools. Check you recognise them.", odd[:8]))
        return out
