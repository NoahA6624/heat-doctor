"""One-click fixes. Every action is user-initiated from the dashboard (with a
confirmation for anything that changes state) and deliberately conservative:
we open the right Windows tool rather than silently changing system settings.
"""
from __future__ import annotations

import os
import subprocess
import time

import psutil

from .util import CREATE_NO_WINDOW, IS_MAC, IS_WINDOWS, fmt_bytes, run

# Never offer to kill these.
PROTECTED = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
             "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe", "memory compression", "memcompression", "fontdrvhost.exe",
             "msmpeng.exe", "securityhealthservice.exe", "sihost.exe", "ctfmon.exe", "launchd", "kernel_task",
             "systemd", "init"}

_OPEN_TARGETS = {
    "open_storage_sense": ("ms-settings:storagesense", "Storage settings"),
    "open_startup_apps": ("ms-settings:startupapps", "Startup apps"),
    "open_windows_update": ("ms-settings:windowsupdate", "Windows Update"),
    "open_delivery_opt": ("ms-settings:delivery-optimization", "Delivery Optimization"),
    "open_power": ("ms-settings:powersleep", "Power settings"),
    "open_defender": ("windowsdefender://threat", "Windows Security"),
}
_RUN_TARGETS = {
    "open_task_manager": (["taskmgr.exe"], "Task Manager"),
    "open_resource_monitor": (["resmon.exe"], "Resource Monitor"),
    "open_task_scheduler": (["mmc.exe", "taskschd.msc"], "Task Scheduler"),
    "open_disk_cleanup": (["cleanmgr.exe"], "Disk Cleanup"),
    "open_indexing": (["control.exe", "srchadmin.dll"], "Indexing Options"),
}

LABELS = {
    **{k: v[1] for k, v in _OPEN_TARGETS.items()},
    **{k: v[1] for k, v in _RUN_TARGETS.items()},
    "open_downloads": "Open Downloads",
    "open_file_location": "Show file",
    "clean_temp": "Clean temp files",
    "defender_quick_scan": "Run quick virus scan",
    "defender_scan_file": "Scan this file",
    "end_process": "End process",
}
CONFIRM = {
    "clean_temp": "Delete files in your temp folder that are more than a day old? Files in use are skipped.",
    "end_process": "End this process? Unsaved work in it will be lost.",
}


def available() -> dict:
    """Which actions this platform supports (the UI hides the rest)."""
    if IS_WINDOWS:
        ids = list(LABELS)
    else:
        ids = ["open_downloads", "open_file_location", "clean_temp", "end_process"]
    return {i: {"label": LABELS[i], "confirm": CONFIRM.get(i)} for i in ids}


def _open(target: str):
    if IS_WINDOWS:
        os.startfile(target)  # noqa: S606 - fixed, known targets only
    elif IS_MAC:
        subprocess.Popen(["open", target])
    else:
        subprocess.Popen(["xdg-open", target])


def _mpcmdrun() -> str | None:
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),):
        p = os.path.join(base, "Windows Defender", "MpCmdRun.exe")
        if os.path.exists(p):
            return p
    return None


def perform(action: str, params: dict) -> dict:
    if action not in available():
        return {"ok": False, "message": "That action isn't available on this computer."}
    try:
        if action in _OPEN_TARGETS:
            _open(_OPEN_TARGETS[action][0])
            return {"ok": True, "message": f"Opened {_OPEN_TARGETS[action][1]}."}
        if action in _RUN_TARGETS:
            subprocess.Popen(_RUN_TARGETS[action][0])
            return {"ok": True, "message": f"Opened {_RUN_TARGETS[action][1]}."}
        if action == "open_downloads":
            _open(os.path.join(os.path.expanduser("~"), "Downloads"))
            return {"ok": True, "message": "Opened your Downloads folder."}
        if action == "open_file_location":
            path = str(params.get("path") or "")
            if not os.path.exists(path):
                return {"ok": False, "message": "That file no longer exists."}
            if IS_WINDOWS:
                subprocess.Popen(["explorer.exe", "/select,", os.path.normpath(path)])
            else:
                _open(os.path.dirname(path))
            return {"ok": True, "message": "Opened the file's folder."}
        if action == "clean_temp":
            return _clean_temp()
        if action == "end_process":
            return _end_process(params)
        if action == "defender_quick_scan":
            exe = _mpcmdrun()
            if not exe:
                return {"ok": False, "message": "Microsoft Defender isn't available."}
            subprocess.Popen([exe, "-Scan", "-ScanType", "1"], creationflags=CREATE_NO_WINDOW)
            return {"ok": True, "message": "Quick scan started. Results appear in Windows Security > Protection history."}
        if action == "defender_scan_file":
            exe = _mpcmdrun()
            path = str(params.get("path") or "")
            if not exe:
                return {"ok": False, "message": "Microsoft Defender isn't available."}
            if not os.path.isfile(path):
                return {"ok": False, "message": "That file no longer exists."}
            code, out, err = run([exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"], timeout=180)
            text = (out or err).strip().splitlines()
            summary = next((ln for ln in reversed(text) if "threat" in ln.lower() or "found" in ln.lower()), None)
            if code == 0:
                return {"ok": True, "message": "Defender found no threats in this file."}
            if code == 2:
                return {"ok": True, "message": "Defender found a threat in this file. Open Windows Security to remove it.",
                        "severity": "critical"}
            return {"ok": False, "message": summary or "Scan didn't finish. Try running the app as administrator."}
    except Exception as e:
        return {"ok": False, "message": f"Couldn't do that: {e}"}
    return {"ok": False, "message": "Unknown action."}


def _clean_temp() -> dict:
    temp = os.environ.get("TEMP") or os.environ.get("TMPDIR") or "/tmp"
    if not os.path.isdir(temp) or temp in ("/", "C:\\"):
        return {"ok": False, "message": "Couldn't find your temp folder."}
    cutoff = time.time() - 24 * 3600
    freed = removed = skipped = 0
    for root, dirs, files in os.walk(temp, topdown=False):
        for f in files:
            p = os.path.join(root, f)
            try:
                st = os.lstat(p)
                if st.st_mtime > cutoff:
                    continue
                os.remove(p)
                freed += st.st_size
                removed += 1
            except OSError:
                skipped += 1
        if root != temp:
            try:
                if os.stat(root).st_mtime < cutoff:
                    os.rmdir(root)  # only succeeds if empty
            except OSError:
                pass
    return {"ok": True, "message": f"Freed {fmt_bytes(freed)} ({removed} files). {skipped} in-use files were skipped."}


def _end_process(params: dict) -> dict:
    pids = params.get("pids") or ([params["pid"]] if params.get("pid") else [])
    me = os.getpid()
    ended, errors = 0, []
    for pid in pids[:50]:
        try:
            pid = int(pid)
            if pid <= 4 or pid == me:
                continue
            p = psutil.Process(pid)
            if (p.name() or "").lower() in PROTECTED:
                errors.append(f"{p.name()} is a core system process and can't be ended here.")
                continue
            p.terminate()
            ended += 1
        except psutil.AccessDenied:
            errors.append(f"PID {pid}: access denied (try running as administrator).")
        except (psutil.NoSuchProcess, ValueError):
            continue
    if ended:
        return {"ok": True, "message": f"Ended {ended} process{'es' if ended != 1 else ''}." +
                (" " + errors[0] if errors else "")}
    return {"ok": False, "message": errors[0] if errors else "Nothing to end. It may have already exited."}
