"""Small shared helpers: platform checks, PowerShell runner, formatting."""
from __future__ import annotations

import json
import os
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


SCRIPTS = os.path.join(os.path.dirname(__file__), "scripts")


def run(cmd: list[str], timeout: float = 20, stdin: str | None = None) -> tuple[int, str, str]:
    """Run a command without flashing a console window. Never raises."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input=stdin,
            creationflags=CREATE_NO_WINDOW, encoding="utf-8", errors="replace",
        )
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # missing binary, timeout, ...
        return -1, "", str(e)


def powershell(script_name: str, timeout: float = 30, stdin: str | None = None) -> tuple[int, str, str]:
    """Run one of the bundled, human-readable scripts in heat_doctor/scripts/ by path.
    (No -EncodedCommand: hidden commands look like malware, and these are meant to be inspectable.)"""
    path = os.path.join(SCRIPTS, os.path.basename(script_name))
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path],
               timeout=timeout, stdin=stdin)


def powershell_json(script_name: str, timeout: float = 30, stdin: str | None = None):
    code, out, _ = powershell(script_name, timeout, stdin)
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def fmt_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_rate(bps: float) -> str:
    return fmt_bytes(bps) + "/s"
