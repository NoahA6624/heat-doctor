"""Temperature and hardware probes.

Everything here is "slow path": it shells out, so the collector calls it every
15 seconds or so, not on every tick. Every function degrades to empty data
instead of raising, because sensor access varies wildly between machines.
"""
from __future__ import annotations

import json
import re
import shutil

import psutil

from .util import IS_WINDOWS, as_list, powershell_json, run



def _num(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None  # 0 means "not reported" on most firmware


def _smartctl_temps() -> dict[str, float]:
    """Fallback via smartmontools, if the user has it installed."""
    exe = shutil.which("smartctl")
    if not exe:
        return {}
    temps = {}
    code, out, _ = run([exe, "--scan", "-j"], timeout=10)
    try:
        devices = json.loads(out).get("devices", [])
    except ValueError:
        return {}
    for d in devices:
        code, out, _ = run([exe, "-j", "-A", d["name"]], timeout=10)
        try:
            data = json.loads(out)
            t = data.get("temperature", {}).get("current")
            if t:
                temps[data.get("model_name") or d["name"]] = float(t)
        except ValueError:
            pass
    return temps


def _probe_once(include_drives: bool = True) -> dict:
    result = {"drives": [], "zones": [], "pages_per_sec": None, "power_plan": None}
    if IS_WINDOWS:
        data = (powershell_json("drive_probe.ps1", timeout=25) or {}) if include_drives else {}
        for d in as_list(data.get("drives")):
            result["drives"].append({
                "name": d.get("name") or "Drive",
                "media": d.get("media") or "Unknown",
                "bus": d.get("bus") or "",
                "size": d.get("size") or 0,
                "health": d.get("health") or "",
                "temp": _num(d.get("temp")),
                "temp_max": _num(d.get("temp_max")),
                "wear": d.get("wear"),
                "hours": d.get("hours"),
                "read_errors": d.get("read_errors"),
                "write_errors": d.get("write_errors"),
            })
        m = re.search(r"\(([^)]+)\)", data.get("plan") or "")
        result["power_plan"] = m.group(1) if m else None
    else:
        # Linux exposes NVMe / drivetemp / CPU sensors through psutil.
        try:
            temps = psutil.sensors_temperatures() or {}
        except Exception:
            temps = {}
        for chip, entries in temps.items():
            for e in entries:
                if not e.current:
                    continue
                if chip in ("nvme", "drivetemp"):
                    result["drives"].append({
                        "name": f"{chip} {e.label}".strip(), "media": "SSD" if chip == "nvme" else "Unknown",
                        "bus": chip, "size": 0, "health": "", "temp": e.current,
                        "temp_max": e.critical, "wear": None, "hours": None,
                        "read_errors": None, "write_errors": None,
                    })
                else:
                    result["zones"].append({"name": f"{chip} {e.label}".strip(), "c": e.current})

    # smartctl fallback for drives whose temperature we could not read.
    if result["drives"] and all(d["temp"] is None for d in result["drives"]):
        st = _smartctl_temps()
        if st:
            vals = list(st.values())
            for i, d in enumerate(result["drives"]):
                if i < len(vals):
                    d["temp"] = vals[i]
    return result


class Probe:
    """Cheap, repeated sensor reads. PDH counters every call; the PowerShell drive
    probe (which spawns a process) only every 30 s when temperatures are readable,
    or every 5 minutes when they aren't (standard user), to stay light."""

    def __init__(self):
        self.counters = None
        if IS_WINDOWS:
            from .pdh import Counters
            self.counters = Counters({
                "zones": r"\Thermal Zone Information(*)\High Precision Temperature",
                "pages": r"\Memory\Pages/sec",
            })
        self.last_drives = 0.0
        self.cache = {"drives": [], "zones": [], "pages_per_sec": None, "power_plan": None}

    def read(self) -> dict:
        import time
        now = time.time()
        has_temps = any(d.get("temp") for d in self.cache["drives"])
        interval = 30 if has_temps else 300
        if not IS_WINDOWS or now - self.last_drives >= interval:
            fresh = _probe_once()
            self.cache["drives"] = fresh["drives"]
            if fresh["power_plan"]:
                self.cache["power_plan"] = fresh["power_plan"]
            if not IS_WINDOWS:
                self.cache["zones"] = fresh["zones"]
            self.last_drives = now
        if self.counters and self.counters.ok:
            vals = self.counters.read()
            zones = []
            for name, v in (vals.get("zones") or {}).items():
                c = round(v / 10 - 273.15, 1)  # tenths of a kelvin
                if -20 < c < 130:
                    zones.append({"name": name.strip("\\").replace("_TZ.", "") or "zone", "c": c})
            self.cache["zones"] = zones
            pages = vals.get("pages") or {}
            self.cache["pages_per_sec"] = next(iter(pages.values()), None)
        return {k: (list(v) if isinstance(v, list) else v) for k, v in self.cache.items()}
