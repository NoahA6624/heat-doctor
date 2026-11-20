"""Rule-based diagnosis: turns raw samples into ranked, plain-English findings."""
from __future__ import annotations

import time

from . import knowledge
from .util import IS_WINDOWS, fmt_bytes, fmt_rate

MB = 1024 ** 2
SEV = {"critical": 4, "serious": 3, "warning": 2, "info": 1, "good": 0}


def _f(area, severity, title, detail, evidence=None, fixes=None, actions=None, **extra):
    d = {"area": area, "severity": severity, "title": title, "detail": detail,
         "evidence": evidence or [], "fixes": fixes or [], "actions": actions or []}
    d.update(extra)
    return d


def heat_points(g: dict) -> float:
    """Rough 'how much heat is this process responsible for' score.
    10 MB/s of sustained disk traffic counts about the same as 12% of total CPU."""
    return (g["read_bps"] + g["write_bps"]) / MB + 0.8 * g["cpu_pct"]


def _avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def _drive_thresholds(media: str):
    if (media or "").upper() == "HDD":
        return 45, 50, 55
    return 55, 65, 75  # NVMe/SATA SSDs start throttling around 70-80 °C


def build(col, window_s: float, storage_state: dict, security_state: dict) -> dict:
    hist = col.history_since(window_s)
    groups, span = col.window_groups(window_s)
    with col.lock:
        probe = dict(col.probe)
        parts = list(col.partitions)
        mem = dict(getattr(col, "mem", {}) or {})
        pages = [v for t, v in col.pages_hist if t >= time.time() - window_s]

    findings: list[dict] = []
    if span < 10:
        findings.append(_f("general", "info", "Collecting data…",
                           "Leave the app open for a minute. The diagnosis gets more accurate the longer it runs, "
                           "especially while the computer is running hot."))

    cpu_avg = _avg([h["cpu"] for h in hist]) or 0
    read_avg = _avg([h["read_bps"] for h in hist]) or 0
    write_avg = _avg([h["write_bps"] for h in hist]) or 0
    io_avg = read_avg + write_avg
    busy_frac = (sum(1 for h in hist if h["read_bps"] + h["write_bps"] > 5 * MB) / len(hist)) if hist else 0
    pages_avg = _avg(pages)

    # ---------------------------------------------------------- temperature
    drives = probe.get("drives") or []
    temp_known = False
    hottest_sev = "good"
    for d in drives:
        t = d.get("temp")
        if not t:
            continue
        temp_known = True
        warn, serious, crit = _drive_thresholds(d.get("media"))
        sev = "critical" if t >= crit else "serious" if t >= serious else "warning" if t >= warn else "good"
        if SEV[sev] > SEV[hottest_sev]:
            hottest_sev = sev
        ev = [f"Now: {t:.0f} °C"]
        if d.get("temp_max"):
            ev.append(f"Rated maximum: {d['temp_max']:.0f} °C")
        ev.append(f"{d.get('media') or ''} {d.get('bus') or ''}".strip())
        if sev == "good":
            findings.append(_f("heat", "good", f"{d['name']} is at a healthy {t:.0f} °C",
                               "Drive temperature is in the normal range right now.", ev))
        else:
            findings.append(_f("heat", sev, f"{d['name']} is running hot: {t:.0f} °C",
                "SSDs slow themselves down (thermal throttling) above roughly 70 °C, and sustained heat shortens "
                "their life. The findings below show what is driving it." if (d.get("media") or "").upper() != "HDD" else
                "Hard drives above 50 °C wear out noticeably faster. The findings below show what is driving it.",
                ev, ["Deal with the top suspects below first.",
                     "Keep vents clear and use the laptop on a hard, flat surface (not a bed or lap).",
                     "Clean dust out of the fans and vents if the machine is more than a year or two old."]))
    if drives and not temp_known:
        findings.append(_f("heat", "info", "Drive temperature sensor needs administrator access",
            "Windows only shares the drive's own temperature with administrator programs. Everything else works, "
            "but for a direct reading restart Heat Doctor with 'run_as_admin' (or install smartmontools).",
            [f"Detected: {', '.join(d['name'] for d in drives)}"]))

    zones = probe.get("zones") or []
    if zones:
        zmax = max(z["c"] for z in zones)
        if zmax >= 90:
            findings.append(_f("heat", "critical", f"System thermal sensor at {zmax:.0f} °C",
                "The motherboard/CPU area is extremely hot. Expect throttling and fan noise.",
                [f"{z['name']}: {z['c']:.0f} °C" for z in zones][:4]))
        elif zmax >= 80:
            findings.append(_f("heat", "serious", f"System thermal sensor at {zmax:.0f} °C",
                "The motherboard/CPU area is very warm.", [f"{z['name']}: {z['c']:.0f} °C" for z in zones][:4]))

    # ------------------------------------------------------------ suspects
    running = [g for g in groups if g["read_bps"] + g["write_bps"] > 0 or g["cpu_pct"] > 0]
    total_pts = sum(heat_points(g) for g in running) or 1
    suspects = []
    for g in sorted(running, key=heat_points, reverse=True)[:25]:
        entry = knowledge.lookup(g["name"], g["services"])
        suspects.append({**g, "share": heat_points(g) / total_pts, "points": heat_points(g),
                         "kb": knowledge.public(entry)})

    for s in [x for x in suspects if x["key"] != col.SELF_KEY][:6]:
        io = s["read_bps"] + s["write_bps"]
        cpu = s["cpu_pct"]
        if io < 2 * MB and cpu < 8:
            continue
        sev = "serious" if io >= 20 * MB or cpu >= 30 else "warning" if io >= 5 * MB or cpu >= 12 else "info"
        kb = s["kb"]
        ev = []
        if io >= 0.5 * MB:
            ev.append(f"Disk: {fmt_rate(s['read_bps'])} read, {fmt_rate(s['write_bps'])} written (average)")
        if cpu >= 1:
            ev.append(f"CPU: {cpu:.0f}% of the whole machine (average)")
        ev.append(f"{s['share'] * 100:.0f}% of the estimated heat load")
        if s["instances"] > 1:
            ev.append(f"{s['instances']} processes")
        label = kb["label"] if kb else s["name"]
        detail = kb["about"] if kb else (
            "This program is one of the biggest sources of disk and/or CPU load right now. If you don't recognise it, "
            "check the Security panel and search its name online.")
        acts = list(kb["actions"]) if kb else []
        if s["name"].lower() not in ("system", "registry", "memory compression", "memcompression") and s["pids"]:
            acts.append("end_process")
        findings.append(_f("suspect", sev, f"{label}" + (f" ({s['name']})" if kb else ""), detail, ev,
                           kb["fixes"] if kb else ["If it's an app you use, close it when you don't need it.",
                                                   "If it's unfamiliar, scan it with the Security panel."],
                           acts, key=s["key"], pids=s["pids"]))

    # -------------------------------------------------------- disk activity
    if hist:
        if io_avg >= 40 * MB:
            findings.append(_f("disk", "serious", f"Drive is under heavy, constant load ({fmt_rate(io_avg)} on average)",
                f"The drive was busy {busy_frac * 100:.0f}% of the time in this window. Constant I/O is the main "
                "thing that heats an SSD.", [f"Read {fmt_rate(read_avg)}, write {fmt_rate(write_avg)}"]))
        elif io_avg >= 8 * MB:
            findings.append(_f("disk", "warning", f"Drive is regularly busy ({fmt_rate(io_avg)} on average)",
                "More background disk activity than an idle PC should have.",
                [f"Read {fmt_rate(read_avg)}, write {fmt_rate(write_avg)}", f"Busy {busy_frac * 100:.0f}% of the time"]))
        elif span >= 30:
            findings.append(_f("disk", "good", "Disk activity is low",
                f"Average {fmt_rate(io_avg)}. Disk I/O isn't what's heating the drive right now."))

    # ---------------------------------------------------------- CPU / soak
    top_cpu = sorted(groups, key=lambda g: g["cpu_pct"], reverse=True)[:3]
    if hist and cpu_avg >= 25:
        sev = "serious" if cpu_avg >= 50 else "warning"
        findings.append(_f("cpu", sev, f"CPU has been busy ({cpu_avg:.0f}% average)",
            ("In a laptop the SSD sits next to the CPU and shares its cooling, so a busy CPU heats the drive too. "
             if col.laptop else "Sustained CPU load raises the temperature of everything in the case. ")
            + "Top CPU users: " + ", ".join(f"{g['name']} ({g['cpu_pct']:.0f}%)" for g in top_cpu if g["cpu_pct"] >= 1),
            fixes=["Close or limit the top CPU users.",
                   "Use the 'Best power efficiency' / balanced power mode when you don't need full speed."],
            actions=["open_power", "open_task_manager"]))

    # ---------------------------------------------------------------- RAM
    mem_pct = mem.get("percent", 0)
    top_mem = sorted(groups, key=lambda g: g["private"] or g["rss"], reverse=True)[:5]
    mem_ev = [f"{g['name']}: {fmt_bytes(g['private'] or g['rss'])}" for g in top_mem]
    paging = pages_avg is not None and pages_avg > 600
    if mem_pct >= 90 or (mem_pct >= 80 and paging):
        findings.append(_f("memory", "serious", f"RAM is almost full ({mem_pct:.0f}% used)",
            "When RAM runs out Windows pages memory to the drive. That's constant disk writing, which means heat, "
            "wear and a slow PC.", mem_ev + ([f"Paging: {pages_avg:.0f} pages/s"] if pages_avg else []),
            ["Close the biggest memory users listed here, especially browsers with many tabs.",
             "Turn off apps that start with Windows but you rarely use.",
             "If this happens every day, more RAM is the real fix."], ["open_startup_apps", "open_task_manager"]))
    elif mem_pct >= 80 or paging:
        findings.append(_f("memory", "warning", f"RAM is getting tight ({mem_pct:.0f}% used)",
            "You're close to the point where Windows starts paging to disk.", mem_ev,
            ["Close apps and tabs you're not using."], ["open_task_manager"]))
    elif mem:
        findings.append(_f("memory", "good", f"RAM is fine ({mem_pct:.0f}% used)",
            f"{fmt_bytes(mem.get('available', 0))} available.", mem_ev[:3]))

    # ------------------------------------------------------------ storage
    for p in parts:
        free_pct = 100 - p["percent"]
        if free_pct < 10:
            findings.append(_f("storage", "serious", f"{p['mount']} is nearly full ({fmt_bytes(p['free'])} free)",
                "A nearly full SSD has fewer spare blocks, so every write costs it more work (and heat), "
                "and Windows can't grow the page file.",
                [f"{p['percent']:.0f}% used of {fmt_bytes(p['total'])}"],
                ["Run the storage scan below to see what's taking space.", "Turn on Storage Sense."],
                ["open_storage_sense", "open_disk_cleanup"]))
        elif free_pct < 20:
            findings.append(_f("storage", "warning", f"{p['mount']} is getting full ({fmt_bytes(p['free'])} free)",
                "Keep at least 15-20% of an SSD free for best speed and lifespan.",
                [f"{p['percent']:.0f}% used of {fmt_bytes(p['total'])}"],
                ["Run the storage scan below."], ["open_storage_sense"]))
    hogs = storage_state.get("hogs") or []
    for h in hogs[:3]:
        if h["size"] >= 2 * 1024 ** 3 and h["id"] != "system_files":
            findings.append(_f("storage", "info", f"{h['label']}: {fmt_bytes(h['size'])}", h["tip"],
                               [p for p in h.get("paths", [])][:2], actions=[h["action"]] if h.get("action") else []))

    # ------------------------------------------------------------- drive health
    for d in drives:
        wear = d.get("wear")
        if isinstance(wear, (int, float)) and wear >= 80:
            findings.append(_f("health", "serious", f"{d['name']} has used {wear:.0f}% of its rated life",
                "Back up your files and plan to replace the drive."))
        if (d.get("health") or "").lower() not in ("", "healthy"):
            findings.append(_f("health", "critical", f"Windows reports {d['name']} as {d['health']}",
                "Back up your important files now."))

    # ------------------------------------------------------------ security
    sec = security_state or {}
    for sf in (sec.get("findings") or [])[:5]:
        if SEV.get(sf["severity"], 0) >= SEV["serious"]:
            findings.append(_f("security", sf["severity"], sf["title"], sf["detail"], sf["evidence"],
                               actions=sf["actions"], pid=sf.get("pid"), path=sf.get("path")))

    # --------------------------------------------------------- laptop tips
    if col.laptop and any(SEV[f["severity"]] >= SEV["warning"] and f["area"] in ("heat", "cpu", "disk") for f in findings):
        findings.append(_f("heat", "info", "Laptop cooling checklist",
            "Heat is often mechanical, not software.",
            [f"Power mode: {probe['power_plan']}"] if probe.get("power_plan") else [],
            ["Use it on a desk, not on fabric. A cheap stand or cooling pad helps.",
             "Blow dust out of the vents with compressed air (with the machine off).",
             "Check the manufacturer's utility for a 'quiet' or 'cool' thermal profile.",
             "Keep BIOS and the SSD's firmware up to date."], ["open_power"]))

    findings.sort(key=lambda f: (SEV[f["severity"]], f["area"] == "suspect"), reverse=True)

    # ------------------------------------------------------------- verdict
    worst = max((SEV[f["severity"]] for f in findings), default=0)
    status = next(k for k, v in SEV.items() if v == worst)
    top = next((s for s in suspects if s["key"] != col.SELF_KEY and ((s["read_bps"] + s["write_bps"]) >= 2 * MB or s["cpu_pct"] >= 8)), None)
    if span < 10:
        headline, summary = "Collecting data…", "Give it a minute to gather a baseline."
    elif top:
        lab = top["kb"]["label"] if top["kb"] else top["name"]
        headline = f"Most likely cause: {lab}"
        summary = (f"{top['name']} accounts for about {top['share'] * 100:.0f}% of the disk + CPU load "
                   f"over the last {int(window_s // 60) or 1} min.")
        if mem_pct >= 85:
            summary += f" RAM is also {mem_pct:.0f}% full, which adds paging writes."
    elif worst >= SEV["warning"]:
        bad = next(f for f in findings if SEV[f["severity"]] == worst)
        headline, summary = bad["title"], bad["detail"]
    else:
        headline = "Nothing abnormal right now"
        summary = ("Leave Heat Doctor running in the background. When the drive feels hot, open the dashboard: "
                   "the history shows what was running at the time.")

    temps = [d["temp"] for d in drives if d.get("temp")]
    return {
        "status": status, "headline": headline, "summary": summary, "findings": findings,
        "suspects": suspects[:15],
        "memory_top": [{"name": g["name"], "key": g["key"], "bytes": g["private"] or g["rss"], "rss": g["rss"],
                        "instances": g["instances"], "pids": g["pids"],
                        "kb": knowledge.public(knowledge.lookup(g["name"], g["services"]))}
                       for g in sorted(groups, key=lambda g: g["private"] or g["rss"], reverse=True)[:12] if g["running"]],
        "stats": {"cpu_avg": cpu_avg, "read_avg": read_avg, "write_avg": write_avg, "busy_frac": busy_frac,
                  "drive_temp": max(temps) if temps else None, "temp_status": hottest_sev,
                  "zone_temp": max((z["c"] for z in zones), default=None), "pages_avg": pages_avg,
                  "span": span},
    }


def text_report(diag: dict) -> str:
    lines = [f"== {diag['headline']} ==", diag["summary"], ""]
    for f in diag["findings"]:
        lines.append(f"[{f['severity'].upper():8}] {f['title']}")
        if f["detail"]:
            lines.append(f"           {f['detail']}")
        for e in f["evidence"]:
            lines.append(f"           - {e}")
        for x in f["fixes"]:
            lines.append(f"           > {x}")
    lines.append("")
    lines.append("Top suspects (disk + CPU):")
    for s in diag["suspects"][:8]:
        lines.append(f"  {s['share'] * 100:5.1f}%  {s['key'][:50]:50}  R {fmt_rate(s['read_bps']):>11}  "
                     f"W {fmt_rate(s['write_bps']):>11}  CPU {s['cpu_pct']:5.1f}%")
    return "\n".join(lines)
