"""'Ask Claude': sends a privacy-trimmed snapshot of the diagnosis to Claude and
streams back recommendations. Optional - needs `pip install anthropic` and an
API key (ANTHROPIC_API_KEY, `ant auth login`, or pasted into the dashboard).
"""
from __future__ import annotations

import json
import os
import platform
import re

from .util import IS_WINDOWS, fmt_bytes

MODEL = os.environ.get("HEAT_DOCTOR_MODEL", "claude-opus-5-5")

SYSTEM = """You are the built-in advisor of Heat Doctor, a PC monitoring and diagnostics app used by ordinary, \
non-technical people. You receive a JSON snapshot the app collected on the user's computer: temperatures, disk I/O \
and CPU per process, RAM usage, storage usage, and the results of lightweight malware heuristics.

Give practical, specific recommendations to make the computer run cooler, faster and safer, based on the data. \
Rules:
- Lead with the single most impactful fix, then a short prioritised list. Tie each recommendation to the evidence \
(process names, numbers) in the snapshot.
- Prefer safe, reversible steps and built-in Windows/macOS tools. Give exact menu paths or commands.
- Say clearly when something needs a closer look rather than guessing. Never tell the user to disable their \
antivirus or delete system files.
- If a security finding looks like real malware, say so plainly and tell them to run a full Microsoft Defender \
(or their antivirus) scan and, if confirmed, to seek help.
- Keep it short: about 250 words unless the user asks for more. Use Markdown headings and bullets."""

_key_override: str | None = None
_CONFIG = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~/.config"), "HeatDoctor", "config.json")


def _load_saved_key():
    global _key_override
    try:
        with open(_CONFIG, encoding="utf-8") as fh:
            _key_override = json.load(fh).get("api_key") or None
    except (OSError, ValueError):
        pass


_load_saved_key()


def sdk_installed() -> bool:
    # find_spec checks without importing: the SDK is large, so it's only loaded on the first question.
    import importlib.util
    return importlib.util.find_spec("anthropic") is not None


def status() -> dict:
    return {
        "sdk": sdk_installed(),
        "key_source": "app" if _key_override else ("env" if os.environ.get("ANTHROPIC_API_KEY") else None),
        "saved": os.path.exists(_CONFIG),
        "model": MODEL,
    }


def set_key(key: str | None, remember: bool) -> dict:
    global _key_override
    key = (key or "").strip() or None
    if key and not re.fullmatch(r"sk-ant-[A-Za-z0-9_\-]{20,}", key):
        return {"ok": False, "message": "That doesn't look like an Anthropic API key (it should start with sk-ant-)."}
    _key_override = key
    if remember and key:
        os.makedirs(os.path.dirname(_CONFIG), exist_ok=True)
        with open(_CONFIG, "w", encoding="utf-8") as fh:
            json.dump({"api_key": key}, fh)
    elif not key and os.path.exists(_CONFIG):
        os.remove(_CONFIG)
    return {"ok": True, "message": "Key saved on this computer." if remember and key else
            ("Key set for this session." if key else "Key removed.")}


def _scrub(obj):
    """Replace the user's home folder / user name in paths so they never leave the machine."""
    home = os.path.expanduser("~")
    user = os.path.basename(home)
    s = json.dumps(obj, default=str)
    s = s.replace(home.replace("\\", "\\\\"), "~").replace(home, "~")
    if len(user) >= 3:
        s = re.sub(re.escape(user), "<user>", s, flags=re.I)
    return json.loads(s)


def build_snapshot(col, diag: dict, storage: dict, security: dict) -> dict:
    with col.lock:
        probe = dict(col.probe)
        parts = list(col.partitions)
        mem = dict(getattr(col, "mem", {}) or {})
    snap = {
        "system": {"os": f"{platform.system()} {platform.release()} ({platform.version()})",
                   "cpu_threads": col.ncpu, "ram_total": fmt_bytes(col.total_ram), "laptop": col.laptop,
                   "power_plan": probe.get("power_plan"), "running_as_admin": col.admin},
        "verdict": {"status": diag["status"], "headline": diag["headline"], "summary": diag["summary"]},
        "averages": {k: (round(v, 1) if isinstance(v, float) else v) for k, v in diag["stats"].items()},
        "drives": [{k: d.get(k) for k in ("name", "media", "bus", "temp", "temp_max", "wear", "health")}
                   for d in probe.get("drives", [])],
        "thermal_zones": probe.get("zones"),
        "memory": {"percent_used": mem.get("percent"), "available": fmt_bytes(mem.get("available", 0)),
                   "top": [{"name": m["name"], "memory": fmt_bytes(m["bytes"]), "instances": m["instances"]}
                           for m in diag["memory_top"][:10]]},
        "partitions": [{"mount": p["mount"], "free": fmt_bytes(p["free"]), "percent_used": p["percent"]} for p in parts],
        "heat_suspects": [{"process": s["key"], "what": (s["kb"] or {}).get("label"),
                           "read_per_s": fmt_bytes(s["read_bps"]), "write_per_s": fmt_bytes(s["write_bps"]),
                           "cpu_pct": round(s["cpu_pct"], 1), "share_pct": round(s["share"] * 100, 1)}
                          for s in diag["suspects"][:10]],
        "findings": [{"severity": f["severity"], "area": f["area"], "title": f["title"], "evidence": f["evidence"][:4]}
                     for f in diag["findings"][:20]],
        "storage_hogs": [{"what": h["label"], "size": fmt_bytes(h["size"])} for h in (storage.get("hogs") or [])[:10]],
        "largest_folders": [{"folder": f["name"], "size": fmt_bytes(f["size"]),
                             "biggest_subfolders": [{"name": c["name"], "size": fmt_bytes(c["size"])} for c in f.get("children", [])[:4]]}
                            for f in (storage.get("folders") or [])[:8]],
        "security": {"scanned": security.get("status") == "done",
                     "antivirus": security.get("av"), "defender": security.get("defender"),
                     "findings": [{"severity": f["severity"], "title": f["title"], "evidence": f["evidence"][:3]}
                                  for f in (security.get("findings") or [])[:12]]},
    }
    return _scrub(snap)


def stream_answer(question: str, snapshot: dict, history: list[dict]):
    """Yields ('text', str) chunks, then ('done', info) or ('error', message)."""
    try:
        import anthropic
    except ImportError:
        yield "error", "The Anthropic SDK isn't installed. Run: pip install anthropic"
        return

    client = anthropic.Anthropic(api_key=_key_override) if _key_override else anthropic.Anthropic()

    # Earlier Q&A goes in as plain text inside one fresh user turn, so every request is self-contained.
    convo = ""
    for h in history[-4:]:
        convo += f"<earlier_question>{h.get('q', '')[:2000]}</earlier_question>\n" \
                 f"<earlier_answer>{h.get('a', '')[:4000]}</earlier_answer>\n"
    content = [
        {"type": "text", "text": "<system_snapshot>\n" + json.dumps(snapshot, indent=1) + "\n</system_snapshot>"},
    ]
    if convo:
        content.append({"type": "text", "text": convo})
    content.append({"type": "text", "text": question.strip()[:4000] or
                    "What is making my computer run hot and slow, and what should I do about it?"})

    try:
        with client.beta.messages.stream(
            model=MODEL,
            max_tokens=16000,
            system=SYSTEM,
            messages=[{"role": "user", "content": content}],
            output_config={"effort": "medium"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        ) as stream:
            for text in stream.text_stream:
                yield "text", text
            final = stream.get_final_message()
        if final.stop_reason == "refusal":
            yield "error", "Claude declined to answer this one. Try rephrasing the question."
            return
        if final.stop_reason == "max_tokens":
            yield "text", "\n\n*(Answer was cut off. Ask a narrower follow-up.)*"
        yield "done", {"model": final.model}
    except anthropic.AuthenticationError:
        yield "error", "Your API key was rejected. Check it in the key settings."
    except anthropic.PermissionDeniedError:
        yield "error", "This API key doesn't have access to the model."
    except anthropic.RateLimitError:
        yield "error", "Rate limited by the API. Wait a minute and try again."
    except anthropic.APIStatusError as e:
        yield "error", f"API error ({e.status_code}): {e.message}"
    except anthropic.APIConnectionError:
        yield "error", "Couldn't reach the Claude API. Check your internet connection."
    except Exception as e:  # e.g. no credentials configured at all
        msg = str(e)
        if "api_key" in msg.lower() or "auth" in msg.lower() or "credential" in msg.lower():
            msg = "No API key found. Add one with the key button, or set ANTHROPIC_API_KEY."
        yield "error", msg
