"""Entry point: `python -m heat_doctor` (or the `heat-doctor` command)."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import webbrowser

from . import __version__
from .util import IS_MAC, IS_WINDOWS


def _find_app_browser() -> str | None:
    """A Chromium-based browser that supports --app (Chrome, Edge, Brave, Chromium)."""
    candidates = []
    if IS_WINDOWS:
        roots = [os.environ.get(k) for k in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA")]
        rels = [r"Google\Chrome\Application\chrome.exe", r"Microsoft\Edge\Application\msedge.exe",
                r"BraveSoftware\Brave-Browser\Application\brave.exe", r"Chromium\Application\chrome.exe"]
        candidates = [os.path.join(r, rel) for rel in rels for r in roots if r]
    elif IS_MAC:
        candidates = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                      "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                      "/Applications/Chromium.app/Contents/MacOS/Chromium"]
    else:
        candidates = [shutil.which(n) or "" for n in
                      ("google-chrome", "google-chrome-stable", "microsoft-edge", "brave-browser", "chromium", "chromium-browser")]
    return next((c for c in candidates if c and os.path.exists(c)), None)


def open_ui(url: str, mode: str):
    if mode == "none":
        return
    if mode == "window":
        exe = _find_app_browser()
        if exe:
            try:
                subprocess.Popen([exe, f"--app={url}", "--window-size=1320,900"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except OSError:
                pass
    webbrowser.open(url)  # any browser: Firefox, Safari, Chrome, Edge...


def _already_running(port: int) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1.5) as r:
            return r.headers.get("Server", "").startswith("HeatDoctor")
    except Exception:
        return False


def main(argv=None):
    # pythonw (no console) sets these to None; keep print() from crashing.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")
    ap = argparse.ArgumentParser(prog="heat-doctor", description="PC heat, performance and security diagnostics.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--open", choices=["window", "browser", "none"], default="window",
                    help="window = standalone app window (Chrome/Edge/Brave), browser = new tab in your default "
                         "browser, none = just run the server")
    ap.add_argument("--report", type=int, metavar="SECONDS",
                    help="no UI: sample for SECONDS, print a diagnosis to the terminal and exit")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if args.report:
        from .collector import Collector
        from . import diagnose
        col = Collector()
        col.last_client = time.time() + 10 ** 9  # sample at the fast rate
        col.start()
        print(f"Sampling for {args.report} s…", file=sys.stderr)
        time.sleep(args.report)
        print(diagnose.text_report(diagnose.build(col, args.report, {}, {})))
        return

    if _already_running(args.port):
        print("Heat Doctor is already running; opening it.")
        open_ui(f"http://127.0.0.1:{args.port}/", args.open)
        return

    from .server import serve
    app, httpd, port = serve(args.port)
    url = f"http://127.0.0.1:{port}/"
    print(f"Heat Doctor {__version__} running at {url}")
    print("Close this window or press Ctrl+C to stop.")
    open_ui(url, args.open)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        app.col.stop()
        httpd.server_close()


if __name__ == "__main__":
    main()
