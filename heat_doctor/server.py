"""Tiny local web server (standard library only).

Security: binds to 127.0.0.1 only, checks the Host header (blocks DNS
rebinding) and requires a per-launch random token on every API call (blocks
other websites from poking the API through your browser).
"""
from __future__ import annotations

import json
import mimetypes
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import psutil

from . import __version__, actions, assistant, diagnose
from .collector import Collector
from .security import SecurityScanner
from .storage import StorageScanner
from .util import IS_WINDOWS

STATIC = os.path.join(os.path.dirname(__file__), "static")
SECURITY_RESCAN = 30 * 60


class App:
    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.col = Collector()
        self.storage = StorageScanner()
        self.security = SecurityScanner()
        self.httpd: ThreadingHTTPServer | None = None

    def start_background(self):
        self.col.start()

        def security_loop():
            time.sleep(15)
            while True:
                self.security.start()
                time.sleep(SECURITY_RESCAN)
        threading.Thread(target=security_loop, daemon=True).start()

    def diag(self, window: float) -> dict:
        return diagnose.build(self.col, window, self.storage.snapshot(), self.security.snapshot())

    def state(self, window: float) -> dict:
        self.col.touch()
        d = self.diag(window)
        hist = self.col.history_since(window)
        step = max(1, len(hist) // 600)
        with self.col.lock:
            probe = dict(self.col.probe)
            parts = list(self.col.partitions)
            mem = dict(getattr(self.col, "mem", {}) or {})
            latest = self.col.history[-1] if self.col.history else None
        return {
            "version": __version__, "now": time.time(), "window": window, "latest": latest,
            "history": hist[::step], "diag": d, "drives": probe.get("drives", []), "zones": probe.get("zones", []),
            "power_plan": probe.get("power_plan"), "partitions": parts, "memory": mem,
            "storage": self.storage.snapshot(), "security": self.security.snapshot(),
            "actions": actions.available(), "assistant": assistant.status(),
            "meta": {"admin": self.col.admin, "laptop": self.col.laptop, "windows": IS_WINDOWS,
                     "cpus": self.col.ncpu, "ram_total": self.col.total_ram,
                     "uptime": time.time() - self.col.started, "interval": self.col.interval,
                     "self": self.col.self_usage(), "boot": psutil.boot_time()},
        }


def make_handler(app: App, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "HeatDoctor"

        def log_message(self, *a):  # keep the console quiet
            pass

        # ----------------------------------------------------------- helpers
        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, default=str).encode(), "application/json")

        def _guard(self, api: bool) -> bool:
            if self.headers.get("Host") not in allowed_hosts:
                self._send(403, b"Forbidden host", "text/plain")
                return False
            if api and not secrets.compare_digest(self.headers.get("X-HD-Token", ""), app.token):
                self._send(403, b"Bad token", "text/plain")
                return False
            return True

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 1_000_000:
                return {}
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return {}

        # -------------------------------------------------------------- GET
        def do_GET(self):
            u = urlparse(self.path)
            api = u.path.startswith("/api/")
            if not self._guard(api):
                return
            if u.path in ("/", "/index.html"):
                with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                    html = fh.read().replace(b"__HD_TOKEN__", app.token.encode())
                csp = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
                return self._send(200, html, "text/html; charset=utf-8", {"Content-Security-Policy": csp})
            if u.path.startswith("/static/"):
                name = os.path.basename(u.path)
                path = os.path.join(STATIC, name)
                if not os.path.isfile(path):
                    return self._send(404, b"Not found", "text/plain")
                with open(path, "rb") as fh:
                    ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
                    return self._send(200, fh.read(), ctype)
            if u.path == "/api/state":
                q = parse_qs(u.query)
                try:
                    window = max(30.0, min(3600.0, float(q.get("window", ["300"])[0])))
                except ValueError:
                    window = 300.0
                return self._json(app.state(window))
            if u.path == "/api/report":
                return self._send(200, diagnose.text_report(app.diag(600)).encode(), "text/plain; charset=utf-8")
            self._send(404, b"Not found", "text/plain")

        # ------------------------------------------------------------- POST
        def do_POST(self):
            u = urlparse(self.path)
            if not self._guard(True):
                return
            body = self._body()
            if u.path == "/api/storage/scan":
                return self._json({"ok": True, "started": app.storage.start()})
            if u.path == "/api/security/scan":
                return self._json({"ok": True, "started": app.security.start()})
            if u.path == "/api/action":
                return self._json(actions.perform(str(body.get("action")), body.get("params") or {}))
            if u.path == "/api/key":
                return self._json(assistant.set_key(body.get("key"), bool(body.get("remember"))))
            if u.path == "/api/ask":
                return self._ask(body)
            if u.path == "/api/quit":
                self._json({"ok": True})
                threading.Thread(target=app.httpd.shutdown, daemon=True).start()
                return
            self._send(404, b"Not found", "text/plain")

        def _ask(self, body: dict):
            window = float(body.get("window") or 600)
            d = app.diag(window)
            snap = assistant.build_snapshot(app.col, d, app.storage.snapshot(), app.security.snapshot())
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                for kind, payload in assistant.stream_answer(str(body.get("question") or ""), snap,
                                                             body.get("history") or []):
                    self.wfile.write(b"data: " + json.dumps({"type": kind, "data": payload}).encode() + b"\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

    return Handler


def serve(port: int = 8765) -> tuple[App, ThreadingHTTPServer, int]:
    app = App()
    httpd = None
    for p in [port] + list(range(port + 1, port + 20)):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), make_handler(app, p))
            port = p
            break
        except OSError:
            continue
    if httpd is None:
        raise SystemExit("No free port found between %d and %d" % (port, port + 20))
    httpd.daemon_threads = True
    app.httpd = httpd
    app.start_background()
    return app, httpd, port
