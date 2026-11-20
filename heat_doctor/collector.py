"""Background sampler.

Two loops:
  * fast loop (2 s while the dashboard is open, 6 s when nobody is watching):
    system CPU / RAM / disk throughput plus per-process disk I/O, CPU and memory.
  * slow loop (15 s): temperatures, paging rate, power plan, partitions, and the
    svchost -> Windows service map.

Everything is kept in fixed-size ring buffers, so memory use is bounded.
"""
from __future__ import annotations

import collections
import threading
import time

import psutil

from . import sensors
from .util import IS_WINDOWS as _W

if _W:
    from . import winproc
else:
    winproc = None  # type: ignore
from .util import IS_WINDOWS, is_admin

HISTORY_LEN = 1800          # one hour at 2 s
ACTIVE_INTERVAL = 2.0
IDLE_INTERVAL = 6.0
SLOW_INTERVAL = 15.0
SERVICE_MAP_INTERVAL = 90.0
IDLE_AFTER = 30.0            # seconds without a dashboard poll


class Collector:
    def __init__(self):
        self.lock = threading.Lock()
        self.history = collections.deque(maxlen=HISTORY_LEN)
        self.proc_samples = collections.deque(maxlen=HISTORY_LEN)
        self.group_meta: dict[str, dict] = {}
        self.latest_groups: list[dict] = []
        self.probe: dict = {"drives": [], "zones": [], "pages_per_sec": None, "power_plan": None}
        self.pages_hist = collections.deque(maxlen=240)
        self.partitions: list[dict] = []
        self.svc_map: dict[int, list[str]] = {}
        self.started = time.time()
        self.last_client = 0.0
        self.ncpu = psutil.cpu_count() or 1
        self.admin = is_admin()
        self.laptop = self._has_battery()
        self.total_ram = psutil.virtual_memory().total
        self._prev_proc: dict = {}
        self._prev_disk = None
        self._prev_t = None
        self._stop = threading.Event()
        self._me = psutil.Process()
        self._my_pids: set[int] = {self._me.pid}
        self._me.cpu_percent(None)
        psutil.cpu_percent(None)

    # ------------------------------------------------------------------ setup
    @staticmethod
    def _has_battery() -> bool:
        try:
            return psutil.sensors_battery() is not None
        except Exception:
            return False

    def start(self):
        threading.Thread(target=self._fast_loop, name="fast", daemon=True).start()
        threading.Thread(target=self._slow_loop, name="slow", daemon=True).start()

    def stop(self):
        self._stop.set()

    def touch(self):
        """Called whenever the dashboard polls; switches to the faster rate."""
        self.last_client = time.time()

    @property
    def interval(self) -> float:
        return ACTIVE_INTERVAL if time.time() - self.last_client < IDLE_AFTER else IDLE_INTERVAL

    # ------------------------------------------------------------- slow loop
    def _slow_loop(self):
        last_svc = 0.0
        prober = sensors.Probe()
        while not self._stop.is_set():
            try:
                if IS_WINDOWS and time.time() - last_svc > SERVICE_MAP_INTERVAL:
                    self.svc_map = self._service_map()
                    last_svc = time.time()
                probe = prober.read()
                parts = self._partitions()
                with self.lock:
                    self.probe = probe
                    self.partitions = parts
                    if probe.get("pages_per_sec") is not None:
                        self.pages_hist.append((time.time(), float(probe["pages_per_sec"])))
            except Exception as e:  # never let the sampler die
                print("slow loop error:", e)
            self._stop.wait(SLOW_INTERVAL)

    @staticmethod
    def _service_map() -> dict[int, list[str]]:
        m: dict[int, list[str]] = {}
        try:
            for s in psutil.win_service_iter():
                try:
                    d = s.as_dict()
                except Exception:
                    continue
                if d.get("pid"):
                    m.setdefault(d["pid"], []).append(d["name"])
        except Exception:
            pass
        return m

    @staticmethod
    def _partitions() -> list[dict]:
        out = []
        for p in psutil.disk_partitions(all=False):
            if "cdrom" in p.opts or not p.fstype:
                continue
            try:
                u = psutil.disk_usage(p.mountpoint)
            except Exception:
                continue
            out.append({"mount": p.mountpoint, "fstype": p.fstype, "total": u.total,
                        "used": u.used, "free": u.free, "percent": u.percent})
        return out

    # ------------------------------------------------------------- fast loop
    def _fast_loop(self):
        while not self._stop.is_set():
            t0 = time.time()
            try:
                self._sample()
            except Exception as e:
                print("sample error:", e)
            self._stop.wait(max(0.2, self.interval - (time.time() - t0)))

    SELF_KEY = "Heat Doctor (this app)"

    def _group_key(self, pid: int, name: str) -> tuple[str, list[str]]:
        if pid in self._my_pids:
            return self.SELF_KEY, ["HeatDoctor"]
        if name.lower() == "svchost.exe":
            svcs = self.svc_map.get(pid)
            if svcs:
                return f"svchost.exe [{', '.join(sorted(svcs)[:3])}]", svcs
        return name, []

    @staticmethod
    def _read_proc(p):
        try:
            io = p.io_counters()
            rb, wb = io.read_bytes, io.write_bytes
        except Exception:
            rb = wb = None
        try:
            ct = p.cpu_times()
            cpu = ct.user + ct.system
        except Exception:
            cpu = None
        try:
            mi = p.memory_info()
            rss = mi.rss
            private = (getattr(mi, "private", 0) or mi.vms) if IS_WINDOWS else mi.rss
        except Exception:
            rss = private = 0
        return rb, wb, cpu, rss, private

    def _processes(self):
        """Yields (pid, name, read_bytes, write_bytes, cpu_seconds, rss, private) for every process."""
        if winproc is not None and winproc.available:
            try:
                for pid, name, cpu, rb, wb, ws, priv in winproc.snapshot():
                    yield pid, name, rb, wb, cpu, ws, priv
                return
            except OSError:
                pass
        for p in psutil.process_iter(["pid", "name"]):
            with p.oneshot():
                rb, wb, cpu, rss, private = self._read_proc(p)
            yield p.info["pid"], p.info["name"], rb, wb, cpu, rss, private

    def _sample(self):
        now = time.time()
        dt = (now - self._prev_t) if self._prev_t else None

        cur: dict = {}
        groups: dict[str, dict] = {}
        try:  # our own process + any PowerShell helpers we spawned, so they're labelled as ours
            self._my_pids = {self._me.pid} | {c.pid for c in self._me.children(recursive=True)}
        except Exception:
            self._my_pids = {self._me.pid}
        for pid, name, rb, wb, cpu, rss, private in self._processes():
            if pid == 0:
                continue  # System Idle Process
            name = name or f"pid {pid}"
            cur[(pid, name)] = (rb, wb, cpu)

            key, svcs = self._group_key(pid, name)
            g = groups.get(key)
            if g is None:
                g = groups[key] = {"key": key, "name": name, "services": svcs, "rb": 0, "wb": 0,
                                   "cpu_s": 0.0, "rss": 0, "private": 0, "instances": 0, "pids": []}
            g["instances"] += 1
            g["rss"] += rss or 0
            g["private"] += private or 0
            if len(g["pids"]) < 50:
                g["pids"].append(pid)

            prev = self._prev_proc.get((pid, name))
            if prev and dt:
                if rb is not None and prev[0] is not None:
                    g["rb"] += max(0, rb - prev[0])
                    g["wb"] += max(0, wb - prev[1])
                if cpu is not None and prev[2] is not None:
                    g["cpu_s"] += max(0.0, cpu - prev[2])
        self._prev_proc = cur

        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        cpu_pct = psutil.cpu_percent(None)
        try:
            disk = psutil.disk_io_counters()
        except Exception:
            disk = None

        read_bps = write_bps = iops = 0.0
        if disk and self._prev_disk and dt:
            read_bps = max(0, disk.read_bytes - self._prev_disk.read_bytes) / dt
            write_bps = max(0, disk.write_bytes - self._prev_disk.write_bytes) / dt
            iops = max(0, (disk.read_count + disk.write_count)
                       - (self._prev_disk.read_count + self._prev_disk.write_count)) / dt
        self._prev_disk = disk
        self._prev_t = now
        if not dt:
            return  # first tick only primes the counters

        latest = []
        compact = {}
        for g in groups.values():
            g["read_bps"] = g["rb"] / dt
            g["write_bps"] = g["wb"] / dt
            g["cpu_pct"] = g["cpu_s"] / dt / self.ncpu * 100
            latest.append(g)
            if g["rb"] or g["wb"] or g["cpu_s"] > 0.001:
                compact[g["key"]] = (g["rb"], g["wb"], g["cpu_s"])

        with self.lock:
            probe = self.probe
            drive_temps = [d["temp"] for d in probe["drives"] if d.get("temp")]
            zone_temps = [z["c"] for z in probe["zones"]]
            self.history.append({
                "t": now, "cpu": round(cpu_pct, 1), "mem": round(vm.percent, 1),
                "swap": round(sw.percent, 1),
                "read_bps": read_bps, "write_bps": write_bps, "iops": round(iops, 1),
                "drive_temp": max(drive_temps) if drive_temps else None,
                "zone_temp": max(zone_temps) if zone_temps else None,
            })
            self.proc_samples.append((now, dt, compact))
            for g in latest:
                self.group_meta[g["key"]] = {"name": g["name"], "services": g["services"]}
            self.latest_groups = latest
            self.mem = {"total": vm.total, "used": vm.used, "available": vm.available,
                        "percent": vm.percent, "swap_total": sw.total, "swap_used": sw.used,
                        "swap_percent": sw.percent}

    # ---------------------------------------------------------------- queries
    def window_groups(self, window_s: float) -> tuple[list[dict], float]:
        """Per-process totals over the last `window_s` seconds."""
        now = time.time()
        tot: dict[str, list[float]] = {}
        span = 0.0
        with self.lock:
            samples = list(self.proc_samples)
            latest = {g["key"]: g for g in self.latest_groups}
            meta = dict(self.group_meta)
        for t, dt, d in reversed(samples):
            if t < now - window_s:
                break
            span += dt
            for k, (rb, wb, c) in d.items():
                a = tot.setdefault(k, [0.0, 0.0, 0.0])
                a[0] += rb
                a[1] += wb
                a[2] += c
        out = []
        keys = set(tot) | set(latest)
        for k in keys:
            rb, wb, c = tot.get(k, (0, 0, 0))
            m = meta.get(k, {"name": k, "services": []})
            lg = latest.get(k, {})
            out.append({
                "key": k, "name": m["name"], "services": m["services"],
                "read_bps": rb / span if span else 0, "write_bps": wb / span if span else 0,
                "cpu_pct": c / span / self.ncpu * 100 if span else 0,
                "now_read_bps": lg.get("read_bps", 0), "now_write_bps": lg.get("write_bps", 0),
                "now_cpu_pct": lg.get("cpu_pct", 0),
                "rss": lg.get("rss", 0), "private": lg.get("private", 0),
                "instances": lg.get("instances", 0), "pids": lg.get("pids", []),
                "running": k in latest,
            })
        return out, span

    def history_since(self, window_s: float) -> list[dict]:
        cutoff = time.time() - window_s
        with self.lock:
            return [h for h in self.history if h["t"] >= cutoff]

    def self_usage(self) -> dict:
        try:
            return {"cpu_pct": self._me.cpu_percent(None) / self.ncpu,
                    "rss": self._me.memory_info().rss}
        except Exception:
            return {"cpu_pct": 0, "rss": 0}
