"""On-demand storage scan: known space hogs + largest folders in the user profile.

Runs in a background thread with a time budget, so it never pegs the disk for
long. Uses os.scandir, which on Windows gets file sizes from the directory
listing itself (no extra syscall per file).
"""
from __future__ import annotations

import glob
import os
import stat
import threading
import time

from .util import IS_MAC, IS_WINDOWS

TIME_BUDGET = 40.0  # seconds for the whole scan


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _known_locations() -> list[dict]:
    home = os.path.expanduser("~")
    if IS_WINDOWS:
        local = _env("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        windir = _env("WINDIR", r"C:\Windows")
        sysdrive = _env("SystemDrive", "C:") + "\\"
        browser_caches = []
        for base in (os.path.join(local, "Google", "Chrome", "User Data"),
                     os.path.join(local, "Microsoft", "Edge", "User Data"),
                     os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")):
            for sub in ("Cache", "Code Cache", os.path.join("Service Worker", "CacheStorage")):
                browser_caches += glob.glob(os.path.join(base, "*", sub))
        return [
            {"id": "user_temp", "label": "Your temp files", "paths": [_env("TEMP", os.path.join(local, "Temp"))],
             "tip": "Safe to clean. Programs re-create what they need.", "action": "clean_temp"},
            {"id": "win_temp", "label": "Windows temp files", "paths": [os.path.join(windir, "Temp")],
             "tip": "Clean with Disk Cleanup or Storage Sense.", "action": "open_storage_sense"},
            {"id": "wu_cache", "label": "Windows Update download cache",
             "paths": [os.path.join(windir, "SoftwareDistribution", "Download")],
             "tip": "Disk Cleanup > 'Clean up system files' > Windows Update Cleanup.", "action": "open_disk_cleanup"},
            {"id": "recycle", "label": "Recycle Bin", "paths": [os.path.join(sysdrive, "$Recycle.Bin")],
             "tip": "Empty it from the desktop, or let Storage Sense do it automatically.", "action": "open_storage_sense"},
            {"id": "downloads", "label": "Downloads folder", "paths": [os.path.join(home, "Downloads")],
             "tip": "Installers and archives pile up here. Sort by size and delete what you don't need.", "action": "open_downloads"},
            {"id": "browser_cache", "label": "Browser caches", "paths": browser_caches,
             "tip": "Clear from each browser's settings (Privacy > Clear browsing data > Cached images and files)."},
            {"id": "crash", "label": "Crash dumps",
             "paths": [os.path.join(local, "CrashDumps"), os.path.join(windir, "Minidump"), os.path.join(windir, "MEMORY.DMP"),
                       os.path.join(windir, "LiveKernelReports")],
             "tip": "Safe to remove unless you're debugging crashes. Disk Cleanup can do it.", "action": "open_disk_cleanup"},
            {"id": "winold", "label": "Previous Windows install (Windows.old)", "paths": [os.path.join(sysdrive, "Windows.old")],
             "tip": "Removable 10 days after an upgrade via Storage settings > Temporary files.", "action": "open_storage_sense"},
            {"id": "system_files", "label": "Hibernation + page file",
             "paths": [os.path.join(sysdrive, "hiberfil.sys"), os.path.join(sysdrive, "pagefile.sys"), os.path.join(sysdrive, "swapfile.sys")],
             "tip": "Managed by Windows. Don't delete these. hiberfil.sys goes away if you run `powercfg /h off` (disables hibernate)."},
            {"id": "dev_caches", "label": "Developer caches (npm, pip, NuGet, Gradle, conda)",
             "paths": [os.path.join(local, "npm-cache"), os.path.join(local, "pip", "cache"),
                       os.path.join(home, ".nuget", "packages"), os.path.join(home, ".gradle", "caches"),
                       os.path.join(home, "anaconda3", "pkgs"), os.path.join(home, "miniconda3", "pkgs"),
                       os.path.join(local, "Yarn", "Cache")],
             "tip": "Safe to clear with each tool (npm cache clean --force, pip cache purge, conda clean -a)."},
            {"id": "docker", "label": "Docker / WSL disk images", "paths": [os.path.join(local, "Docker")],
             "tip": "Prune unused images (docker system prune). WSL disks only shrink after compacting."},
        ]
    caches = os.path.join(home, "Library", "Caches") if IS_MAC else os.path.join(home, ".cache")
    trash = os.path.join(home, ".Trash") if IS_MAC else os.path.join(home, ".local", "share", "Trash")
    return [
        {"id": "caches", "label": "App caches", "paths": [caches], "tip": "Mostly safe to clear while apps are closed."},
        {"id": "trash", "label": "Trash", "paths": [trash], "tip": "Empty the trash."},
        {"id": "downloads", "label": "Downloads folder", "paths": [os.path.join(home, "Downloads")],
         "tip": "Sort by size and delete old installers.", "action": "open_downloads"},
    ]


class _Budget:
    def __init__(self, seconds: float):
        self.deadline = time.time() + seconds
        self.hit = False

    def out(self) -> bool:
        if time.time() > self.deadline:
            self.hit = True
        return self.hit


def dir_size(path: str, budget: _Budget) -> tuple[int, int]:
    """Total bytes and file count under `path`, skipping links/reparse points."""
    if not os.path.exists(path):
        return 0, 0
    try:
        st = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode):
            return st.st_size, 1
    except OSError:
        return 0, 0
    total = files = 0
    stack = [path]
    while stack:
        if budget.out():
            break
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            attrs = getattr(e.stat(follow_symlinks=False), "st_file_attributes", 0)
                            if attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT (junctions)
                                continue
                            stack.append(e.path)
                        else:
                            st = e.stat(follow_symlinks=False)
                            attrs = getattr(st, "st_file_attributes", 0)
                            # Skip cloud-only placeholders (OneDrive "online-only"): no local bytes.
                            if attrs & 0x00400000 or attrs & 0x00040000:
                                continue
                            total += st.st_size
                            files += 1
                    except OSError:
                        continue
        except OSError:
            continue
    return total, files


class StorageScanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.state = {"status": "idle", "started": None, "finished": None, "hogs": [], "folders": [], "partial": False}

    def start(self) -> bool:
        with self.lock:
            if self.state["status"] == "running":
                return False
            self.state = {"status": "running", "started": time.time(), "finished": None,
                          "hogs": [], "folders": [], "partial": False}
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self.state)

    def _run(self):
        hogs = []
        hog_partial = False
        overall = _Budget(35.0)
        for loc in _known_locations():
            if overall.out():
                break
            budget = _Budget(4.0)  # every category gets its own slice, so one huge folder can't starve the rest
            size = files = 0
            existing = []
            for p in loc["paths"]:
                s, f = dir_size(p, budget)
                if s or os.path.exists(p):
                    existing.append(p)
                size += s
                files += f
            hog_partial |= budget.hit
            if size > 0:
                hogs.append({"id": loc["id"], "label": loc["label"], "size": size, "files": files, "partial": budget.hit,
                             "tip": loc["tip"], "action": loc.get("action"), "paths": existing[:3]})
            with self.lock:
                self.state["hogs"] = sorted(hogs, key=lambda h: h["size"], reverse=True)
        hogs.sort(key=lambda h: h["size"], reverse=True)
        with self.lock:
            self.state["hogs"] = hogs

        # Largest folders in the user profile: each top-level folder gets its own time slice,
        # then the three biggest are drilled one level deeper.
        overall = _Budget(TIME_BUDGET)
        folder_partial = False
        home = os.path.expanduser("~")
        folders = []
        try:
            entries = [e for e in os.scandir(home) if e.is_dir(follow_symlinks=False) and not e.is_symlink()]
        except OSError:
            entries = []
        for e in entries:
            if overall.out():
                folder_partial = True
                break
            budget = _Budget(5.0)
            s, f = dir_size(e.path, budget)
            folder_partial |= budget.hit
            if s > 50 * 1024 ** 2:
                folders.append({"path": e.path, "name": e.name, "size": s, "files": f, "children": [], "partial": budget.hit})
                with self.lock:
                    self.state["folders"] = sorted(folders, key=lambda x: x["size"], reverse=True)[:15]
        folders.sort(key=lambda x: x["size"], reverse=True)
        for top in folders[:3]:
            kids = []
            try:
                for e in os.scandir(top["path"]):
                    if overall.out():
                        break
                    if e.is_dir(follow_symlinks=False) and not e.is_symlink():
                        s, f = dir_size(e.path, _Budget(2.0))
                        if s > 50 * 1024 ** 2:
                            kids.append({"path": e.path, "name": e.name, "size": s, "files": f})
            except OSError:
                pass
            top["children"] = sorted(kids, key=lambda x: x["size"], reverse=True)[:6]
        budget = overall
        hog_partial = hog_partial or folder_partial

        with self.lock:
            self.state.update(folders=folders[:15], status="done", finished=time.time(), partial=budget.hit or hog_partial)
