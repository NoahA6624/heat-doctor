"""What common background processes are, why they heat a machine, and what to do.

Each entry matches on lowercase process names and/or Windows service names
(for svchost.exe groups). `actions` refer to ids in actions.py so the UI can
show one-click buttons next to the advice.
"""
from __future__ import annotations

KB = [
    {
        "id": "self", "label": "Heat Doctor itself",
        "names": set(), "services": {"HeatDoctor"},
        "about": "This app's own monitoring, including the short PowerShell checks it runs for drive sensors and security scans.",
        "fixes": ["Nothing to do. Its footprint is shown at the top of the window."],
        "actions": [],
    },
    {
        "id": "search", "label": "Windows Search indexing",
        "names": {"searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe"},
        "services": {"WSearch"},
        "about": "Windows Search reads every file in indexed folders to build its search database. "
                 "After big file changes, updates or a new sync it can grind the drive for hours.",
        "fixes": ["Remove large or fast-changing folders (Downloads, code projects, game libraries) from Indexing Options.",
                  "Let it finish once while plugged in. If it never finishes, rebuild the index from Indexing Options > Advanced."],
        "actions": ["open_indexing"],
    },
    {
        "id": "defender", "label": "Microsoft Defender scanning",
        "names": {"msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe", "mpcmdrun.exe"},
        "services": {"WinDefend"},
        "about": "Defender scans files as they are written and runs scheduled full scans. "
                 "Constant scanning usually means another program is writing lots of files.",
        "fixes": ["Find the program writing the files (see the disk column) and deal with it first.",
                  "Add exclusions only for trusted, write-heavy folders such as build output or VM disks."],
        "actions": ["open_defender"],
    },
    {
        "id": "sync", "label": "Cloud sync",
        "names": {"onedrive.exe", "dropbox.exe", "googledrivefs.exe", "icloudservices.exe", "icloudckks.exe",
                  "boxsync.exe", "megasync.exe", "nextcloud.exe", "synology drive client.exe"},
        "services": set(),
        "about": "Sync clients hash and upload or download changed files. A first sync, a big photo or video "
                 "folder, or a sync conflict loop can keep the drive busy all day.",
        "fixes": ["Pause syncing to confirm it is the cause, then use Files On-Demand so files stay in the cloud.",
                  "Exclude folders that change constantly, such as node_modules, VM images or game installs."],
        "actions": [],
    },
    {
        "id": "update", "label": "Windows Update",
        "names": {"tiworker.exe", "trustedinstaller.exe", "usocoreworker.exe", "mousocoreworker.exe",
                  "setuphost.exe", "wuauclt.exe", "windows10upgraderapp.exe"},
        "services": {"wuauserv", "UsoSvc", "TrustedInstaller", "BITS"},
        "about": "Updates download, unpack and install components, which writes many gigabytes. "
                 "A stuck update can retry forever.",
        "fixes": ["Open Windows Update, install anything pending and restart.",
                  "If the same update fails over and over, run the Windows Update troubleshooter."],
        "actions": ["open_windows_update"],
    },
    {
        "id": "dosvc", "label": "Delivery Optimization (update sharing)",
        "names": set(), "services": {"DoSvc"},
        "about": "Delivery Optimization caches updates and can upload them to other PCs, "
                 "which keeps the disk and network busy.",
        "fixes": ["Turn off 'Allow downloads from other PCs' in Delivery Optimization settings."],
        "actions": ["open_delivery_opt"],
    },
    {
        "id": "sysmain", "label": "SysMain (Superfetch)",
        "names": set(), "services": {"SysMain"},
        "about": "SysMain preloads frequently used apps into RAM. It helps on HDDs, "
                 "but on some machines it causes constant disk reads.",
        "fixes": ["If it is your top disk user for a long time, set the SysMain service to Manual in services.msc and restart."],
        "actions": [],
    },
    {
        "id": "dps", "label": "Diagnostic Policy Service",
        "names": set(), "services": {"DPS", "WdiServiceHost", "WdiSystemHost"},
        "about": "Windows' troubleshooting service. It logs app and network usage to a database (SRUDB.dat); "
                 "when that file grows large the service can use lots of CPU and disk continuously.",
        "fixes": [r"Restart the PC first. If it stays busy, an oversized C:\Windows\System32\sru\SRUDB.dat is the usual cause: "
                  "stop the DPS service, rename that file, and start the service again (needs administrator)."],
        "actions": [],
    },
    {
        "id": "telemetry", "label": "Windows telemetry / compatibility checks",
        "names": {"compattelrunner.exe", "devicecensus.exe"},
        "services": {"DiagTrack"},
        "about": "Compatibility and diagnostics tasks scan installed programs and files. They usually finish within an hour.",
        "fixes": ["Set Diagnostic data to 'Required only' in Privacy & security > Diagnostics & feedback."],
        "actions": [],
    },
    {
        "id": "kernel", "label": "Windows kernel (System): paging and file flushing",
        "names": {"system", "registry"},
        "services": set(),
        "about": "Windows charges the 'System' process for flushing other apps' cached writes and for paging memory "
                 "to disk. If RAM is nearly full, this is usually paging.",
        "fixes": ["Check the RAM panel: close memory-heavy apps or browser tabs so Windows stops paging.",
                  "If RAM is fine, look at the next biggest writer. System is often flushing that app's data."],
        "actions": ["open_resource_monitor"],
    },
    {
        "id": "memcomp", "label": "Memory compression",
        "names": {"memory compression", "memcompression"}, "services": set(),
        "about": "Windows compresses memory when RAM runs low. Heavy activity here means you are short on RAM.",
        "fixes": ["Close memory-heavy apps, reduce browser tabs, or add more RAM."],
        "actions": ["open_task_manager"],
    },
    {
        "id": "browser", "label": "Web browser",
        "names": {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
                  "arc.exe", "msedgewebview2.exe", "google chrome", "safari"},
        "services": set(),
        "about": "Browsers write cache, session state and video buffers all the time, and every tab uses RAM and CPU. "
                 "A few busy tabs (video, web apps, crypto-mining sites) can heat a laptop on their own.",
        "fixes": ["Open the browser's own task manager (Shift+Esc in Chrome/Edge) and close the heaviest tabs.",
                  "Turn on Memory Saver / Efficiency mode and remove extensions you don't use."],
        "actions": [],
    },
    {
        "id": "games", "label": "Game launcher / downloads",
        "names": {"steam.exe", "steamwebhelper.exe", "steamservice.exe", "epicgameslauncher.exe",
                  "battle.net.exe", "eadesktop.exe", "ubisoftconnect.exe", "galaxyclient.exe", "riotclientservices.exe"},
        "services": set(),
        "about": "Launchers download, unpack and verify game files, often in the background. These are very large writes.",
        "fixes": ["Limit background downloads to off-hours in the launcher's settings, or pause updates while you work."],
        "actions": [],
    },
    {
        "id": "torrent", "label": "Torrent client",
        "names": {"qbittorrent.exe", "utorrent.exe", "bittorrent.exe", "transmission-qt.exe", "deluge.exe", "tixati.exe"},
        "services": set(),
        "about": "Seeding reads from the disk all the time; downloading writes constantly.",
        "fixes": ["Stop seeding finished torrents, or cap upload/download speeds."],
        "actions": [],
    },
    {
        "id": "vm", "label": "Virtual machine / WSL / Docker",
        "names": {"vmmem", "vmmemwsl", "vmmem.exe", "vmwp.exe", "com.docker.backend.exe", "docker desktop.exe",
                  "virtualboxvm.exe", "vmware-vmx.exe"},
        "services": set(),
        "about": "A whole operating system is running inside this process, with its own disk and RAM use.",
        "fixes": ["Shut down WSL (`wsl --shutdown`) or stop containers and VMs when you're not using them.",
                  "Cap WSL memory in %USERPROFILE%\\.wslconfig (for example memory=4GB)."],
        "actions": [],
    },
    {
        "id": "dev", "label": "Developer tools",
        "names": {"code.exe", "node.exe", "python.exe", "pythonw.exe", "java.exe", "javaw.exe", "devenv.exe",
                  "msbuild.exe", "idea64.exe", "pycharm64.exe", "rider64.exe", "cargo.exe", "rustc.exe", "go.exe"},
        "services": set(),
        "about": "Builds, file watchers, language servers and package installs read and write many small files.",
        "fixes": ["Stop watch/dev servers you've forgotten about, and exclude build folders from indexing and cloud sync."],
        "actions": [],
    },
    {
        "id": "backup", "label": "Backup software",
        "names": {"bzserv.exe", "bztransmit.exe", "carbonite.exe", "acronis_cyber_protect.exe", "trueimagehomeservice.exe",
                  "reflectservice.exe", "veeam.endpoint.service.exe", "crashplanservice.exe", "idrive.exe"},
        "services": {"fhsvc"},
        "about": "Backups read your whole disk. The first backup, or one after big changes, can take hours.",
        "fixes": ["Schedule backups for when the PC is idle and plugged in."],
        "actions": [],
    },
    {
        "id": "av3p", "label": "Third-party antivirus",
        "names": {"mcshield.exe", "mfemms.exe", "mfevtps.exe", "nortonsecurity.exe", "ns.exe", "avastsvc.exe",
                  "avgsvc.exe", "bdservicehost.exe", "ekrn.exe", "mbamservice.exe", "avp.exe"},
        "services": set(),
        "about": "Running two antivirus products, or a heavy suite, doubles the scanning on every file you touch.",
        "fixes": ["Use one real-time antivirus only. Microsoft Defender is enough for most people."],
        "actions": ["open_defender"],
    },
    {
        "id": "creative", "label": "Creative / media app",
        "names": {"adobe desktop service.exe", "creative cloud.exe", "photoshop.exe", "afterfx.exe",
                  "adobe premiere pro.exe", "resolve.exe", "obs64.exe", "lightroom.exe", "handbrake.exe"},
        "services": set(),
        "about": "Media apps use big scratch/cache files and lots of CPU or GPU.",
        "fixes": ["Point scratch/cache disks at a drive with plenty of free space and clear old media caches."],
        "actions": [],
    },
    {
        "id": "chat", "label": "Chat / meeting app",
        "names": {"teams.exe", "ms-teams.exe", "slack.exe", "discord.exe", "zoom.exe", "whatsapp.exe"},
        "services": set(),
        "about": "These are Electron/WebView apps: each one is a browser of its own, with cache writes and real RAM use.",
        "fixes": ["Quit the ones you aren't using and turn off 'open at startup'."],
        "actions": ["open_startup_apps"],
    },
    {
        "id": "wmi", "label": "WMI provider host",
        "names": {"wmiprvse.exe"}, "services": {"Winmgmt"},
        "about": "Answers system queries from other programs. Sustained high CPU means some app is polling it too hard. "
                 "OEM utilities and monitoring tools are common causes.",
        "fixes": ["Close vendor utilities and hardware monitors one at a time to find the one that's hammering WMI."],
        "actions": [],
    },
]

_BY_NAME = {}
_BY_SVC = {}
for _e in KB:
    for _n in _e["names"]:
        _BY_NAME[_n] = _e
    for _s in _e["services"]:
        _BY_SVC[_s.lower()] = _e


def lookup(name: str, services: list[str] | None = None) -> dict | None:
    for s in services or []:
        e = _BY_SVC.get(s.lower())
        if e:
            return e
    return _BY_NAME.get((name or "").lower())


def public(entry: dict | None) -> dict | None:
    if not entry:
        return None
    return {k: entry[k] for k in ("id", "label", "about", "fixes", "actions")}
