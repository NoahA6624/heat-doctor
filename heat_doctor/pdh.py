"""Windows performance counters via PDH (no PowerShell process needed).

A persistent query is collected on each slow tick, so rate counters such as
Memory\\Pages/sec are computed by Windows between our two collections.
English counter names are used so it works on non-English Windows too.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

PDH_FMT_DOUBLE = 0x00000200
PDH_MORE_DATA = 0x800007D2


class _FmtValue(ctypes.Structure):
    _fields_ = [("CStatus", wintypes.DWORD), ("doubleValue", ctypes.c_double)]


class _FmtItem(ctypes.Structure):
    _fields_ = [("szName", wintypes.LPWSTR), ("FmtValue", _FmtValue)]


class Counters:
    def __init__(self, paths: dict[str, str]):
        self.ok = False
        self.handles: dict[str, ctypes.c_void_p] = {}
        try:
            self.pdh = ctypes.WinDLL("pdh")
            for fn in ("PdhOpenQueryW", "PdhAddEnglishCounterW", "PdhCollectQueryData", "PdhGetFormattedCounterArrayW"):
                getattr(self.pdh, fn).restype = ctypes.c_uint32  # PDH status codes are unsigned
            self.query = ctypes.c_void_p()
            if self.pdh.PdhOpenQueryW(None, None, ctypes.byref(self.query)) != 0:
                return
            for key, path in paths.items():
                h = ctypes.c_void_p()
                if self.pdh.PdhAddEnglishCounterW(self.query, ctypes.c_wchar_p(path), None, ctypes.byref(h)) == 0:
                    self.handles[key] = h
            self.pdh.PdhCollectQueryData(self.query)  # prime rate counters
            self.ok = bool(self.handles)
        except (AttributeError, OSError):
            self.ok = False

    def read(self) -> dict[str, dict[str, float]]:
        """{key: {instance_name: value}} - single-instance counters use the instance name ''."""
        out: dict[str, dict[str, float]] = {}
        if not self.ok or self.pdh.PdhCollectQueryData(self.query) != 0:
            return out
        for key, h in self.handles.items():
            size = wintypes.DWORD(0)
            count = wintypes.DWORD(0)
            status = self.pdh.PdhGetFormattedCounterArrayW(h, PDH_FMT_DOUBLE, ctypes.byref(size), ctypes.byref(count), None)
            if status != PDH_MORE_DATA or not size.value:
                continue
            buf = (ctypes.c_byte * size.value)()
            if self.pdh.PdhGetFormattedCounterArrayW(h, PDH_FMT_DOUBLE, ctypes.byref(size), ctypes.byref(count), buf) != 0:
                continue
            items = ctypes.cast(buf, ctypes.POINTER(_FmtItem))
            vals = {}
            for i in range(count.value):
                it = items[i]
                if it.FmtValue.CStatus in (0, 1):  # PDH_CSTATUS_VALID_DATA / NEW_DATA
                    vals[it.szName or ""] = it.FmtValue.doubleValue
            out[key] = vals
        return out
