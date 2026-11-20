"""Fast whole-system process snapshot for Windows.

psutil queries processes one at a time; for processes a standard user can't
open it falls back to a full system query *per process*, which costs seconds on
a machine with hundreds of processes. NtQuerySystemInformation returns CPU
times, memory and I/O counters for every process in a single call, with no
admin rights needed - the same source Task Manager uses.
"""
from __future__ import annotations

import ctypes
import struct

SystemProcessInformation = 5
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

# Offsets into SYSTEM_PROCESS_INFORMATION (64-bit layout).
_OFF = {
    "next": 0, "user": 40, "kernel": 48, "name_len": 56, "name_ptr": 64, "pid": 80,
    "working_set": 144, "private": 200, "read": 232, "write": 240,
}

available = False
try:
    if struct.calcsize("P") == 8:
        _ntdll = ctypes.WinDLL("ntdll")
        _query = _ntdll.NtQuerySystemInformation
        _query.restype = ctypes.c_ulong
        _query.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        available = True
except (AttributeError, OSError):
    available = False

_bufsize = 1 << 20


def snapshot() -> list[tuple]:
    """[(pid, name, cpu_seconds, read_bytes, write_bytes, working_set, private_bytes), ...]"""
    global _bufsize
    while True:
        buf = ctypes.create_string_buffer(_bufsize)
        needed = ctypes.c_ulong(0)
        status = _query(SystemProcessInformation, buf, _bufsize, ctypes.byref(needed))
        if status == STATUS_INFO_LENGTH_MISMATCH:
            _bufsize = max(_bufsize * 2, needed.value + 65536)
            continue
        if status != 0:
            raise OSError(f"NtQuerySystemInformation failed: 0x{status:08x}")
        break

    raw = buf.raw
    base = ctypes.addressof(buf)
    out = []
    off = 0
    u32, u64, u16 = struct.Struct("<I").unpack_from, struct.Struct("<Q").unpack_from, struct.Struct("<H").unpack_from
    while True:
        nxt = u32(raw, off + _OFF["next"])[0]
        pid = u64(raw, off + _OFF["pid"])[0]
        name_len = u16(raw, off + _OFF["name_len"])[0]
        name_ptr = u64(raw, off + _OFF["name_ptr"])[0]
        if name_len and base <= name_ptr < base + len(raw):
            s = name_ptr - base
            name = raw[s:s + name_len].decode("utf-16-le", errors="replace")
        else:
            name = "System Idle Process" if pid == 0 else ""
        cpu = (u64(raw, off + _OFF["user"])[0] + u64(raw, off + _OFF["kernel"])[0]) / 1e7
        out.append((pid, name, cpu, u64(raw, off + _OFF["read"])[0], u64(raw, off + _OFF["write"])[0],
                    u64(raw, off + _OFF["working_set"])[0], u64(raw, off + _OFF["private"])[0]))
        if not nxt:
            break
        off += nxt
    return out
