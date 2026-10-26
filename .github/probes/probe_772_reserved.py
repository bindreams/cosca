# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Throwaway probe: are reserved names in a middle position, or before a trailing separator, devices?

Prints, per string, `RtlIsDosDeviceName_U` (hex: length<<16 | offset, 0 = not a device),
`GetFullPathNameW` and the NT path from `RtlDosPathNameToNtPathName_U_WithStatus`.
"""

import ctypes
import os
import platform
import sys
import tempfile
from ctypes import wintypes

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort), ("MaximumLength", ctypes.c_ushort), ("Buffer", ctypes.c_void_p)]


ntdll.RtlIsDosDeviceName_U.argtypes = [wintypes.LPCWSTR]
ntdll.RtlIsDosDeviceName_U.restype = ctypes.c_ulong
ntdll.RtlDosPathNameToNtPathName_U_WithStatus.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(UNICODE_STRING),
    ctypes.c_void_p,
    ctypes.c_void_p,
]
ntdll.RtlDosPathNameToNtPathName_U_WithStatus.restype = ctypes.c_long
ntdll.RtlFreeUnicodeString.argtypes = [ctypes.POINTER(UNICODE_STRING)]
kernel32.GetFullPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPWSTR, ctypes.c_void_p]
kernel32.GetFullPathNameW.restype = wintypes.DWORD


def is_device(s: str) -> str:
    return hex(ntdll.RtlIsDosDeviceName_U(s))


def full_path(s: str) -> str:
    buf = ctypes.create_unicode_buffer(4096)
    n = kernel32.GetFullPathNameW(s, len(buf), buf, None)
    return repr(buf[:n]) if n else "FAILED"


def nt_path(s: str) -> str:
    nt = UNICODE_STRING()
    status = ntdll.RtlDosPathNameToNtPathName_U_WithStatus(s, ctypes.byref(nt), None, None)
    if status < 0:
        return f"FAILED({status & 0xFFFFFFFF:#x})"
    out = ctypes.wstring_at(nt.Buffer, nt.Length // 2)
    ntdll.RtlFreeUnicodeString(ctypes.byref(nt))
    return repr(out)


# Spellings `to_win32_string` accepts as written, never measured on the older device rules: a reserved
# name in a middle position, a trailing separator after one, and names with a space or `:` suffix.
ROWS = [
    r"C:\x\NUL" + "\\",
    r"C:\NUL\x",
    r"x\NUL\y",
    r"\NUL.txt\x",
    r"C:\x\COM1" + "\\",
    r"x\COM1.txt\y",
    r"C:\x\nul .txt",
    r"C:\x\NUL:",
    r"C:\x\NUL:stream",
]
# Controls: known last-name and relative-first-name readings.
CONTROLS = [r"C:\x\nul", r"nul\x", r"COM1.TXT\file1.txt", r"C:\x\a.txt"]


def show(label: str, s: str) -> None:
    print(f"  {label:9} {s!r}")
    print(f"            isdos={is_device(s)} gfpn={full_path(s)}")
    print(f"            nt={nt_path(s)}")


def main() -> None:
    cwd = tempfile.mkdtemp(prefix="probe772-")
    os.chdir(cwd)
    print(f"platform: {platform.platform()} {platform.machine()} (sys.getwindowsversion={sys.getwindowsversion()})")
    print(f"cwd: {os.getcwd()}")
    for c in CONTROLS:
        print("control")
        show("control", c)
    for r in ROWS:
        print("row")
        show("row", r)


main()
