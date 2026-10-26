# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
r"""Throwaway probe: do reserved-name strings with a trailing `\.` name the file on this Windows?

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


# (input, proposed faithful string) pairs from review F1.
PAIRS = [
    (r"a\nul", r"a\nul\."),
    (r"nul", r".\nul\."),
    (r"\x\nul", r"\x\nul\."),
    (r"\nul", r"\nul\."),
    (r"C:nul", r"C:.\nul\."),
    (r"\:nul", r"\.\:nul"),
    (r"a\com1", r"a\com1\."),
    (r"a\nul.txt", r"a\nul.txt\."),
    (r"nul\x", r".\nul\x"),
    (r"com1.txt\f", r".\com1.txt\f"),
    # A rooted path that starts `\??\`, which Win32 hands to the object manager untouched.
    (r"\??\C:\x", r"\.\??\C:\x"),
    (r"\??\x", r"\.\??\x"),
    (r"\??\nul", r"\.\??\nul\."),
    (r"\??\C:\nul", r"\.\??\C:\nul\."),
    ("\\??\\", "\\.\\??\\"),
]
# UNC and device paths: does any Windows read a reserved name in them as a device?
UNC_AND_DEVICE = [
    r"\\s\h\nul",
    r"\\s\h\com1",
    r"\\s\h\a\nul.txt",
    r"\\.\x\nul",
    r"\\.\nul",
    "//s/h/nul",
    r"\\s\nul",
    r"\\s\h\nul\.",
    r"\\.\x\nul\.",
]
# Controls: no proposal.
CONTROLS = [r"com1.txt\x", r"COM1.TXT\file1.txt", r"C:\x\nul", r"C:\x\nul\.", r"a\nul\.", r"a\com1\."]


def show(label: str, s: str) -> None:
    print(f"  {label:9} {s!r}")
    print(f"            isdos={is_device(s)} gfpn={full_path(s)}")
    print(f"            nt={nt_path(s)}")


def main() -> None:
    cwd = tempfile.mkdtemp(prefix="probe772-")
    os.chdir(cwd)
    print(f"platform: {platform.platform()} {platform.machine()} (sys.getwindowsversion={sys.getwindowsversion()})")
    print(f"cwd: {os.getcwd()}")
    for inp, prop in PAIRS:
        print("pair")
        show("input", inp)
        show("proposed", prop)
    for c in CONTROLS:
        print("control")
        show("control", c)
    for u in UNC_AND_DEVICE:
        print("unc_or_device")
        show("row", u)


main()
