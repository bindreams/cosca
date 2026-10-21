"""Windows Job Object wrapper for devvm (ctypes only). Import it on Windows only.

Windows has no process groups to kill, so a child that spawns children (`vagrant` execs a Ruby
process) is bounded by putting the whole tree in a Job Object that kills its members when the
job's handle closes or is terminated. No kill goes through a bare pid: the child is assigned by
the process handle `subprocess.Popen` holds, so its pid cannot be reused while it runs.
"""

from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes
from types import TracebackType

CREATE_SUSPENDED = 0x00000004
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
TH32CS_SNAPTHREAD = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_NO_MORE_FILES = 18
RESUME_FAILED = 0xFFFFFFFF

_HANDLE = wintypes.HANDLE
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount",
        "WriteOperationCount",
        "OtherOperationCount",
        "ReadTransferCount",
        "WriteTransferCount",
        "OtherTransferCount",
    )]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


def _declare(name: str, argtypes: list, restype) -> None:
    function = getattr(_kernel32, name)
    function.argtypes = argtypes
    function.restype = restype


_declare("CreateJobObjectW", [ctypes.c_void_p, wintypes.LPCWSTR], _HANDLE)
_declare("SetInformationJobObject", [_HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL)
_declare("AssignProcessToJobObject", [_HANDLE, _HANDLE], wintypes.BOOL)
_declare("TerminateJobObject", [_HANDLE, wintypes.UINT], wintypes.BOOL)
_declare("CloseHandle", [_HANDLE], wintypes.BOOL)
_declare("CreateToolhelp32Snapshot", [wintypes.DWORD, wintypes.DWORD], _HANDLE)
_declare("Thread32First", [_HANDLE, ctypes.POINTER(_ThreadEntry32)], wintypes.BOOL)
_declare("Thread32Next", [_HANDLE, ctypes.POINTER(_ThreadEntry32)], wintypes.BOOL)
_declare("OpenThread", [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], _HANDLE)
_declare("ResumeThread", [_HANDLE], wintypes.DWORD)


def _check(ok: object) -> None:
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def _suspended_thread_ids(pid: int) -> list[int]:
    """Thread ids of process `pid`, from a Toolhelp snapshot.

    Only called for a process that is still suspended from creation, so it has exactly one
    thread and cannot start another.
    """
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = _ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        ids = []
        more = _kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while more:
            if entry.th32OwnerProcessID == pid:
                ids.append(entry.th32ThreadID)
            more = _kernel32.Thread32Next(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != ERROR_NO_MORE_FILES:
            raise ctypes.WinError(ctypes.get_last_error())
        return ids
    finally:
        _kernel32.CloseHandle(snapshot)


def _resume(pid: int) -> None:
    ids = _suspended_thread_ids(pid)
    assert len(ids) == 1, f"a process suspended at creation has one thread, found {len(ids)}"
    thread = _kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, ids[0])
    _check(thread)
    try:
        previous = _kernel32.ResumeThread(thread)
        if previous == RESUME_FAILED:
            raise ctypes.WinError(ctypes.get_last_error())
        assert previous == 1, f"the creation-suspended thread had suspend count {previous}"
    finally:
        _kernel32.CloseHandle(thread)


class KillOnCloseJob:
    """A Job Object whose members all die when it is terminated or its handle closes.

    Use as a context manager. Children made with `popen` belong to the job from their first
    instruction, so no descendant exists outside it. The job allows no breakaway, so a
    descendant created with CREATE_BREAKAWAY_FROM_JOB fails to start instead of escaping.
    Leaving the `with` block, and the owning process exiting by any means, closes the handle and
    kills whatever is left.
    """

    def __init__(self) -> None:
        self._handle: int | None = None

    def __enter__(self) -> KillOnCloseJob:
        handle = _kernel32.CreateJobObjectW(None, None)
        _check(handle)
        info = _ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            _check(
                _kernel32.SetInformationJobObject(
                    handle,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    ctypes.byref(info),
                    ctypes.sizeof(info),
                )
            )
        except BaseException:
            _kernel32.CloseHandle(handle)
            raise
        self._handle = handle
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            _kernel32.CloseHandle(handle)

    def popen(self, argv: list[str], **popen_kwargs) -> subprocess.Popen:
        """`subprocess.Popen(argv, **popen_kwargs)`, started inside the job.

        The child is created suspended, assigned to the job through the handle Popen holds,
        then resumed. If assignment or resume fails, the child is killed through that handle
        and reaped before the error is raised.
        """
        assert self._handle is not None, "KillOnCloseJob.popen outside its with block"
        flags = popen_kwargs.pop("creationflags", 0) | CREATE_SUSPENDED
        proc = subprocess.Popen(argv, creationflags=flags, **popen_kwargs)
        try:
            _check(_kernel32.AssignProcessToJobObject(self._handle, int(proc._handle)))
            _resume(proc.pid)
        except BaseException:
            proc.kill()
            proc.wait()
            raise
        return proc

    def terminate(self) -> None:
        """Kill every process in the job."""
        assert self._handle is not None, "KillOnCloseJob.terminate outside its with block"
        _check(_kernel32.TerminateJobObject(self._handle, 1))
