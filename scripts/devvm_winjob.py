"""Windows Job Object wrapper for devvm (ctypes only). Import it on Windows only.

Windows has no process groups to kill, so a child that spawns children (`vagrant` execs a Ruby
process) is bounded by putting the whole tree in a Job Object that kills its members when the
job's handle closes or is terminated. The child is created directly inside the job
(PROC_THREAD_ATTRIBUTE_JOB_LIST), so it is never outside it, and no kill goes through a bare
pid: termination is by job handle or by the process handle this module holds.
"""

from __future__ import annotations

import ctypes
import math
import msvcrt
import os
import subprocess
import threading
import time
from ctypes import wintypes
from types import TracebackType
from typing import IO, Any

CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
DUPLICATE_SAME_ACCESS = 0x00000002
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE = -12
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_INSUFFICIENT_BUFFER = 122
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
STILL_ACTIVE = 259
KILLED_EXIT_CODE = 1

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


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", _HANDLE),
        ("hStdOutput", _HANDLE),
        ("hStdError", _HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("StartupInfo", _StartupInfo), ("lpAttributeList", ctypes.c_void_p)]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", _HANDLE),
        ("hThread", _HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def _declare(name: str, argtypes: list, restype) -> None:
    function = getattr(_kernel32, name)
    function.argtypes = argtypes
    function.restype = restype


_declare("CreateJobObjectW", [ctypes.c_void_p, wintypes.LPCWSTR], _HANDLE)
_declare("SetInformationJobObject", [_HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL)
_declare("TerminateJobObject", [_HANDLE, wintypes.UINT], wintypes.BOOL)
_declare("CloseHandle", [_HANDLE], wintypes.BOOL)
_declare("GetCurrentProcess", [], _HANDLE)
_declare("GetStdHandle", [wintypes.DWORD], _HANDLE)
_declare(
    "DuplicateHandle",
    [_HANDLE, _HANDLE, _HANDLE, ctypes.POINTER(_HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD],
    wintypes.BOOL,
)
_declare(
    "CreatePipe",
    [ctypes.POINTER(_HANDLE), ctypes.POINTER(_HANDLE), ctypes.c_void_p, wintypes.DWORD],
    wintypes.BOOL,
)
_declare(
    "InitializeProcThreadAttributeList",
    [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)],
    wintypes.BOOL,
)
_declare(
    "UpdateProcThreadAttribute",
    [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ],
    wintypes.BOOL,
)
_declare("DeleteProcThreadAttributeList", [ctypes.c_void_p], None)
_declare(
    "CreateProcessW",
    [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfoEx),
        ctypes.POINTER(_ProcessInformation),
    ],
    wintypes.BOOL,
)
_declare("WaitForSingleObject", [_HANDLE, wintypes.DWORD], wintypes.DWORD)
_declare("GetExitCodeProcess", [_HANDLE, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
_declare("TerminateProcess", [_HANDLE, wintypes.UINT], wintypes.BOOL)


def _check(ok: object) -> None:
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def _inheritable_copy(handle: int) -> int:
    copy = _HANDLE()
    process = _kernel32.GetCurrentProcess()
    _check(_kernel32.DuplicateHandle(process, handle, process, ctypes.byref(copy), 0, True, DUPLICATE_SAME_ACCESS))
    return copy.value


def _close_all(handles: list[int]) -> None:
    for handle in handles:
        _kernel32.CloseHandle(handle)


def _make_attribute_list(job: int, inherited: list[int]) -> tuple[ctypes.Array, list[object]]:
    """A PROC_THREAD_ATTRIBUTE_LIST that puts the child in `job` and lets it inherit `inherited`.

    Returns the list's buffer and the arrays it points into; keep both alive until
    CreateProcessW returns, then call DeleteProcThreadAttributeList on the buffer.
    """
    count = 2 if inherited else 1
    size = ctypes.c_size_t()
    _kernel32.InitializeProcThreadAttributeList(None, count, 0, ctypes.byref(size))
    if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(size.value)
    _check(_kernel32.InitializeProcThreadAttributeList(buffer, count, 0, ctypes.byref(size)))
    values: list[object] = []
    try:
        wanted = [(PROC_THREAD_ATTRIBUTE_JOB_LIST, [job]), (PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited)]
        for attribute, handles in wanted:
            if not handles:
                continue
            array = (_HANDLE * len(handles))(*handles)
            values.append(array)
            _check(_kernel32.UpdateProcThreadAttribute(buffer, 0, attribute, array, ctypes.sizeof(array), None, None))
    except BaseException:
        _kernel32.DeleteProcThreadAttributeList(buffer)
        raise
    return buffer, values


class JobProcess:
    """A process created inside a `KillOnCloseJob`: the part of `subprocess.Popen` devvm uses.

    `communicate` and `wait` behave as `Popen`'s do, including raising `subprocess.TimeoutExpired`
    and resuming on a later call. `returncode` is the exit code once the process has been waited
    for, `None` before.
    """

    def __init__(
        self,
        args: list[str],
        process: int,
        pid: int,
        stdout: IO[Any] | None,
        stderr: IO[Any] | None,
    ) -> None:
        self.args = args
        self.pid = pid
        self.returncode: int | None = None
        self._process: int | None = process
        self._streams = {"stdout": stdout, "stderr": stderr}
        self._output: dict[str, Any] = {}
        self._errors: list[BaseException] = []
        self._readers: list[threading.Thread] | None = None

    def _read(self, name: str, stream: IO[Any]) -> None:
        try:
            self._output[name] = stream.read()
        except BaseException as error:
            self._errors.append(error)
        finally:
            stream.close()

    def communicate(self, timeout: float | None = None) -> tuple[Any, Any]:
        """Read stdout and stderr to EOF and wait for exit; `(None, None)` for unpiped streams."""
        deadline = None if timeout is None else time.monotonic() + timeout
        if self._readers is None:
            self._readers = [
                threading.Thread(target=self._read, args=(name, stream), daemon=True)
                for name, stream in self._streams.items()
                if stream is not None
            ]
            for reader in self._readers:
                reader.start()
        for reader in self._readers:
            reader.join(None if deadline is None else max(deadline - time.monotonic(), 0))
            if reader.is_alive():
                raise subprocess.TimeoutExpired(self.args, timeout)
        self.wait(None if deadline is None else max(deadline - time.monotonic(), 0))
        if self._errors:
            raise self._errors[0]
        return self._output.get("stdout"), self._output.get("stderr")

    def wait(self, timeout: float | None = None) -> int:
        if self._process is not None:
            milliseconds = INFINITE if timeout is None else math.ceil(timeout * 1000)
            assert timeout is None or milliseconds < INFINITE, "timeout too large for WaitForSingleObject"
            result = _kernel32.WaitForSingleObject(self._process, milliseconds)
            if result == WAIT_TIMEOUT:
                raise subprocess.TimeoutExpired(self.args, timeout)
            if result != WAIT_OBJECT_0:
                raise ctypes.WinError(ctypes.get_last_error())
            code = wintypes.DWORD()
            _check(_kernel32.GetExitCodeProcess(self._process, ctypes.byref(code)))
            self.returncode = code.value
            _kernel32.CloseHandle(self._process)
            self._process = None
        assert self.returncode is not None
        return self.returncode

    def kill(self) -> None:
        """Terminate this process alone (not its descendants; use `KillOnCloseJob.terminate`)."""
        if self._process is None:
            return
        if not _kernel32.TerminateProcess(self._process, KILLED_EXIT_CODE):
            # An exited process refuses termination; anything still running must not hide the error.
            error = ctypes.get_last_error()
            code = wintypes.DWORD()
            _check(_kernel32.GetExitCodeProcess(self._process, ctypes.byref(code)))
            if code.value == STILL_ACTIVE:
                raise ctypes.WinError(error)


class KillOnCloseJob:
    """A Job Object whose members all die when it is terminated or its handle closes.

    Use as a context manager. Children made with `popen` are created inside the job, so no
    descendant exists outside it. The job grants no breakaway permission: a descendant created
    with CREATE_BREAKAWAY_FROM_JOB still starts, but stays in the job, so it dies with it. Leaving
    the `with` block, and the owning process exiting by any means, closes the handle and kills
    whatever is left.
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

    def popen(
        self,
        argv: list[str],
        *,
        cwd: str | os.PathLike[str] | None = None,
        env: dict[str, str] | None = None,
        stdout: int | None = None,
        stderr: int | None = None,
        text: bool = False,
        creationflags: int = 0,
    ) -> JobProcess:
        """Start `argv` inside the job, like `subprocess.Popen(argv, ...)` with the same meaning
        for the arguments it has.

        `stdout` and `stderr` are `subprocess.PIPE` or `None` (inherit); stdin is always
        inherited. Only the standard handles and the job reach the child. Raises `OSError` if the
        process cannot be created, in which case nothing was started.
        """
        assert self._handle is not None, "KillOnCloseJob.popen outside its with block"
        assert stdout in (None, subprocess.PIPE) and stderr in (None, subprocess.PIPE)

        to_close: list[int] = []  # handles the parent must close once the child has its copies
        parent_ends: dict[str, int] = {}  # read ends of the pipes, owned by the returned process
        try:
            child_in = self._inherited_std(STD_INPUT_HANDLE, to_close)
            child_out, child_err = None, None
            for name, std_id, spec in (("stdout", STD_OUTPUT_HANDLE, stdout), ("stderr", STD_ERROR_HANDLE, stderr)):
                if spec is None:
                    child_end = self._inherited_std(std_id, to_close)
                else:
                    read, write = _HANDLE(), _HANDLE()
                    _check(_kernel32.CreatePipe(ctypes.byref(read), ctypes.byref(write), None, 0))
                    parent_ends[name] = read.value
                    to_close.append(write.value)
                    child_end = _inheritable_copy(write.value)
                    to_close.append(child_end)
                if name == "stdout":
                    child_out = child_end
                else:
                    child_err = child_end

            inherited = [h for h in (child_in, child_out, child_err) if h is not None]
            info = _StartupInfoEx()
            info.StartupInfo.cb = ctypes.sizeof(info)
            info.StartupInfo.dwFlags = STARTF_USESTDHANDLES
            info.StartupInfo.hStdInput = child_in
            info.StartupInfo.hStdOutput = child_out
            info.StartupInfo.hStdError = child_err
            attributes, _keepalive = _make_attribute_list(self._handle, inherited)
            info.lpAttributeList = ctypes.addressof(attributes)
            command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            environment = None
            if env is not None:
                environment = ctypes.create_unicode_buffer("".join(f"{k}={v}\0" for k, v in env.items()) + "\0")
            created = _ProcessInformation()
            try:
                _check(
                    _kernel32.CreateProcessW(
                        None,
                        command_line,
                        None,
                        None,
                        bool(inherited),
                        creationflags | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                        environment,
                        None if cwd is None else os.fspath(cwd),
                        ctypes.byref(info),
                        ctypes.byref(created),
                    )
                )
            finally:
                _kernel32.DeleteProcThreadAttributeList(attributes)
            _kernel32.CloseHandle(created.hThread)

            streams: dict[str, IO[Any] | None] = {"stdout": None, "stderr": None}
            try:
                for name in list(parent_ends):
                    fd = msvcrt.open_osfhandle(parent_ends[name], os.O_RDONLY)
                    del parent_ends[name]  # the fd owns the handle now
                    try:
                        streams[name] = open(fd, "r" if text else "rb")
                    except BaseException:
                        os.close(fd)
                        raise
            except BaseException:
                _kernel32.TerminateProcess(created.hProcess, KILLED_EXIT_CODE)
                _kernel32.CloseHandle(created.hProcess)
                for stream in streams.values():
                    if stream is not None:
                        stream.close()
                raise
            return JobProcess(argv, created.hProcess, created.dwProcessId, streams["stdout"], streams["stderr"])
        except BaseException:
            _close_all(list(parent_ends.values()))
            raise
        finally:
            _close_all(to_close)

    @staticmethod
    def _inherited_std(std_id: int, to_close: list[int]) -> int | None:
        """An inheritable duplicate of the parent's standard handle, or None if it has none."""
        handle = _kernel32.GetStdHandle(std_id)
        if handle in (None, INVALID_HANDLE_VALUE):
            return None
        copy = _inheritable_copy(handle)
        to_close.append(copy)
        return copy

    def terminate(self) -> None:
        """Kill every process in the job."""
        assert self._handle is not None, "KillOnCloseJob.terminate outside its with block"
        _check(_kernel32.TerminateJobObject(self._handle, KILLED_EXIT_CODE))
