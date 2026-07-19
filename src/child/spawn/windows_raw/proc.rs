//! The raw-child process handle and the `CreateProcessW`/wait FFI primitives.
//!
//! [`RawChild`] owns the process `HANDLE` a raw spawn returns and answers the
//! same wait/kill/identity questions as the std backend. [`create_process`] and
//! [`wait_handle_or_cancel`] are the shared FFI seams the async backend reuses
//! (Task 7): the former is the sole `CreateProcessW` call site, the latter a
//! cancellable process wait.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Instant;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_EVENT, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForMultipleObjects, WaitForSingleObject,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOEXW,
};

use crate::error::Error;

/// `WaitForSingleObject`/`WaitForMultipleObjects` "no timeout" sentinel.
const INFINITE: u32 = 0xFFFF_FFFF;

/// A child spawned via raw `CreateProcessW`, owning its process handle directly.
#[derive(Debug)]
pub(crate) struct RawChild {
    proc: OwnedHandle,
    pid: u32,
}

impl RawChild {
    pub(crate) fn new(proc: OwnedHandle, pid: u32) -> RawChild {
        RawChild { proc, pid }
    }

    fn handle(&self) -> HANDLE {
        HANDLE(self.proc.as_raw_handle())
    }

    pub(crate) fn id(&self) -> u32 {
        self.pid
    }

    /// The process handle, for foreign/async control that borrows it (Task 7).
    #[allow(dead_code)] // consumed by the async backend in Task 7
    pub(crate) fn process_handle(&self) -> HANDLE {
        self.handle()
    }

    /// Block until the child exits, returning its status.
    pub(crate) fn wait(&self) -> io::Result<ExitStatus> {
        match wait_handle_or_cancel(self.handle(), None)? {
            WaitOutcome::Exited => exit_status(self.handle()),
            WaitOutcome::Cancelled => unreachable!("wait with no cancel handle cannot be cancelled"),
        }
    }

    /// The exit status if the child has already exited, else `None`.
    pub(crate) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        // SAFETY: `handle` is our live, owned process handle; a zero timeout polls without blocking.
        let r = unsafe { WaitForSingleObject(self.handle(), 0) };
        if r == WAIT_OBJECT_0 {
            Ok(Some(exit_status(self.handle())?))
        } else if r == WAIT_TIMEOUT {
            Ok(None)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Block until the child exits or `deadline` passes (`Ok(None)` at expiry). The wait is on a
    /// real external event (child exit); the timeout is the caller's deadline, not a sync bet.
    pub(crate) fn wait_deadline(&self, deadline: Instant) -> io::Result<Option<ExitStatus>> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            // Cap below INFINITE so a >49-day deadline never becomes an unbounded wait; the loop
            // re-arms against the true deadline if the OS wait returns early on the cap.
            let millis = u32::try_from(remaining.as_millis()).unwrap_or(INFINITE - 1);
            // SAFETY: `handle` is our live, owned process handle.
            let r = unsafe { WaitForSingleObject(self.handle(), millis) };
            if r == WAIT_OBJECT_0 {
                return Ok(Some(exit_status(self.handle())?));
            } else if r == WAIT_TIMEOUT {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                continue; // capped wait elapsed before the deadline; re-arm
            } else {
                return Err(io::Error::last_os_error());
            }
        }
    }

    /// Hard-kill the process. An already-exited child is success (matches std's `kill`).
    pub(crate) fn kill(&self) -> io::Result<()> {
        // SAFETY: `handle` is our live, owned process handle; exit code 1 is the forced-kill code.
        match unsafe { TerminateProcess(self.handle(), 1) } {
            Ok(()) => Ok(()),
            // TerminateProcess fails on an already-exited process; treat that as success.
            Err(e) => {
                if self.try_wait()?.is_some() {
                    Ok(())
                } else {
                    Err(e.into())
                }
            }
        }
    }
}

/// The outcome of [`wait_handle_or_cancel`].
pub(crate) enum WaitOutcome {
    /// The process handle signaled — the child exited.
    Exited,
    /// The cancel handle signaled first (async grace cancellation, Task 7).
    Cancelled,
}

/// Wait for `proc` to exit, or for `cancel` (if given) to signal first. With no cancel handle this
/// is a plain blocking wait; the cancel arm backs the async backend's grace cancellation (Task 7).
pub(crate) fn wait_handle_or_cancel(proc: HANDLE, cancel: Option<HANDLE>) -> io::Result<WaitOutcome> {
    match cancel {
        Some(cancel) => {
            let handles = [proc, cancel];
            // SAFETY: both handles are live for the duration of the wait.
            let r = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
            if r == WAIT_OBJECT_0 {
                Ok(WaitOutcome::Exited)
            } else if r == WAIT_EVENT(WAIT_OBJECT_0.0 + 1) {
                Ok(WaitOutcome::Cancelled)
            } else {
                Err(io::Error::last_os_error())
            }
        }
        None => {
            // SAFETY: `proc` is live for the duration of the wait.
            let r = unsafe { WaitForSingleObject(proc, INFINITE) };
            if r == WAIT_OBJECT_0 {
                Ok(WaitOutcome::Exited)
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

/// Read an exited process's status. Only valid after the handle has signaled.
fn exit_status(handle: HANDLE) -> io::Result<ExitStatus> {
    let mut code: u32 = 0;
    // SAFETY: `handle` is a live, owned process handle; the process has exited so its code is final.
    unsafe { GetExitCodeProcess(handle, &mut code) }?;
    Ok(ExitStatus::from_raw(code))
}

/// The sole `CreateProcessW` call site, shared by the sync and async raw backends. The caller
/// pre-fills `si.StartupInfo` (`dwFlags`/`hStd*`) and `si.lpAttributeList`, and passes a mutable
/// NUL-terminated `cmdline` (`CreateProcessW` may edit it in place). Sets `si.StartupInfo.cb` here
/// so every caller gets the extended-struct size right. Returns the owned process handle + pid.
pub(crate) fn create_process(
    app: Option<&[u16]>,
    cmdline: &mut [u16],
    si: &mut STARTUPINFOEXW,
    env: &Option<Vec<u16>>,
    cwd: &Option<Vec<u16>>,
    flags: u32,
) -> Result<(OwnedHandle, u32), Error> {
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();
    let app = app.map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
    let cwd = cwd.as_ref().map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
    let env_ptr = env.as_ref().map(|b| b.as_ptr() as *const core::ffi::c_void);
    // SAFETY: all pointers are valid for the call; `cmdline` is a mutable NUL-terminated buffer
    // `CreateProcessW` may edit in place; `&si.StartupInfo` is backed by the full `STARTUPINFOEXW`
    // (cb set above, EXTENDED_STARTUPINFO_PRESENT in `flags`).
    unsafe {
        CreateProcessW(
            app,
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            true,
            PROCESS_CREATION_FLAGS(flags),
            env_ptr,
            cwd,
            &si.StartupInfo,
            &mut pi,
        )
    }
    .map_err(|e| Error::Io(e.into()))?;
    // SAFETY: `CreateProcessW` succeeded, so `hProcess` is a valid handle we now own.
    let proc = unsafe { OwnedHandle::from_raw_handle(pi.hProcess.0) };
    // SAFETY: `hThread` is owned and unneeded; close it. This runs under the spawn lock, so a
    // panic here (debug_assert) would poison the lock and cascade to every future spawn — log only.
    if let Err(e) = unsafe { CloseHandle(pi.hThread) } {
        log::debug!("CloseHandle(hThread): {e:?}");
    }
    Ok((proc, pi.dwProcessId))
}
