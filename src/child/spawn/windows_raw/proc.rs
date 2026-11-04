//! The `CreateProcessW`/wait FFI primitives of the raw backend. [`create_process`] is the sole
//! `CreateProcessW` call site, shared with the async backend, which also reuses
//! [`wait_handle_or_cancel`], a cancellable process wait. The sync raw child is an
//! [`OwnedChild`](crate::child::owned::OwnedChild) over a
//! [`WindowsProcess`](crate::os_process::windows::WindowsProcess).

use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::process::ExitStatus;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW,
};

use crate::error::{win32_io_error, Error};

/// `WaitForSingleObject`/`WaitForMultipleObjects` "no timeout" sentinel.
#[cfg(feature = "tokio")]
const INFINITE: u32 = 0xFFFF_FFFF;

/// The outcome of [`wait_handle_or_cancel`]. `Copy`/`Eq`: the async backend clones it across the
/// per-instance test observer channel and asserts on it.
#[cfg(feature = "tokio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitOutcome {
    /// The process handle signaled — the child exited.
    Exited,
    /// The cancel handle signaled first (async grace cancellation).
    Cancelled,
}

/// Wait for `proc` to exit, or for `cancel` (if given) to signal first. With no cancel handle this
/// is a plain blocking wait; the cancel arm backs the async backend's grace cancellation.
#[cfg(feature = "tokio")]
pub(crate) fn wait_handle_or_cancel(proc: HANDLE, cancel: Option<HANDLE>) -> io::Result<WaitOutcome> {
    use windows::Win32::Foundation::{WAIT_EVENT, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{WaitForMultipleObjects, WaitForSingleObject};

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

/// Read an exited process's status. Only valid after the handle has signaled. `pub(crate)`: the
/// async raw backend reads its exit status through the same seam.
pub(crate) fn exit_status(handle: HANDLE) -> io::Result<ExitStatus> {
    let mut code: u32 = 0;
    // SAFETY: `handle` is a live, owned process handle; the process has exited so its code is final.
    unsafe { GetExitCodeProcess(handle, &mut code) }.map_err(win32_io_error)?;
    Ok(ExitStatus::from_raw(code))
}

/// The sole `CreateProcessW` call site, shared by the sync and async raw backends. The caller
/// pre-fills `si.StartupInfo` (`dwFlags`/`hStd*`) and `si.lpAttributeList`, and passes a mutable
/// NUL-terminated `cmdline` (`CreateProcessW` may edit it in place). Sets `si.StartupInfo.cb` here
/// so every caller gets the extended-struct size right. Returns the owned process handle + pid.
///
/// `bInheritHandles` is TRUE exactly when `si.lpAttributeList` (the HANDLE_LIST) is set, so the
/// child inherits only the listed handles, never every inheritable handle of this process.
/// Microsoft's guidance ([`UpdateProcThreadAttribute`]) is to pass the list with `bInheritHandles`
/// TRUE; `STARTF_USESTDHANDLES` requires `bInheritHandles` ([`STARTUPINFOW`]), so cosca passes a
/// list whenever it sets the flag. The list scopes the child, not the window: another spawner in
/// this process that passes `bInheritHandles` TRUE with no list can still take a listed handle
/// while it is inheritable. See the module doc of `child::spawn::windows_raw`.
///
/// [`UpdateProcThreadAttribute`]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
/// [`STARTUPINFOW`]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow
pub(crate) fn create_process(
    app: Option<&[u16]>,
    cmdline: &mut [u16],
    si: &mut STARTUPINFOEXW,
    env: Option<&[u16]>,
    cwd: &Option<Vec<u16>>,
    flags: u32,
) -> Result<(OwnedHandle, u32), Error> {
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();
    let app = app.map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
    let cwd = cwd.as_ref().map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
    let env_ptr = env.map(|b| b.as_ptr() as *const core::ffi::c_void);
    let inherit = !si.lpAttributeList.0.is_null();
    debug_assert!(
        si.StartupInfo.dwFlags.0 & STARTF_USESTDHANDLES.0 == 0 || inherit,
        "STARTF_USESTDHANDLES requires a HANDLE_LIST"
    );
    // SAFETY: all pointers are valid for the call; `cmdline` is a mutable NUL-terminated buffer
    // `CreateProcessW` may edit in place; `&si.StartupInfo` is backed by the full `STARTUPINFOEXW`
    // (cb set above, EXTENDED_STARTUPINFO_PRESENT in `flags`).
    unsafe {
        CreateProcessW(
            app,
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            inherit,
            PROCESS_CREATION_FLAGS(flags),
            env_ptr,
            cwd,
            &si.StartupInfo,
            &mut pi,
        )
    }
    .map_err(|e| Error::Io(win32_io_error(e)))?;
    // SAFETY: `CreateProcessW` succeeded, so `hProcess` is a valid handle we now own.
    let proc = unsafe { OwnedHandle::from_raw_handle(pi.hProcess.0) };
    // SAFETY: `hThread` is owned and unneeded; close it. This runs under the spawn lock, so a
    // panic here (debug_assert) would poison the lock and cascade to every future spawn — log only.
    if let Err(e) = unsafe { CloseHandle(pi.hThread) } {
        log::debug!("CloseHandle(hThread): {e:?}");
    }
    Ok((proc, pi.dwProcessId))
}

#[cfg(test)]
#[path = "proc_tests.rs"]
mod proc_tests;
