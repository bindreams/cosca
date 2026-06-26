//! Windows death-watch + kill. `OpenProcess` returns a HANDLE that pins the kernel
//! object, so a reused pid cannot fool it; we re-verify the start_token once at open.
//! No reaping concept on Windows.

use std::time::Instant;

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

use crate::error::Error;
use crate::identity::ProcessId;

fn close(handle: HANDLE) {
    // Match identity/windows.rs: a failed CloseHandle of an owned handle is a contract
    // violation, asserted in debug.
    let closed = unsafe { CloseHandle(handle) };
    debug_assert!(closed.is_ok(), "CloseHandle of an owned process handle should not fail");
}

pub(crate) fn block_until_exit(id: ProcessId, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
    // SAFETY: OpenProcess tolerates a dead/invalid pid (returns Err); the handle is
    // closed on every return path below.
    let handle = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, id.pid()) }
    {
        Ok(h) => h,
        // gone / unopenable => exited (an access-denied live process reads as exited here,
        // mirroring ProcessId::is_alive, which also treats open-failure as not-running).
        Err(_) => return Ok(true),
    };
    if !id.exists() {
        close(handle);
        return Ok(true); // recycled before open
    }
    let ms: u32 = match crate::wait::remaining(deadline) {
        None => INFINITE,
        Some(d) => d.as_millis().min((INFINITE - 1) as u128) as u32,
    };
    // SAFETY: `handle` is a live process handle held for the wait's duration.
    let waited = unsafe { WaitForSingleObject(handle, ms) };
    close(handle);
    if waited == WAIT_OBJECT_0 {
        Ok(true)
    } else if waited == WAIT_TIMEOUT {
        Ok(false)
    } else {
        Err(Error::Io(std::io::Error::last_os_error()))
    }
}

pub(crate) fn kill(id: ProcessId) -> Result<(), Error> {
    // Open for terminate AND query, so the SAME held handle both pins the kernel object
    // (pid-reuse-safe) and lets us re-verify identity before terminating.
    // SAFETY: OpenProcess tolerates an invalid pid; the handle is closed on every path below.
    let handle = match unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, id.pid()) } {
        Ok(h) => h,
        // Can't open: gone => already-dead Ok; live but denied => Err (is_alive is the
        // signaled-state check, synchronously correct on exit — not zombie-inclusive exists).
        Err(e) => {
            return if id.is_alive() {
                Err(Error::Io(e.into()))
            } else {
                Ok(())
            }
        }
    };
    // Re-verify identity on the HELD handle: a pid recycled before OpenProcess pins the
    // NEW process, whose creation token won't match — abort (the original is already gone).
    if !crate::identity::windows_handle_is(handle, id) {
        close(handle);
        return Ok(());
    }
    // SAFETY: handle is live; close on every path.
    let res = unsafe { TerminateProcess(handle, 1) };
    close(handle);
    match res {
        Ok(()) => Ok(()),
        Err(e) => {
            if id.is_alive() {
                Err(Error::Io(e.into()))
            } else {
                Ok(())
            }
        }
    }
}

pub(crate) fn terminate(id: ProcessId) -> Result<(), Error> {
    let _ = id;
    Err(Error::Unsupported {
        op: "graceful terminate (SIGTERM-equivalent)".into(),
        platform: "windows",
        detail: "Windows has no per-process graceful-termination signal; for a contained \
                 child use graceful_shutdown_tree (CTRL_BREAK to the group)"
            .into(),
    })
}
