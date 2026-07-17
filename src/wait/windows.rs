//! Windows death-watch + kill. `OpenProcess` returns a HANDLE that pins the kernel
//! object, so a reused pid cannot fool it; we re-verify the start_token once at open.
//! No reaping concept on Windows.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, SetEvent, TerminateProcess, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
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
    // Capture BEFORE close(): CloseHandle would overwrite GetLastError.
    let wait_err = (waited != WAIT_OBJECT_0 && waited != WAIT_TIMEOUT).then(std::io::Error::last_os_error);
    close(handle);
    match wait_err {
        None => Ok(waited == WAIT_OBJECT_0), // exited, or WAIT_TIMEOUT => still alive
        Some(e) => Err(Error::Io(e)),
    }
}

/// An unnamed manual-reset event, initially unsignaled, for releasing
/// `block_until_exit_or_cancel` early. Signal with [`signal_cancel`]; `OwnedHandle` closes it.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))] // only consumer is tokio::wait::grace_wait
pub(crate) fn new_cancel_event() -> Result<OwnedHandle, Error> {
    // SAFETY: creating an unnamed event has no preconditions; the handle is immediately
    // wrapped in an OwnedHandle, which closes it.
    let h = unsafe { CreateEventW(None, true, false, None) }.map_err(|e| Error::Io(e.into()))?;
    // SAFETY: `h` is a freshly created, owned event handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0 as _) })
}

#[cfg_attr(not(feature = "tokio"), allow(dead_code))] // only consumer is tokio::wait::grace_wait
pub(crate) fn signal_cancel(event: &OwnedHandle) {
    // SAFETY: `event` is a live event handle (the OwnedHandle keeps it open).
    let set = unsafe { SetEvent(HANDLE(event.as_raw_handle())) };
    // SetEvent on a live owned event has no documented failure mode; a silent failure would
    // degrade the cancellation contract to an unbounded park, so fail LOUD. Release builds
    // skip the assert during an unwind (the in-flight panic wins — never double-panic);
    // debug builds assert even then, an abort being an acceptable price for visibility there.
    debug_assert!(set.is_ok(), "SetEvent on an owned event handle failed: {set:?}");
    if !std::thread::panicking() {
        assert!(set.is_ok(), "SetEvent on an owned event handle failed: {set:?}");
    } else if let Err(e) = &set {
        // RELEASE unwind (a debug build already aborted above — visibility over grace,
        // the shipped policy): cannot assert while a panic is in flight, so leave the
        // loudest trace we can for the possible unbounded park.
        log::error!("SetEvent failed during unwind ({e}); a parked watcher may not release");
    }
}

/// `block_until_exit`, releasable early: returns `Ok(false)` as soon as `cancel` is signaled
/// (the process wins a tie — it is the lower wait index). `Ok(true)` = exited within `grace`;
/// `None` = unbounded.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))] // only consumer is tokio::wait::grace_wait
pub(crate) fn block_until_exit_or_cancel(
    id: ProcessId,
    grace: Option<Duration>,
    cancel: &OwnedHandle,
) -> Result<bool, Error> {
    // SAFETY: OpenProcess tolerates a dead/invalid pid (returns Err); the handle is
    // closed on every return path below.
    let handle = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, id.pid()) }
    {
        Ok(h) => h,
        // gone / unopenable => exited (mirroring block_until_exit).
        Err(_) => return Ok(true),
    };
    if !id.exists() {
        close(handle);
        return Ok(true); // recycled before open
    }
    let ms = match grace {
        None => INFINITE,
        // Capped at INFINITE-1 (~49.7 days) — the cancel event releases large graces early;
        // a debug_assert flags the rare clamp.
        Some(d) => {
            let clamped = d.as_millis().min((INFINITE - 1) as u128) as u32;
            debug_assert!(
                d.as_millis() <= (INFINITE - 1) as u128,
                "Windows grace clamped to INFINITE-1 ms (~49.7 days): {}",
                d.as_secs()
            );
            clamped
        }
    };
    let handles = [handle, HANDLE(cancel.as_raw_handle())];
    // SAFETY: both handles are live for the wait's duration.
    let waited = unsafe { WaitForMultipleObjects(&handles, false, ms) };
    // Capture BEFORE close(): CloseHandle would overwrite GetLastError.
    let wait_failed = (waited == WAIT_FAILED).then(std::io::Error::last_os_error);
    close(handle);
    if waited == WAIT_OBJECT_0 {
        Ok(true) // process exited
    } else if waited.0 == WAIT_OBJECT_0.0 + 1 || waited == WAIT_TIMEOUT {
        Ok(false) // released by cancel, or grace elapsed — still alive either way
    } else if let Some(e) = wait_failed {
        Err(Error::Io(e))
    } else {
        // Events cannot be abandoned (a mutex verdict); anything else is undocumented.
        // Report the raw verdict — GetLastError is only meaningful for WAIT_FAILED.
        debug_assert!(false, "unexpected WaitForMultipleObjects verdict: {waited:?}");
        Err(Error::Io(std::io::Error::other(format!(
            "unexpected WaitForMultipleObjects result: {waited:?}"
        ))))
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
