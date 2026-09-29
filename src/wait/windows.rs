//! Windows death-watch + kill. `OpenProcess` returns a HANDLE that pins the kernel
//! object, so a reused pid cannot fool it; we re-verify the start_token once at open.
//! No reaping concept on Windows.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Instant;

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CreateEventW, SetEvent, TerminateProcess, WaitForMultipleObjects, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

use crate::error::Error;
use crate::identity::{HandleIdentity, Liveness, Opened, ProcessId};

fn close(handle: HANDLE) {
    // Match identity/windows.rs: a failed CloseHandle of an owned handle is a contract
    // violation, asserted in debug.
    let closed = unsafe { CloseHandle(handle) };
    debug_assert!(closed.is_ok(), "CloseHandle of an owned process handle should not fail");
}

pub(crate) fn block_until_exit(id: ProcessId, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
    let handle = match crate::identity::windows_open_classified(
        id.pid(),
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
    ) {
        Opened::Found(h) => h,
        Opened::Gone => return Ok(true), // no such pid => exited
        // Denied on a LIVE process => a real failure: reporting "exited" would let a
        // supervisor conclude a healthy service had died. The error comes from the
        // classifier, not `last_os_error()`: `is_alive()` below runs a whole
        // open/query/wait cycle that would overwrite the thread-s last-error first.
        Opened::Denied(e) => {
            return match id.is_alive() {
                Liveness::Dead => Ok(true),
                Liveness::Alive | Liveness::Unknown => {
                    log::warn!(
                        "wait: pid {} could not be opened to watch for its exit ({e}) - reporting an error, not an exit",
                        id.pid()
                    );
                    Err(Error::Unassessable {
                        detail: format!("pid {} could not be opened to watch for its exit", id.pid()),
                        source: Some(e.into()),
                    })
                }
            }
        }
    };
    // The handle already in hand answers the recycle question with no race; a second by-pid
    // lookup would not.
    match crate::identity::windows_handle_identity(handle, id) {
        HandleIdentity::Same => {}
        HandleIdentity::Different => {
            close(handle);
            return Ok(true); // recycled before open - the original is gone
        }
        HandleIdentity::Unreadable(e) => {
            log::warn!(
                "wait: pid {} opened but its identity could not be verified ({e})",
                id.pid()
            );
            close(handle);
            return Err(Error::Unassessable {
                detail: format!("pid {} opened but its identity could not be verified", id.pid()),
                source: Some(e.into()),
            });
        }
    }
    // A WAIT_TIMEOUT is never trusted: recheck the real deadline each round (see win32_timeout_ms).
    // SAFETY: `handle` is a live process handle held for the wait's duration.
    let waited = crate::wait::wait_until(deadline, |ms| unsafe { WaitForSingleObject(handle, ms) });
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
// consumers: tokio::wait::grace_wait and the async raw backend (tokio::spawn::windows_raw).
#[cfg_attr(
    not(feature = "tokio"),
    allow(
        dead_code,
        reason = "only consumer is tokio::wait::grace_wait and the async raw backend, behind the tokio feature"
    )
)]
pub(crate) fn new_cancel_event() -> Result<OwnedHandle, Error> {
    // SAFETY: creating an unnamed event has no preconditions; the handle is immediately
    // wrapped in an OwnedHandle, which closes it.
    let h = unsafe { CreateEventW(None, true, false, None) }.map_err(|e| Error::Io(e.into()))?;
    // SAFETY: `h` is a freshly created, owned event handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0 as _) })
}

// consumers: tokio::wait::grace_wait and the async raw backend (tokio::spawn::windows_raw).
#[cfg_attr(
    not(feature = "tokio"),
    allow(
        dead_code,
        reason = "only consumer is tokio::wait::grace_wait and the async raw backend, behind the tokio feature"
    )
)]
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
/// (the process wins a tie — it is the lower wait index). `Ok(true)` = exited by `deadline`;
/// `None` = unbounded. `deadline` is an absolute instant on the real clock, fixed by the caller
/// before any hop to another thread; every re-arm recomputes against it.
#[cfg_attr(
    not(feature = "tokio"),
    allow(
        dead_code,
        reason = "only consumer is tokio::wait::grace_wait and the async raw backend, behind the tokio feature"
    )
)]
pub(crate) fn block_until_exit_or_cancel(
    id: ProcessId,
    deadline: Option<Instant>,
    cancel: &OwnedHandle,
) -> Result<bool, Error> {
    #[cfg(feature = "tokio")]
    crate::bounded::assert_may_block("waiting for a process to exit or be cancelled");
    let handle = match crate::identity::windows_open_classified(
        id.pid(),
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
    ) {
        Opened::Found(h) => h,
        Opened::Gone => return Ok(true), // no such pid => exited
        // Denied on a LIVE process => a real failure: reporting "exited" would let a
        // supervisor conclude a healthy service had died. The error comes from the
        // classifier, not `last_os_error()`: `is_alive()` below runs a whole
        // open/query/wait cycle that would overwrite the thread-s last-error first.
        Opened::Denied(e) => {
            return match id.is_alive() {
                Liveness::Dead => Ok(true),
                Liveness::Alive | Liveness::Unknown => {
                    log::warn!(
                        "wait: pid {} could not be opened to watch for its exit ({e}) - reporting an error, not an exit",
                        id.pid()
                    );
                    Err(Error::Unassessable {
                        detail: format!("pid {} could not be opened to watch for its exit", id.pid()),
                        source: Some(e.into()),
                    })
                }
            }
        }
    };
    // The handle already in hand answers the recycle question with no race; a second by-pid
    // lookup would not.
    match crate::identity::windows_handle_identity(handle, id) {
        HandleIdentity::Same => {}
        HandleIdentity::Different => {
            close(handle);
            return Ok(true); // recycled before open - the original is gone
        }
        HandleIdentity::Unreadable(e) => {
            log::warn!(
                "wait: pid {} opened but its identity could not be verified ({e})",
                id.pid()
            );
            close(handle);
            return Err(Error::Unassessable {
                detail: format!("pid {} opened but its identity could not be verified", id.pid()),
                source: Some(e.into()),
            });
        }
    }
    #[cfg(test)]
    crate::wait::read_probe::mark("identity verified");
    // Test-only seam proving (immediately, not by elapsed time) that this wait is never
    // genuinely entered on a still-alive target — see `armed_probe`'s own doc for why it's
    // gated on `is_armed()`.
    #[cfg(test)]
    if armed_probe::is_armed() {
        // SAFETY: `handle` is a live, identity-verified process handle; ms=0 is a
        // non-blocking poll, never a wait.
        let already = unsafe { WaitForSingleObject(handle, 0) };
        if already == WAIT_FAILED {
            // Capture BEFORE anything else could overwrite GetLastError.
            let e = std::io::Error::last_os_error();
            // `handle` was identity-verified moments ago — a non-blocking poll on it failing
            // is a contract violation, not "not yet signalled" (the WAIT_TIMEOUT case below).
            // Must never reach `notify_armed_unsignalled`: folding an OS failure into "armed
            // on an unsignalled target" would false-flag a correct run as the very regression
            // this seam exists to catch.
            debug_assert!(
                false,
                "armed_probe: non-blocking poll of an identity-verified handle failed: {e}"
            );
        } else if already != WAIT_OBJECT_0 {
            armed_probe::notify_armed_unsignalled();
            // Force the real wait below to return at once instead of genuinely spending
            // `ms` — a bug this seam catches must fail fast, not hang out the grace.
            signal_cancel(cancel);
        }
    }
    let handles = [handle, HANDLE(cancel.as_raw_handle())];
    // A WAIT_TIMEOUT is never trusted: recheck the real deadline each round (see win32_timeout_ms).
    // SAFETY: both handles are live for the wait's duration.
    let waited = crate::wait::wait_until(deadline.map(Some), |ms| unsafe {
        WaitForMultipleObjects(&handles, false, ms)
    });
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
    let handle =
        match crate::identity::windows_open_classified(id.pid(), PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)
        {
            Opened::Found(h) => h,
            Opened::Gone => return Ok(()), // no such pid => already dead is success
            // Live-or-unassessable => Err. An Unknown liveness must NOT be reported as a
            // successful kill.
            Opened::Denied(e) => {
                return if id.is_alive() == Liveness::Dead {
                    Ok(())
                } else {
                    log::warn!(
                        "wait: pid {} could not be opened to terminate it ({e}) - reporting an error, not a kill",
                        id.pid()
                    );
                    Err(Error::Unassessable {
                        detail: format!("pid {} could not be opened to terminate it", id.pid()),
                        source: Some(e.into()),
                    })
                }
            }
        };
    // Re-verify identity on the HELD handle: a pid recycled before the open pins the NEW
    // process, whose creation token will not match. An UNREADABLE token is not proof the
    // target is gone, so it must not report a successful kill.
    match crate::identity::windows_handle_identity(handle, id) {
        HandleIdentity::Same => {}
        HandleIdentity::Different => {
            close(handle);
            return Ok(()); // pid recycled; the original is already gone
        }
        HandleIdentity::Unreadable(e) => {
            log::warn!(
                "wait: pid {} opened but its identity could not be verified ({e})",
                id.pid()
            );
            close(handle);
            return Err(Error::Unassessable {
                detail: format!("pid {} opened but its identity could not be verified", id.pid()),
                source: Some(e.into()),
            });
        }
    }
    // SAFETY: handle is live; close on every path.
    let res = unsafe { TerminateProcess(handle, 1) };
    // Re-check BEFORE close: the held handle pins the kernel object, so the by-pid resolve
    // inside `is_alive` cannot land on a recycled pid. After `close` it could. Windows denies
    // TerminateProcess on an already-exited process, so this arm is reached routinely on a
    // successful shutdown, and `is_alive` reads the SIGNALED STATE - unambiguous, unlike
    // GetExitCodeProcess, which cannot tell a live process from one that exited with 259.
    let verdict = res.is_err().then(|| id.is_alive());
    close(handle);
    match res {
        Ok(()) => Ok(()),
        Err(_) if verdict == Some(Liveness::Dead) => Ok(()),
        Err(e) => {
            log::warn!(
                "wait: TerminateProcess(pid {}) failed and the target is not provably dead ({e})",
                id.pid()
            );
            Err(Error::Io(e.into()))
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

/// Test-only seam proving a root-only watch on an already-reaped root never reaches a live
/// target — immediately, never by elapsed time. A `WAIT_TIMEOUT`-based counter could only ever
/// be told apart from correct code by how long the call ran, which would make elapsed time the
/// real assertion.
///
/// An already-reaped root does not pin down WHICH of `block_until_exit_or_cancel`'s three
/// outcomes it lands on (`Opened::Gone`, an already-signalled `HandleIdentity::Same`, or
/// `HandleIdentity::Different` — the last only if the OS recycles the pid in the window before
/// the watch opens it), so this alone does not deterministically prove the `Different` mutant is
/// caught. `grace_wait_resolves_immediately_on_an_identity_mismatch`
/// (`src/tokio/wait_tests.rs`) proves that one directly: a genuinely live child watched under an
/// identity naming the same pid but a wrong start token is `Different` on every run.
///
/// The call site (`block_until_exit_or_cancel`, just before the real wait) only polls and acts
/// when [`is_armed`] is true. `block_until_exit_or_cancel` is the SAME function every other
/// grace-wait test in the binary calls, several of them precisely to watch a genuinely
/// still-alive target run its real wait to completion (e.g.
/// `grace_wait_true_when_child_dies_mid_wait`); gating on `is_armed` is what keeps this seam
/// from force-releasing THEIR waits too. Only once armed does it do a non-blocking
/// `WaitForSingleObject(handle, 0)` on the TARGET — not `cancel` — the instant before the real
/// wait would be entered. If that target is not ALREADY signaled (the process has not already
/// exited), this is exactly the regression shape this test exists to catch: a real wait is
/// about to be genuinely entered on a live target. [`notify_armed_unsignalled`] fires, and the
/// call site immediately force-signals `cancel` so the real wait that follows returns at once
/// instead of genuinely spending the grace — a caught bug fails fast, not slow.
///
/// A [`crate::relayed_probe`]. `blocking_watch` relays it to the blocking-pool thread; a
/// process-global slot would force-cancel an unrelated test's wait.
#[cfg(test)]
pub(crate) mod armed_probe {
    use crate::relayed_probe::{self, Probe};
    use std::sync::mpsc::Sender;

    pub(crate) struct Armed;
    impl Probe for Armed {
        type Event = ();
    }

    pub(crate) type Guard = relayed_probe::Guard<Armed>;

    #[cfg_attr(
        not(feature = "tokio"),
        allow(
            dead_code,
            reason = "only consumer is tokio::wait::grace_wait and the async raw backend, behind the tokio feature"
        )
    )]
    pub(crate) fn install(tx: Sender<()>) -> Guard {
        relayed_probe::install(tx)
    }

    /// Whether the CURRENT thread has an observer installed — gates the call site's poll and
    /// forced cancel so they run only for the one test that opted in, never for any other
    /// caller of `block_until_exit_or_cancel` in the same binary or on another thread.
    pub(crate) fn is_armed() -> bool {
        relayed_probe::is_installed::<Armed>()
    }

    pub(crate) fn notify_armed_unsignalled() {
        relayed_probe::notify::<Armed>(());
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
