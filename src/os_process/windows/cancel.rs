//! The Windows cancel event and the process wait it releases, for [`crate::os_process`]'s async
//! driver and the async raw spawn backend.

use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::time::Instant;

use windows::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};

use crate::error::{win32_io_error, Error};

/// An unnamed manual-reset event, initially unsignaled, for releasing
/// [`wait_process_or_cancel`] early. Signal with [`signal_cancel`]; `OwnedHandle` closes it.
// consumers: tokio::drive and the async raw backend (tokio::spawn::windows_raw).
#[cfg_attr(
    not(feature = "tokio"),
    allow(
        dead_code,
        reason = "only consumers are the async driver and the async raw backend, behind the tokio feature"
    )
)]
pub(crate) fn new_cancel_event() -> Result<OwnedHandle, Error> {
    // SAFETY: creating an unnamed event has no preconditions; the handle is immediately
    // wrapped in an OwnedHandle, which closes it.
    owned_event(unsafe { CreateEventW(None, true, false, None) })
}

/// The owned event, or the `CreateEventW` failure as its Win32 code.
fn owned_event(created: windows::core::Result<HANDLE>) -> Result<OwnedHandle, Error> {
    let h = created.map_err(|e| Error::Io(win32_io_error(e)))?;
    // SAFETY: `h` is a freshly created, owned event handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0 as _) })
}

// consumers: tokio::drive and the async raw backend (tokio::spawn::windows_raw).
#[cfg_attr(
    not(feature = "tokio"),
    allow(
        dead_code,
        reason = "only consumers are the async driver and the async raw backend, behind the tokio feature"
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

/// Wait on a process handle already in hand, releasable early: the blocking half of the async
/// driver's Windows arm. `Ok(true)` = the process exited (it wins a tie: it is the lower wait
/// index); `Ok(false)` = `cancel` was signalled or `deadline` passed. `deadline` is an absolute
/// instant on the real clock, fixed by the caller before any hop to another thread; every re-arm
/// recomputes against it.
#[cfg_attr(
    not(feature = "tokio"),
    allow(dead_code, reason = "only consumer is the async driver, behind the tokio feature")
)]
pub(crate) fn wait_process_or_cancel(
    process: BorrowedHandle<'_>,
    deadline: Option<Instant>,
    cancel: &OwnedHandle,
) -> Result<bool, Error> {
    #[cfg(feature = "tokio")]
    crate::bounded::assert_may_block("waiting for a process to exit or be cancelled");
    let handle = HANDLE(process.as_raw_handle());
    // Test-only seam proving (immediately, not by elapsed time) that this wait is never
    // genuinely entered on a still-alive target — see `armed_probe`'s own doc for why it's
    // gated on `is_armed()`.
    #[cfg(test)]
    if armed_probe::is_armed() {
        // SAFETY: `handle` is a live, identity-verified process handle; ms=0 is a
        // non-blocking poll, never a wait.
        let already = unsafe { windows::Win32::System::Threading::WaitForSingleObject(handle, 0) };
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
    let waited = crate::wait::wait_until(deadline, |ms| unsafe { WaitForMultipleObjects(&handles, false, ms) });
    let wait_failed = (waited == WAIT_FAILED).then(std::io::Error::last_os_error);
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

/// Test-only seam proving, immediately and never by elapsed time, that a wait is not entered on a
/// still-alive target.
///
/// The call site (`wait_process_or_cancel`, just before the real wait) polls and acts only when
/// [`is_armed`] is true, so the other tests that watch a live target through the same function run
/// their real waits to completion. Armed, it does a non-blocking `WaitForSingleObject(handle, 0)`
/// on the target, not `cancel`. A target that is not already signalled is the regression this
/// seam catches: [`notify_armed_unsignalled`] fires, and the call site force-signals `cancel` so
/// the real wait returns at once. A caught bug fails fast, not slow.
///
/// A [`crate::relayed_probe`]. `cancellable_blocking` relays it to the blocking-pool thread; a
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
            reason = "only consumers are the async driver and the async raw backend, behind the tokio feature"
        )
    )]
    pub(crate) fn install(tx: Sender<()>) -> Guard {
        relayed_probe::install(tx)
    }

    /// Whether the CURRENT thread has an observer installed — gates the call site's poll and
    /// forced cancel so they run only for the one test that opted in, never for any other
    /// caller of `wait_process_or_cancel` in the same binary or on another thread.
    pub(crate) fn is_armed() -> bool {
        relayed_probe::is_installed::<Armed>()
    }

    pub(crate) fn notify_armed_unsignalled() {
        relayed_probe::notify::<Armed>(());
    }
}

#[cfg(test)]
#[path = "cancel_tests.rs"]
mod cancel_tests;
