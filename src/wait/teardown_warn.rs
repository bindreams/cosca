//! A teardown that blocks a runtime thread on what it killed (principle 2): a failed async spawn's,
//! or the armed drop's. Each of those waits runs through [`wait_warning`], which warns once if the
//! wait passes a threshold.

use std::time::{Duration, Instant};

/// When a teardown's warn is due, and how long into the wait that is.
#[derive(Clone, Copy)]
pub(crate) struct Due {
    pub(crate) until: Instant,
    pub(crate) after: Duration,
}

impl Due {
    /// Due `after` from now, if there is a threshold.
    #[cfg_attr(
        not(any(test, feature = "tokio")),
        allow(dead_code, reason = "only an async spawn's teardown has a threshold to start from")
    )]
    pub(crate) fn in_(after: Option<Duration>) -> Option<Due> {
        after.map(|after| Due {
            until: crate::wait::now() + after,
            after,
        })
    }
}

/// Runs `wait` on `state`: a teardown's blocking wait for something it killed.
///
/// With `due`, `ended_by(state, due.until)` first watches for what `wait` waits for, blocking no
/// later than `due.until`, and `warn(due.after)` runs once if it answers `false`. `ended_by` answers
/// `true` for anything it cannot read, leaving it to `wait`. Then `wait` runs, unbounded, and its
/// answer is the result: the threshold picks the message and nothing else. Without `due`, only
/// `wait` runs.
pub(crate) fn wait_warning<S, R>(
    mut state: S,
    due: Option<Due>,
    ended_by: impl FnOnce(&mut S, Instant) -> bool,
    warn: impl FnOnce(Duration),
    wait: impl FnOnce(S) -> R,
) -> R {
    if let Some(due) = due {
        #[cfg(feature = "tokio")]
        crate::bounded::assert_may_block("a teardown's warned wait");
        if !ended_by(&mut state, due.until) {
            warn(due.after);
        }
    }
    wait(state)
}

/// For [`wait_warning`]: whether the process `handle` names has exited (the handle is signalled) by
/// `until`. Any answer but a timeout, an error included, is `true`, for the wait to find.
#[cfg(all(windows, feature = "tokio"))]
pub(crate) fn handle_signaled_by(handle: windows::Win32::Foundation::HANDLE, until: Instant) -> bool {
    use windows::Win32::Foundation::{WAIT_FAILED, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::WaitForSingleObject;

    let mut failed = None;
    // SAFETY: the caller's live process handle, kept open across the call.
    let waited = crate::wait::wait_until(Some(until), |ms| {
        let waited = unsafe { WaitForSingleObject(handle, ms) };
        if waited == WAIT_FAILED {
            failed = Some(std::io::Error::last_os_error());
        }
        waited
    });
    #[cfg(test)]
    let waited = if crate::child::spawn::fault::take_late_exit() {
        WAIT_TIMEOUT
    } else {
        waited
    };
    if let Some(e) = failed {
        log::debug!("a look at a killed child's exit failed ({e}); the wait that follows decides");
    }
    waited != WAIT_TIMEOUT
}

#[cfg(test)]
#[path = "teardown_warn_tests.rs"]
mod teardown_warn_tests;
