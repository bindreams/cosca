//! A teardown that blocks a runtime thread on what it killed (principle 2): a failed async spawn's,
//! or the armed drop's. Each of those waits runs through [`wait_warning`], which warns once if the
//! wait passes a threshold.

use std::time::{Duration, Instant};

/// When a teardown's warn is due, and how long into the wait that is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Due {
    pub(crate) until: Instant,
    pub(crate) after: Duration,
}

impl Due {
    /// Due `after` from now, if there is a threshold.
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
        if !ended_by(&mut state, due.until) {
            warn(due.after);
        }
    }
    wait(state)
}

#[cfg(test)]
#[path = "teardown_warn_tests.rs"]
mod teardown_warn_tests;
