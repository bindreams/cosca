//! [`SendOutcome`] and [`StopError`]: what `terminate` and `terminate_tree` say of the stop's send when
//! they fail.

use crate::error::Error;

/// How the last prepared send of a stop went ([`StopError::outcome`]).
///
/// `Sent` says the send went out, not that the child took it: a child that ignores Ctrl+C is still `Sent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SendOutcome {
    /// The send went out: on Unix to at least one process. An error beside it is what a check after the
    /// send found: a member it could not reach while it reached others, a member that refused it.
    Sent,
    /// Nothing was sent: a refusal, a failure before the send was made, a child that had already exited, a
    /// send that went to no process (the group or the cgroup had no member, or the kernel refused every
    /// member), whatever a check after it found. The error says why.
    NotSent,
    /// Nothing was sent because the child had not set its console up when the console-event proxy asked
    /// (Windows: it had not connected its console yet, or did so just after the attach), so asking again can succeed. The
    /// call is the caller's to repeat, with its own bound; `stop::send_console_event_via_proxy` says how long
    /// the window lasted.
    NotYet,
    /// Whether the send went out cannot be told: an action that made no prepared send and failed, or, on
    /// Windows, the console-event proxy ran and did not confirm its event, or may have run, or its exit is
    /// no answer.
    Unknown,
}

/// The error of [`Child::terminate`](crate::Child::terminate) and
/// [`Child::terminate_tree`](crate::Child::terminate_tree): the [`Error`] the stop action answered, and how
/// the last prepared send of the action went ([`SendOutcome`]).
///
/// It shows and chains as the error inside it does: `Display` is that error's, and
/// [`source`](std::error::Error::source) is that error's own source, so a report of a `StopError`
/// ([`Report`](crate::error::Report)) reads as a report of the [`Error`]. `?` turns it into the [`Error`]
/// ([`From`]).
///
/// The [`Error`] is reached by [`error`](StopError::error), or by `Error::from`. It is not a layer of the
/// `source()` chain, so a walk of that chain that downcasts to [`Error`] must downcast to `StopError`
/// first.
///
/// The outcome is the last prepared send's, whatever the action did after it.
#[derive(Debug)]
pub struct StopError {
    error: Error,
    outcome: SendOutcome,
}

impl StopError {
    pub(crate) fn new(error: Error, outcome: SendOutcome) -> StopError {
        StopError { error, outcome }
    }

    /// The error the stop action answered.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// How the last prepared send of the stop action went.
    pub fn outcome(&self) -> SendOutcome {
        self.outcome
    }
}

impl std::fmt::Display for StopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for StopError {
    /// The source of the error inside, not that error: the layer is transparent.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.error)
    }
}

impl From<StopError> for Error {
    fn from(stopped: StopError) -> Error {
        stopped.error
    }
}

#[cfg(test)]
#[path = "outcome_tests.rs"]
mod outcome_tests;
