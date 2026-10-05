//! What a [`ShimLink`](super::ShimLink) reports: the one outcome of the shim's run (D7), and the
//! results of `kill` (D5).

use std::io;

use crate::elevation::shim::protocol::{decode_frame, Frame, FrameError, NotExecuted, Refusal};
use crate::identity::ProcessId;

/// Why the acceptor stopped serving (D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptorFailure {
    /// `accept` or `poll` failed with this errno.
    Errno(i32),
    /// The acceptor thread panicked.
    Panicked,
}

/// Why the program never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotStartedCause {
    /// cosca withheld the answer: the front ended, or `kill` or teardown refused the start, and the
    /// acceptor did not fail.
    Withheld,
    /// The acceptor failed while the start was not `Live`. It wins over [`Withheld`](Self::Withheld),
    /// even when `kill` had refused the start first (D4).
    AcceptorFailed(AcceptorFailure),
    /// An `F` frame: the shim has positive evidence the program never ran.
    NotExecuted(NotExecuted),
    /// An `R` frame: the shim refused after hello.
    ShimRefused(Refusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotStarted {
    /// Whether a shim said hello.
    pub(crate) shim_connected: bool,
    pub(crate) cause: NotStartedCause,
}

/// The link's one outcome. Set once, under the link's lock, and cached (D7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkOutcome {
    /// `S`: the program's exact wait status.
    Exited(i32),
    NotStarted(NotStarted),
    /// `L`: the possibly-started program was killed by the shim after supervision failed; its wait
    /// status.
    SupervisionLost(i32),
    /// `U`: the possibly-started program has exited and its status cannot be tied to it.
    StatusLost,
    /// No valid frame: EOF with nothing or part of one, a garbled frame, or a read error. The program
    /// may still be running.
    ShimLost,
}

impl LinkOutcome {
    /// Whether the program has ended, or never ran. `ShimLost` is neither.
    pub(crate) fn program_is_gone(&self) -> bool {
        !matches!(self, LinkOutcome::ShimLost)
    }
}

/// The outcome the bytes read so far settle, if any. A short or garbled frame is a real outcome (a
/// shim of another version, a crash mid-write), so it is `ShimLost` and never a `debug_assert`
/// (principle 7). `bytes` is at most one frame; `eof` says no more
/// will come.
pub(super) fn classify(bytes: &[u8], eof: bool) -> Option<LinkOutcome> {
    match decode_frame(bytes) {
        // `H` is the one frame cosca consumed before it answered.
        Ok(Frame::Hello) => Some(LinkOutcome::ShimLost),
        Ok(Frame::Status(ws)) => Some(LinkOutcome::Exited(ws)),
        Ok(Frame::Lost(ws)) => Some(LinkOutcome::SupervisionLost(ws)),
        Ok(Frame::StatusLost) => Some(LinkOutcome::StatusLost),
        Ok(Frame::NotExecuted(n)) => Some(LinkOutcome::NotStarted(NotStarted {
            shim_connected: true,
            cause: NotStartedCause::NotExecuted(n),
        })),
        Ok(Frame::Refused(r)) => Some(LinkOutcome::NotStarted(NotStarted {
            shim_connected: true,
            cause: NotStartedCause::ShimRefused(r),
        })),
        Err(FrameError::Garbled) => Some(LinkOutcome::ShimLost),
        Err(FrameError::Truncated) => eof.then_some(LinkOutcome::ShimLost),
    }
}

/// What a successful [`kill`](super::ShimLink::kill) means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillOutcome {
    /// `K` reached the shim's socket. That is all it says (D5).
    Delivered,
    /// The program has ended or never ran; nothing was sent.
    AlreadyEnded,
    /// There is no shim to signal: the start is refused, and the caller must SIGKILL the front.
    RefusedStart,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum KillError {
    /// The shim is gone or its answer unreadable; the program may still run.
    #[error("the shim is lost")]
    ShimLost,
    /// The shim's socket is full (`EAGAIN`/`ENOBUFS`): `K` was not delivered.
    #[error("the shim's socket would block")]
    Unkillable,
    #[error("a fork copy of the link cannot control it")]
    NotOwner,
    #[error("sending to the shim: {0}")]
    Io(io::Error),
}

/// A control call from a pid that did not bind the link (D21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a fork copy of the link cannot control it")]
pub(crate) struct NotOwner;

/// D21: only the process that bound the link controls it. A bare pid does not tell processes apart:
/// a fork copy in another pid namespace can have the owner's pid.
pub(super) fn owner_check(owner: ProcessId, current: ProcessId) -> Result<(), NotOwner> {
    if owner == current {
        Ok(())
    } else {
        Err(NotOwner)
    }
}
