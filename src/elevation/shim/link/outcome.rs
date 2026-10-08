//! What a [`ShimLink`](super::ShimLink) reports: the one outcome of the shim's run, and the
//! results of `kill`.

use std::io;

use crate::elevation::shim::fork_guard::Origin;
use crate::elevation::shim::protocol::{decode_frame, Frame, FrameError, NotExecuted, Refusal};

/// Why the acceptor stopped serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptorFailure {
    Errno(i32),
    Panicked,
}

/// Why the program never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotStartedCause {
    /// cosca withheld the answer: the front ended, or `kill` or teardown refused the start, and the
    /// acceptor did not fail.
    Withheld,
    /// The acceptor failed while the start was not `Live`. It wins over [`Withheld`](Self::Withheld),
    /// even when `kill` had refused the start first.
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

/// The link's one outcome. Set once, under the link's lock, and cached.
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

/// The outcome the bytes read so far settle, if any. `bytes` is at most one frame; `eof` says no
/// more will come. A short or garbled frame is a real outcome (a shim of another version, a crash
/// mid-write), so it is `ShimLost`, never an assertion.
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
    /// `K` reached the shim's socket. That is all it says.
    Delivered,
    /// The program has ended or never ran; nothing was sent.
    AlreadyEnded,
    /// There is no shim to signal: the start is refused, and the caller must SIGKILL the front.
    RefusedStart,
}

/// Why [`ShimLink::wait`](super::ShimLink::wait) did not return an outcome.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WaitError {
    #[error(transparent)]
    NotOwner(#[from] NotOwner),
    /// Waiting for the shim failed here, say for lack of memory. The outcome is not settled: the
    /// shim may be fine, and a later call can still read its frame.
    #[error("waiting for the shim: {0}")]
    Poll(io::Error),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum KillError {
    /// The shim is gone or its answer unreadable; the program may still run.
    #[error("the shim is lost")]
    ShimLost,
    /// The shim's socket is full (`EAGAIN`/`ENOBUFS`): `K` was not delivered.
    #[error("the shim's socket would block")]
    Unkillable,
    #[error(transparent)]
    NotOwner(#[from] NotOwner),
    #[error("sending to the shim: {0}")]
    Io(io::Error),
}

/// A control call from a process that did not bind the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a fork copy of the link cannot control it")]
pub(crate) struct NotOwner;

/// Only the process that bound the link controls it; a process that cannot be told (`Unknown`) is
/// refused too.
pub(super) fn owner_check(origin: Origin) -> Result<(), NotOwner> {
    if origin == Origin::Original {
        Ok(())
    } else {
        Err(NotOwner)
    }
}
