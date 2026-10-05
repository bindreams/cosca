//! The state both the acceptor thread and the caller's threads act on, behind one lock (D4, D7).
//!
//! No thread holds the lock across a blocking call: every socket call made under it is nonblocking.

use std::io::{PipeReader, PipeWriter};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use rustix::io::Errno;

use super::outcome::{classify, AcceptorFailure, KillError, KillOutcome, LinkOutcome, NotStarted, NotStartedCause};
use super::probe::{DropReason, LinkEvent, Probe};
use super::sys::{self, Read};
use crate::elevation::shim::protocol::Command;

/// Whether a shim has been told to start the program (D4). Only ever moves right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartState {
    /// Nobody has been answered.
    Pending,
    /// A shim was answered `A`.
    Live,
    /// The start is refused: every shim is answered `N`.
    Refused,
}

/// A frame is a tag and four bytes.
const FRAME_LEN: usize = 5;

pub(super) struct Inner {
    start: StartState,
    /// Root peers that said hello.
    hellos: u32,
    /// The frame read so far.
    frame: [u8; FRAME_LEN],
    frame_len: usize,
    outcome: Option<LinkOutcome>,
    failure: Option<AcceptorFailure>,
    /// The socket path has been removed.
    unlinked: bool,
}

/// What [`Shared::observe`] saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observed {
    pub(crate) start: StartState,
    pub(crate) outcome: Option<LinkOutcome>,
    pub(crate) acceptor_failure: Option<AcceptorFailure>,
}

pub(super) struct Shared {
    inner: Mutex<Inner>,
    /// The shim's connection, set once, by the `Pending` to `Live` transition. Closed only in
    /// teardown (D7): a reader never closes it.
    pub(super) conn: OnceLock<UnixStream>,
    /// Written once, when the outcome is set, so a waiter that found nothing to read and then lost
    /// the frame to another reader still wakes: it polls this next to `conn`.
    settled: (PipeReader, PipeWriter),
    pub(super) sock_path: PathBuf,
    /// The euid a shim must have: root, in production.
    pub(super) peer_euid: u32,
    pub(super) probe: Probe,
}

impl Shared {
    pub(super) fn new(sock_path: PathBuf, peer_euid: u32, probe: Probe, settled: (PipeReader, PipeWriter)) -> Self {
        Shared {
            inner: Mutex::new(Inner {
                start: StartState::Pending,
                hellos: 0,
                frame: [0; FRAME_LEN],
                frame_len: 0,
                outcome: None,
                failure: None,
                unlinked: false,
            }),
            conn: OnceLock::new(),
            settled,
            sock_path,
            peer_euid,
            probe,
        }
    }

    /// A panic under the lock must not wedge teardown, so a poisoned lock is recovered: the data is
    /// only ever updated in whole steps.
    pub(super) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // Transitions -----

    fn unlink(&self, inner: &mut Inner) {
        if std::mem::replace(&mut inner.unlinked, true) {
            return;
        }
        match std::fs::remove_file(&self.sock_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::debug!("the socket {} was already gone", self.sock_path.display());
            }
            Err(e) => log::warn!("cannot remove the socket {}: {e}", self.sock_path.display()),
        }
    }

    /// `Pending` to `Refused`, removing the path in the same critical section (D4).
    pub(super) fn refuse_pending(&self, inner: &mut Inner) {
        if inner.start == StartState::Pending {
            inner.start = StartState::Refused;
            self.unlink(inner);
        }
    }

    /// The acceptor cannot go on (D4): the start is refused, unless a shim already has the answer `A`.
    pub(super) fn fail_closed(&self, failure: AcceptorFailure) {
        let mut inner = self.lock();
        match inner.start {
            StartState::Pending | StartState::Refused => {
                log::error!(
                    "the acceptor for {} failed ({failure:?}); the start is refused",
                    self.sock_path.display()
                );
                inner.failure.get_or_insert(failure);
                self.refuse_pending(&mut inner);
            }
            StartState::Live => {
                log::warn!(
                    "the acceptor for {} stopped ({failure:?}); the running shim is unaffected",
                    self.sock_path.display()
                );
                self.unlink(&mut inner);
            }
        }
    }

    /// A root peer said hello (D4): answers it under the lock.
    pub(super) fn answer_hello(&self, conn: UnixStream) {
        let mut inner = self.lock();
        inner.hellos += 1;
        let further = inner.hellos > 1;
        let path = self.sock_path.display();
        if inner.start == StartState::Pending {
            match sys::send_byte(conn.as_fd(), Command::Allow.encode()) {
                Ok(()) => {
                    inner.start = StartState::Live;
                    let set = self.conn.set(conn);
                    debug_assert!(set.is_ok(), "the connection is set once, at the first Live");
                    self.unlink(&mut inner);
                    self.probe.event(|| LinkEvent::Answered(Command::Allow));
                }
                Err(e) => {
                    log::debug!("cannot answer the shim at {path}: {e}; the start is refused");
                    self.refuse_pending(&mut inner);
                    self.probe.event(|| LinkEvent::Dropped(DropReason::AnswerFailed));
                }
            }
            return;
        }
        if further {
            log::warn!("a further root peer at {path} said hello; answered N");
        } else {
            log::debug!("a root peer at {path} said hello after the start was refused; answered N");
        }
        self.deny(&conn);
    }

    /// Answers `N`, best effort, and lets `conn` close.
    pub(super) fn deny(&self, conn: &UnixStream) {
        if let Err(e) = sys::send_byte(conn.as_fd(), Command::Deny.encode()) {
            log::debug!("cannot answer N at {}: {e}", self.sock_path.display());
        }
        self.probe.event(|| LinkEvent::Answered(Command::Deny));
    }

    // Reading the one outcome -----

    fn set_outcome(&self, inner: &mut Inner, outcome: LinkOutcome) {
        debug_assert!(inner.outcome.is_none(), "the outcome is set once");
        let path = self.sock_path.display();
        match outcome {
            LinkOutcome::Exited(_) => {}
            LinkOutcome::NotStarted(n) => log::debug!("the program at {path} never ran: {n:?}"),
            LinkOutcome::SupervisionLost(ws) => {
                log::warn!("supervision of the program at {path} was lost; the shim killed it (status {ws:#x})");
            }
            LinkOutcome::StatusLost => {
                log::warn!("the program at {path} has exited and its status is lost");
            }
            LinkOutcome::ShimLost => {
                log::warn!("the shim at {path} was lost; the program may still be running");
            }
        }
        inner.outcome = Some(outcome);
        // Under the lock, so a waiter that sees no outcome and then polls sees this byte at the
        // latest: the outcome is set before the byte, and the byte stays.
        if let Err(e) = rustix::io::write(&self.settled.1, &[1]) {
            log::warn!(
                "cannot signal the outcome of the shim at {}: {e}",
                self.sock_path.display()
            );
        }
    }

    /// Reads what the connection has into the frame buffer, without blocking, until the frame
    /// settles the outcome or nothing more is there. The caller has seen `Live`.
    fn read_frame(&self, inner: &mut Inner) {
        let conn = self.conn.get().expect("Live has a connection");
        while inner.outcome.is_none() {
            let len = inner.frame_len;
            let (settled, more) = match sys::read_some(conn.as_fd(), &mut inner.frame[len..]) {
                Read::Bytes(n) => {
                    inner.frame_len += n;
                    self.probe.event(|| LinkEvent::Read(n, std::thread::current().id()));
                    (classify(&inner.frame[..inner.frame_len], false), true)
                }
                Read::Eof => (classify(&inner.frame[..len], true), false),
                Read::Empty => (None, false),
                Read::Failed(e) => {
                    log::warn!("reading from the shim at {}: {e}", self.sock_path.display());
                    (Some(LinkOutcome::ShimLost), false)
                }
            };
            if let Some(outcome) = settled {
                self.set_outcome(inner, outcome);
            } else if !more {
                break;
            }
        }
    }

    /// The outcome once the front is gone and its status is known, if it is settled: `Pending`
    /// becomes `Refused` (D7). `None` means `Live` and no complete frame yet.
    pub(super) fn settle(&self) -> Option<LinkOutcome> {
        let mut inner = self.lock();
        if inner.outcome.is_none() {
            self.refuse_pending(&mut inner);
            if inner.start == StartState::Refused {
                let cause = inner
                    .failure
                    .map_or(NotStartedCause::Withheld, NotStartedCause::AcceptorFailed);
                let shim_connected = inner.hellos > 0;
                self.set_outcome(
                    &mut inner,
                    LinkOutcome::NotStarted(NotStarted { shim_connected, cause }),
                );
            } else {
                self.read_frame(&mut inner);
            }
        }
        inner.outcome
    }

    /// Blocks until the outcome is settled (D7). Waiters block on readiness outside the lock, then
    /// read under it.
    pub(super) fn wait(&self) -> LinkOutcome {
        loop {
            if let Some(outcome) = self.settle() {
                return outcome;
            }
            let conn = self.conn.get().expect("Live has a connection");
            self.probe.event(|| LinkEvent::Parked(std::thread::current().id()));
            self.probe.waiter_gate();
            // Another reader may settle the outcome from here on and leave `conn` empty, with the
            // shim's end still open: only the settled signal then wakes this waiter.
            let armed = |fds| {
                self.probe.event(|| LinkEvent::Polling {
                    fds,
                    settled_readable: sys::is_readable(&self.settled.0),
                });
            };
            if let Err(e) = sys::wait_for_frame_or_outcome(conn.as_fd(), &self.settled.0, armed) {
                // Cannot wait on the shim any more: the honest answer is that it is lost.
                log::warn!("waiting for the shim at {}: {e}", self.sock_path.display());
                let mut inner = self.lock();
                if inner.outcome.is_none() {
                    self.set_outcome(&mut inner, LinkOutcome::ShimLost);
                }
                return inner.outcome.expect("just set");
            }
        }
    }

    /// The state and outcome, after one nonblocking read when `Live`; moves nothing (D7a).
    pub(super) fn observe(&self) -> Observed {
        let mut inner = self.lock();
        if inner.start == StartState::Live && inner.outcome.is_none() {
            self.read_frame(&mut inner);
        }
        Observed {
            start: inner.start,
            outcome: inner.outcome,
            acceptor_failure: inner.failure,
        }
    }

    // `kill` (D5) -----

    pub(super) fn kill(&self) -> Result<KillOutcome, KillError> {
        let mut inner = self.lock();
        if inner.start != StartState::Live {
            self.refuse_pending(&mut inner);
            return Ok(KillOutcome::RefusedStart);
        }
        match inner.outcome {
            Some(LinkOutcome::ShimLost) => return Err(KillError::ShimLost),
            Some(_) => return Ok(KillOutcome::AlreadyEnded),
            None => {}
        }
        let conn = self.conn.get().expect("Live has a connection");
        match sys::send_byte(conn.as_fd(), Command::Kill.encode()) {
            Ok(()) => Ok(KillOutcome::Delivered),
            Err(Errno::PIPE | Errno::CONNRESET | Errno::NOTCONN) => {
                // The shim is gone. Whether the program is depends on what it said first.
                self.read_frame(&mut inner);
                match inner.outcome {
                    Some(outcome) if outcome.program_is_gone() => Ok(KillOutcome::AlreadyEnded),
                    _ => Err(KillError::ShimLost),
                }
            }
            Err(Errno::AGAIN | Errno::NOBUFS) => Err(KillError::Unkillable),
            Err(e) => {
                log::warn!("sending K to the shim at {}: {e}", self.sock_path.display());
                Err(KillError::ShimLost)
            }
        }
    }
}
