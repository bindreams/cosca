//! The state both the acceptor thread and the caller's threads act on, behind one lock.
//!
//! No thread holds the lock across a blocking call: every socket call made under it is nonblocking.

use std::io::{PipeReader, PipeWriter};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use rustix::io::Errno;

use super::outcome::{classify, AcceptorFailure, KillError, KillOutcome, LinkOutcome, NotStarted, NotStartedCause};
use super::probe::{DropReason, LinkEvent, Probe};
use super::sys::{self, Read};
use crate::elevation::shim::protocol::Command;

/// Whether a shim has been told to start the program. Moves only `Pending` to `Live` or `Pending`
/// to `Refused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartState {
    Pending,
    Live,
    Refused,
}

/// The length of a frame; see `protocol::decode_frame`.
const FRAME_LEN: usize = 5;

pub(super) struct Inner {
    start: StartState,
    /// Root peers that said hello.
    hello_seen: bool,
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
    /// teardown: a reader never closes it.
    pub(super) conn: OnceLock<UnixStream>,
    /// Written once, when the outcome is set, so a waiter that found nothing to read and then lost
    /// the frame to another reader still wakes: it polls this next to `conn`.
    pub(super) settled: (PipeReader, PipeWriter),
    /// Only for logs and tests: the socket is removed through `dir`, never by this path.
    pub(super) sock_path: PathBuf,
    /// The private directory, open: the socket is removed relative to it.
    dir: OwnedFd,
    /// The euid a shim must have: root, in production.
    pub(super) peer_euid: u32,
    pub(super) probe: Probe,
    /// Set in this process's memory before the stop byte is written. The acceptor stops only when it
    /// is set: a byte written by a fork copy, which cannot set the owner's flag, is consumed and
    /// ignored.
    stopping: AtomicBool,
}

impl Shared {
    pub(super) fn new(
        sock_path: PathBuf,
        dir: OwnedFd,
        peer_euid: u32,
        probe: Probe,
        settled: (PipeReader, PipeWriter),
    ) -> Self {
        Shared {
            inner: Mutex::new(Inner {
                start: StartState::Pending,
                hello_seen: false,
                frame: [0; FRAME_LEN],
                frame_len: 0,
                outcome: None,
                failure: None,
                unlinked: false,
            }),
            conn: OnceLock::new(),
            settled,
            sock_path,
            dir,
            peer_euid,
            probe,
            stopping: AtomicBool::new(false),
        }
    }

    /// Recovers a poisoned lock so a panic cannot wedge teardown.
    pub(super) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn unlink(&self, inner: &mut Inner) {
        if std::mem::replace(&mut inner.unlinked, true) {
            return;
        }
        match sys::unlink_socket(self.dir.as_fd(), super::SOCKET_NAME) {
            Ok(()) => {}
            Err(Errno::NOENT) => {
                log::debug!("the socket {} was already gone", self.sock_path.display());
            }
            Err(e) => log::warn!("cannot remove the socket {}: {e}", self.sock_path.display()),
        }
    }

    pub(super) fn request_stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    pub(super) fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// `Pending` to `Refused` in this process's memory only: no path is removed, and the lock is only
    /// tried, since a fork copy may hold a snapshot of it locked. Returns whether it took effect.
    pub(super) fn refuse_pending_in_memory(&self) -> bool {
        let Ok(mut inner) = self.inner.try_lock() else {
            return false;
        };
        if inner.start == StartState::Pending {
            inner.start = StartState::Refused;
        }
        true
    }

    /// `Pending` to `Refused`, removing the path in the same critical section.
    pub(super) fn refuse_pending(&self, inner: &mut Inner) {
        if inner.start == StartState::Pending {
            inner.start = StartState::Refused;
            self.unlink(inner);
        }
    }

    /// The acceptor cannot go on: refuses the start unless a shim already has `A`.
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

    /// A root peer said hello: answers it under the lock.
    pub(super) fn answer_hello(&self, conn: UnixStream) {
        let mut inner = self.lock();
        let further = std::mem::replace(&mut inner.hello_seen, true);
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

    /// Answers `N`; a failed send is only logged.
    pub(super) fn deny(&self, conn: &UnixStream) {
        if let Err(e) = sys::send_byte(conn.as_fd(), Command::Deny.encode()) {
            log::debug!("cannot answer N at {}: {e}", self.sock_path.display());
        }
        self.probe.event(|| LinkEvent::Answered(Command::Deny));
    }

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
        // Written under the lock: a waiter that saw no outcome is guaranteed to see this byte when it
        // polls. The write end is nonblocking, and a full pipe is already readable.
        let written = match self.probe.settled_write_error() {
            Some(injected) => Err(injected),
            None => sys::write_byte(self.settled.1.as_fd()),
        };
        if let Err(e) = written {
            if e != Errno::AGAIN {
                debug_assert!(false, "writing the settled byte failed: {e}");
                log::warn!(
                    "cannot signal the outcome of the shim at {}: {e}",
                    self.sock_path.display()
                );
            }
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

    /// The settled outcome, if any. Refuses a pending start; `None` means `Live` with no complete
    /// frame yet.
    pub(super) fn settle(&self) -> Option<LinkOutcome> {
        let mut inner = self.lock();
        if inner.outcome.is_none() {
            self.refuse_pending(&mut inner);
            if inner.start == StartState::Refused {
                let cause = inner
                    .failure
                    .map_or(NotStartedCause::Withheld, NotStartedCause::AcceptorFailed);
                let shim_connected = inner.hello_seen;
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

    /// Blocks until the outcome is settled. Waiters block on readiness outside the lock, then read
    /// under it. A failure to wait is returned and settles nothing: the shim may be fine.
    pub(super) fn wait(&self) -> Result<LinkOutcome, Errno> {
        loop {
            if let Some(outcome) = self.settle() {
                return Ok(outcome);
            }
            let conn = self.conn.get().expect("Live has a connection");
            self.probe.event(|| LinkEvent::Parked(std::thread::current().id()));
            self.probe.waiter_gate();
            // Poll `settled` too: another reader may take the frame and leave `conn` silent.
            let armed = |fds| {
                self.probe.event(|| LinkEvent::Polling {
                    fds,
                    settled_readable: sys::is_readable(&self.settled.0),
                });
            };
            let waited = match self.probe.wait_poll_error() {
                Some(injected) => Err(injected),
                None => sys::wait_for_frame_or_outcome(conn.as_fd(), &self.settled.0, armed),
            };
            if let Err(e) = waited {
                log::warn!("waiting for the shim at {}: {e}", self.sock_path.display());
                return Err(e);
            }
        }
    }

    /// The state and outcome, after one nonblocking read when `Live`; moves nothing.
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
        let sent = match self.probe.send_error() {
            Some(injected) => Err(injected),
            None => sys::send_byte(conn.as_fd(), Command::Kill.encode()),
        };
        match sent {
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
                Err(KillError::Io(e.into()))
            }
        }
    }
}
