//! macOS: an [`OsChild`] over the child's pid and unique id. There is no handle, so every act checks
//! the pid's unique id first, and a child is an unreaped zombie at worst, which pins the number.
//!
//! Two kqueues, deliberately. The exit kqueue ([`ExitWatch`]) is never read, so a look at it is a
//! zero-timeout `poll` that takes nothing from any waiter. The reap kqueue is drained by the one
//! waiter that holds the reap, inside [`OsChild::try_reap`], and waited on by it afterwards.

use std::os::fd::AsFd;
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};

use super::{ExitWatch, Kqueue};
use crate::error::Error;
use crate::os_process::child::{Foreign, OsChild, PeekOutcome, TryReapOutcome};
use crate::os_process::{Exit, OsProcess, WaitFor};
use crate::signal::{via_audit_token, Sent, Sig};
use crate::wait::exit_only::{self, Reap, Target};
use crate::wait::macos::{drain_exit_events, register_exit_events, OnTracer, TracerWatch};

/// A child of this process, named by its pid and `p_uniqueid`.
#[derive(Debug)]
pub(crate) struct MacChild {
    pid: u32,
    /// The child's unique id: never reused, so it tells the child from a process that took its pid.
    unique: u64,
    /// Armed for the child's exit and never read: [`OsProcess::exited`], and `try_reap`'s "an exit
    /// was seen".
    exit: ExitWatch,
    /// Armed for the child's exit, its reap and its signals, and for `SIGCHLD`: what the reap waiter
    /// drains and then waits on.
    reap: Kqueue,
    /// The tracers `reap` also watches. Locked only inside `try_reap`, which has one caller at a time.
    tracer: Mutex<TracerWatch>,
}

impl MacChild {
    /// Take over the child `pid`, whose unique id the spawn read as `unique`. A pid already past
    /// registration (`ESRCH`) is not a failure: the child has exited, and `exited` says so. Any other
    /// refusal is, and the caller tears the child down.
    pub(crate) fn new(pid: u32, unique: u64) -> Result<MacChild, Error> {
        let exit = ExitWatch::proc_exit(pid)?;
        let reap = Kqueue::new()?;
        // Whether the registration got `ESRCH` is no news here: `exit` read the same.
        register_exit_events(&reap, pid).map_err(Error::Io)?;
        Ok(MacChild {
            pid,
            unique,
            exit,
            reap,
            tracer: Mutex::new(TracerWatch::default()),
        })
    }

    fn target(&self) -> Target<'static> {
        Target::pid(self.pid, Some(self.unique))
    }

    /// The tracer watch, for the one `try_reap` caller. A second concurrent caller breaks the
    /// contract; in release it waits its turn.
    fn tracer(&self) -> MutexGuard<'_, TracerWatch> {
        match self.tracer.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => {
                debug_assert!(false, "try_reap has one caller at a time");
                self.tracer.lock().unwrap_or_else(PoisonError::into_inner)
            }
        }
    }
}

#[cfg(test)]
impl MacChild {
    /// Whether the reap kqueue has an event pending, read without taking it.
    pub(crate) fn event_pending(&self) -> bool {
        crate::os_process::macos::kqueue::test_hooks::event_pending(&self.reap)
    }
}

impl OsProcess for MacChild {
    /// By audit token, which the kernel checks against the pid's `p_idversion`: a bare errno on a
    /// refused send; `Gone` once the unique id says the pid names another process; `Delivered` for
    /// this child's own unreaped zombie.
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        via_audit_token(self.pid, Some(self.unique), sig).map_err(Error::Io)
    }

    fn exited(&self) -> Result<Exit<'_>, Error> {
        if self.exit.exited()? {
            Ok(Exit::Exited)
        } else {
            Ok(Exit::Running(WaitFor::Readable(self.exit.as_fd())))
        }
    }
}

impl OsChild for MacChild {
    /// `waitid(WNOWAIT)` by pid, checked against the unique id; a running child whose id cannot be
    /// read is an error. Touches no kqueue.
    fn peek(&self) -> Result<PeekOutcome, Error> {
        exit_only::peek_verified(&self.target()).map_err(Error::Io)
    }

    /// In this order: drain the reap kqueue (a `NOTE_REAP` is a foreign reap), peek, then consume the
    /// record, or wait on the tracer chain, or recheck, or wait on the reap kqueue. An event after
    /// the drain stays queued, so it wakes the wait this returns.
    fn try_reap(&self) -> Result<TryReapOutcome<'_>, Error> {
        let mut tracer = self.tracer();
        let (reaped, _exited) = drain_exit_events(&self.reap, self.pid, &mut tracer).map_err(Error::Io)?;
        if reaped {
            return Ok(TryReapOutcome::Foreign(Foreign::Gone));
        }
        let target = self.target();
        let (peeked, holder) = exit_only::peek_traced(&target).map_err(Error::Io)?;
        match peeked {
            PeekOutcome::Exit(_) => Ok(match exit_only::try_reap(&target).map_err(Error::Io)? {
                Reap::Reaped(record) => TryReapOutcome::Reaped(record),
                Reap::Foreign(foreign) => TryReapOutcome::Foreign(foreign),
                // The record went between the two looks: a tracer took it, so look again.
                Reap::Running => TryReapOutcome::Recheck,
            }),
            PeekOutcome::Foreign(foreign) => Ok(TryReapOutcome::Foreign(foreign)),
            PeekOutcome::Running => {
                if let Some(holder) = holder {
                    return Ok(
                        match tracer.held_by(&self.reap, holder).map_err(|e| Error::Io(e.into()))? {
                            OnTracer::Block => TryReapOutcome::Running(WaitFor::Readable(self.reap.as_fd())),
                            // The loop's backoff governs; the watch's own interval is not used.
                            OnTracer::Recheck(_) => TryReapOutcome::Recheck,
                        },
                    );
                }
                // The exit was seen, but nothing is there to consume and no tracer holds it: XNU is
                // still finishing the exit. The exit kqueue stays readable, so this is read live.
                if self.exit.exited()? {
                    return Ok(TryReapOutcome::Recheck);
                }
                Ok(TryReapOutcome::Running(WaitFor::Readable(self.reap.as_fd())))
            }
        }
    }
}
