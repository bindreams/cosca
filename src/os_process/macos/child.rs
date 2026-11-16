//! macOS: an [`OsChild`] over the child's pid and unique id. There is no handle, so every act checks
//! the pid's unique id first, and a child is an unreaped zombie at worst, which pins the number.
//! The child owns the [`Kernel`] it asks.
//!
//! Three kinds of kqueue, deliberately, so that a kqueue that is read has one reader. The exit kqueue
//! ([`ExitWatch`]) is never read, so a look at it is a zero-timeout `poll` that takes nothing from
//! any waiter. The reap kqueue is drained by the one waiter that holds the reap, inside
//! [`OsChild::try_observe`], and waited on by it afterwards. Each exit wait ([`OsProcess::exit_wait`])
//! arms and drains one of its own.

use std::os::fd::AsFd;
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};

use super::{ExitWatch, Kqueue};
use crate::error::Error;
use crate::identity::{has_exited, held_by, Held, Kernel};
use crate::os_process::child::{Foreign, KillRefusal, OsChild, PeekOutcome, TryObserveOutcome};
use crate::os_process::drive::{Step, Waitable};
use crate::os_process::{Exit, ExitWait, OsProcess, WaitFor};
use crate::signal::{via_audit_token, Sent, Sig};
use crate::wait::exit_only::{self, Reap, Target};
use crate::wait::macos::{drain_exit_events, register_exit_events, OnTracer, TracerWatch};

/// A child of this process, named by its pid and `p_uniqueid`.
pub(crate) struct MacosChild<K> {
    /// What every read of the child asks.
    kernel: K,
    pid: u32,
    /// The child's unique id: never reused, so it tells the child from a process that took its pid.
    unique: u64,
    /// Armed for the child's exit and never read: [`OsProcess::exited`], and `try_observe`'s "an exit
    /// was seen".
    exit: ExitWatch,
    /// Armed for the child's exit, its reap and its signals, and for `SIGCHLD`: what the reap waiter
    /// drains and then waits on.
    reap: Kqueue,
    /// The tracers `reap` also watches. Locked only inside `try_observe`, which has one caller at a time.
    tracer: Mutex<TracerWatch>,
}

impl<K> std::fmt::Debug for MacosChild<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacosChild")
            .field("pid", &self.pid)
            .field("unique", &self.unique)
            .field("exit", &self.exit)
            .field("reap", &self.reap)
            .field("tracer", &self.tracer)
            .finish_non_exhaustive()
    }
}

impl<K: Kernel + Send> MacosChild<K> {
    /// Take over the child `pid`, whose unique id the spawn read as `unique`, asking `kernel`, which
    /// the child then owns. A pid already past registration (`ESRCH`) is not a failure: the child
    /// has exited, and `exited` says so. Any other refusal is, and the caller tears the child down.
    pub(crate) fn new(kernel: K, pid: u32, unique: u64) -> Result<MacosChild<K>, Error> {
        let exit = ExitWatch::proc_exit(&kernel, pid)?;
        let reap = Kqueue::new()?;
        // An ESRCH here is not read as an exit: only the exit watch reports one.
        register_exit_events(&kernel, &reap, pid).map_err(Error::Io)?;
        Ok(MacosChild {
            kernel,
            pid,
            unique,
            exit,
            reap,
            tracer: Mutex::new(TracerWatch::default()),
        })
    }

    fn target(&self) -> Target<'_> {
        Target::pid(&self.kernel, self.pid, Some(self.unique))
    }

    /// The tracer watch, for the one `try_observe` caller. A second concurrent caller breaks the
    /// contract; in release it waits its turn.
    fn tracer(&self) -> MutexGuard<'_, TracerWatch> {
        match self.tracer.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => {
                debug_assert!(false, "try_observe has one caller at a time");
                self.tracer.lock().unwrap_or_else(PoisonError::into_inner)
            }
        }
    }
}

impl<K: Kernel + Send> OsProcess for MacosChild<K> {
    /// By audit token, which the kernel checks against the pid's `p_idversion`: a bare errno on a
    /// refused send; `Gone` once the unique id says the pid names another process; `Delivered` for
    /// this child's own unreaped zombie.
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        via_audit_token(&self.kernel, self.pid, Some(self.unique), sig).map_err(Error::Io)
    }

    /// `Exited` once the child is a zombie or gone, as [`MacosProcess`](super::MacosProcess) answers it
    /// ([`ExitWatch::look`]), and also when the watch cannot say: XNU withholds `NOTE_EXIT` from a
    /// parent that does not hold the child (`p_oppid` set), so a
    /// child whose parent is another process, a tracer or launchd, may be a zombie with its watch
    /// unfired. Then the zombie read decides: `Exited` for a zombie or gone, `Recheck` for a child
    /// still running, since no event will come while another process is the parent. A child whose
    /// parent is this process and whose watch has not fired is `Running` on the watch, with no
    /// zombie read. A refused read is [`Error::Unassessable`] with its errno as the source.
    ///
    /// A look reads the parent as of now: a tracer that attaches after it is caught by the wait
    /// ([`exit_wait`](OsProcess::exit_wait)), not by the look.
    ///
    /// The waiter's look ([`try_observe`](OsChild::try_observe)) does not come through here: it
    /// reads the watch raw and peeks `waitid` itself, so this adds nothing to it.
    fn exited(&self) -> Result<Exit<'_>, Error> {
        match self.exit.look(&self.kernel, self.pid, self.unique)? {
            Exit::Running(wait_for) => self.exited_past_the_watch(wait_for),
            look => Ok(look),
        }
    }

    /// The wait that catches what a look cannot: a tracer attaching after the look (the attach's
    /// `SIGSTOP` is a `NOTE_SIGNAL`, and from then on no `NOTE_EXIT` reaches this process). It owns a
    /// kqueue armed before its first look, and no other wait or look reads it.
    fn exit_wait(&self) -> Result<ExitWait<'_>, Error> {
        Ok(Box::new(ChildExit::arm(self)?))
    }
}

/// One wait for a [`MacosChild`]'s exit, on a kqueue of its own: armed for `NOTE_EXIT`, `NOTE_SIGNAL`
/// and `NOTE_REAP` of the child and for `SIGCHLD`, as the reap waiter's is. Every look drains it
/// first, so what woke the wait is taken, and what comes after the drain stays queued for the wait
/// the look returns: no wake is lost, and none is taken from another waiter. The shared exit watch
/// is still only polled.
struct ChildExit<'a, K> {
    child: &'a MacosChild<K>,
    kq: Kqueue,
    /// The registration found the pid past registration (`ESRCH`): no event will come.
    unarmed: bool,
    /// A drain read the child's `NOTE_EXIT`. The shared watch's knote may not be queued yet, so the
    /// look it reads can still say `Running`: that is a recheck, never a wait on a kqueue whose
    /// `NOTE_EXIT` is gone.
    exit_seen: bool,
}

impl<'a, K: Kernel + Send> ChildExit<'a, K> {
    fn arm(child: &'a MacosChild<K>) -> Result<Self, Error> {
        let kq = Kqueue::new()?;
        let unarmed = register_exit_events(&child.kernel, &kq, child.pid).map_err(Error::Io)?;
        Ok(Self {
            child,
            kq,
            unarmed,
            exit_seen: false,
        })
    }
}

impl<K: Kernel + Send> Waitable for ChildExit<'_, K> {
    type Output = ();

    fn look(&mut self) -> Result<Step<'_, ()>, Error> {
        // A `NOTE_REAP` is a foreign reap: the look below reads it as the pid gone.
        let (_reaped, exited) =
            drain_exit_events(&self.kq, self.child.pid, &mut TracerWatch::default()).map_err(Error::Io)?;
        self.exit_seen |= exited;
        Ok(match self.child.exited()? {
            Exit::Exited => Step::Done(()),
            Exit::Recheck => Step::Recheck,
            Exit::Running(_) if self.unarmed || self.exit_seen => Step::Recheck,
            Exit::Running(_) => Step::Wait(WaitFor::Readable(self.kq.as_fd())),
        })
    }
}

impl<K: Kernel + Send> MacosChild<K> {
    /// [`exited`](OsProcess::exited) for a watch that has not fired: `Running` on `wait_for` only
    /// while this process is the child's parent.
    fn exited_past_the_watch<'a>(&self, wait_for: WaitFor<'a>) -> Result<Exit<'a>, Error> {
        let refused = |errno| {
            crate::os_process::macos::exit_read_refused(
                self.pid,
                errno,
                "its exit watch has not fired, and whether it has exited could not be read",
            )
        };
        let exited = match held_by(&self.kernel, self.pid, self.unique) {
            Held::Parent(parent) if parent == std::process::id() => return Ok(Exit::Running(wait_for)),
            Held::Parent(_) => has_exited(&self.kernel, self.pid, self.unique).map_err(refused)?,
            // Another process now, or reaped: exited.
            Held::Other | Held::Gone => true,
            Held::Refused(errno) => return Err(refused(errno)),
        };
        if !exited {
            return Ok(Exit::Recheck);
        }
        self.exit.confirm();
        Ok(Exit::Exited)
    }
}

impl<K: Kernel + Send> OsChild for MacosChild<K> {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn kernel(&self) -> &dyn Kernel {
        &self.kernel
    }

    /// The signal is refused with `EPERM` alone, but the identity read it is checked by is refused
    /// with whatever errno the kernel answers.
    fn kill_refusal(&self) -> KillRefusal {
        KillRefusal::Any
    }

    /// `waitid(WNOWAIT)` by pid, checked against the unique id; a running child whose id cannot be
    /// read is an error. Touches no kqueue.
    fn peek(&self) -> Result<PeekOutcome, Error> {
        exit_only::peek_verified(&self.target()).map_err(Error::Io)
    }

    /// The record is left in place; an event after the drain stays queued, so it wakes the returned
    /// wait.
    fn try_observe(&self) -> Result<TryObserveOutcome<'_>, Error> {
        let mut tracer = self.tracer();
        let (reaped, _exited) = drain_exit_events(&self.reap, self.pid, &mut tracer).map_err(Error::Io)?;
        if reaped {
            return Ok(TryObserveOutcome::Foreign(Foreign::Gone));
        }
        let (peeked, holder) = exit_only::peek_traced(&self.target()).map_err(Error::Io)?;
        match peeked {
            PeekOutcome::Exit(record) => Ok(TryObserveOutcome::Exited(record)),
            PeekOutcome::Foreign(foreign) => Ok(TryObserveOutcome::Foreign(foreign)),
            PeekOutcome::Running => {
                if let Some(holder) = holder {
                    return Ok(
                        match tracer
                            .held_by(&self.kernel, &self.reap, holder)
                            .map_err(|e| Error::Io(e.into()))?
                        {
                            OnTracer::Block => TryObserveOutcome::Running(WaitFor::Readable(self.reap.as_fd())),
                            // The loop's backoff governs; the watch's own interval is not used.
                            OnTracer::Recheck(_) => TryObserveOutcome::Recheck,
                        },
                    );
                }
                // The exit was seen, but nothing is there to consume and no tracer holds it: XNU is
                // still finishing the exit. The exit kqueue stays readable, so this is read live.
                if self.exit.exited()? {
                    return Ok(TryObserveOutcome::Recheck);
                }
                Ok(TryObserveOutcome::Running(WaitFor::Readable(self.reap.as_fd())))
            }
        }
    }

    /// The peek-then-consume of [`exit_only::try_reap`], with `second_reap` for a child this process
    /// traces. Touches no kqueue: the handle is ending.
    fn try_reap(&self) -> Result<Reap, Error> {
        exit_only::try_reap(&self.target()).map_err(Error::Io)
    }

    fn exact_consume(&self) -> bool {
        false
    }
}
