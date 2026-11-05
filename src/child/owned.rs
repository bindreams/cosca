//! The parent's policy over its child, written once: concurrent `wait` and `signal` on one spawned
//! child from any number of threads, reap once, "already reaped is gone", and holding off reaps across
//! a check-then-send. The OS part is an [`OsChild`], which states what the OS says now.
//!
//! **The handle never reaps at adoption, and never blocks in a reap.** Every reap is a look through
//! [`OsChild::try_reap`], taken by the one waiter that holds the wait, and it never blocks: a
//! non-blocking `waitid`, only of an exit record, on the pidfd (Linux) or the pid (macOS); on Windows
//! there is nothing to consume, and the reap reads the signalled process handle's exit code (see
//! [`crate::wait::exit_only`]). A child that this process traces is therefore never taken for exited
//! when it merely stops.
//!
//! # States
//!
//! `N` (nobody is waiting), `W { token }` (one thread, the *holder*, runs the wait loop) and
//! `E(record)` (the exit record is cached, the child is reaped). Only the holder looks with
//! `try_reap` and waits on what the look returned, with the lock released; every other waiter blocks
//! on the [`Condvar`] and re-dispatches on each wake. While `W` is held, only the holder reaps.
//!
//! - Every lock is taken poison-tolerantly (`lock().unwrap_or_else(PoisonError::into_inner)`),
//!   `Condvar` results included. `Debug` alone uses `try_lock`.
//! - Every state write calls `notify_all` ([`Inner::set`], then [`OwnedChild::notify`]).
//! - The holder is armed by a [`HolderGuard`] whose `Drop` restores `N` (and wakes the waiters):
//!   an `Err`, a `?` or a panic can never strand the waiters, and a normal return can never
//!   restore `N` under a new holder, because [`HolderGuard::finish`] consumes the guard.
//! - A holder re-reads the state after it re-locks, before it acts on a look.
//! - Every timed block is clamped and looped ([`crate::wait::clamp_block`], and `drive::run` for the
//!   holder's), and after every wake `crate::wait::now() >= deadline` decides expiry, never the
//!   primitive's own "timed out".

use std::fmt;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::os_process::child::{ExitRecord, Foreign, OsChild, PeekOutcome};
use crate::signal::{Sent, Sig};

#[path = "owned/holder.rs"]
mod holder;
#[path = "owned/slot.rs"]
pub(crate) mod slot;
#[path = "owned/teardown.rs"]
pub(crate) mod teardown;
#[path = "owned/unreaped.rs"]
pub(crate) mod unreaped;
#[path = "owned/waiting.rs"]
mod waiting;

#[cfg(test)]
#[path = "owned/over.rs"]
mod over;
#[cfg(test)]
#[path = "owned/seams.rs"]
pub(crate) mod seams;

/// What the handle knows about the child's exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Nobody is waiting.
    N,
    /// The thread that drew `token` is the holder, running the wait loop.
    W { token: u64 },
    /// Reaped: the exit record is cached.
    E(ExitRecord),
}

struct Inner {
    state: State,
    /// The next holder's token: one per holder, so a stale guard cannot touch a newer holder.
    next_token: u64,
    /// Every state write and every `notify_all`, in order, pushed in the critical section that
    /// makes it: what the tests check a hand-off against.
    #[cfg(test)]
    log: Vec<Logged>,
}

/// One entry of [`Inner::log`].
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Logged {
    Write(State),
    Notify,
}

impl Inner {
    /// Write `state`. The caller wakes the waiters with [`OwnedChild::notify`] in the same
    /// critical section.
    fn set(&mut self, state: State) {
        self.state = state;
        #[cfg(test)]
        self.log.push(Logged::Write(state));
    }
}

/// The lock guard. In a test build it also records which thread holds the lock, so a thread that
/// locks it again panics instead of deadlocking.
#[cfg(not(test))]
type Guard<'a> = MutexGuard<'a, Inner>;

#[cfg(test)]
struct Guard<'a> {
    guard: Option<MutexGuard<'a, Inner>>,
    owner: &'a Mutex<Option<std::thread::ThreadId>>,
}

#[cfg(test)]
impl std::ops::Deref for Guard<'_> {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        self.guard.as_ref().expect("a live guard")
    }
}

#[cfg(test)]
impl std::ops::DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut Inner {
        self.guard.as_mut().expect("a live guard")
    }
}

#[cfg(test)]
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if self.guard.is_some() {
            *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
    }
}

/// How a wait on a child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildWaitOutcome {
    /// The child's exit record: this handle reaped it, now or earlier.
    Exited(ExitRecord),
    /// The child is not this process's to reap.
    Foreign(Foreign),
    /// The deadline passed with the child still running, after one final look.
    DeadlinePassed,
}

/// A spawned child that several threads may wait on and signal at once.
pub(crate) struct OwnedChild {
    /// Outside the mutex: the holder waits on the `WaitFor` its look returned with the lock released.
    os: Box<dyn OsChild>,
    inner: Mutex<Inner>,
    condvar: Condvar,
    /// The thread that holds `inner`, for [`OwnedChild::lock`]'s self-deadlock check.
    #[cfg(test)]
    owner: Mutex<Option<std::thread::ThreadId>>,
}

// Construction =====

impl OwnedChild {
    /// Take over `os`. **Makes no call to it**: an already-exited child is still a zombie afterwards.
    pub(crate) fn new(os: Box<dyn OsChild>) -> OwnedChild {
        OwnedChild {
            os,
            inner: Mutex::new(Inner {
                state: State::N,
                next_token: 0,
                #[cfg(test)]
                log: Vec::new(),
            }),
            condvar: Condvar::new(),
            #[cfg(test)]
            owner: Mutex::new(None),
        }
    }

    /// Take over the std `child`, whose identity `id` the caller has just read, through
    /// [`adopt_std`](crate::os_process::child::adopt_std). **Never reaps**: an already-exited child
    /// is still a zombie afterwards. Tests only: a spawn adopts through the handle it holds.
    #[cfg(test)]
    #[allow(
        clippy::result_large_err,
        reason = "the child is handed back untouched for the caller to deal with"
    )]
    pub(crate) fn adopt(
        child: std::process::Child,
        id: crate::identity::ProcessId,
    ) -> Result<OwnedChild, (Error, std::process::Child)> {
        crate::os_process::child::adopt_std(child, id).map(OwnedChild::new)
    }

    /// The child's pid, if its spawn learned it; see [`OsChild::pid`].
    pub(crate) fn pid(&self) -> Option<u32> {
        self.os.pid()
    }

    /// The OS object that names the child, borrowed from `self`.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn os_handle(&self) -> crate::os_process::child::OsHandle<'_> {
        self.os.os_handle()
    }

    /// The root's pidfd where it has one (Linux; macOS names no process by a handle), for the checks
    /// of a cgroup or a group that take it.
    #[cfg(unix)]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        #[cfg(target_os = "linux")]
        return Some(self.os_handle());
        #[cfg(not(target_os = "linux"))]
        None
    }

    /// Whether this handle's own wait has recorded the reap, read under the lock. A reap by
    /// someone else is not seen here.
    pub(crate) fn is_reaped(&self) -> bool {
        matches!(self.lock().state, State::E(_))
    }

    /// Whether the root is still this handle's child to act on, from the handle's own evidence; see
    /// [`ReapHold::state`].
    #[cfg(unix)]
    pub(crate) fn state(&self) -> crate::signal::RootState {
        self.state_locked(&self.lock())
    }

    /// [`state`](Self::state), under `lock`.
    #[cfg(unix)]
    fn state_locked(&self, lock: &Guard<'_>) -> crate::signal::RootState {
        use crate::signal::RootState;
        if matches!(lock.state, State::E(_)) {
            return RootState::Reaped { own: true };
        }
        RootState::of_peek(self.os.peek().map_err(Error::into_io))
    }

    /// Whether this thread holds the lock. Tests only.
    #[cfg(all(unix, test))]
    pub(crate) fn is_held_by_current_thread(&self) -> bool {
        *self.owner.lock().unwrap_or_else(PoisonError::into_inner) == Some(std::thread::current().id())
    }

    fn lock(&self) -> Guard<'_> {
        #[cfg(test)]
        {
            let me = std::thread::current().id();
            let owner = self.owner.lock().unwrap_or_else(PoisonError::into_inner);
            assert_ne!(
                *owner,
                Some(me),
                "self-deadlock: this thread locked an OwnedChild it already holds"
            );
            drop(owner);
            let guard = match self.inner.try_lock() {
                Ok(guard) => guard,
                Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    seams::lock_contended();
                    self.inner.lock().unwrap_or_else(PoisonError::into_inner)
                }
            };
            *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = Some(me);
            Guard {
                guard: Some(guard),
                owner: &self.owner,
            }
        }
        #[cfg(not(test))]
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wake every waiter, in the critical section that wrote the state.
    #[cfg_attr(not(test), allow(unused_variables, reason = "only a test build logs the wake"))]
    fn notify(&self, lock: &mut Guard<'_>) {
        #[cfg(test)]
        lock.log.push(Logged::Notify);
        self.condvar.notify_all();
    }

    /// `Condvar::wait` on `lock`.
    fn cv_wait<'a>(&'a self, lock: Guard<'a>) -> Guard<'a> {
        #[cfg(test)]
        {
            let mut lock = lock;
            let inner = lock.guard.take().expect("a live guard");
            *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = None;
            let inner = self.condvar.wait(inner).unwrap_or_else(PoisonError::into_inner);
            *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = Some(std::thread::current().id());
            lock.guard = Some(inner);
            lock
        }
        #[cfg(not(test))]
        self.condvar.wait(lock).unwrap_or_else(PoisonError::into_inner)
    }

    /// `Condvar::wait_timeout` on `lock`.
    fn cv_wait_timeout<'a>(&'a self, lock: Guard<'a>, dur: Duration) -> Guard<'a> {
        #[cfg(test)]
        {
            let mut lock = lock;
            let inner = lock.guard.take().expect("a live guard");
            *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = None;
            let (inner, _) = self
                .condvar
                .wait_timeout(inner, dur)
                .unwrap_or_else(PoisonError::into_inner);
            *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = Some(std::thread::current().id());
            lock.guard = Some(inner);
            lock
        }
        #[cfg(not(test))]
        {
            let (lock, _) = self
                .condvar
                .wait_timeout(lock, dur)
                .unwrap_or_else(PoisonError::into_inner);
            lock
        }
    }
}

// Signals and holds =====

impl OwnedChild {
    /// Send `sig` to the child: [`Sent::Gone`] once this handle has reaped it, and otherwise what
    /// the OS says, with a refused send's bare errno. Under the lock, so none of our reaps lands
    /// between the check and the send.
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        self.signal_locked(&self.lock(), sig)
    }

    /// [`signal`](Self::signal), under `lock`.
    fn signal_locked(&self, lock: &Guard<'_>, sig: Sig) -> Result<Sent, Error> {
        if matches!(lock.state, State::E(_)) {
            return Ok(Sent::Gone);
        }
        self.os.signal(sig)
    }

    /// The exit record or the foreign verdict a peek sees, without reaping, under `lock`.
    fn peek_locked(&self, lock: &Guard<'_>) -> Result<PeekOutcome, Error> {
        match lock.state {
            State::E(record) => Ok(PeekOutcome::Exit(record)),
            State::N | State::W { .. } => self.os.peek(),
        }
    }

    /// Whether the child has exited by `deadline` (`None`: for ever), read through the OS's own look
    /// ([`OsProcess::exited`](crate::os_process::OsProcess::exited)): a zombie its tracer holds
    /// counts on Linux; on macOS only at the hand-back (XNU withholds `NOTE_EXIT` from a
    /// non-tracer parent while `p_oppid` is set, `kern_event.c:1203-1210`). Reaps nothing: during a
    /// graceful tree shutdown the root stays an unreaped zombie until the group kill is done, so its
    /// pid names no one else (principle 4). Takes no lock, so it may run while another thread waits.
    pub(crate) fn exited_by(&self, deadline: Option<Instant>) -> Result<bool, Error> {
        crate::os_process::drive::exited_until(&*self.os, deadline)
    }

    /// Hold off this handle's reaps (every reap is taken under its lock) until the result drops:
    /// what it reads and sends meanwhile is one step to a `wait` on another thread. Nothing that locks the
    /// handle may be called while it is held.
    #[cfg(unix)]
    pub(crate) fn hold(&self, pid: u32) -> ReapHold<'_> {
        ReapHold {
            child: self,
            pid,
            lock: self.lock(),
        }
    }

    /// A contract breach after the `E` write: a consuming reap handed back a record that is not
    /// an exit. The state is already `E`, so this must run with the lock released.
    fn log_unreadable(&self, record: ExitRecord) {
        if let ExitRecord::Unreadable { si_code } = record {
            log::warn!(
                "{:?}: a consuming waitid returned si_code {si_code}, not an exit record",
                self.os
            );
            debug_assert!(false, "a consuming waitid on a zombie returned si_code {si_code}");
        }
    }
}

/// [`OwnedChild::hold`]: the handle's lock, and what may be read and sent under it.
#[cfg(unix)]
pub(crate) struct ReapHold<'a> {
    child: &'a OwnedChild,
    pid: u32,
    lock: Guard<'a>,
}

#[cfg(unix)]
impl ReapHold<'_> {
    /// What a peek through the child's own handle shows (the exit record once this handle has reaped
    /// it), without reaping.
    pub(crate) fn peek(&self) -> Result<PeekOutcome, Error> {
        self.child.peek_locked(&self.lock)
    }

    /// Whether the root is still this handle's child to act on, from the handle's own evidence, read
    /// under the lock so none of our reaps lands between the state and a send. A `Reaped` is `own`
    /// when this handle's wait collected it.
    ///
    /// A peek through the handle decides (Linux: the pidfd; macOS: the pid, checked against its
    /// unique id, with an unreadable id on a running child an error).
    pub(crate) fn state(&self) -> crate::signal::RootState {
        self.child.state_locked(&self.lock)
    }

    /// [`OwnedChild::signal`], under this hold.
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        self.child.signal_locked(&self.lock, sig)
    }

    /// The root's group, for a send by the root's pid: its check reads this hold's
    /// [`state`](Self::state), so no reap of ours lands between a check and its send. On Linux the
    /// root's pidfd names the group exactly; on macOS there is none.
    pub(crate) fn group(&self) -> crate::containment::GroupRoot<'_> {
        crate::containment::GroupRoot::new(self.child.pidfd(), self)
    }
}

/// Whether the root's pid still names its group, from this hold's own evidence.
#[cfg(unix)]
impl crate::containment::RootCheck for ReapHold<'_> {
    fn check(&self) -> Result<(), String> {
        super::tree_call::group_number_holds(self.pid, self.state())
    }
}

// Debug =====

impl fmt::Debug for OwnedChild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("OwnedChild");
        d.field("os", &self.os);
        // `try_lock`, never `lock`: formatting must not block behind a waiter.
        match self.inner.try_lock() {
            Ok(inner) => d.field("state", &inner.state),
            Err(std::sync::TryLockError::Poisoned(e)) => d.field("state", &e.into_inner().state),
            Err(std::sync::TryLockError::WouldBlock) => d.field("state", &format_args!("locked")),
        };
        d.finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "owned_tests.rs"]
mod owned_tests;
