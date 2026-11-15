//! The parent's policy over its child, written once: concurrent `wait` and `signal` on one spawned
//! child from any number of threads, reap once, and "already reaped is gone". The OS part is an
//! [`OsChild`], which states what the OS says now.
//!
//! **The handle never reaps at adoption, never reaps in a wait, and never blocks in a reap.** A wait
//! is a look through [`OsChild::try_observe`], taken by the one waiter that holds the wait, and it
//! never blocks and never consumes (see [`crate::wait::exit_only`]). A child that this
//! process traces is therefore never taken for exited when it merely stops. The one reap is the
//! handle's `Drop` (unix), which consumes the exit record with a non-blocking
//! [`OsChild::try_reap`], so a root whose exit a wait has seen stays a zombie that pins its number
//! (a process group's, a session's) until the handle ends.
//!
//! # States
//!
//! `N` (nobody is waiting), `W { token }` (one thread, the *holder*, runs the wait loop) and
//! `Exited(record)` (the exit was observed and the record is cached; the zombie is still this
//! process's). Only the holder looks with `try_observe` and waits on what the look returned, or
//! pauses for a recheck, with the lock released for both; every other waiter blocks on the
//! [`Condvar`] and re-dispatches on each wake. While `W` is held, only the holder looks.
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
    /// The exit was observed and the record is cached. The zombie is not consumed: it stays this
    /// process's, pinning the child's number, until the handle drops.
    Exited(ExitRecord),
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
    /// The child's exit record: this handle's wait saw it, now or earlier; the zombie stays until the
    /// handle drops.
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

    /// Take over the child `pidfd` names, whose pid is `pid` if known, asking `kernel`, which the box
    /// then owns. **Makes no call to it**, as [`new`](Self::new). The one constructor of a Linux box
    /// over a pidfd.
    #[cfg(target_os = "linux")]
    pub(crate) fn over_pidfd<K: crate::identity::Kernel + Send + 'static>(
        kernel: K,
        pid: Option<u32>,
        pidfd: std::os::fd::OwnedFd,
    ) -> OwnedChild {
        OwnedChild::new(Box::new(crate::os_process::linux::LinuxProcess::new(
            kernel, pid, pidfd,
        )))
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

    /// [`adopt`](Self::adopt) on macOS with the kernel `kernel(pid, unique)` makes, for a test whose
    /// rows name the child's pid and unique id; see
    /// [`adopt_std_over`](crate::os_process::child::adopt_std_over).
    #[cfg(all(test, target_os = "macos"))]
    #[allow(
        clippy::result_large_err,
        reason = "the child is handed back untouched for the caller to deal with"
    )]
    pub(crate) fn adopt_over<K: crate::identity::Kernel + Send + 'static>(
        kernel: impl FnOnce(u32, u64) -> K,
        child: std::process::Child,
        id: crate::identity::ProcessId,
    ) -> Result<OwnedChild, (Error, std::process::Child)> {
        crate::os_process::child::adopt_std_over(kernel, child, id).map(OwnedChild::new)
    }

    /// The child's pid, if its spawn learned it; see [`OsChild::pid`].
    pub(crate) fn pid(&self) -> Option<u32> {
        self.os.pid()
    }

    /// A number that names this child's OS handle object and no other's, for as long as the child is
    /// not moved out of its box: what a wait carried across an await is checked against.
    pub(crate) fn handle_id(&self) -> usize {
        std::ptr::from_ref::<dyn OsChild>(&*self.os).cast::<()>() as usize
    }

    /// The child as the process the OS names, to watch for its exit without reaping it.
    pub(crate) fn os_process(&self) -> &dyn crate::os_process::OsProcess {
        &*self.os
    }

    /// The kernel the child's box was built with, lent for a read the policy layer makes by the
    /// child's number; see [`OsChild::kernel`].
    pub(crate) fn kernel(&self) -> &dyn crate::identity::Kernel {
        self.os.kernel()
    }

    /// What a kill of the child may be refused for; see [`OsChild::kill_refusal`].
    pub(crate) fn kill_refusal(&self) -> crate::os_process::child::KillRefusal {
        self.os.kill_refusal()
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

    /// Whether this handle's own wait has recorded the exit, read under the lock. The zombie itself
    /// is consumed only when the handle drops.
    pub(crate) fn exit_seen(&self) -> bool {
        matches!(self.lock().state, State::Exited(_))
    }

    /// Whether the handle's end consumes the root's exit as it is now, which [`Drop`] decides by the
    /// same rule. Windows keeps no zombie to consume.
    pub(crate) fn consumes_at_drop(&self) -> bool {
        #[cfg(unix)]
        return self.drop_consumes(self.exit_seen());
        #[cfg(not(unix))]
        true
    }

    /// What a peek through the child's own handle shows (the exit record once this handle's wait
    /// has seen it), without reaping.
    pub(crate) fn peek(&self) -> Result<PeekOutcome, Error> {
        self.peek_locked(&self.lock())
    }

    /// Whether the child is running, answered from its exit edge (see
    /// [`OsProcess::exited`](crate::os_process::OsProcess::exited)), so a zombie only a tracer sees
    /// is `Dead`. The reap peek is read only where the edge is silent: an exit record or a reap
    /// elsewhere.
    ///
    /// An edge that fired and could not be confirmed (`exited` failed) is answered by the peek where
    /// the peek can: an exit record or a reap elsewhere is `Dead`; otherwise the failure stands,
    /// also when the peek reads the child running, which proves nothing (a tracer can hold the
    /// zombie, which the real parent's `waitid` does not see). A `Recheck` (the exit watch fired, and
    /// the process is not yet a zombie, or another process holds the running child) answers `Alive`
    /// until the zombie, as `ProcessId::is_alive` does, unless the peek shows the exit record.
    pub(crate) fn liveness(&self) -> Result<crate::identity::Liveness, Error> {
        use crate::identity::Liveness;
        use crate::os_process::Exit;
        match self.os.exited() {
            Ok(Exit::Exited) => return Ok(Liveness::Dead),
            Ok(Exit::Running(_) | Exit::Recheck) => {}
            Err(refused) => {
                return match self.peek() {
                    Ok(PeekOutcome::Exit(_) | PeekOutcome::Foreign(_)) => Ok(Liveness::Dead),
                    Ok(PeekOutcome::Running) => Err(refused),
                    Err(peek) => {
                        log::debug!(
                            "liveness: child {:?}: the exit confirmation was refused ({}), and the peek behind it failed too ({})",
                            self.pid(),
                            crate::error::Report(&refused),
                            crate::error::Report(&peek)
                        );
                        Err(refused)
                    }
                };
            }
        }
        Ok(match self.peek()? {
            PeekOutcome::Exit(_) | PeekOutcome::Foreign(_) => Liveness::Dead,
            PeekOutcome::Running => Liveness::Alive,
        })
    }

    /// Whether the root is still this handle's child to act on, from the handle's own evidence: always
    /// the OS's own answer. A root whose exit this handle saw is an unreaped zombie of ours, which
    /// reads `Unreaped` as any zombie does, and a reaper elsewhere that took it since reads as a
    /// foreign reap.
    ///
    /// A peek through the handle decides (Linux: the pidfd; macOS: the pid, checked against its
    /// unique id, with an unreadable id on a running child an error).
    #[cfg(unix)]
    pub(crate) fn state(&self) -> crate::signal::RootState {
        crate::signal::RootState::of_peek(self.os.peek().map_err(Error::into_io))
    }

    /// The drop's rule: it consumes where the consume names the child exactly, and otherwise only
    /// an exit this handle's wait saw (`seen`).
    #[cfg(unix)]
    fn drop_consumes(&self, seen: bool) -> bool {
        seen || self.os.exact_consume()
    }

    /// See [`OsChild::number_holder`].
    #[cfg(unix)]
    pub(crate) fn number_holder(&self, pid: u32) -> crate::identity::NumberRead {
        self.os.number_holder(pid)
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
            let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
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
    /// Send `sig` to the child: [`Sent::Gone`] once this handle has seen it exit (an exit is
    /// permanent, and a zombie acts on no signal), and otherwise what the OS says, with a refused
    /// send's bare errno. Under the lock, so the state read and the send are one step.
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        let lock = self.lock();
        if matches!(lock.state, State::Exited(_)) {
            return Ok(Sent::Gone);
        }
        self.os.signal(sig)
    }

    /// The exit record or the foreign verdict a peek sees, without reaping, under `lock`.
    fn peek_locked(&self, lock: &Guard<'_>) -> Result<PeekOutcome, Error> {
        match lock.state {
            State::Exited(record) => Ok(PeekOutcome::Exit(record)),
            State::N | State::W { .. } => self.os.peek(),
        }
    }

    /// Whether the child has exited by `deadline` (`None`: for ever), read through the OS's own look
    /// ([`OsProcess::exited`](crate::os_process::OsProcess::exited)): a zombie its tracer holds
    /// counts, and so does one launchd holds. On macOS, while another process is the parent the look
    /// reads the zombie itself and the wait re-looks with the driver's backoff (`MacosChild::exited`
    /// says why). A tracer that attaches during the wait wakes it, through the wait's own kqueue
    /// ([`OsProcess::exit_wait`](crate::os_process::OsProcess::exit_wait)).
    /// Reaps nothing: during a graceful tree shutdown the root stays an unreaped zombie until the
    /// group kill is done, so its pid names no one else. Takes no lock, so it may run
    /// while another thread waits.
    pub(crate) fn exited_by(&self, deadline: Option<Instant>) -> Result<bool, Error> {
        crate::os_process::drive::exited_until(&*self.os, deadline)
    }

    /// The root `pid` of a tree call, which reads this handle's evidence and sends through it.
    pub(crate) fn hold(&self, pid: u32) -> RootHandle<'_> {
        RootHandle { child: self, pid }
    }

    /// A contract breach: the drop's consume handed back a record that is not an exit. A look
    /// never yields one.
    #[cfg(unix)]
    fn log_unreadable(&self, record: ExitRecord) {
        if let ExitRecord::Unreadable { si_code } = record {
            log::warn!(
                "{:?}: a consuming waitid returned si_code {si_code}, not an exit record",
                self.os
            );
            // The drop calls this: an assert mid-unwind aborts, so `warn` reports.
            debug_assert!(
                std::thread::panicking(),
                "a consuming waitid on a zombie returned si_code {si_code}"
            );
        }
    }
}

/// The end of the handle is where the root is reaped, armed or not: one non-blocking consume,
/// where the consume names the child exactly ([`OsChild::exact_consume`]: Linux) in every state,
/// and by the child's number (macOS) only for an exit this handle's wait saw, since that consume is
/// a check and not a pin. A root still running is left, as a disarmed drop leaves it. On macOS the
/// zombie of a root whose exit no wait of this handle saw is left too, and an armed drop's
/// teardown has waited by then, so only a disarmed drop meets one. A handle that something forgot
/// (`mem::forget`) consumes nothing. See [`wait`](OwnedChild::wait) for what the zombie costs until here.
#[cfg(unix)]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        use crate::wait::exit_only::Reap;
        let seen = matches!(
            self.inner.get_mut().unwrap_or_else(PoisonError::into_inner).state,
            State::Exited(_)
        );
        if !self.drop_consumes(seen) {
            return;
        }
        match self.os.try_reap() {
            Ok(Reap::Reaped(record)) => self.log_unreadable(record),
            // Not exited, or a zombie only its tracer can reap: nothing to consume here.
            Ok(Reap::Running) => {}
            Ok(Reap::Foreign(foreign)) => {
                log::debug!(
                    "{:?}: nothing left to reap at the end of the handle ({foreign:?})",
                    self.os
                );
            }
            Err(error) => log::warn!(
                "{:?}: reaping at the end of the handle failed ({}); a zombie may be left",
                self.os,
                crate::error::Report(&error)
            ),
        }
    }
}

/// [`OwnedChild::hold`]: the root of a tree call, through its handle. On Unix a send by the root's
/// pid is checked against the handle's own [`state`](crate::containment::Root::state) right before
/// it; on Linux the root's pidfd names the group exactly, and on macOS there is none. On Windows
/// nothing is sent by the root's pid: the call sends the root its own signal through the handle.
pub(crate) struct RootHandle<'a> {
    child: &'a OwnedChild,
    pid: u32,
}

impl RootHandle<'_> {
    /// [`OwnedChild::signal`].
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        self.child.signal(sig)
    }

    /// [`OwnedChild::state`].
    #[cfg(unix)]
    pub(crate) fn state(&self) -> crate::signal::RootState {
        self.child.state()
    }
}

impl crate::containment::Root for RootHandle<'_> {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        RootHandle::signal(self, sig)
    }

    #[cfg(unix)]
    fn state(&self) -> crate::signal::RootState {
        RootHandle::state(self)
    }

    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.child.pidfd()
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
pub(crate) mod owned_tests;
