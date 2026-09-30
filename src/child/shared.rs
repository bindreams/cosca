//! cosca's own shared child handle: concurrent `wait`, `try_wait`, `wait_deadline` and `kill` on
//! one spawned child, from any number of threads.
//!
//! **The handle never reaps at adoption, and never blocks in a reap.** Every reap is taken under
//! the handle's lock and never blocks: a non-blocking `waitid`, only of an exit record, on the
//! pidfd (Linux) or the pid (macOS); on Windows there is nothing to consume, and the reap reads
//! the signalled process handle's exit code (see [`crate::wait::exit_only`]). A child that this
//! process traces is therefore never taken for exited when it merely stops.
//!
//! # States
//!
//! `N` (nobody is waiting), `W { token }` (one thread, the *holder*, is blocked in the unlocked
//! wait) and `E(reaped)` (the status is cached, the child is reaped). Only the holder runs the
//! unlocked wait; every other waiter blocks on the [`Condvar`] and re-dispatches on each wake.
//! While `W` is held, only the holder reaps.
//!
//! - Every lock is taken poison-tolerantly (`lock().unwrap_or_else(PoisonError::into_inner)`),
//!   `Condvar` results included. `Debug` alone uses `try_lock`.
//! - Every state write calls `notify_all` ([`Inner::set`], then [`SharedChild::notify`]).
//! - The holder is armed by a [`HolderGuard`] whose `Drop` restores `N` (and wakes the waiters)
//!   only if the state is still its own `W`: an `Err`, a `?` or a panic can never strand the
//!   waiters, and a normal return can never restore `N` under a new holder, because
//!   [`HolderGuard::finish`] consumes the guard.
//! - A holder re-reads the state after it re-locks, before it acts on the wait's result.
//! - Every timed block is clamped and looped ([`crate::wait::clamp_block`]; on macOS the
//!   `kevent` timeout's own cap), and after every wake `crate::wait::now() >= deadline` decides
//!   expiry, never the primitive's own "timed out".
//!
//! `pidfd: None` (Linux), and an identity read that said `ESRCH` at adoption (macOS), mean the child
//! was already reaped elsewhere when it was adopted: every wait answers `ECHILD`, and `kill` is
//! success.

use std::fmt;
use std::io;
use std::process::ExitStatus;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use std::time::Instant;

use crate::error::Error;
use crate::identity::ProcessId;
use crate::wait::exit_only::{self, Peek, Reap, Reaped, Target};

#[path = "shared/holder.rs"]
mod holder;
#[path = "shared/unlocked.rs"]
mod unlocked;

#[cfg(test)]
#[path = "shared/seams.rs"]
pub(crate) mod seams;

/// What the handle knows about the child's exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Nobody is waiting.
    N,
    /// The thread that drew `token` is the holder, blocked in the unlocked wait.
    W { token: u64 },
    /// Reaped: the outcome is cached.
    E(Reaped),
}

struct Inner {
    /// Kept alive for its stdio; also the signal path on Windows.
    #[cfg_attr(
        unix,
        allow(dead_code, reason = "Unix signals through the pidfd or the verified pid")
    )]
    child: std::process::Child,
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
    /// Write `state`. The caller wakes the waiters with [`SharedChild::notify`] in the same
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

/// A spawned child that several threads may wait on and kill at once.
pub(crate) struct SharedChild {
    /// Outside the mutex: `id()` never locks.
    id: ProcessId,
    /// Outside the mutex: the holder polls it unlocked. `None` only when the child was already
    /// reaped elsewhere at adoption.
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::OwnedFd>,
    /// The child's unique id, the one identity every by-pid check on macOS uses (see
    /// [`crate::signal::Identity`]).
    #[cfg(target_os = "macos")]
    identity: crate::signal::Identity,
    /// A duplicate of the std `Child`'s process handle, usable unlocked.
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
    inner: Mutex<Inner>,
    condvar: Condvar,
    /// The thread that holds `inner`, for [`SharedChild::lock`]'s self-deadlock check.
    #[cfg(test)]
    owner: Mutex<Option<std::thread::ThreadId>>,
}

// Construction =====

impl SharedChild {
    /// Take over `child`, whose identity `id` the spawn has just read. **Never reaps**: an
    /// already-exited child is still a zombie afterwards.
    ///
    /// Linux opens the pidfd by number and confirms it names our child. A failure is
    /// `Err((error, child))`, with the child handed back untouched for the caller to tear down.
    #[allow(
        clippy::result_large_err,
        reason = "the child is handed back untouched for the caller to tear down"
    )]
    pub(crate) fn adopt(
        child: std::process::Child,
        id: ProcessId,
    ) -> Result<SharedChild, (Error, std::process::Child)> {
        debug_assert_eq!(child.id(), id.pid(), "the identity must be the child's");
        #[cfg(target_os = "linux")]
        let pidfd = match crate::wait::backend::open_own_child(id.pid(), Some(id)) {
            Ok(pidfd) => pidfd,
            Err(e) => return Err((e, child)),
        };
        #[cfg(target_os = "macos")]
        let identity = match crate::signal::Identity::read(id.pid()) {
            crate::signal::Identity::Unreadable(errno) if errno < 0 => {
                return Err((
                    Error::Unassessable {
                        detail: format!(
                            "pid {}: its identity could not be read (errno {errno}); the child was not adopted",
                            id.pid()
                        ),
                        source: Some(io::Error::from_raw_os_error(errno)),
                    },
                    child,
                ));
            }
            identity => identity,
        };
        #[cfg(windows)]
        let handle = match Self::duplicate_handle(&child) {
            Ok(handle) => handle,
            Err(e) => return Err((Error::Io(e), child)),
        };
        Ok(SharedChild {
            id,
            #[cfg(target_os = "linux")]
            pidfd,
            #[cfg(target_os = "macos")]
            identity,
            #[cfg(windows)]
            handle,
            inner: Mutex::new(Inner {
                child,
                state: State::N,
                next_token: 0,
                #[cfg(test)]
                log: Vec::new(),
            }),
            condvar: Condvar::new(),
            #[cfg(test)]
            owner: Mutex::new(None),
        })
    }

    #[cfg(windows)]
    fn duplicate_handle(child: &std::process::Child) -> io::Result<std::os::windows::io::OwnedHandle> {
        use std::os::windows::io::AsHandle;
        #[cfg(test)]
        if seams::take_forced_duplicate_handle_error() {
            return Err(io::Error::from_raw_os_error(
                windows::Win32::Foundation::ERROR_ACCESS_DENIED.0 as i32,
            ));
        }
        child.as_handle().try_clone_to_owned()
    }

    /// The child's process id.
    pub(crate) fn id(&self) -> u32 {
        self.id.pid()
    }

    fn lock(&self) -> Guard<'_> {
        #[cfg(test)]
        {
            let me = std::thread::current().id();
            let owner = self.owner.lock().unwrap_or_else(PoisonError::into_inner);
            assert_ne!(
                *owner,
                Some(me),
                "self-deadlock: this thread locked a SharedChild it already holds"
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

    /// The handle that names the child, or `None` when it was reaped elsewhere before adoption.
    fn target(&self) -> Option<Target<'_>> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            self.pidfd.as_ref().map(|fd| Target::PidFd(fd.as_fd()))
        }
        #[cfg(target_os = "macos")]
        {
            // Gone at adoption: reaped elsewhere, so nothing is consumed by a bare pid.
            Some(Target::pid(self.id.pid(), self.identity.unique()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle;
            Some(Target::Handle(self.handle.as_handle()))
        }
    }
}

// Outcomes =====

/// The `ECHILD` every method answers when the child was reaped by someone else.
fn echild() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ECHILD)
    }
    #[cfg(windows)]
    {
        io::Error::other("the child was already reaped elsewhere")
    }
}

/// The status a cached outcome answers.
fn status_of(reaped: Reaped) -> io::Result<ExitStatus> {
    match reaped {
        Reaped::Status(status) => Ok(status),
        Reaped::Unreadable { si_code } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the child's exit record was unreadable (si_code {si_code})"),
        )),
    }
}

// The methods =====

impl SharedChild {
    /// Block until the child exits, and reap it.
    pub(crate) fn wait(&self) -> io::Result<ExitStatus> {
        match self.wait_inner(None)? {
            Some(status) => Ok(status),
            None => {
                debug_assert!(false, "an unbounded wait ended with no exit");
                Err(io::Error::other("an unbounded wait ended with no exit"))
            }
        }
    }

    /// The exit status if the child has exited, else `None`. Never blocks, and never reaps a
    /// child that another thread is waiting on: that thread reaps it.
    pub(crate) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        let mut lock = self.lock();
        if let State::E(reaped) = lock.state {
            return status_of(reaped).map(Some);
        }
        let Some(target) = self.target() else {
            return Err(echild());
        };
        match lock.state {
            State::E(_) => unreachable!("handled above"),
            // Another thread holds `W`, so only it reaps: report what a peek sees.
            State::W { .. } => self.peeked_status(&target),
            State::N => match exit_only::try_reap(&target)? {
                Reap::Reaped(reaped) => {
                    lock.set(State::E(reaped));
                    self.notify(&mut lock);
                    drop(lock);
                    self.log_unreadable(reaped);
                    status_of(reaped).map(Some)
                }
                Reap::Running => Ok(None),
                Reap::Foreign(_) => Err(echild()),
            },
        }
    }

    /// Block until the child exits or `deadline` passes (`Ok(None)` at expiry, after one final
    /// look). Never returns `None` before `crate::wait::now()` reaches `deadline`.
    pub(crate) fn wait_deadline(&self, deadline: Instant) -> io::Result<Option<ExitStatus>> {
        self.wait_inner(Some(deadline))
    }

    /// Hard-kill the child. Already-exited, reaped by us, or reaped elsewhere is success, logged
    /// at `debug` where nothing was sent.
    ///
    /// - **Linux:** through the pidfd. No pidfd (the child was gone when adopted) sends nothing.
    /// - **macOS:** by pid, only while the pid's unique id is still the child's, under the lock:
    ///   no reap of ours can run between the state read and the call.
    /// - **Windows:** through the process handle.
    pub(crate) fn kill(&self) -> io::Result<()> {
        let lock = self.lock();
        if matches!(lock.state, State::E(_)) {
            return Ok(());
        }
        #[cfg(test)]
        exit_only::seams::signal_sent();
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            crate::signal::via_pidfd(
                self.pidfd.as_ref().map(AsFd::as_fd),
                self.id(),
                crate::signal::Sig::Kill,
            )
            .map(drop)
        }
        #[cfg(target_os = "macos")]
        {
            crate::signal::via_verified_pid(self.id(), self.identity, crate::signal::Sig::Kill).map(drop)
        }
        #[cfg(windows)]
        {
            let mut lock = lock;
            lock.child.kill()
        }
    }

    /// A contract breach after the `E` write: a consuming reap handed back a record that is not
    /// an exit. The state is already `E`, so this must run with the lock released.
    fn log_unreadable(&self, reaped: Reaped) {
        if let Reaped::Unreadable { si_code } = reaped {
            log::warn!(
                "pid {}: a consuming waitid returned si_code {si_code}, not an exit record",
                self.id()
            );
            debug_assert!(false, "a consuming waitid on a zombie returned si_code {si_code}");
        }
    }

    /// The status a peek saw, without reaping.
    fn peeked_status(&self, target: &Target<'_>) -> io::Result<Option<ExitStatus>> {
        match exit_only::peek(target)? {
            Peek::Running => Ok(None),
            Peek::Exit(reaped) => status_of(reaped).map(Some),
            Peek::Foreign(_) => Err(echild()),
        }
    }
}

// Debug =====

impl fmt::Debug for SharedChild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("SharedChild");
        d.field("pid", &self.id.pid());
        // `try_lock`, never `lock`: formatting must not block behind a waiter.
        match self.inner.try_lock() {
            Ok(inner) => d.field("state", &inner.state),
            Err(std::sync::TryLockError::Poisoned(e)) => d.field("state", &e.into_inner().state),
            Err(std::sync::TryLockError::WouldBlock) => d.field("state", &format_args!("locked")),
        };
        d.finish_non_exhaustive()
    }
}

#[path = "shared/waiting.rs"]
mod waiting;

#[cfg(test)]
#[path = "shared_tests.rs"]
mod shared_tests;
