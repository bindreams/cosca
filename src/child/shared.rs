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
//! - Every state write calls `notify_all`.
//! - The holder is armed by a [`HolderGuard`] whose `Drop` restores `N` (and wakes the waiters)
//!   only if the state is still its own `W`: an `Err`, a `?` or a panic can never strand the
//!   waiters, and a normal return can never restore `N` under a new holder, because
//!   [`HolderGuard::finish`] consumes the guard.
//! - A holder re-reads the state after it re-locks, before it acts on the wait's result.
//! - Every timed block is clamped and looped ([`crate::wait::clamp_block`]; on macOS the
//!   `kevent` timeout's own cap), and after every wake `crate::wait::now() >= deadline` decides
//!   expiry, never the primitive's own "timed out".
//!
//! `pidfd: None` (Linux) means the child was already reaped elsewhere when it was adopted: every
//! wait answers `ECHILD`, and `kill` is success.

use std::fmt;
use std::io;
use std::process::ExitStatus;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
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
}

/// A spawned child that several threads may wait on and kill at once.
pub(crate) struct SharedChild {
    /// Outside the mutex: `id()` never locks.
    id: ProcessId,
    /// Outside the mutex: the holder polls it unlocked. `None` only when the child was already
    /// reaped elsewhere at adoption.
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::OwnedFd>,
    /// A duplicate of the std `Child`'s process handle, usable unlocked.
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
    inner: Mutex<Inner>,
    condvar: Condvar,
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
        #[cfg(windows)]
        let handle = match Self::duplicate_handle(&child) {
            Ok(handle) => handle,
            Err(e) => return Err((Error::Io(e), child)),
        };
        Ok(SharedChild {
            id,
            #[cfg(target_os = "linux")]
            pidfd,
            #[cfg(windows)]
            handle,
            inner: Mutex::new(Inner {
                child,
                state: State::N,
                next_token: 0,
            }),
            condvar: Condvar::new(),
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

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The child's start time, which tells it from a process that later reuses its pid.
    #[cfg(target_os = "macos")]
    fn start(&self) -> crate::identity::StartToken {
        crate::identity::StartToken::from_raw(self.id.start_token_raw())
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
            Some(Target::pid(self.id.pid(), Some(self.start())))
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
                    lock.state = State::E(reaped);
                    self.condvar.notify_all();
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
    /// - **macOS:** by pid, only while the pid's start time is still the child's, under the lock:
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
            crate::signal::via_verified_pid(self.id(), self.start(), crate::signal::Sig::Kill).map(drop)
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
