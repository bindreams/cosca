//! Linux death-watch + kill via pidfd (kernel >= 5.3). `pidfd_open` returns a fd that
//! becomes readable (POLLIN) when the task becomes a zombie (exits); polling never reaps.
//! `pidfd_send_signal` is identity-bound (no pid-reuse race). `ENOSYS` on < 5.3 => Unsupported.

use std::time::Instant;

use rustix::event::{poll, PollFd, PollFlags};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};

use crate::error::Error;
use crate::identity::{Existence, Liveness, ProcessId};

/// Open a pidfd for `id`, re-verifying identity. `Ok(None)` => already gone (treat as exited).
pub(crate) fn open_verified(id: ProcessId, what: &'static str) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; pidfd cast would truncate",
        id.pid()
    );
    let raw = Pid::from_raw(id.pid() as i32).expect("a resolvable ProcessId is never pid 0");
    let pidfd = match pidfd_open_checked(raw) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::SRCH) => return Ok(None),
        // pidfd_open needs a pid that resolves to a thread-group leader task. EINVAL (< 6.16) /
        // ENOENT (>= 6.16) means either a reaped process-group leader whose pid lives on as a PGID
        // (gone), or a non-leader tid: live, or a ptraced zombie thread kept until its tracer
        // waits. Errno alone can't tell, so re-verify via exists() and is_alive(). Unknown is
        // never treated as gone.
        Err(e @ (rustix::io::Errno::INVAL | rustix::io::Errno::NOENT)) => {
            return match exists_checked(id) {
                Existence::Gone => Ok(None),
                Existence::Present => match alive_checked(id) {
                    Liveness::Dead => Ok(None),
                    Liveness::Alive => Err(Error::NotThreadGroupLeader {
                        pid: id.pid(),
                        detail: what.into(),
                        source: std::io::Error::from(e),
                    }),
                    Liveness::Unknown => Err(identity_unassessable(id, what, Some(e))),
                },
                Existence::Unknown => Err(identity_unassessable(id, what, Some(e))),
            };
        }
        Err(rustix::io::Errno::NOSYS) => {
            return Err(Error::Unsupported {
                op: "foreign process wait/kill".into(),
                platform: "linux",
                detail: "pidfd_open requires Linux kernel >= 5.3".into(),
            });
        }
        Err(e) => return Err(Error::Io(std::io::Error::from(e))),
    };
    // Re-verify: a pid recycled before open means the original is already gone. An
    // unassessable pid (hidepid, EPERM) is NOT gone and must not be treated as one.
    match exists_checked(id) {
        Existence::Present => Ok(Some(pidfd)),
        Existence::Gone => Ok(None),
        Existence::Unknown => Err(identity_unassessable(id, what, None)),
    }
}

/// `id`'s existence or liveness could not be established: logs at `warn` and builds the
/// `Unassessable` error. Never treated as gone. `errno` is the `pidfd_open` failure that made the
/// query necessary, if any.
fn identity_unassessable(id: ProcessId, what: &'static str, errno: Option<rustix::io::Errno>) -> Error {
    let cause = errno.map_or(String::new(), |e| format!(" (pidfd_open: {e})"));
    log::warn!("wait: pid {} identity could not be confirmed{cause}; {what}", id.pid());
    Error::Unassessable {
        detail: format!("pid {} identity could not be confirmed{cause}; {what}", id.pid()),
        source: errno.map(std::io::Error::from),
    }
}

/// `pidfd_open`, with a test seam: a forced errno (see [`fault::force_pidfd_open_errno_once`])
/// replaces the syscall once.
#[cfg(test)]
fn pidfd_open_checked(raw: Pid) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    match fault::take_forced_pidfd_open_errno() {
        Some(errno) => Err(errno),
        None => pidfd_open(raw, PidfdFlags::empty()),
    }
}
#[cfg(not(test))]
fn pidfd_open_checked(raw: Pid) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    pidfd_open(raw, PidfdFlags::empty())
}

/// `id.exists()`, with a test seam: a forced [`Existence`] (see [`fault::force_exists_once`])
/// replaces the `/proc` read once, to drive the `Unknown` arms.
#[cfg(test)]
fn exists_checked(id: ProcessId) -> Existence {
    match fault::take_forced_exists() {
        Some(existence) => existence,
        None => id.exists(),
    }
}
#[cfg(not(test))]
fn exists_checked(id: ProcessId) -> Existence {
    id.exists()
}

/// `id.is_alive()`, with a test seam: a forced [`Liveness`] (see [`fault::force_alive_once`])
/// replaces the `/proc` read once.
#[cfg(test)]
fn alive_checked(id: ProcessId) -> Liveness {
    match fault::take_forced_alive() {
        Some(liveness) => liveness,
        None => id.is_alive(),
    }
}
#[cfg(not(test))]
fn alive_checked(id: ProcessId) -> Liveness {
    id.is_alive()
}

#[cfg(test)]
pub(crate) mod fault {
    use crate::identity::{Existence, Liveness};
    use std::cell::Cell;
    thread_local! {
        static FORCE_PIDFD_OPEN_ERRNO: Cell<Option<rustix::io::Errno>> = const { Cell::new(None) };
        static FORCE_EXISTS: Cell<Option<Existence>> = const { Cell::new(None) };
        static FORCE_ALIVE: Cell<Option<Liveness>> = const { Cell::new(None) };
    }

    /// Disarms the forced errno on drop, so an unconsumed force can't leak into the next test on
    /// this thread.
    #[must_use = "dropping this immediately disarms the forced errno; bind it for the probe's duration"]
    pub(crate) struct ForcedPidfdOpenErrno(());

    /// Force the NEXT `pidfd_open` inside `open_verified` on THIS thread to fail with `errno`,
    /// consumed the first time it's read.
    pub(crate) fn force_pidfd_open_errno_once(errno: rustix::io::Errno) -> ForcedPidfdOpenErrno {
        FORCE_PIDFD_OPEN_ERRNO.with(|f| f.set(Some(errno)));
        ForcedPidfdOpenErrno(())
    }

    impl Drop for ForcedPidfdOpenErrno {
        fn drop(&mut self) {
            FORCE_PIDFD_OPEN_ERRNO.with(|f| f.set(None));
        }
    }

    pub(crate) fn take_forced_pidfd_open_errno() -> Option<rustix::io::Errno> {
        FORCE_PIDFD_OPEN_ERRNO.with(|f| f.take())
    }

    /// Disarms the forced `Existence` on drop; see [`ForcedPidfdOpenErrno`].
    #[must_use = "dropping this immediately disarms the forced existence; bind it for the probe's duration"]
    pub(crate) struct ForcedExists(());

    /// Force the NEXT `id.exists()` re-verify inside `open_verified` on THIS thread to answer
    /// `existence`, consumed the first time it's read.
    pub(crate) fn force_exists_once(existence: Existence) -> ForcedExists {
        FORCE_EXISTS.with(|f| f.set(Some(existence)));
        ForcedExists(())
    }

    impl Drop for ForcedExists {
        fn drop(&mut self) {
            FORCE_EXISTS.with(|f| f.set(None));
        }
    }

    pub(crate) fn take_forced_exists() -> Option<Existence> {
        FORCE_EXISTS.with(|f| f.take())
    }

    /// Disarms the forced `Liveness` on drop; see [`ForcedPidfdOpenErrno`].
    #[must_use = "dropping this immediately disarms the forced liveness; bind it for the probe's duration"]
    pub(crate) struct ForcedAlive(());

    /// Force the NEXT `id.is_alive()` inside `open_verified` on THIS thread to answer `liveness`,
    /// consumed the first time it's read.
    pub(crate) fn force_alive_once(liveness: Liveness) -> ForcedAlive {
        FORCE_ALIVE.with(|f| f.set(Some(liveness)));
        ForcedAlive(())
    }

    impl Drop for ForcedAlive {
        fn drop(&mut self) {
            FORCE_ALIVE.with(|f| f.set(None));
        }
    }

    pub(crate) fn take_forced_alive() -> Option<Liveness> {
        FORCE_ALIVE.with(|f| f.take())
    }
}

pub(crate) fn block_until_exit(id: ProcessId, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
    let Some(pidfd) = open_verified(id, "its exit cannot be observed")? else {
        return Ok(true);
    };
    loop {
        let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
        // rustix 1.x poll takes Option<&Timespec> (None = infinite); Timespec is
        // { tv_sec: i64, tv_nsec: Nsecs }. Build it from the remaining duration.
        let ts = crate::wait::remaining(deadline).map(|d| rustix::event::Timespec {
            tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: d.subsec_nanos() as _,
        });
        match poll(&mut fds, ts.as_ref()) {
            Ok(0) => return Ok(false), // timed out, still alive
            Ok(_) => {
                let revents = fds[0].revents();
                // POLLNVAL on an fd we own and hold alive is a contract violation.
                debug_assert!(
                    !revents.contains(PollFlags::NVAL),
                    "pidfd reported POLLNVAL — owned-fd contract violation"
                );
                if revents.contains(PollFlags::ERR) {
                    return Err(Error::Io(std::io::Error::other("pidfd poll returned POLLERR")));
                }
                return Ok(true); // POLLIN (zombie) / POLLHUP (reaped) => exited
            }
            Err(rustix::io::Errno::INTR) => continue, // retry only on EINTR (no cap)
            Err(e) => return Err(Error::Io(std::io::Error::from(e))),
        }
    }
}

pub(crate) fn kill(id: ProcessId) -> Result<(), Error> {
    let Some(pidfd) = open_verified(id, "no signal was sent")? else {
        return Ok(());
    };
    match pidfd_send_signal(&pidfd, Signal::KILL) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::SRCH) => Ok(()), // exited between re-verify and signal
        Err(e) => Err(Error::Io(std::io::Error::from(e))),
    }
}

pub(crate) fn terminate(id: ProcessId) -> Result<(), Error> {
    let Some(pidfd) = open_verified(id, "no signal was sent")? else {
        return Ok(());
    };
    match pidfd_send_signal(&pidfd, Signal::TERM) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::SRCH) => Ok(()), // exited between re-verify and signal
        Err(e) => Err(Error::Io(std::io::Error::from(e))),
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;
