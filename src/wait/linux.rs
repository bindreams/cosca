//! Linux death-watch + kill via pidfd (kernel >= 5.3). `pidfd_open` returns a fd that
//! becomes readable (POLLIN) when the task becomes a zombie (exits); polling never reaps.
//! `pidfd_send_signal` is identity-bound (no pid-reuse race). `ENOSYS` on < 5.3 => Unsupported.

use std::time::Instant;

use rustix::event::{poll, PollFd, PollFlags};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};

use crate::error::Error;
use crate::identity::{Existence, ProcessId};

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
        // `pidfd_open` requires the pid number to resolve to a THREAD-GROUP LEADER task
        // (`pid_has_task(pid, PIDTYPE_TGID)`, v6.15 kernel/fork.c:2114); a pid number that
        // resolves to something else fails this even though it is not gone. Two concrete cases
        // (not exhaustive — e.g. a pid held only as a session ID, or reused as another
        // process's tid, land here too; `exists()` below tells all of them apart the same way):
        //   - A process-group leader that has exited and been REAPED, while another member
        //     of its group is still alive, keeps its number's `struct pid` alive as that
        //     group's PGID — resolvable, but with no thread-group-leader task attached.
        //     Before Linux 6.16 this is EINVAL; 6.16 (commit 8cf4b738) changes it to ESRCH,
        //     already handled above.
        //   - A LIVE thread that is not its process's thread-group leader (a non-leader tid)
        //     fails the same check for the opposite reason — the task exists but was never a
        //     leader. Before 6.16 this is ALSO EINVAL (indistinguishable from the reaped-
        //     leader case by errno alone); 6.16+ gives ENOENT.
        // One errno can mean either "gone" or "live", so re-verify identity instead of
        // guessing: `Gone` confirms the reaped-leader case (report exited, matching the SRCH
        // arm above). `Present` confirms a live, non-leader task — reporting that as exited
        // would be an early verdict, so this keeps an error, but not the bare errno: on 6.16+
        // that is a plain `NotFound` (from `ENOENT`) for a process that is very much still
        // running, which a caller treating `NotFound` as "gone" would misread as exited.
        // `live_non_leader_error` names the real cause instead. `Unknown` (the OS refused the
        // existence query) gets the same treatment as the post-open re-verify below — never
        // treated as "gone" either.
        Err(e @ (rustix::io::Errno::INVAL | rustix::io::Errno::NOENT)) => {
            return match id.exists() {
                Existence::Gone => Ok(None),
                Existence::Present => Err(live_non_leader_error(id, what, e)),
                Existence::Unknown => {
                    log::warn!("wait: pid {} identity could not be confirmed; {what}", id.pid());
                    Err(Error::Unassessable {
                        detail: format!("pid {} identity could not be confirmed; {what}", id.pid()),
                        source: None,
                    })
                }
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
    match id.exists() {
        Existence::Present => Ok(Some(pidfd)),
        Existence::Gone => Ok(None),
        Existence::Unknown => {
            // The decision site `read_stat`-s debug-level probe relies on.
            log::warn!("wait: pid {} identity could not be confirmed; {what}", id.pid());
            Err(Error::Unassessable {
                detail: format!("pid {} identity could not be confirmed; {what}", id.pid()),
                source: None,
            })
        }
    }
}

/// `id` resolves to a live task, but `pidfd_open` refused it: on Linux, that means it names a
/// thread that exists but is not its process's thread-group leader. `source` is folded into the
/// message (not just `#[source]`'d) so the cause survives even where a caller only prints the
/// error, not its chain: the bare errno alone reads as a plain "not found" — `source` is
/// `NotFound` on 6.16+ (`ENOENT`) for a process that is very much still running — which a
/// caller treating `NotFound` as "gone" would misread as exited.
fn live_non_leader_error(id: ProcessId, what: &'static str, source: rustix::io::Errno) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "pid {} names a live thread, not a thread-group leader; {what} (pidfd_open: {source})",
            id.pid()
        ),
    ))
}

/// `pidfd_open`, seamed for tests: a forced errno (armed via
/// [`fault::force_pidfd_open_errno_once`]) stands in for the real syscall exactly once, so a
/// test can drive `open_verified`'s `EINVAL`/`ENOENT` arm deterministically regardless of which
/// errno the host kernel actually produces for a given scenario (see `linux_tests.rs`'s module
/// doc for why the real-syscall path alone cannot exercise it on a >= 6.16 kernel). Compiles to
/// a direct call in a non-test build — no seam, no overhead.
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

#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    thread_local! {
        static FORCE_PIDFD_OPEN_ERRNO: Cell<Option<rustix::io::Errno>> = const { Cell::new(None) };
    }

    /// Disarms the forced errno on drop, even if it was never consumed — so a test that panics
    /// before its own `pidfd_open_checked` call (or whose code path never reaches one at all)
    /// cannot leave a forced errno armed for whatever test runs next on this thread.
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
