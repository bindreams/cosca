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
    let pidfd = match pidfd_open(raw, PidfdFlags::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::SRCH) => return Ok(None),
        // `pidfd_open` requires the pid number to resolve to a THREAD-GROUP LEADER task
        // (`pid_has_task(pid, PIDTYPE_TGID)`, v6.15 kernel/fork.c:2114); a pid number that is
        // live but not a leader fails this even though the process it names is not gone:
        //   - A process-group leader that has exited and been REAPED, while another member
        //     of its group is still alive, keeps its number's `struct pid` alive as that
        //     group's PGID — resolvable, but with no TGID task attached. Before Linux 6.16
        //     this is EINVAL; 6.16 (commit 8cf4b738) changes it to ESRCH, already handled
        //     above.
        //   - A LIVE thread that is not its process's group leader (a non-leader tid) fails
        //     the same check for the opposite reason — the task exists but was never a
        //     leader. Before 6.16 this is ALSO EINVAL (indistinguishable from the reaped-
        //     leader case by errno alone); 6.16+ gives ENOENT.
        // Since one errno can mean either "gone" or "live", re-verify identity instead of
        // guessing: `Gone` confirms the reaped-leader case (report exited, matching the SRCH
        // arm above); `Present`/`Unknown` means the pid still names a live, non-leader task,
        // and reporting that as exited would be an early verdict — keep the original error.
        Err(e @ (rustix::io::Errno::INVAL | rustix::io::Errno::NOENT)) => {
            return match id.exists() {
                Existence::Gone => Ok(None),
                Existence::Present | Existence::Unknown => Err(Error::Io(std::io::Error::from(e))),
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
