//! Linux death-watch + kill via pidfd (kernel >= 5.3). `pidfd_open` returns a fd that
//! becomes readable (POLLIN) when the task becomes a zombie (exits); polling never reaps.
//! `pidfd_send_signal` is identity-bound (no pid-reuse race). `ENOSYS` on < 5.3 => Unsupported.

use std::time::Instant;

use rustix::event::{poll, PollFd, PollFlags};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};

use crate::error::Error;
use crate::identity::ProcessId;

/// Open a pidfd for `id`, re-verifying identity. `Ok(None)` => already gone (treat as exited).
fn open_verified(id: ProcessId) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; pidfd cast would truncate",
        id.pid()
    );
    let raw = Pid::from_raw(id.pid() as i32).expect("a resolvable ProcessId is never pid 0");
    let pidfd = match pidfd_open(raw, PidfdFlags::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::SRCH) => return Ok(None),
        Err(rustix::io::Errno::NOSYS) => {
            return Err(Error::Unsupported {
                op: "foreign process wait/kill".into(),
                platform: "linux",
                detail: "pidfd_open requires Linux kernel >= 5.3".into(),
            });
        }
        Err(e) => return Err(Error::Io(std::io::Error::from(e))),
    };
    // Re-verify: a pid recycled before open means the original is already gone.
    if !id.exists() {
        return Ok(None);
    }
    Ok(Some(pidfd))
}

pub(crate) fn block_until_exit(id: ProcessId, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
    let Some(pidfd) = open_verified(id)? else {
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
    let Some(pidfd) = open_verified(id)? else { return Ok(()) };
    match pidfd_send_signal(&pidfd, Signal::KILL) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::SRCH) => Ok(()), // exited between re-verify and signal
        Err(e) => Err(Error::Io(std::io::Error::from(e))),
    }
}
