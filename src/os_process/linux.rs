//! Linux: an [`OsProcess`] over a verified pidfd. The pidfd names the process for good, so a pid
//! reused after [`open`](super::open) can be neither signalled nor mistaken for the original.

use std::os::fd::{AsFd, OwnedFd};
use std::time::Instant;

use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::signal::{send_pidfd, Sent, Sig};

pub(crate) mod open;
pub(crate) use open::{open_verified, probe_pidfd_support, spawn_open_error};

#[derive(Debug)]
pub(crate) struct LinuxProcess {
    id: ProcessId,
    pidfd: OwnedFd,
}

impl LinuxProcess {
    pub(crate) fn new(id: ProcessId, pidfd: OwnedFd) -> Self {
        Self { id, pidfd }
    }
}

impl OsProcess for LinuxProcess {
    fn signal(&mut self, sig: Sig) -> Result<Sent, Error> {
        send_pidfd(self.pidfd.as_fd(), self.id.pid(), sig).map_err(|e| Error::Io(std::io::Error::from(e)))
    }

    fn exited(&mut self) -> Result<Exit<'_>, Error> {
        loop {
            let mut fds = [PollFd::new(&self.pidfd, PollFlags::IN)];
            match poll(&mut fds, Some(&Timespec { tv_sec: 0, tv_nsec: 0 })) {
                Ok(0) => return Ok(Exit::Running(WaitFor::Readable(self.pidfd.as_fd()))),
                Ok(_) => {
                    pidfd_readable(fds[0].revents()).map_err(Error::Io)?;
                    return Ok(Exit::Exited);
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(Error::Io(std::io::Error::from(e))),
            }
        }
    }
}

/// Polls `pidfd` until its process has exited (the pidfd is readable: a zombie, or reaped) or
/// `deadline` passes, and says which. `None`/`Some(None)` is unbounded. Reads no state and reaps
/// nothing: the pidfd names the process for good, so a reused pid cannot answer it.
pub(crate) fn poll_pidfd_exit(
    pidfd: std::os::fd::BorrowedFd<'_>,
    deadline: Option<Option<Instant>>,
) -> std::io::Result<bool> {
    let seen = crate::wait::rearm_until(deadline, |remaining| {
        // Capped like every timed block; the round is re-armed against the real deadline.
        let remaining = remaining.map(crate::wait::clamp_block);
        #[cfg(test)]
        crate::wait::block_probe::record(remaining);
        let ts = remaining.map(|d| Timespec {
            tv_sec: d.as_secs() as i64,
            tv_nsec: d.subsec_nanos() as _,
        });
        // A deadline wait never arms an unbounded poll.
        debug_assert!(
            matches!(deadline, None | Some(None)) || ts.is_some(),
            "a deadline wait armed an unbounded poll"
        );
        let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
        match poll(&mut fds, ts.as_ref()) {
            Ok(0) => Ok(None),
            Ok(_) => pidfd_readable(fds[0].revents()).map(Some),
            // A signal: go round again against the recomputed remaining time.
            Err(rustix::io::Errno::INTR) => Ok(None),
            Err(e) => Err(std::io::Error::from(e)),
        }
    })?;
    Ok(seen.is_some())
}

/// What a `poll` that reported events on a pidfd found: `Ok(())` for `POLLIN` (a zombie) or
/// `POLLHUP` (reaped), both an exit; `POLLERR` is an error.
pub(crate) fn pidfd_readable(revents: rustix::event::PollFlags) -> std::io::Result<()> {
    // POLLNVAL on an fd we own and hold alive is a contract violation.
    debug_assert!(
        !revents.contains(PollFlags::NVAL),
        "pidfd reported POLLNVAL: owned-fd contract violation"
    );
    if revents.contains(PollFlags::ERR) {
        return Err(std::io::Error::other("pidfd poll returned POLLERR"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;
