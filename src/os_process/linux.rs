//! Linux: an [`OsProcess`] over a verified pidfd. The pidfd names the process for good, so a pid
//! reused after [`open`](super::open) can be neither signalled nor mistaken for the original.

use std::os::fd::{AsFd, OwnedFd};

use super::child::{OsChild, OsHandle, PeekOutcome, TryReapOutcome};
use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
use crate::signal::{send_pidfd, Sent, Sig};
use crate::wait::exit_only::{self, Reap, Target};

pub(crate) mod open;

#[derive(Debug)]
pub(crate) struct LinuxProcess {
    pid: Option<u32>,
    pidfd: OwnedFd,
}

impl LinuxProcess {
    /// A process named by `pidfd`, which was opened while `pid` (if known) was provably it.
    pub(crate) fn new(pid: Option<u32>, pidfd: OwnedFd) -> Self {
        Self { pid, pidfd }
    }
}

impl OsProcess for LinuxProcess {
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        send_pidfd(self.pidfd.as_fd(), self.pid, sig).map_err(|e| Error::Io(std::io::Error::from(e)))
    }

    fn exited(&self) -> Result<Exit<'_>, Error> {
        if super::poll::is_readable(self.pidfd.as_fd()).map_err(Error::Io)? {
            Ok(Exit::Exited)
        } else {
            Ok(Exit::Running(WaitFor::Readable(self.pidfd.as_fd())))
        }
    }

    fn os_handle(&self) -> OsHandle<'_> {
        self.pidfd.as_fd()
    }
}

impl OsChild for LinuxProcess {
    fn pid(&self) -> Option<u32> {
        self.pid
    }

    fn peek(&self) -> Result<PeekOutcome, Error> {
        exit_only::linux::peek(&Target::PidFd(self.pidfd.as_fd())).map_err(Error::Io)
    }

    fn try_reap(&self) -> Result<TryReapOutcome<'_>, Error> {
        let pidfd = self.pidfd.as_fd();
        // Read before the reap, so an exit that lands between the two is not mistaken for a zombie a
        // tracer holds: a pidfd readable before a reap that finds no record is that zombie, and
        // `poll` on it would return at once for ever.
        let readable = super::poll::is_readable(pidfd).map_err(Error::Io)?;
        Ok(match exit_only::try_reap(&Target::PidFd(pidfd)).map_err(Error::Io)? {
            Reap::Reaped(record) => TryReapOutcome::Reaped(record),
            Reap::Foreign(foreign) => TryReapOutcome::Foreign(foreign),
            Reap::Running if readable => TryReapOutcome::Recheck,
            Reap::Running => TryReapOutcome::Running(WaitFor::Readable(pidfd)),
        })
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;
