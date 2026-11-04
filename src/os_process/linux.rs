//! Linux: an [`OsProcess`] over a verified pidfd. The pidfd names the process for good, so a pid
//! reused after [`open`](super::open) can be neither signalled nor mistaken for the original.

use std::os::fd::{AsFd, OwnedFd};

use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::signal::{send_pidfd, Sent, Sig};

pub(crate) mod open;

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
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        send_pidfd(self.pidfd.as_fd(), self.id.pid(), sig).map_err(|e| Error::Io(std::io::Error::from(e)))
    }

    fn exited(&self) -> Result<Exit<'_>, Error> {
        if super::poll::is_readable(self.pidfd.as_fd()).map_err(Error::Io)? {
            Ok(Exit::Exited)
        } else {
            Ok(Exit::Running(WaitFor::Readable(self.pidfd.as_fd())))
        }
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;
