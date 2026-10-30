//! Linux: an [`OsProcess`] over a verified pidfd. The pidfd names the process for good, so a pid
//! reused after [`open`](super::open) can be neither signalled nor mistaken for the original.

use std::os::fd::{AsFd, OwnedFd};

use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::{Exit, OsHandle, OsProcess, WaitFor};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::signal::{via_pidfd, Sent, Sig};

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
    fn identity(&self) -> ProcessId {
        self.id
    }

    fn signal(&mut self, sig: Sig) -> Result<Sent, Error> {
        via_pidfd(Some(self.pidfd.as_fd()), self.id.pid(), sig).map_err(Error::Io)
    }

    fn exited(&mut self) -> Result<Exit<'_>, Error> {
        loop {
            let mut fds = [PollFd::new(&self.pidfd, PollFlags::IN)];
            match poll(&mut fds, Some(&Timespec { tv_sec: 0, tv_nsec: 0 })) {
                Ok(0) => return Ok(Exit::Running(WaitFor::Readable(self.pidfd.as_fd()))),
                Ok(_) => {
                    crate::wait::pidfd_readable(fds[0].revents()).map_err(Error::Io)?;
                    return Ok(Exit::Exited);
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(Error::Io(std::io::Error::from(e))),
            }
        }
    }

    fn os_handle(&self) -> Option<OsHandle<'_>> {
        Some(self.pidfd.as_fd())
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;
