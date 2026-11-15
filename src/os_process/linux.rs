//! Linux: an [`OsProcess`] over a verified pidfd. The pidfd names the process for good, so a pid
//! reused after [`open`](super::open) can be neither signalled nor mistaken for the original.

use std::os::fd::{AsFd, OwnedFd};

use super::child::{KillRefusal, OsChild, OsHandle, PeekOutcome, TryReapOutcome};
use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
use crate::identity::Kernel;
use crate::signal::{send_pidfd, Sent, Sig};
use crate::wait::exit_only::{self, Reap, Target};

pub(crate) mod fork;
pub(crate) mod open;

/// A process named by a pidfd. It owns the [`Kernel`] it was built with, which a read of the process by
/// its number asks (see [`OsChild::kernel`]).
pub(crate) struct LinuxProcess<K> {
    kernel: K,
    pid: Option<u32>,
    pidfd: OwnedFd,
}

impl<K> std::fmt::Debug for LinuxProcess<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxProcess")
            .field("pid", &self.pid)
            .field("pidfd", &self.pidfd)
            .finish_non_exhaustive()
    }
}

impl<K: Kernel + Send> LinuxProcess<K> {
    /// A process named by `pidfd`, which was opened while `pid` (if known) was provably it, asking
    /// `kernel`, which the process then owns.
    pub(crate) fn new(kernel: K, pid: Option<u32>, pidfd: OwnedFd) -> Self {
        Self { kernel, pid, pidfd }
    }
}

impl<K: Kernel + Send> OsProcess for LinuxProcess<K> {
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        let sent = send_pidfd(self.pidfd.as_fd(), self.pid, sig);
        // After the syscall, whatever it answered, as macOS's `send_with_token` records.
        #[cfg(test)]
        crate::send_log::record_by_identity(self.pid.unwrap_or(0), sig.as_libc());
        sent.map_err(|e| Error::Io(std::io::Error::from(e)))
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

impl<K: Kernel + Send> OsChild for LinuxProcess<K> {
    fn pid(&self) -> Option<u32> {
        self.pid
    }

    fn kernel(&self) -> &dyn Kernel {
        &self.kernel
    }

    /// `pidfd_send_signal` is refused only with `EPERM`.
    fn kill_refusal(&self) -> KillRefusal {
        KillRefusal::Permission
    }

    fn peek(&self) -> Result<PeekOutcome, Error> {
        #[cfg(test)]
        if let Some(forced) = exit_only::seams::take_forced_peek() {
            return forced.map_err(Error::Io);
        }
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
