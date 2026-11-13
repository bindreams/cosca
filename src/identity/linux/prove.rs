//! Opening a pid and proving that the pidfd is the process a `Pidfs` id names.
//!
//! The inode of a pidfd is one per process and is never reissued, so a pidfd opened by pid whose inode
//! is the id's is that process, and a pid that opens to another inode has been reused. The proof needs
//! no `/proc`.

use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Arc;

use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags};

use super::kernel::{Kernel, PIDFD_THREAD};
use crate::error::{Error, Failures};
use crate::identity::RawPid;

#[derive(Debug, Clone, Copy)]
enum Call {
    PidfdOpen,
    PidfsIno,
    Poll,
    Openat2,
}

/// A call that failed, and the errno it answered.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailedCall {
    call: Call,
    errno: Errno,
}

impl FailedCall {
    /// A `pidfd_open` that answered `errno`.
    pub(crate) const fn pidfd_open(errno: Errno) -> FailedCall {
        FailedCall {
            call: Call::PidfdOpen,
            errno,
        }
    }

    /// A read of a pidfd's inode that answered `errno`.
    pub(crate) const fn pidfs_ino(errno: Errno) -> FailedCall {
        FailedCall {
            call: Call::PidfsIno,
            errno,
        }
    }

    /// A `poll` of a pidfd that answered `errno`.
    pub(crate) const fn poll(errno: Errno) -> FailedCall {
        FailedCall {
            call: Call::Poll,
            errno,
        }
    }

    /// An `openat2` that answered `errno`.
    pub(crate) const fn openat2(errno: Errno) -> FailedCall {
        FailedCall {
            call: Call::Openat2,
            errno,
        }
    }

    /// The call's name, as an error says what failed.
    pub(crate) const fn name(&self) -> &'static str {
        match self.call {
            Call::PidfdOpen => "pidfd_open",
            Call::PidfsIno => "pidfs_ino",
            Call::Poll => "poll",
            Call::Openat2 => "openat2",
        }
    }

    pub(crate) const fn errno(&self) -> Errno {
        self.errno
    }

    /// What cosca requires of the kernel, when this call is a [`Refusal`]: the one sentence an
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) for a refused call carries as its
    /// `detail`. The table is the one place that says which errno of which call is a refusal.
    pub(crate) fn requirement(&self) -> Option<String> {
        let (floor, errno) = match (self.call, self.errno) {
            (Call::PidfdOpen, Errno::NOSYS) => ("5.3", "ENOSYS"),
            (Call::PidfdOpen, Errno::PERM) => ("5.3", "EPERM"),
            (Call::PidfdOpen, Errno::ACCESS) => ("5.3", "EACCES"),
            (Call::PidfdOpen, Errno::NODEV) => ("5.3", "ENODEV"),
            (Call::Openat2, Errno::NOSYS) => ("5.6", "ENOSYS"),
            (Call::Openat2, Errno::PERM) => ("5.6", "EPERM"),
            (Call::Openat2, Errno::NODEV) => ("5.6", "ENODEV"),
            _ => return None,
        };
        let name = self.name();
        Some(format!(
            "cosca requires {name} (Linux \u{2265} {floor}), refused here: {name} answered {errno}"
        ))
    }

    /// This call as a [`Refusal`], when it is one.
    pub(crate) fn refusal(self) -> Option<Refusal> {
        self.requirement().map(|requirement| Refusal {
            call: self,
            requirement,
            beside: None,
        })
    }

    /// [`Error::Unsupported`] naming `op` and the [`requirement`](Self::requirement), when this
    /// call is a refusal. The errno is its `source`.
    pub(crate) fn unsupported(&self, op: impl Into<String>) -> Option<Error> {
        self.refusal().map(|refusal| refusal.unsupported(op))
    }
}

/// A [`FailedCall`] that is a refusal, with the [`requirement`](FailedCall::requirement) it names,
/// built once: a holder never asks again whether the call was refused.
///
/// The rule, stated here once for every place an `openat2` or `pidfd_open` is met: a call is refused
/// when its errno is in [`requirement`](FailedCall::requirement)'s table. A read in `/proc` is an
/// `openat2` here, so the same holds for the view-open, the reads that establish the view, the
/// `/proc` listing and each pid's `stat`. That `stat` answering `EPERM` is `hidepid`'s answer, and a
/// refusal only if the checked directory refuses `self/stat` too: the re-check's errno is then the
/// refusal, and the pid's failure is kept beside it. Every other errno is the call's own failure.
#[derive(Debug)]
pub(crate) struct Refusal {
    call: FailedCall,
    requirement: String,
    /// The failure of the pid the refusal was met beside, when there is one: the pid's own `EPERM`
    /// beside a checked directory that refuses `self/stat`.
    beside: Option<Arc<Error>>,
}

impl Refusal {
    /// This refusal, with `failure`, the other failure it was met beside, kept as a second cause.
    pub(crate) fn beside(mut self, failure: Arc<Error>) -> Refusal {
        self.beside = Some(failure);
        self
    }

    pub(crate) fn requirement(&self) -> &str {
        &self.requirement
    }

    /// The failures behind the refusal: the refusing errno, then the other failure, as an
    /// [`Error::Several`] when there is one.
    pub(crate) fn cause(&self) -> Error {
        let own = std::io::Error::from(self.call.errno());
        match &self.beside {
            None => Error::Io(own),
            Some(beside) => Error::Several(Failures::new(Error::io_cause(own), [Arc::clone(beside)])),
        }
    }

    /// [`Error::Unsupported`] naming `op` and the requirement, with [`cause`](Self::cause) as its
    /// `source`.
    pub(crate) fn unsupported(&self, op: impl Into<String>) -> Error {
        Error::Unsupported {
            op: op.into(),
            platform: "linux",
            detail: self.requirement.clone(),
            source: Some(Arc::new(self.cause())),
        }
    }
}

/// `error`, what a [`Refusal`] ended the scan `caller` with, logged at `warn` and handed back. The
/// one place such a refusal is warned about, where it is met: its caller does not log it again.
pub(crate) fn warn_refused<E: std::error::Error + 'static>(caller: &str, error: E) -> E {
    log::warn!("{caller}: {report}", report = crate::error::Report(&error));
    error
}

/// What opening `pid` found about the process a `Pidfs` id names.
#[derive(Debug)]
pub(crate) enum Proof {
    /// `pid` holds that process, and `fd` is its pidfd. `thread` is the errno the open of the group
    /// leader answered when `pid` is a thread that leads no group, which `PIDFD_THREAD` then opened.
    Holds { fd: OwnedFd, thread: Option<Errno> },
    /// `pid` holds no process, or another one: the id's process is gone.
    Lost,
    /// Nothing was proven: the open or the inode read failed in a way that says nothing about `pid`.
    /// A refusal of `pidfd_open` is `Unsupported`, not a reason to look in `/proc`.
    Unknown(FailedCall),
}

/// `pid` as a `pidfd_open` target: `None` for a number no process can hold.
pub(super) fn target(pid: RawPid) -> Option<Pid> {
    i32::try_from(pid).ok().and_then(Pid::from_raw)
}

/// A pidfd opened by pid. `thread` is the errno of the first open when the pidfd came from the retry.
pub(super) struct Opened {
    pub(super) fd: OwnedFd,
    pub(super) thread: Option<Errno>,
}

/// Opens a pidfd for `target`. A thread that leads no group is refused with `EINVAL` (before 6.16) or
/// `ENOENT` (from 6.16), and only that is retried with `PIDFD_THREAD`; the retry's error is the answer
/// then. A kernel without `PIDFD_THREAD` answers the retry `EINVAL`, as does 6.12 for a reaped group
/// leader whose number lives on as a process-group id.
pub(super) fn open(kernel: &dyn Kernel, target: Pid) -> Result<Opened, Errno> {
    match kernel.pidfd_open(target, PidfdFlags::empty()) {
        Ok(fd) => Ok(Opened { fd, thread: None }),
        Err(first @ (Errno::INVAL | Errno::NOENT)) => kernel.pidfd_open(target, PIDFD_THREAD).map(|fd| Opened {
            fd,
            thread: Some(first),
        }),
        Err(e) => Err(e),
    }
}

/// Opens `pid` and proves that its pidfd has inode `ino`.
pub(crate) fn prove(kernel: &dyn Kernel, pid: RawPid, ino: u64) -> Proof {
    let Some(target) = target(pid) else {
        return Proof::Lost;
    };
    let opened = match open(kernel, target) {
        Ok(opened) => opened,
        // `ESRCH`: nobody holds the number. `EINVAL`/`ENOENT` from the retry: no process of a kernel
        // that has pidfs holds it as a task, so the id's process does not.
        Err(Errno::SRCH | Errno::INVAL | Errno::NOENT) => return Proof::Lost,
        Err(e) => return Proof::Unknown(FailedCall::pidfd_open(e)),
    };
    match kernel.pidfs_ino(opened.fd.as_fd()) {
        Ok(Some(found)) if found == ino => Proof::Holds {
            fd: opened.fd,
            thread: opened.thread,
        },
        Ok(_) => Proof::Lost,
        Err(e) => Proof::Unknown(FailedCall::pidfs_ino(e)),
    }
}

#[cfg(test)]
#[path = "prove_tests.rs"]
mod prove_tests;
