//! Opening a pid and proving that the pidfd is the process a `Pidfs` id names.
//!
//! The inode of a pidfd is one per process and is never reissued, so a pidfd opened by pid whose inode
//! is the id's is that process, and a pid that opens to another inode has been reused. The proof needs
//! no `/proc`.

use std::os::fd::{AsFd as _, OwnedFd};

use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags};

use super::kernel::{Kernel, PIDFD_THREAD};
use crate::identity::{RawPid, UnknownCause};

/// A call that failed, and the errno it answered. The name is what an error says failed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailedCall {
    name: &'static str,
    errno: Errno,
}

impl FailedCall {
    /// A `pidfd_open` that answered `errno`.
    pub(crate) const fn pidfd_open(errno: Errno) -> FailedCall {
        FailedCall {
            name: "pidfd_open",
            errno,
        }
    }

    /// A read of a pidfd's inode that answered `errno`.
    pub(crate) const fn pidfs_ino(errno: Errno) -> FailedCall {
        FailedCall {
            name: "pidfs_ino",
            errno,
        }
    }

    /// A `poll` of a pidfd that answered `errno`.
    pub(crate) const fn poll(errno: Errno) -> FailedCall {
        FailedCall { name: "poll", errno }
    }

    pub(crate) const fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) const fn errno(&self) -> Errno {
        self.errno
    }
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
    /// A refusal of `pidfd_open` is in the cause, and is `Unsupported`, not a reason to look in `/proc`.
    Unknown(UnknownCause),
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

/// The cause of an `Unknown` that a failed pidfd call left.
pub(super) fn cause(call: FailedCall) -> UnknownCause {
    UnknownCause::of_call(call)
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
        Err(e) => return Proof::Unknown(cause(FailedCall::pidfd_open(e))),
    };
    match kernel.pidfs_ino(opened.fd.as_fd()) {
        Ok(Some(found)) if found == ino => Proof::Holds {
            fd: opened.fd,
            thread: opened.thread,
        },
        Ok(_) => Proof::Lost,
        Err(e) => Proof::Unknown(cause(FailedCall::pidfs_ino(e))),
    }
}

#[cfg(test)]
#[path = "prove_tests.rs"]
mod prove_tests;
