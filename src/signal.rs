//! The signals cosca sends to a process it owns, and the one place each addressing mode's
//! "already gone" is decided.

use std::io;

use crate::error::io_context;

/// A signal cosca sends to an owned process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sig {
    Kill,
}

#[cfg(target_os = "linux")]
impl Sig {
    fn as_rustix(self) -> rustix::process::Signal {
        match self {
            Sig::Kill => rustix::process::Signal::KILL,
        }
    }
}

#[cfg(target_os = "macos")]
impl Sig {
    fn as_libc(self) -> libc::c_int {
        match self {
            Sig::Kill => libc::SIGKILL,
        }
    }
}

/// What a send did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sent {
    /// The signal was handed to the OS for the child.
    Delivered,
    /// Nothing was delivered because the child is gone. Not an error; logged at `debug`.
    Gone,
}

/// Send `sig` through `pidfd`, which names the child for good, so a reused pid cannot be hit.
/// `None` is a child that was already gone when its handle was made.
#[cfg(target_os = "linux")]
pub(crate) fn via_pidfd(pidfd: Option<std::os::fd::BorrowedFd<'_>>, pid: u32, sig: Sig) -> io::Result<Sent> {
    let Some(pidfd) = pidfd else {
        log::debug!("child {pid} has no pidfd (it was gone when adopted); {sig:?} not sent");
        return Ok(Sent::Gone);
    };
    #[cfg(test)]
    crate::send_log::record(pid, sig, crate::send_log::Via::Pidfd);
    match rustix::process::pidfd_send_signal(pidfd, sig.as_rustix()) {
        Ok(()) => Ok(Sent::Delivered),
        Err(rustix::io::Errno::SRCH) => {
            log::debug!("pidfd_send_signal({sig:?}) to child {pid}: it is already gone");
            Ok(Sent::Gone)
        }
        Err(e) => Err(io_context("pidfd_send_signal", e.into())),
    }
}

/// A child's identity, read the moment its handle is made, while the child is ours and unreaped:
/// the 64-bit unique id, which is never reused and survives `exec`. It is the only identity macOS
/// checks a by-pid action against. It names the child unless something else reaped the child, and
/// its pid was reused, before that read: macOS has no handle to pin the pid (principle 5).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Identity {
    Known(u64),
    /// The process was already gone.
    Gone,
    /// The read failed with this errno.
    Unreadable(i32),
}

#[cfg(target_os = "macos")]
impl Identity {
    /// The unique id, when the read found one.
    pub(crate) fn unique(self) -> Option<u64> {
        match self {
            Identity::Known(id) => Some(id),
            Identity::Gone | Identity::Unreadable(_) => None,
        }
    }

    pub(crate) fn read(pid: u32) -> Identity {
        use crate::identity::{uniq_info, ReadPurpose, UniqRead};
        match uniq_info(pid, ReadPurpose::Adopt) {
            UniqRead::Found(info) => Identity::Known(info.unique_id),
            UniqRead::Gone => Identity::Gone,
            UniqRead::Refused(errno) => Identity::Unreadable(errno),
        }
    }
}

/// Send `sig` to `pid` by number, only while it still has `identity`. Nothing is sent to a pid
/// that is gone or reused. An identity that cannot be read is an error carrying the errno, so an
/// `EPERM` stays `PermissionDenied`. The window between the check and `kill(2)` is macOS's own: it
/// has no handle to send through.
#[cfg(target_os = "macos")]
pub(crate) fn via_verified_pid(pid: u32, identity: Identity, sig: Sig) -> io::Result<Sent> {
    use crate::identity::{uniq_info, ReadPurpose, UniqRead};
    let unreadable = |errno: i32| {
        io_context(
            format!("pid {pid}: its identity could not be read; {sig:?} not sent"),
            io::Error::from_raw_os_error(errno),
        )
    };
    let expected = match identity {
        Identity::Known(unique_id) => unique_id,
        Identity::Gone => {
            log::debug!("child {pid} was gone when adopted; {sig:?} not sent");
            return Ok(Sent::Gone);
        }
        Identity::Unreadable(errno) => return Err(unreadable(errno)),
    };
    match uniq_info(pid, ReadPurpose::Kill) {
        UniqRead::Found(now) if now.unique_id == expected => {}
        UniqRead::Found(_) | UniqRead::Gone => {
            log::debug!("child {pid} is gone or its pid names another process; {sig:?} not sent");
            return Ok(Sent::Gone);
        }
        UniqRead::Refused(errno) => return Err(unreadable(errno)),
    }
    // `kill(0, sig)` signals the caller's whole process group.
    let Some(target) = crate::identity::probe::signal_target(pid) else {
        debug_assert!(false, "a child's pid {pid} is not a single-process signal target");
        return Err(io::Error::other(format!(
            "pid {pid} is not a single-process signal target; {sig:?} not sent"
        )));
    };
    #[cfg(test)]
    crate::send_log::record(pid, sig, crate::send_log::Via::Pid);
    // SAFETY: `target` is a positive pid, so the signal goes to one process.
    if unsafe { libc::kill(target, sig.as_libc()) } == 0 {
        return Ok(Sent::Delivered);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ESRCH) {
        log::debug!("kill({pid}, {sig:?}): the child is already gone");
        return Ok(Sent::Gone);
    }
    Err(io_context("kill", e))
}

#[cfg(test)]
#[path = "signal_tests.rs"]
mod signal_tests;
