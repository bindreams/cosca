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

/// Send `sig` to `pid` by number, only while it still names the process whose start time is
/// `start`. Nothing is sent to a pid that is gone or reused, and an unreadable identity is an
/// error. The window between the check and `kill(2)` is macOS's own: it has no handle to send
/// through.
#[cfg(target_os = "macos")]
pub(crate) fn via_verified_pid(pid: u32, start: crate::identity::StartToken, sig: Sig) -> io::Result<Sent> {
    use crate::identity::{pbi_start_quiet, ReadPurpose, Resolved};
    match pbi_start_quiet(pid, ReadPurpose::Kill) {
        Resolved::Found(now) if now == start => {}
        Resolved::Found(_) | Resolved::Gone => {
            log::debug!("child {pid} is gone or its pid names another process; {sig:?} not sent");
            return Ok(Sent::Gone);
        }
        Resolved::Unknown => {
            return Err(io::Error::other(format!(
                "pid {pid}: its identity could not be confirmed; {sig:?} not sent"
            )));
        }
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
