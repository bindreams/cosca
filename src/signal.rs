//! The signals cosca sends to a process it owns, and the one place each addressing mode's
//! "already gone" is decided.

#[cfg(unix)]
use std::io;

#[cfg(unix)]
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
    #[cfg(test)]
    if seams::kills_refused() {
        return Err(io_context(
            "pidfd_send_signal",
            io::Error::from_raw_os_error(libc::EPERM),
        ));
    }
    match rustix::process::pidfd_send_signal(pidfd, sig.as_rustix()) {
        Ok(()) => Ok(Sent::Delivered),
        Err(rustix::io::Errno::SRCH) => {
            log::debug!("pidfd_send_signal({sig:?}) to child {pid}: it is already gone");
            Ok(Sent::Gone)
        }
        Err(e) => Err(io_context("pidfd_send_signal", e.into())),
    }
}

/// A process's unique id by pid: the 64-bit id that is never reused and survives `exec`, which is
/// the only identity macOS checks a by-pid action against. `Ok(None)` is a pid with no process
/// (`ESRCH`); `Err(errno)` is a refused read. Tests only: production spawns take the child's own
/// report (`child::spawn::unique_report`).
#[cfg(all(target_os = "macos", test))]
pub(crate) fn read_identity(pid: u32) -> Result<Option<u64>, i32> {
    use crate::identity::{uniq_info, ReadPurpose, UniqRead};
    match uniq_info(pid, ReadPurpose::Adopt) {
        UniqRead::Found(info) => Ok(Some(info.unique_id)),
        UniqRead::Gone => Ok(None),
        UniqRead::Refused(errno) => Err(errno),
    }
}

/// The error for adopting a child whose by-pid identity read was refused with `errno`. Tests
/// only: a spawn takes the child's own report.
#[cfg(all(target_os = "macos", test))]
pub(crate) fn identity_unreadable(pid: u32, errno: i32) -> crate::error::Error {
    crate::error::Error::Unassessable {
        detail: format!("pid {pid}: its identity could not be read (errno {errno}); the child was not adopted"),
        source: Some(io::Error::from_raw_os_error(errno)),
    }
}

/// Send `sig` to `pid` by number, only while it still has the unique id `identity` (`None`: no id
/// is held, so nothing is sent). Nothing is
/// sent to a pid that is gone or reused. A refused re-read is an error carrying the errno, so an
/// `EPERM` stays `PermissionDenied`. The window between the check and `kill(2)` is macOS's own: it
/// has no handle to send through.
#[cfg(target_os = "macos")]
pub(crate) fn via_verified_pid(pid: u32, identity: Option<u64>, sig: Sig) -> io::Result<Sent> {
    use crate::identity::{uniq_info, ReadPurpose, UniqRead};
    let unreadable = |errno: i32| {
        io_context(
            format!("pid {pid}: its identity could not be read; {sig:?} not sent"),
            io::Error::from_raw_os_error(errno),
        )
    };
    let Some(expected) = identity else {
        log::debug!("child {pid} holds no unique id; {sig:?} not sent");
        return Ok(Sent::Gone);
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
    #[cfg(test)]
    if seams::kills_refused() {
        return Err(io_context("kill", io::Error::from_raw_os_error(libc::EPERM)));
    }
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

/// Test seam: while the guard lives, every kill sent on this thread is refused with `EPERM` and
/// not sent, as the kernel refuses a signal to another user's process. Thread-local, with an RAII
/// reset.
#[cfg(all(test, unix))]
pub(crate) mod seams {
    use std::cell::Cell;

    thread_local! {
        static REFUSED: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn refuse_kills() -> RefusedKills {
        REFUSED.with(|r| r.set(true));
        RefusedKills(())
    }

    #[must_use = "kills are sent again as soon as the guard is dropped"]
    pub(crate) struct RefusedKills(());

    impl Drop for RefusedKills {
        fn drop(&mut self) {
            REFUSED.with(|r| r.set(false));
        }
    }

    pub(super) fn kills_refused() -> bool {
        REFUSED.with(Cell::get)
    }
}

#[cfg(all(test, unix))]
#[path = "signal_tests.rs"]
mod signal_tests;
