//! Linux `exit_only`: `waitid(P_PIDFD, ...)`, atomic on the pidfd, never by pid.

use std::io;
use std::os::fd::BorrowedFd;

use rustix::io::Errno;
use rustix::process::{waitid, WaitId, WaitIdOptions};

use super::{is_exit_record, reaped_from_record, Foreign, Peek, Reap, Record, Target};

fn pidfd<'a>(target: &Target<'a>) -> BorrowedFd<'a> {
    match target {
        Target::PidFd(fd) => *fd,
    }
}

/// One `waitid(P_PIDFD, options)`: `Ok(None)` when nothing matched (`si_signo == 0`, rustix
/// zeroes the `siginfo_t` first). `EINTR` retries.
pub(crate) fn waitid_record(fd: BorrowedFd<'_>, options: WaitIdOptions) -> Result<Option<Record>, Errno> {
    #[cfg(test)]
    super::seams::waitid_called(options.bits());
    loop {
        match waitid(WaitId::PidFd(fd), options) {
            Ok(status) => {
                return Ok(status.map(|st| Record {
                    si_code: st.raw_code(),
                    si_status: st.exit_status().or_else(|| st.terminating_signal()).unwrap_or(0),
                }))
            }
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

pub(super) fn peek(target: &Target<'_>) -> io::Result<Peek> {
    let fd = pidfd(target);
    match waitid_record(
        fd,
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(Some(record)) if is_exit_record(record.si_code) => Ok(Peek::Exit(reaped_from_record(record))),
        // A ptrace stop, which Linux reports to the tracer whatever the options say: not an exit.
        Ok(Some(_)) | Ok(None) => Ok(Peek::Running),
        Err(Errno::CHILD) => Ok(Peek::Foreign(Foreign::Gone)),
        Err(e) => {
            // Our own pidfd is open and names a child: the kernel has no other reason to refuse it.
            debug_assert!(
                !matches!(e, Errno::BADF | Errno::INVAL),
                "waitid(P_PIDFD) refused our own pidfd: {e}"
            );
            Err(e.into())
        }
    }
}

pub(super) fn try_reap(target: &Target<'_>) -> io::Result<Reap> {
    match peek(target)? {
        Peek::Exit(_) => {}
        Peek::Running => return Ok(Reap::Running),
        Peek::Foreign(f) => return Ok(Reap::Foreign(f)),
    }
    let fd = pidfd(target);
    #[cfg(test)]
    if let Some(forced) = super::seams::take_forced_reap() {
        return match forced {
            super::seams::ForcedReap::None => Ok(Reap::Running),
            super::seams::ForcedReap::Errno(e) => Err(io::Error::from_raw_os_error(e)),
        };
    }
    match waitid_record(fd, WaitIdOptions::EXITED | WaitIdOptions::NOHANG) {
        Ok(Some(record)) => Ok(Reap::Reaped(reaped_from_record(super::consumed(record)))),
        // Peeked as an exit, then nothing to consume: a zombie only its tracer can reap.
        Ok(None) => Ok(Reap::Running),
        Err(Errno::CHILD) => Ok(Reap::Foreign(Foreign::Gone)),
        Err(e) => Err(e.into()),
    }
}

pub(super) fn wait_visible_exit(target: &Target<'_>) -> io::Result<Peek> {
    #[cfg(test)]
    super::seams::step(super::seams::HolderStep::BlockingWaitid);
    #[cfg(test)]
    let forced_none = super::seams::take_forced_visible_none();
    #[cfg(not(test))]
    let forced_none = false;
    #[cfg(test)]
    let forced_errno = super::seams::take_forced_visible_errno();
    #[cfg(not(test))]
    let forced_errno: Option<i32> = None;
    let record = if let Some(errno) = forced_errno {
        Err(Errno::from_raw_os_error(errno))
    } else if forced_none {
        Ok(None)
    } else {
        waitid_record(pidfd(target), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT)
    };
    match record {
        Ok(Some(record)) if is_exit_record(record.si_code) => Ok(Peek::Exit(reaped_from_record(record))),
        Ok(Some(_)) => Ok(Peek::Running),
        Ok(None) => no_record(),
        Err(Errno::CHILD) => Ok(Peek::Foreign(Foreign::Gone)),
        Err(e) => Err(e.into()),
    }
}

/// A blocking `waitid` cannot legitimately find nothing: without `NOHANG` it waits.
fn no_record() -> io::Result<Peek> {
    debug_assert!(false, "a blocking waitid(P_PIDFD, WEXITED) returned no record");
    Err(io::Error::other("a blocking waitid on the pidfd returned no record"))
}

pub(super) fn reap_blocking(target: &Target<'_>) -> io::Result<Result<super::Reaped, Foreign>> {
    let fd = pidfd(target);
    loop {
        #[cfg(test)]
        let forced_none = super::seams::take_forced_visible_none();
        #[cfg(not(test))]
        let forced_none = false;
        let record = if forced_none {
            Ok(None)
        } else {
            waitid_record(fd, WaitIdOptions::EXITED)
        };
        match record {
            Ok(Some(record)) if is_exit_record(record.si_code) => return Ok(Ok(reaped_from_record(record))),
            // A ptrace stop, reported whatever the options say: not an exit; the next call blocks.
            Ok(Some(_)) => continue,
            Ok(None) => {
                debug_assert!(false, "a blocking waitid(P_PIDFD, WEXITED) returned no record");
                return Err(io::Error::other("a blocking waitid on the pidfd returned no record"));
            }
            Err(Errno::CHILD) => return Ok(Err(Foreign::Gone)),
            Err(e) => return Err(e.into()),
        }
    }
}

/// Open a pidfd for `pid`, a child this process spawned, and confirm it names that child.
/// `Ok(None)` means the child is gone: something else reaped it, so there is nothing to wait on.
///
/// This never goes through [`open_verified`](crate::os_process::linux::open::open_verified), whose
/// `EINVAL`/`ENOENT` arm applies foreign-process semantics: for a child we forked the number is a
/// thread-group leader, so `ESRCH`, `EINVAL` and `ENOENT` alike mean it is gone (before 6.16 an
/// `EINVAL` covers a reaped leader whose number lives on as a PGID or SID; from 6.16 an `ESRCH`
/// does, and `ENOENT` covers a number reused by a non-leader thread). A refusal (`ENOSYS`,
/// `EPERM`, `EACCES`, `ENODEV`) is [`Error::Unsupported`](crate::error::Error::Unsupported), with
/// no fallback; any other errno is `Io`.
///
/// - With `Some(id)`, and only when the checked `/proc` view is
///   [`ProcView::Same`](crate::identity::ProcView::Same), the identity is checked too: `Gone` is
///   gone, and `Unknown` skips the check (never a release). A diverged or unassessable view skips
///   it: a live child is never released as foreign because of the view, and the confirmation
///   below decides.
/// - Then, on every view, `waitid(P_PIDFD, WEXITED | WNOHANG | WNOWAIT)` confirms the pidfd names
///   our child: `ECHILD` is gone. A pid reused by a process that is not our child answers it,
///   even if its start time matched.
#[cfg(test)]
pub(crate) fn open_own_child(
    pid: u32,
    id: Option<crate::identity::ProcessId>,
) -> Result<Option<rustix::fd::OwnedFd>, crate::error::Error> {
    use std::os::fd::AsFd;

    use rustix::process::Pid;

    use crate::error::Error;
    use crate::identity::{Existence, ProcView};
    use crate::os_process::linux::open::{exists_checked, pidfd_open_checked, spawn_open_error};

    debug_assert!(
        pid <= i32::MAX as u32,
        "pid {pid} exceeds i32::MAX; pidfd cast would truncate"
    );
    let raw = Pid::from_raw(pid as i32).expect("a spawned child's pid is never 0");
    let pidfd = match pidfd_open_checked(raw) {
        Ok(pidfd) => pidfd,
        Err(rustix::io::Errno::SRCH | rustix::io::Errno::INVAL | rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(spawn_open_error(e)),
    };
    // Never in a stdio slot: with 0, 1 or 2 closed, the lowest free number is one, and the
    // application may `dup2` its stdio back over it, destroying the pidfd.
    let pidfd = crate::above_stdio::above_stdio(pidfd).map_err(Error::Io)?;
    if let Some(id) = id {
        if let ProcView::Same(proc_dir) = crate::identity::proc_view() {
            if exists_checked(id, &proc_dir) == Existence::Gone {
                return Ok(None);
            }
        }
    }
    match super::peek(&Target::PidFd(pidfd.as_fd())) {
        Ok(Peek::Foreign(Foreign::Gone)) => Ok(None),
        Ok(_) => Ok(Some(pidfd)),
        Err(e) => Err(Error::Io(e)),
    }
}
