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
        Err(e) => Err(e.into()),
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

/// Block in `waitid(P_PIDFD, WEXITED | WNOWAIT)` until the exit of the child `pid` is visible.
///
/// Contract: a blocking `waitid` answers with the child it was asked about, so `si_pid == pid`.
/// A `waitid` that returned without waiting (`WNOHANG`) leaves `si_pid` zero.
pub(super) fn wait_visible_exit(target: &Target<'_>, pid: u32) -> io::Result<Peek> {
    #[cfg(test)]
    super::seams::step(super::seams::HolderStep::BlockingWaitid);
    #[cfg(test)]
    let forced_none = super::seams::take_forced_visible_none();
    #[cfg(not(test))]
    let forced_none = false;
    let record = if forced_none {
        Ok(None)
    } else {
        blocking_waitid_record(pidfd(target), pid)
    };
    match record {
        Ok(Some(record)) if is_exit_record(record.si_code) => Ok(Peek::Exit(reaped_from_record(record))),
        Ok(Some(_)) => Ok(Peek::Running),
        Ok(None) => no_record(),
        Err(Errno::CHILD) => Ok(Peek::Foreign(Foreign::Gone)),
        Err(e) => Err(e.into()),
    }
}

/// The blocking `waitid(P_PIDFD, WEXITED | WNOWAIT)`, through libc for `si_pid`, which rustix does
/// not expose. `EINTR` retries.
fn blocking_waitid_record(fd: BorrowedFd<'_>, pid: u32) -> Result<Option<Record>, Errno> {
    use std::os::fd::AsRawFd as _;
    let options = libc::WEXITED | libc::WNOWAIT;
    #[cfg(test)]
    super::seams::waitid_called(options as u32);
    loop {
        // SAFETY: an all-zero `siginfo_t` is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is a live pidfd and `info` is a valid out-pointer.
        let rc = unsafe { libc::waitid(libc::P_PIDFD, fd.as_raw_fd() as libc::id_t, &mut info, options) };
        if rc == -1 {
            match Errno::from_io_error(&io::Error::last_os_error()) {
                Some(Errno::INTR) => continue,
                Some(e) => return Err(e),
                None => unreachable!("waitid fails with an errno"),
            }
        }
        // SAFETY: the `siginfo_t` of a successful `waitid` has valid `si_pid` and `si_status`.
        let (si_pid, si_status) = unsafe { (info.si_pid(), info.si_status()) };
        debug_assert_eq!(
            si_pid, pid as libc::pid_t,
            "a blocking waitid(P_PIDFD, WEXITED) answered for another pid, or returned without waiting"
        );
        return Ok((info.si_signo != 0).then_some(Record {
            si_code: info.si_code,
            si_status,
        }));
    }
}

/// A blocking `waitid` cannot legitimately find nothing: without `NOHANG` it waits.
fn no_record() -> io::Result<Peek> {
    debug_assert!(false, "a blocking waitid(P_PIDFD, WEXITED) returned no record");
    Err(io::Error::other("a blocking waitid on the pidfd returned no record"))
}
