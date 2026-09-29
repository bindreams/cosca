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

pub(super) fn wait_visible_exit(target: &Target<'_>) -> io::Result<Peek> {
    match waitid_record(pidfd(target), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT) {
        Ok(Some(record)) if is_exit_record(record.si_code) => Ok(Peek::Exit(reaped_from_record(record))),
        Ok(_) => Ok(Peek::Running),
        Err(Errno::CHILD) => Ok(Peek::Foreign(Foreign::Gone)),
        Err(e) => Err(e.into()),
    }
}
