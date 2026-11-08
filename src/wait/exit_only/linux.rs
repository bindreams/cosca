//! Linux `exit_only`: `waitid(P_PIDFD, ...)`, atomic on the pidfd, never by pid.

use std::io;
use std::os::fd::BorrowedFd;

use rustix::io::Errno;
use rustix::process::{waitid, WaitId, WaitIdOptions};

use super::{exit_record_of, is_exit_record, Reap, Record, Target};
use crate::os_process::child::{Foreign, PeekOutcome};

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

/// One non-blocking `waitid` look at the target; the test hook is not consulted.
pub(crate) fn peek(target: &Target<'_>) -> io::Result<PeekOutcome> {
    let fd = pidfd(target);
    match waitid_record(
        fd,
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(Some(record)) if is_exit_record(record.si_code) => Ok(PeekOutcome::Exit(exit_record_of(record))),
        // A ptrace stop, which Linux reports to the tracer whatever the options say: not an exit.
        Ok(Some(_)) | Ok(None) => Ok(PeekOutcome::Running),
        Err(Errno::CHILD) => Ok(PeekOutcome::Foreign(Foreign::Gone)),
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
        PeekOutcome::Exit(_) => {}
        PeekOutcome::Running => return Ok(Reap::Running),
        PeekOutcome::Foreign(f) => return Ok(Reap::Foreign(f)),
    }
    let fd = pidfd(target);
    match waitid_record(fd, WaitIdOptions::EXITED | WaitIdOptions::NOHANG) {
        Ok(Some(record)) => Ok(Reap::Reaped(exit_record_of(super::consumed(record)))),
        // Peeked as an exit, then nothing to consume: a zombie only its tracer can reap.
        Ok(None) => Ok(Reap::Running),
        Err(Errno::CHILD) => Ok(Reap::Foreign(Foreign::Gone)),
        Err(e) => Err(e.into()),
    }
}
