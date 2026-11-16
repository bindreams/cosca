//! Linux `exit_only`: `waitid(P_PIDFD, ...)`, atomic on the pidfd, never by pid.

use std::io;

use rustix::io::Errno;

use super::{exit_record_of, is_exit_record, Reap, Target};
use crate::os_process::child::{Foreign, PeekOutcome};

/// One non-blocking `waitid` look at the target, through the kernel the target carries.
pub(crate) fn peek(target: &Target<'_>) -> io::Result<PeekOutcome> {
    let Target::PidFd { fd, kernel } = target;
    match kernel.peek(*fd) {
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
    let Target::PidFd { fd, kernel } = target;
    match kernel.consume(*fd) {
        Ok(Some(record)) => Ok(Reap::Reaped(exit_record_of(record))),
        // Peeked as an exit, then nothing to consume: a zombie only its tracer can reap.
        Ok(None) => Ok(Reap::Running),
        Err(Errno::CHILD) => Ok(Reap::Foreign(Foreign::Gone)),
        Err(e) => Err(e.into()),
    }
}
