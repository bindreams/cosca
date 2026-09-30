//! Linux: what an `EPERM` from a signal syscall means.
//!
//! The kernel refuses a signal for a permission reason, and also refuses one to a root-owned
//! zombie. Before anything else the target is checked for having exited.

use std::os::fd::{AsFd as _, BorrowedFd};

use rustix::process::{waitid, WaitId, WaitIdOptions};

use crate::error::Error;
use crate::identity::{Liveness, ProcDir, ProcessId};

use super::{TargetState, Verdict};

// Has the target exited? =====

/// Whether the process behind `pidfd` has exited (is a zombie or gone), without reaping it.
///
/// `waitid(P_PIDFD, WEXITED | WNOHANG | WNOWAIT)` answers exactly for our own child. For a process
/// that is not our child it answers `ECHILD`, and the answer is its `/proc` state instead.
pub(super) fn has_exited(id: ProcessId, pidfd: BorrowedFd<'_>) -> Result<bool, Error> {
    match waitid(
        WaitId::PidFd(pidfd),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(status) => Ok(status.is_some()),
        Err(rustix::io::Errno::CHILD) => {
            let proc_dir = open_proc_dir(id)?;
            match id.is_alive_in(&proc_dir) {
                Liveness::Dead => Ok(true),
                Liveness::Alive => Ok(false),
                Liveness::Unknown => Err(unassessable(id, "its /proc state could not be read", None)),
            }
        }
        Err(errno) => Err(Error::Io(crate::error::io_context(
            "waitid",
            std::io::Error::from(errno),
        ))),
    }
}

// Classification =====

/// Classify the `EPERM` of a signal sent to `id` through a fresh, identity-verified pidfd.
pub(crate) fn classify_kill(id: ProcessId) -> Result<Verdict, Error> {
    let Some(pidfd) = crate::wait::backend::open_verified(id, crate::wait::backend::PidfdOp::Kill)? else {
        return Ok(Verdict::Exited);
    };
    classify_pidfd(id, pidfd.as_fd())
}

/// Classify the `EPERM` of a signal sent to the process `pidfd` names (which `id` describes).
pub(crate) fn classify_pidfd(id: ProcessId, pidfd: BorrowedFd<'_>) -> Result<Verdict, Error> {
    Ok(if has_exited(id, pidfd)? {
        Verdict::Exited
    } else {
        Verdict::Privilege(TargetState::Running)
    })
}

fn open_proc_dir(id: ProcessId) -> Result<ProcDir, Error> {
    ProcDir::open().map_err(|why| unassessable(id, &why.reason, why.source))
}

fn unassessable(id: ProcessId, why: &str, source: Option<std::io::Error>) -> Error {
    let mut detail = format!("pid {} could not be classified after a refused signal: {why}", id.pid());
    if let Some(source) = &source {
        detail.push_str(&format!(": {source}"));
    }
    log::warn!("refusal: {detail}");
    Error::Unassessable { detail, source }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;
