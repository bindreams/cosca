//! Moving a descriptor out of the stdio slots.
//!
//! With 0, 1 or 2 closed, the lowest free number is a stdio slot, and a descriptor created there is
//! at risk twice: the application may `dup2` its stdio back over it, and std `dup2`s a child's
//! stdio into those slots before any `pre_exec` hook runs. A descriptor this crate holds for a
//! child's lifetime is therefore moved to 3 or above.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

/// `fd`, moved to 3 or above, close-on-exec. A descriptor already at 3 or above is returned as it
/// is, so it must already be close-on-exec.
///
/// This narrows the hazard, it does not close it: no syscall that makes a descriptor takes a
/// minimum number, so each creates it at the lowest free number first, and the move follows. A
/// `dup2` by another thread onto a closed stdio slot in that gap is outside this function's
/// contract.
pub(crate) fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    above_stdio_keeping(fd).map_err(|(e, _)| e)
}

/// [`above_stdio`], handing `fd` back if it could not be moved.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "only the Linux pidfd handshake keeps a descriptor it could not move"
    )
)]
pub(crate) fn above_stdio_keeping(fd: OwnedFd) -> Result<OwnedFd, (io::Error, OwnedFd)> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    match rustix::io::fcntl_dupfd_cloexec(&fd, 3) {
        Ok(moved) => Ok(moved),
        Err(e) => Err((e.into(), fd)),
    }
}

#[cfg(test)]
#[path = "above_stdio_tests.rs"]
mod above_stdio_tests;
