//! Closes this test process's std fds, for the tests that reproduce a bug seen only with one of them
//! free.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

use crate::test_own_process::Completion;

/// Dups each of `fds` aside and closes the original, restoring it on drop even if the test panics.
///
/// Closing a std fd is process-wide, so the `&Completion` witness demands a process of the test's own.
pub(crate) struct RestoreStdio {
    saved: Vec<(RawFd, OwnedFd)>,
}

impl RestoreStdio {
    pub(crate) fn close(_own_process: &Completion, fds: &[RawFd]) -> RestoreStdio {
        let mut restore = RestoreStdio {
            saved: Vec::with_capacity(fds.len()),
        };
        for &fd in fds {
            // SAFETY: F_DUPFD_CLOEXEC(fd, 3) duplicates `fd` to a fresh number >= 3, checked below.
            let saved = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(
                saved >= 0,
                "dup fd {fd} aside before closing it: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: `saved` was just returned by a successful F_DUPFD_CLOEXEC.
            restore.saved.push((fd, unsafe { OwnedFd::from_raw_fd(saved) }));
            // SAFETY: closing a descriptor number; the result is checked.
            let closed = unsafe { libc::close(fd) };
            assert_eq!(
                closed,
                0,
                "close the test process' fd {fd}: {}",
                std::io::Error::last_os_error()
            );
        }
        restore
    }
}

impl Drop for RestoreStdio {
    fn drop(&mut self) {
        for (fd, saved) in &self.saved {
            // Retries EINTR like `fd_map::dup2_onto`, and asserts the result: a failed restore
            // would leave this process's std fd wrong for everything that runs after.
            let ret = loop {
                // SAFETY: dup2 onto `fd`; `saved` stays valid whatever this call's outcome.
                let ret = unsafe { libc::dup2(saved.as_raw_fd(), *fd) };
                if ret != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break ret;
                }
            };
            assert_eq!(
                ret,
                *fd,
                "dup2({}, {fd}) while restoring failed: {}",
                saved.as_raw_fd(),
                std::io::Error::last_os_error()
            );
        }
    }
}
