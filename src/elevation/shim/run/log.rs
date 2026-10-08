//! The shim's seam log: lines the test hooks' descriptor receives. Nothing is written without one.

use std::fmt;
use std::os::fd::RawFd;

pub(super) struct Log {
    fd: Option<RawFd>,
}

impl Log {
    pub(super) fn new(fd: Option<RawFd>) -> Log {
        Log { fd }
    }

    pub(super) fn fd(&self) -> Option<RawFd> {
        self.fd
    }

    pub(super) fn line(&self, args: fmt::Arguments<'_>) {
        let Some(fd) = self.fd else { return };
        let mut line = args.to_string();
        line.push('\n');
        write_all(fd, line.as_bytes());
    }
}

/// A short write loop; one `write` of a line to a pipe or a file is atomic enough to keep lines whole
/// (`PIPE_BUF`). A failure is ignored: the log is a seam, not a channel.
fn write_all(fd: RawFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is valid for its length.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        match n {
            1.. => bytes = &bytes[n as usize..],
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
            _ => return,
        }
    }
}
