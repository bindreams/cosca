//! The shim's seam log: lines the test hooks' descriptor receives. Nothing is written without one.

use std::fmt;
use std::os::fd::{BorrowedFd, RawFd};

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

    /// Makes a panic leave its message in the log: once the shim has replaced its standard descriptors
    /// nothing else would show it. Does nothing without a log.
    pub(super) fn say_panics(&self) {
        let Some(fd) = self.fd else { return };
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            write_all(fd, format!("panic: {info}\n").as_bytes());
            previous(info);
        }));
    }

    /// A failure the shim handles: the seam log gets the line, and the `log` crate gets it at `warn`.
    pub(super) fn warn(&self, args: fmt::Arguments<'_>) {
        log::warn!("{args}");
        self.line(args);
    }
}

/// A short write loop; one `write` of a line to a pipe or a file is atomic enough to keep lines whole
/// (`PIPE_BUF`). A failure is ignored: the log is a seam, not a channel.
fn write_all(fd: RawFd, mut bytes: &[u8]) {
    // SAFETY: the hooks own the descriptor for the life of the process.
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    while !bytes.is_empty() {
        match rustix::io::write(fd, bytes) {
            Ok(0) => return,
            Ok(n) => bytes = &bytes[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return,
        }
    }
}
