//! The shim's file-descriptor primitives: polling for input, and giving the shim's standard
//! descriptors up.

use std::os::fd::BorrowedFd;

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{open, Mode, OFlags};
use rustix::io::Errno;

use super::log::Log;

/// Which of `fds` are readable or hung up, in the same order; an absent descriptor is never ready.
/// `EINTR` is retried; every other error is the caller's, and means nothing is known about any
/// descriptor.
fn poll_in<const N: usize>(fds: [Option<BorrowedFd<'_>>; N], block: bool) -> Result<[bool; N], Errno> {
    let mut at = [None; N];
    let mut polled = Vec::with_capacity(N);
    for (slot, fd) in fds.iter().enumerate() {
        if let Some(fd) = fd {
            at[slot] = Some(polled.len());
            polled.push(PollFd::new(fd, PollFlags::IN));
        }
    }
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    loop {
        match poll(&mut polled, (!block).then_some(&zero)) {
            Ok(_) => break,
            Err(Errno::INTR) => {}
            Err(e) => return Err(e),
        }
    }
    let mut ready = [false; N];
    for (slot, index) in at.iter().enumerate() {
        ready[slot] = index.is_some_and(|i| !polled[i].revents().is_empty());
    }
    Ok(ready)
}

/// Blocks until at least one of `fds` is readable or hung up. One of the shim's deliberate blocking
/// calls.
pub(super) fn wait_readable<const N: usize>(fds: [Option<BorrowedFd<'_>>; N]) -> Result<[bool; N], Errno> {
    poll_in(fds, true)
}

/// Which of `fds` are readable or hung up right now. A failed poll is an error, never "not readable".
pub(super) fn readable_now<const N: usize>(fds: [BorrowedFd<'_>; N]) -> Result<[bool; N], Errno> {
    poll_in(fds.map(Some), false)
}

/// Replaces the shim's stdin, stdout and stderr with `/dev/null`, so that it holds no end of the
/// front's pipes. If `/dev/null` cannot be opened the shim keeps them, and says so.
pub(super) fn replace_stdio(log: &Log) {
    let null = match open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()) {
        Ok(null) => null,
        Err(e) => {
            log.warn(format_args!(
                "cannot open /dev/null: {e}; the shim keeps its standard descriptors"
            ));
            crate::elevation::shim::stderr::line(format_args!(
                "cannot open /dev/null: {e}; the shim keeps its standard descriptors"
            ));
            return;
        }
    };
    for (name, replaced) in [
        ("stdin", rustix::stdio::dup2_stdin(&null)),
        ("stdout", rustix::stdio::dup2_stdout(&null)),
        ("stderr", rustix::stdio::dup2_stderr(&null)),
    ] {
        if let Err(e) = replaced {
            log.warn(format_args!("cannot replace {name} with /dev/null: {e}"));
            debug_assert!(false, "dup2 of /dev/null onto {name}: {e}");
        }
    }
}

#[cfg(test)]
#[path = "fds_tests.rs"]
mod fds_tests;
