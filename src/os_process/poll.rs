//! Unix: reading a descriptor's readiness through `poll(2)`, for the descriptors that stand for a
//! process's exit: a pidfd on Linux, a kqueue armed for the exit on macOS. Both poll readable
//! once the process has exited, and neither read changes what the descriptor reports.

use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags, Timespec};

/// One look at `fd` with a zero timeout: `Ok(true)` once it is readable. Never blocks.
pub(crate) fn is_readable(fd: BorrowedFd<'_>) -> std::io::Result<bool> {
    loop {
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        match poll(&mut fds, Some(&Timespec { tv_sec: 0, tv_nsec: 0 })) {
            Ok(0) => return Ok(false),
            Ok(_) => return readable(fds[0].revents()).map(|()| true),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(std::io::Error::from(e)),
        }
    }
}

/// `poll(2)` takes its timeout as an `int` of milliseconds; where there is no `ppoll` (macOS) rustix
/// turns a longer `Timespec` into `EINVAL` before the call.
const MAX_POLL_BLOCK: Duration = Duration::from_millis(i32::MAX as u64);

/// Polls `fd` until it is readable or `deadline` passes, and says which. `None` is unbounded. Reads
/// no state and reaps nothing: a pidfd names its process for good, so a reused pid cannot answer
/// it.
pub(crate) fn poll_readable(fd: BorrowedFd<'_>, deadline: Option<Instant>) -> std::io::Result<bool> {
    let seen = crate::wait::rearm_until(deadline, |remaining| {
        let remaining = remaining.map(|d| d.min(MAX_POLL_BLOCK));
        #[cfg(test)]
        crate::wait::block_probe::record(remaining);
        let ts = remaining.map(|d| Timespec {
            tv_sec: d.as_secs() as i64,
            tv_nsec: d.subsec_nanos() as _,
        });
        debug_assert!(
            deadline.is_none() || ts.is_some(),
            "a deadline wait armed an unbounded poll"
        );
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        match poll(&mut fds, ts.as_ref()) {
            Ok(0) => Ok(None),
            Ok(_) => readable(fds[0].revents()).map(Some),
            // A signal: go round again against the recomputed remaining time.
            Err(rustix::io::Errno::INTR) => Ok(None),
            Err(e) => Err(std::io::Error::from(e)),
        }
    })?;
    Ok(seen.is_some())
}

/// What a `poll` that reported events found: `Ok(())` for `POLLIN` (a zombie, or an armed kqueue
/// holding the exit) or `POLLHUP` (a reaped pidfd), both an exit; `POLLERR` and `POLLNVAL` are errors.
fn readable(revents: PollFlags) -> std::io::Result<()> {
    // POLLNVAL on an fd we own and hold alive is a contract violation.
    debug_assert!(
        !revents.contains(PollFlags::NVAL),
        "poll reported POLLNVAL: owned-fd contract violation"
    );
    if revents.contains(PollFlags::NVAL) {
        return Err(std::io::Error::other("poll reported POLLNVAL on an owned descriptor"));
    }
    if revents.contains(PollFlags::ERR) {
        return Err(std::io::Error::other("poll returned POLLERR"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "poll_tests.rs"]
mod poll_tests;
