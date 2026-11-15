//! Test seams for `exit_only`. Thread-local, take-once, and armed on the thread that makes the
//! call; each `force_*` returns a guard that disarms an unconsumed force on drop, so a leftover
//! never leaks into the next test on this thread.
//!
//! The one seam that answers a box's peek in the OS's place, on macOS (in `exit_only::peek` and its
//! variants) and Linux (in `LinuxProcess::peek`); Windows has none. A test that holds its box states
//! the answer on it (`OwnedChild::script_over`, a `FakeKernel` row) instead. This one is for a
//! test that runs a whole spawn, whose box it cannot reach. A Linux peek is a `waitid` on a pidfd
//! that the kernel answers only with `ECHILD` (a foreign reap, `Ok(Gone)`) or `EBADF`/`EINVAL` (a
//! pidfd that is not ours, debug-asserted); a seccomp or sandbox policy may answer more, and that
//! is what a Linux test forces here.

use std::cell::RefCell;
use std::io;

use crate::os_process::child::PeekOutcome;

thread_local! {
    static FORCED_PEEK: RefCell<std::collections::VecDeque<io::Result<PeekOutcome>>> = const { RefCell::new(std::collections::VecDeque::new()) };
}

/// Disarms an unconsumed force on drop.
#[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
pub(crate) struct Forced(fn());

impl Drop for Forced {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// The next [`peek`](super::peek) on this thread answers `result`.
pub(crate) fn force_peek_once(result: io::Result<PeekOutcome>) -> Forced {
    force_peeks([result])
}

/// The next peeks on this thread answer `results`, one each and in order, then the OS answers again.
pub(crate) fn force_peeks(results: impl IntoIterator<Item = io::Result<PeekOutcome>>) -> Forced {
    FORCED_PEEK.with(|f| *f.borrow_mut() = results.into_iter().collect());
    Forced(|| FORCED_PEEK.with(|f| f.borrow_mut().clear()))
}

/// Panics unless every peek forced on this thread was consumed: a test that counts on a specific
/// number of looks asserts it, so a look that stopped happening fails by assertion.
#[track_caller]
pub(crate) fn assert_peeks_exhausted() {
    let left = FORCED_PEEK.with(|f| f.borrow().len());
    assert_eq!(left, 0, "{left} forced peek(s) were never consumed");
}

pub(crate) fn take_forced_peek() -> Option<io::Result<PeekOutcome>> {
    FORCED_PEEK.with(|f| f.borrow_mut().pop_front())
}
