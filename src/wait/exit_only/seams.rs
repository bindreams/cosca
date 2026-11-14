//! Test seams for `exit_only`. Thread-local, take-once, and armed on the thread that makes the
//! call; each `force_*` returns a guard that disarms an unconsumed force on drop, so a leftover
//! never leaks into the next test on this thread.
//!
//! Only code that holds no kernel it can be given still needs them: the spawn-time macOS code
//! (`HostKernel`) and every Linux peek (a `waitid` on a pidfd). Code over a macOS `Kernel` states
//! `FakeKernel` peek and consume rows instead.

#[cfg(target_os = "macos")]
use std::cell::Cell;
use std::cell::RefCell;
use std::io;

use crate::os_process::child::PeekOutcome;

thread_local! {
    static FORCED_PEEK: RefCell<std::collections::VecDeque<io::Result<PeekOutcome>>> = const { RefCell::new(std::collections::VecDeque::new()) };
    #[cfg(target_os = "macos")]
    static FORCED_SI_CODE: Cell<Option<i32>> = const { Cell::new(None) };
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

/// The next consuming `waitid` on this thread hands back a record with this `si_code`.
#[cfg(target_os = "macos")]
pub(crate) fn force_consuming_record_once(si_code: i32) -> Forced {
    FORCED_SI_CODE.with(|f| f.set(Some(si_code)));
    Forced(|| FORCED_SI_CODE.with(|f| f.set(None)))
}

#[cfg(target_os = "macos")]
pub(crate) fn take_forced_si_code() -> Option<i32> {
    FORCED_SI_CODE.with(Cell::take)
}
