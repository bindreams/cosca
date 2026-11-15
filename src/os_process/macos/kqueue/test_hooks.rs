//! Test-only seams for the tests that wait on a kqueue: a log of what the exit-event reads got back,
//! and a signal sender.

use std::cell::RefCell;

thread_local! {
    static EXIT_EVENTS: RefCell<Vec<(i16, u32)>> = const { RefCell::new(Vec::new()) };
}

/// Record one event a read of a child's exit kqueue got back: its `filter` and `fflags`.
///
/// The events are the OS's answer to a registration, not a `Kernel` row, and no outcome shows them
/// (a knote with and one without `EV_CLEAR` end the same wait the same way).
pub(crate) fn record_event(filter: i16, fflags: u32) {
    EXIT_EVENTS.with(|e| e.borrow_mut().push((filter, fflags)));
}

/// Every event the exit-event reads got back on this thread since the last call, in order.
pub(crate) fn take_events() -> Vec<(i16, u32)> {
    EXIT_EVENTS.with(|e| std::mem::take(&mut *e.borrow_mut()))
}

/// Sends `signal` to `pid`, asserting it was delivered.
pub(crate) fn send_signal(pid: u32, signal: libc::c_int) {
    // SAFETY: `kill` with a pid this test spawned (or its own) and a signal whose default action
    // leaves a running process running.
    let rc = unsafe { libc::kill(pid as libc::pid_t, signal) };
    assert_eq!(rc, 0, "kill({pid}, {signal}): {}", std::io::Error::last_os_error());
}
