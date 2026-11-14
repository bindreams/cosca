//! Test-only seams for the `await_reapable` loop and the tests that wait on it: thread-local hooks that
//! run at a named point of a wait, forced outcomes, and logs of what the loop did.

use std::cell::{Cell, RefCell};
use std::time::Duration;

type OnceHook = Box<dyn FnOnce()>;

thread_local! {
    static AWAIT_EVENTS: RefCell<Vec<(i16, u32)>> = const { RefCell::new(Vec::new()) };
    static ON_ESRCH_REPEEK: RefCell<Option<OnceHook>> = const { RefCell::new(None) };
    static FORCED_EINTR: Cell<Option<Duration>> = const { Cell::new(None) };
}

/// Record one event the `await_reapable` loop got back: its `filter` and `fflags`.
///
/// The events are the OS's answer to a registration, not a `Kernel` row, and no outcome shows them
/// (a knote with and one without `EV_CLEAR` end the same wait `Reapable`).
pub(crate) fn record_event(filter: i16, fflags: u32) {
    AWAIT_EVENTS.with(|e| e.borrow_mut().push((filter, fflags)));
}

/// Every event the `await_reapable` loop got back on this thread since the last call, in order.
pub(crate) fn take_events() -> Vec<(i16, u32)> {
    AWAIT_EVENTS.with(|e| std::mem::take(&mut *e.borrow_mut()))
}

/// Run `hook` on the waiting thread just before the next re-peek that follows an `ESRCH`
/// registration (the backoff's re-peeks). The guard drops an unfired hook.
pub(crate) fn on_esrch_repeek(hook: impl FnOnce() + 'static) -> ForcedOnce {
    ON_ESRCH_REPEEK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    ForcedOnce(|| ON_ESRCH_REPEEK.with(|h| *h.borrow_mut() = None))
}

pub(crate) fn fire_esrch_repeek() {
    if let Some(hook) = ON_ESRCH_REPEEK.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// The next blocking `kevent` call on this thread (not a zero-timeout drain) fails with `EINTR`
/// instead of running, after the frozen clock has advanced by `elapsed`: the time a real
/// interrupted call would have spent.
pub(crate) fn force_eintr_once(elapsed: Duration) -> ForcedOnce {
    FORCED_EINTR.with(|f| f.set(Some(elapsed)));
    ForcedOnce(|| FORCED_EINTR.with(|f| f.set(None)))
}

pub(crate) fn take_forced_eintr() -> Option<Duration> {
    FORCED_EINTR.with(Cell::take)
}

/// Sends `signal` to `pid`, asserting it was delivered.
pub(crate) fn send_signal(pid: u32, signal: libc::c_int) {
    // SAFETY: `kill` with a pid this test spawned (or its own) and a signal whose default action
    // leaves a running process running.
    let rc = unsafe { libc::kill(pid as libc::pid_t, signal) };
    assert_eq!(rc, 0, "kill({pid}, {signal}): {}", std::io::Error::last_os_error());
}

/// Disarms an unconsumed force on drop.
#[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
pub(crate) struct ForcedOnce(fn());

impl Drop for ForcedOnce {
    fn drop(&mut self) {
        (self.0)();
    }
}
