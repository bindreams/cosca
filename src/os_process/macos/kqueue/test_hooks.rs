//! Test-only seams for the `await_reapable` loop and the tests that wait on it: thread-local hooks that
//! run at a named point of a wait, forced outcomes, and logs of what the loop did.

use std::cell::{Cell, RefCell};
use std::time::Duration;

type OnceHook = Box<dyn FnOnce()>;
type RoundHookOnce = (u32, OnceHook);
type EveryRoundHook = Box<dyn FnMut(u32)>;

thread_local! {
    static AWAIT_TIMEOUTS: RefCell<Vec<Option<Duration>>> = const { RefCell::new(Vec::new()) };
    static AWAIT_EVENTS: RefCell<Vec<(i16, u32)>> = const { RefCell::new(Vec::new()) };
    static BACKOFF_TIMERS: RefCell<Vec<Duration>> = const { RefCell::new(Vec::new()) };
    static FORCE_ESRCH_REGISTRATION: Cell<bool> = const { Cell::new(false) };
    static ON_BEFORE_REPEEK: RefCell<Option<OnceHook>> = const { RefCell::new(None) };
    static ON_ESRCH_REPEEK: RefCell<Option<OnceHook>> = const { RefCell::new(None) };
    static ON_KEVENT_ROUND: RefCell<Option<RoundHookOnce>> = const { RefCell::new(None) };
    static ON_EVERY_KEVENT_ROUND: RefCell<Option<EveryRoundHook>> = const { RefCell::new(None) };
    static FORCED_EINTR: Cell<Option<Duration>> = const { Cell::new(None) };
}

/// Record the timeout one `await_reapable` `kevent` call was armed with.
pub(crate) fn record_await_kevent(requested: Option<Duration>) {
    AWAIT_TIMEOUTS.with(|v| v.borrow_mut().push(requested));
}

/// The timeout each `await_reapable` `kevent` call on this thread was armed with, in order.
pub(crate) fn await_requested_timeouts() -> Vec<Option<Duration>> {
    AWAIT_TIMEOUTS.with(|v| v.borrow().clone())
}

/// Record one event the `await_reapable` loop got back: its `filter` and `fflags`.
pub(crate) fn record_event(filter: i16, fflags: u32) {
    AWAIT_EVENTS.with(|e| e.borrow_mut().push((filter, fflags)));
}

/// Every event the `await_reapable` loop got back on this thread since the last call, in order.
pub(crate) fn take_events() -> Vec<(i16, u32)> {
    AWAIT_EVENTS.with(|e| std::mem::take(&mut *e.borrow_mut()))
}

/// Record the interval one `arm_backoff_timer` call armed.
pub(crate) fn record_backoff_timer(interval: Duration) {
    BACKOFF_TIMERS.with(|t| t.borrow_mut().push(interval));
}

/// The interval of each backoff timer armed on this thread since the last call, in order.
#[cfg(feature = "tokio")]
pub(crate) fn take_backoff_timers() -> Vec<Duration> {
    BACKOFF_TIMERS.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

/// The next `await_reapable` on this thread sees its `EVFILT_PROC` registration answered `ESRCH`
/// without calling `kevent`.
pub(crate) fn force_proc_registration_esrch_once() -> ForcedOnce {
    FORCE_ESRCH_REGISTRATION.with(|f| f.set(true));
    ForcedOnce(|| FORCE_ESRCH_REGISTRATION.with(|f| f.set(false)))
}

pub(crate) fn take_forced_esrch_registration() -> bool {
    FORCE_ESRCH_REGISTRATION.with(Cell::take)
}

/// Run `hook` on the waiting thread just before the wait's next re-peek. The guard drops an
/// unfired hook.
pub(crate) fn on_before_repeek(hook: impl FnOnce() + 'static) -> ForcedOnce {
    ON_BEFORE_REPEEK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    ForcedOnce(|| ON_BEFORE_REPEEK.with(|h| *h.borrow_mut() = None))
}

pub(crate) fn fire_before_repeek() {
    if let Some(hook) = ON_BEFORE_REPEEK.with(|h| h.borrow_mut().take()) {
        hook();
    }
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

/// Run `hook` on the waiting thread just before round `round`'s blocking `kevent` in the
/// `await_reapable` loop. The guard drops an unfired hook.
pub(crate) fn on_kevent_round(round: u32, hook: impl FnOnce() + 'static) -> ForcedOnce {
    ON_KEVENT_ROUND.with(|h| *h.borrow_mut() = Some((round, Box::new(hook))));
    ForcedOnce(|| ON_KEVENT_ROUND.with(|h| *h.borrow_mut() = None))
}

/// Run `hook` with the round index on the waiting thread just before every blocking `kevent`
/// round of the `await_reapable` loop. The guard drops it.
pub(crate) fn on_every_kevent_round(hook: impl FnMut(u32) + 'static) -> ForcedOnce {
    ON_EVERY_KEVENT_ROUND.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    ForcedOnce(|| ON_EVERY_KEVENT_ROUND.with(|h| *h.borrow_mut() = None))
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

pub(crate) fn fire_kevent_round(round: u32) {
    // Out of its slot for the call, so the hook may itself install or drop hooks.
    if let Some(mut every) = ON_EVERY_KEVENT_ROUND.with(|h| h.borrow_mut().take()) {
        every(round);
        ON_EVERY_KEVENT_ROUND.with(|h| {
            let mut slot = h.borrow_mut();
            if slot.is_none() {
                *slot = Some(every);
            }
        });
    }
    let hook = ON_KEVENT_ROUND.with(|h| {
        let mut slot = h.borrow_mut();
        match slot.as_ref() {
            Some((r, _)) if *r == round => slot.take().map(|(_, hook)| hook),
            _ => None,
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

/// Whether `kq` has an event pending, by a `poll` of its descriptor, which takes nothing from it.
pub(crate) fn event_pending(kq: &impl std::os::fd::AsFd) -> bool {
    use std::os::fd::AsRawFd;
    let mut fd = libc::pollfd {
        fd: kq.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid `pollfd`, and a zero timeout.
    let n = unsafe { libc::poll(&mut fd, 1, 0) };
    assert!(n >= 0, "poll the wait's kqueue: {}", std::io::Error::last_os_error());
    n == 1
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
