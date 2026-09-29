//! Test-only structural seams for `block_on_kqueue`: hooks and counters that let a test prove
//! "checks the deadline every round, blocks for real, never spins" without timing anything.
//! Thread-local; `HookGuard` resets every seam on `Drop`, including during unwinding.

use std::cell::{Cell, RefCell};
use std::time::Duration;

use nix::sys::event::Kqueue;

type RoundHook = Box<dyn FnMut(u32, &Kqueue)>;
type PostEventHook = Box<dyn FnMut(u32)>;

thread_local! {
    static ROUND_HOOK: RefCell<Option<RoundHook>> = const { RefCell::new(None) };
    static POST_EVENT_HOOK: RefCell<Option<PostEventHook>> = const { RefCell::new(None) };
    static KEVENT_CALLS: Cell<u32> = const { Cell::new(0) };
    static REQUESTED_TIMEOUTS: RefCell<Vec<Option<Duration>>> = const { RefCell::new(Vec::new()) };
    static LAST_EVENT_DATA: Cell<Option<isize>> = const { Cell::new(None) };
    static TIMEOUT_OVERRIDE: Cell<Option<Duration>> = const { Cell::new(None) };
    static CLAMP_OVERRIDE: Cell<Option<Duration>> = const { Cell::new(None) };
    // Set for the duration of any hook call, cleared right after — lets `fire_round_hook` and
    // `fire_post_event_hook` catch a hook that re-enters `block_on_kqueue` (which would try to
    // fire a hook of its own while the outer one's `RefCell` borrow is still held) with a clear
    // message, instead of `RefCell`'s own generic "already borrowed" panic.
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
    // Sanity flag for `HookGuard`'s own nesting guard — see `HookGuard::install`.
    static GUARD_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

const REENTRANCY_MESSAGE: &str = "a test hook must not re-enter block_on_kqueue: its own \
     RefCell borrow is held for the hook's whole call — drive any nested wait through a \
     separate, already-armed kqueue instead (see block_until_marker_ready_again in \
     marker_eof_tests)";

/// Install a closure `block_on_kqueue` invokes once at the top of every round on THIS thread,
/// with the 0-based round index and a borrow of the SAME kqueue `block_on_kqueue` is driving.
fn set_round_hook(hook: impl FnMut(u32, &Kqueue) + 'static) {
    ROUND_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}

/// Install a closure `block_on_kqueue` invokes once a real event has actually arrived
/// (`Ok(n > 0)`), with the round index, before `elapsed` is (re)computed for that event.
fn set_post_event_hook(hook: impl FnMut(u32) + 'static) {
    POST_EVENT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}

pub(crate) fn fire_round_hook(round: u32, kq: &Kqueue) {
    debug_assert!(!IN_HOOK.with(Cell::get), "{REENTRANCY_MESSAGE}");
    IN_HOOK.with(|f| f.set(true));
    ROUND_HOOK.with(|h| {
        if let Some(hook) = h.borrow_mut().as_mut() {
            hook(round, kq);
        }
    });
    IN_HOOK.with(|f| f.set(false));
}

pub(crate) fn fire_post_event_hook(round: u32) {
    debug_assert!(!IN_HOOK.with(Cell::get), "{REENTRANCY_MESSAGE}");
    IN_HOOK.with(|f| f.set(true));
    POST_EVENT_HOOK.with(|h| {
        if let Some(hook) = h.borrow_mut().as_mut() {
            hook(round);
        }
    });
    IN_HOOK.with(|f| f.set(false));
}

/// Count of real `kq.kevent(...)` calls `block_on_kqueue` has issued on THIS thread — one per
/// round, by construction: `EINTR` is retried inside the round it interrupted, never counted or
/// re-fired as a new round (see `block_on_kqueue`'s own doc).
pub(crate) fn kevent_calls() -> u32 {
    KEVENT_CALLS.with(Cell::get)
}

/// The ACTUAL timeout argument passed to each counted `kevent` call so far, in call order
/// (recorded from the literal argument at the call site, including any [`set_timeout_override`]
/// substitution) — proof the requested timeout is both a live recomputation every round AND the
/// value that really reached the syscall.
pub(crate) fn requested_timeouts() -> Vec<Option<Duration>> {
    REQUESTED_TIMEOUTS.with(|v| v.borrow().clone())
}

pub(crate) fn record_kevent_call(requested: Option<Duration>) {
    KEVENT_CALLS.with(|c| c.set(c.get() + 1));
    REQUESTED_TIMEOUTS.with(|v| v.borrow_mut().push(requested));
}

/// The raw `KEvent::data()` field from the most recent `Ok(n > 0)` `kevent` call on THIS
/// thread — e.g. the byte count a non-EOF `EVFILT_READ` event reported. Lets a later round's
/// hook assert that nothing was drained since (by comparing this against a fresh `FIONREAD`
/// read on the same descriptor).
pub(crate) fn last_event_data() -> Option<isize> {
    LAST_EVENT_DATA.with(Cell::get)
}

pub(crate) fn record_event_data(data: isize) {
    LAST_EVENT_DATA.with(|c| c.set(Some(data)));
}

/// Force the NEXT real `kevent` call's requested timeout to `d`, regardless of what
/// `remaining(deadline)` computed — take-semantics, consumed by the first attempt in the
/// current round. Lets a test construct a `kevent` call whose REAL, OS-level timeout is short
/// (so the test runs fast) while `remaining(deadline)` — unaffected by this override — still
/// reports the caller's real deadline as far off, deliberately reproducing the "requested
/// timeout does not faithfully reflect `remaining`" mismatch `block_on_kqueue`'s `Ok(0)`
/// re-check exists to catch, without needing a real mutant or a real long wait.
pub(crate) fn set_timeout_override(d: Duration) {
    TIMEOUT_OVERRIDE.with(|c| c.set(Some(d)));
}

pub(crate) fn take_timeout_override() -> Option<Duration> {
    TIMEOUT_OVERRIDE.with(|c| c.take())
}

/// Lower the per-call `kevent` timeout clamp to `d` until the guard resets, so a test reaches
/// the re-arm path without a multi-year deadline. Read by `block_on_kqueue`'s clamp.
pub(crate) fn set_clamp_override(d: Duration) {
    CLAMP_OVERRIDE.with(|c| c.set(Some(d)));
}

pub(crate) fn clamp_override() -> Option<Duration> {
    CLAMP_OVERRIDE.with(Cell::get)
}

/// Clear every seam back to its default (no hooks, zero counters, no recorded data).
/// Idempotent — safe to call whether or not anything was ever installed.
fn reset() {
    ROUND_HOOK.with(|h| *h.borrow_mut() = None);
    POST_EVENT_HOOK.with(|h| *h.borrow_mut() = None);
    KEVENT_CALLS.with(|c| c.set(0));
    REQUESTED_TIMEOUTS.with(|v| v.borrow_mut().clear());
    LAST_EVENT_DATA.with(|c| c.set(None));
    TIMEOUT_OVERRIDE.with(|c| c.set(None));
    AWAIT_EVENTS.with(|e| e.borrow_mut().clear());
    AWAIT_TIMEOUTS.with(|v| v.borrow_mut().clear());
    CLAMP_OVERRIDE.with(|c| c.set(None));
    IN_HOOK.with(|f| f.set(false));
    GUARD_ACTIVE.with(|f| f.set(false));
}

/// RAII installer for a round hook (and, optionally, a post-event hook): resets every seam,
/// installs the hook(s), and resets again on `Drop` — including during unwinding, so a test
/// that panics mid-assertion never leaks a hook or stale counters into whatever runs on this
/// thread next.
#[must_use]
pub(crate) struct HookGuard {
    _private: (),
}

impl HookGuard {
    pub(crate) fn install(hook: impl FnMut(u32, &Kqueue) + 'static) -> Self {
        // Nesting is not supported: the INNER guard's `Drop` would reset the hooks out from
        // under the OUTER guard, which is still alive and still expects them installed.
        debug_assert!(
            !GUARD_ACTIVE.with(Cell::get),
            "HookGuard::install called while another HookGuard is already active on this \
             thread — nesting is not supported"
        );
        reset();
        set_round_hook(hook);
        GUARD_ACTIVE.with(|f| f.set(true));
        Self { _private: () }
    }

    /// Same as [`install`](Self::install), plus a post-event hook (see
    /// [`set_post_event_hook`]'s own doc).
    pub(crate) fn install_with_post_event(
        round_hook: impl FnMut(u32, &Kqueue) + 'static,
        post_event_hook: impl FnMut(u32) + 'static,
    ) -> Self {
        let guard = Self::install(round_hook);
        set_post_event_hook(post_event_hook);
        guard
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        reset();
    }
}

// The `await_reapable` seams =====

type OnceHook = Box<dyn FnOnce()>;
type RoundHookOnce = (u32, OnceHook);
type EveryRoundHook = Box<dyn FnMut(u32)>;

thread_local! {
    static AWAIT_TIMEOUTS: RefCell<Vec<Option<Duration>>> = const { RefCell::new(Vec::new()) };
    static AWAIT_EVENTS: RefCell<Vec<(i16, u32)>> = const { RefCell::new(Vec::new()) };
    static FORCE_ESRCH_REGISTRATION: Cell<bool> = const { Cell::new(false) };
    static ON_BEFORE_REPEEK: RefCell<Option<OnceHook>> = const { RefCell::new(None) };
    static ON_ESRCH_REPEEK: RefCell<Option<OnceHook>> = const { RefCell::new(None) };
    static ON_KEVENT_ROUND: RefCell<Option<RoundHookOnce>> = const { RefCell::new(None) };
    static ON_EVERY_KEVENT_ROUND: RefCell<Option<EveryRoundHook>> = const { RefCell::new(None) };
    static FORCED_EINTR: Cell<Option<Duration>> = const { Cell::new(None) };
}

/// Record the timeout one `await_reapable` `kevent` call was armed with. Kept apart from
/// [`record_kevent_call`]'s log: a test that counts `block_on_kqueue` rounds must not see the
/// rounds of a child's wait on the same thread.
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

/// Disarms an unconsumed force on drop.
#[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
pub(crate) struct ForcedOnce(fn());

impl Drop for ForcedOnce {
    fn drop(&mut self) {
        (self.0)();
    }
}
