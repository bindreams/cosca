//! Test seams for `exit_only` and the holder that drives it. Thread-local, take-once, and armed
//! on the thread that makes the call; each `force_*` returns a guard that disarms an unconsumed
//! force on drop, so a leftover never leaks into the next test on this thread.

use std::cell::{Cell, RefCell};
use std::io;

use super::Peek;

/// A step of the `SharedChild` holder's wait, in the order the holder took them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HolderStep {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only the Linux holder polls"))]
    Poll,
    /// The one non-blocking look a deadline wait takes at expiry.
    FinalPeek,
    Reap,
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS takes a second peek")
    )]
    SecondPeek,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux holder blocks in waitid")
    )]
    BlockingWaitid,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux holder backs off")
    )]
    Backoff,
}

/// What the next consuming reap finds, in place of the syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForcedReap {
    /// Nothing to consume.
    None,
    /// The syscall fails with this errno.
    Errno(i32),
}

type StepHook = Box<dyn FnOnce()>;

thread_local! {
    static FORCED_PEEK: RefCell<Option<io::Result<Peek>>> = const { RefCell::new(None) };
    static FORCED_REAP: Cell<Option<ForcedReap>> = const { Cell::new(None) };
    static FORCED_SI_CODE: Cell<Option<i32>> = const { Cell::new(None) };
    static STEPS: RefCell<Vec<HolderStep>> = const { RefCell::new(Vec::new()) };
    static STEP_HOOKS: RefCell<Vec<(HolderStep, StepHook)>> = const { RefCell::new(Vec::new()) };
    static SIGNALS: Cell<u32> = const { Cell::new(0) };
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
pub(crate) fn force_peek_once(result: io::Result<Peek>) -> Forced {
    FORCED_PEEK.with(|f| *f.borrow_mut() = Some(result));
    Forced(|| FORCED_PEEK.with(|f| *f.borrow_mut() = None))
}

pub(crate) fn take_forced_peek() -> Option<io::Result<Peek>> {
    FORCED_PEEK.with(|f| f.borrow_mut().take())
}

/// The next consuming reap on this thread finds `what` instead of calling the OS.
pub(crate) fn force_reap_once(what: ForcedReap) -> Forced {
    FORCED_REAP.with(|f| f.set(Some(what)));
    Forced(|| FORCED_REAP.with(|f| f.set(None)))
}

pub(crate) fn take_forced_reap() -> Option<ForcedReap> {
    FORCED_REAP.with(Cell::take)
}

/// The next consuming `waitid` on this thread hands back a record with this `si_code`.
pub(crate) fn force_consuming_record_once(si_code: i32) -> Forced {
    FORCED_SI_CODE.with(|f| f.set(Some(si_code)));
    Forced(|| FORCED_SI_CODE.with(|f| f.set(None)))
}

pub(crate) fn take_forced_si_code() -> Option<i32> {
    FORCED_SI_CODE.with(Cell::take)
}

/// Record that the holder is about to take `step`, and run the hook registered for it, if any.
pub(crate) fn step(step: HolderStep) {
    STEPS.with(|s| s.borrow_mut().push(step));
    let hook = STEP_HOOKS.with(|h| {
        let mut hooks = h.borrow_mut();
        hooks.iter().position(|(s, _)| *s == step).map(|i| hooks.remove(i).1)
    });
    if let Some(hook) = hook {
        hook();
    }
}

/// Every step the holder took on this thread since the last call, in order.
pub(crate) fn holder_steps() -> Vec<HolderStep> {
    STEPS.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// Run `hook` on this thread just before its next `step`.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only Linux tests hook a holder step")
)]
pub(crate) fn on_holder_step(step: HolderStep, hook: impl FnOnce() + 'static) {
    STEP_HOOKS.with(|h| h.borrow_mut().push((step, Box::new(hook))));
}

/// Count one signal cosca sent to a child on this thread.
pub(crate) fn signal_sent() {
    SIGNALS.with(|s| s.set(s.get() + 1));
}

/// Signals cosca sent to a child on this thread since the last call.
pub(crate) fn signals_sent() -> u32 {
    SIGNALS.with(Cell::take)
}
