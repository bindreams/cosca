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

/// Told the `options` of each `waitid` this thread makes.
#[cfg(target_os = "linux")]
type WaitidObserver = Box<dyn FnMut(u32)>;

/// A registered step hook and the id its guard removes it by.
struct RegisteredHook {
    id: u64,
    step: HolderStep,
    hook: StepHook,
}

thread_local! {
    static FORCED_PEEK: RefCell<std::collections::VecDeque<io::Result<Peek>>> = const { RefCell::new(std::collections::VecDeque::new()) };
    static FORCED_REAP: Cell<Option<ForcedReap>> = const { Cell::new(None) };
    static FORCED_SI_CODE: Cell<Option<i32>> = const { Cell::new(None) };
    #[cfg(target_os = "linux")]
    static FORCED_VISIBLE_NONE: Cell<bool> = const { Cell::new(false) };
    #[cfg(target_os = "linux")]
    static WAITID_OBSERVER: RefCell<Option<WaitidObserver>> = const { RefCell::new(None) };
    static STEPS: RefCell<Vec<HolderStep>> = const { RefCell::new(Vec::new()) };
    static STEP_HOOKS: RefCell<Vec<RegisteredHook>> = const { RefCell::new(Vec::new()) };
    static NEXT_HOOK_ID: Cell<u64> = const { Cell::new(0) };
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
    force_peeks([result])
}

/// The next peeks on this thread answer `results`, one each and in order, then the OS answers again.
pub(crate) fn force_peeks(results: impl IntoIterator<Item = io::Result<Peek>>) -> Forced {
    FORCED_PEEK.with(|f| *f.borrow_mut() = results.into_iter().collect());
    Forced(|| FORCED_PEEK.with(|f| f.borrow_mut().clear()))
}

pub(crate) fn take_forced_peek() -> Option<io::Result<Peek>> {
    FORCED_PEEK.with(|f| f.borrow_mut().pop_front())
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

/// The next blocking `waitid` in `wait_visible_exit` or `reap_blocking` on this thread finds no
/// record, which the kernel never answers.
#[cfg(target_os = "linux")]
pub(crate) fn force_visible_none_once() -> Forced {
    FORCED_VISIBLE_NONE.with(|f| f.set(true));
    Forced(|| FORCED_VISIBLE_NONE.with(|f| f.set(false)))
}

#[cfg(target_os = "linux")]
pub(crate) fn take_forced_visible_none() -> bool {
    FORCED_VISIBLE_NONE.with(Cell::take)
}

/// Every `waitid` this thread makes reports its `options` to `observer`, until the guard drops.
/// The observer may panic: that fails the test at the call that broke the contract.
#[cfg(target_os = "linux")]
pub(crate) fn observe_waitid(observer: impl FnMut(u32) + 'static) -> Forced {
    WAITID_OBSERVER.with(|o| *o.borrow_mut() = Some(Box::new(observer)));
    Forced(|| WAITID_OBSERVER.with(|o| *o.borrow_mut() = None))
}

#[cfg(target_os = "linux")]
pub(crate) fn waitid_called(options: u32) {
    // Taken out for the call, so an observer that panics leaves no borrow behind.
    let observer = WAITID_OBSERVER.with(|o| o.borrow_mut().take());
    if let Some(mut observer) = observer {
        observer(options);
        WAITID_OBSERVER.with(|o| {
            o.borrow_mut().get_or_insert(observer);
        });
    }
}

/// Record that the holder is about to take `step`, and run the hook registered for it, if any.
pub(crate) fn step(step: HolderStep) {
    STEPS.with(|s| s.borrow_mut().push(step));
    let hook = STEP_HOOKS.with(|h| {
        let mut hooks = h.borrow_mut();
        hooks.iter().position(|h| h.step == step).map(|i| hooks.remove(i).hook)
    });
    if let Some(hook) = hook {
        hook();
    }
}

/// Every step the holder took on this thread since the last call, in order.
pub(crate) fn holder_steps() -> Vec<HolderStep> {
    STEPS.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// Removes its own unfired step hook on drop, and no other.
#[must_use = "dropping this immediately removes the hook; bind it for the probe's duration"]
pub(crate) struct StepHookGuard(u64);

impl Drop for StepHookGuard {
    fn drop(&mut self) {
        STEP_HOOKS.with(|h| h.borrow_mut().retain(|hook| hook.id != self.0));
    }
}

/// Run `hook` on this thread just before its next `step`.
pub(crate) fn on_holder_step(step: HolderStep, hook: impl FnOnce() + 'static) -> StepHookGuard {
    let id = NEXT_HOOK_ID.with(|n| n.replace(n.get() + 1));
    STEP_HOOKS.with(|h| {
        h.borrow_mut().push(RegisteredHook {
            id,
            step,
            hook: Box::new(hook),
        });
    });
    StepHookGuard(id)
}

/// Count one signal cosca sent to a child on this thread.
pub(crate) fn signal_sent() {
    SIGNALS.with(|s| s.set(s.get() + 1));
}

/// Signals cosca sent to a child on this thread since the last call.
pub(crate) fn signals_sent() -> u32 {
    SIGNALS.with(Cell::take)
}
