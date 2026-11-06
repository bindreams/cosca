use super::{arm, fire, OneShotHook};
use std::cell::Cell;
use std::rc::Rc;

thread_local! {
    static HOOK: OneShotHook = const { OneShotHook::new() };
}

fn counter() -> (Rc<Cell<u32>>, impl FnOnce() + 'static) {
    let count = Rc::new(Cell::new(0));
    let seen = count.clone();
    (count, move || seen.set(seen.get() + 1))
}

#[skuld::test]
fn an_armed_hook_fires_once() {
    let (count, hook) = counter();
    let _guard = arm(&HOOK, hook);
    fire(&HOOK);
    fire(&HOOK);
    assert_eq!(count.get(), 1);
}

#[skuld::test]
fn firing_an_unarmed_slot_does_nothing() {
    fire(&HOOK);
}

#[skuld::test]
fn an_unfired_hook_is_cleared_and_dropped_with_its_guard() {
    let (count, hook) = counter();
    drop(arm(&HOOK, hook));
    fire(&HOOK);
    assert_eq!(count.get(), 0, "a dropped guard must take its hook with it");
    assert_eq!(Rc::strong_count(&count), 1, "the hook itself must be dropped");
}

#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "already armed")]
fn arming_over_a_live_hook_is_refused() {
    let _first = arm(&HOOK, || {});
    let _second = arm(&HOOK, || {});
}

/// The guard of a hook that already fired must leave a hook armed after it alone.
#[skuld::test]
fn a_guard_dropping_after_a_foreign_rearm_leaves_the_foreign_hook() {
    let first = arm(&HOOK, || {});
    fire(&HOOK);
    let (count, hook) = counter();
    let _second = arm(&HOOK, hook);
    drop(first);
    fire(&HOOK);
    assert_eq!(count.get(), 1, "the earlier guard cleared a hook it never armed");
}

/// A guard whose hook fired is satisfied, and a later arming does not unsatisfy it.
///
/// Mutant: `assert_fired` reads the slot, not the guard's own flag, so a foreign hook armed after
/// the fire makes the fired guard panic.
#[skuld::test]
fn assert_fired_is_satisfied_by_a_hook_that_fired() {
    let first = arm(&HOOK, || {});
    fire(&HOOK);
    first.assert_fired();
    let _second = arm(&HOOK, || {});
    first.assert_fired();
}

/// A hook that left the slot without firing (replaced by an arming over it) is not fired, and a
/// later hook's fire does not make it so.
///
/// Mutant: `assert_fired` reads whether the guard's hook is still in the slot, so a hook that left
/// it any other way passes.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "never fired")]
fn assert_fired_panics_for_a_hook_replaced_before_it_fired() {
    let first = arm(&HOOK, || {});
    let replaced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| arm(&HOOK, || {})));
    assert!(replaced.is_err(), "arming over a live hook is refused in debug");
    fire(&HOOK);
    first.assert_fired();
}

#[skuld::test]
#[should_panic(expected = "never fired")]
fn assert_fired_panics_for_a_hook_that_is_still_armed() {
    let guard = arm(&HOOK, || {});
    guard.assert_fired();
}
