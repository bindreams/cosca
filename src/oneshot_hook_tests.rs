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

#[test]
fn an_armed_hook_fires_once() {
    let (count, hook) = counter();
    let _guard = arm(&HOOK, hook);
    fire(&HOOK);
    fire(&HOOK);
    assert_eq!(count.get(), 1);
}

#[test]
fn firing_an_unarmed_slot_does_nothing() {
    fire(&HOOK);
}

#[test]
fn an_unfired_hook_is_cleared_and_dropped_with_its_guard() {
    let (count, hook) = counter();
    drop(arm(&HOOK, hook));
    fire(&HOOK);
    assert_eq!(count.get(), 0, "a dropped guard must take its hook with it");
    assert_eq!(Rc::strong_count(&count), 1, "the hook itself must be dropped");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "already armed")]
fn arming_over_a_live_hook_is_refused() {
    let _first = arm(&HOOK, || {});
    let _second = arm(&HOOK, || {});
}

/// The guard of a hook that already fired must leave a hook armed after it alone.
#[test]
fn a_guard_dropping_after_a_foreign_rearm_leaves_the_foreign_hook() {
    let first = arm(&HOOK, || {});
    fire(&HOOK);
    let (count, hook) = counter();
    let _second = arm(&HOOK, hook);
    drop(first);
    fire(&HOOK);
    assert_eq!(count.get(), 1, "the earlier guard cleared a hook it never armed");
}
