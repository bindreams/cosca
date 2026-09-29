use super::*;
use std::sync::mpsc::channel;

struct A;
impl Probe for A {
    type Event = u8;
}

struct B;
impl Probe for B {
    type Event = &'static str;
}

/// Mutant: make `notify` a no-op -> nothing arrives.
#[test]
fn a_notification_reaches_the_installed_channel() {
    let (tx, rx) = channel();
    let _guard = install::<A>(tx);
    notify::<A>(7);
    assert_eq!(rx.try_iter().collect::<Vec<_>>(), [7]);
}

/// Mutant: make `Guard::drop` a no-op -> the notification still arrives.
#[test]
fn a_guard_uninstalls_on_drop() {
    let (tx, rx) = channel();
    drop(install::<A>(tx));
    notify::<A>(1);
    assert_eq!(rx.try_iter().count(), 0);
    assert!(!is_installed::<A>());
}

/// Mutant: delete the `debug_assert!` in `insert` -> no panic.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "nested on the same thread")]
fn installing_twice_on_one_thread_panics() {
    let (tx, _rx) = channel();
    let _outer = install::<A>(tx.clone());
    let _inner = install::<A>(tx);
}

/// Mutant: key `install` by `TypeId::of::<()>()` for every probe -> `B`'s install trips the
/// nesting assert.
#[test]
fn distinct_probes_do_not_share_a_slot() {
    let (a_tx, a_rx) = channel();
    let (b_tx, b_rx) = channel();
    let _a = install::<A>(a_tx);
    let _b = install::<B>(b_tx);
    notify::<A>(1);
    notify::<B>("b");
    assert_eq!(a_rx.try_iter().collect::<Vec<_>>(), [1]);
    assert_eq!(b_rx.try_iter().collect::<Vec<_>>(), ["b"]);
}

/// Mutant: make the slot process-global -> the other thread's notification arrives.
#[test]
fn another_thread_does_not_see_this_threads_probe() {
    let (tx, rx) = channel();
    let _guard = install::<A>(tx);
    std::thread::scope(|s| {
        s.spawn(|| {
            assert!(!is_installed::<A>());
            notify::<A>(1);
        });
    });
    assert_eq!(rx.try_iter().count(), 0);
}

/// Every installed probe reaches the other thread, and only for the reinstall guard's scope.
///
/// Mutant: make `capture` skip one probe -> the other thread lacks it.
/// Mutant: make `RelayGuard::drop` a no-op -> the pool thread keeps its probes.
#[test]
fn a_relay_carries_every_probe_for_the_guards_scope() {
    let (a_tx, a_rx) = channel();
    let (b_tx, b_rx) = channel();
    let _a = install::<A>(a_tx);
    let _b = install::<B>(b_tx);
    let relay = capture();
    std::thread::scope(|s| {
        s.spawn(move || {
            assert!(!is_installed::<A>() && !is_installed::<B>());
            let guard = relay.reinstall();
            notify::<A>(2);
            notify::<B>("relayed");
            drop(guard);
            assert!(
                !is_installed::<A>() && !is_installed::<B>(),
                "the relay must not outlive its guard"
            );
        });
    });
    assert_eq!(a_rx.try_iter().collect::<Vec<_>>(), [2]);
    assert_eq!(b_rx.try_iter().collect::<Vec<_>>(), ["relayed"]);
}

/// Mutant: make `capture` remove what it reads -> the arming thread loses its probe.
#[test]
fn capturing_leaves_the_arming_threads_probe_installed() {
    let (tx, rx) = channel();
    let _guard = install::<A>(tx);
    drop(capture());
    notify::<A>(3);
    assert_eq!(rx.try_iter().collect::<Vec<_>>(), [3]);
}
