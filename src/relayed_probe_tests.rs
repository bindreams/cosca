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
#[skuld::test]
fn a_notification_reaches_the_installed_channel() {
    let (tx, rx) = channel();
    let _guard = install::<A>(tx);
    notify::<A>(7);
    assert_eq!(rx.try_iter().collect::<Vec<_>>(), [7]);
}

/// Mutant: make `Guard::drop` a no-op -> the notification still arrives.
#[skuld::test]
fn a_guard_uninstalls_on_drop() {
    let (tx, rx) = channel();
    drop(install::<A>(tx));
    notify::<A>(1);
    assert_eq!(rx.try_iter().count(), 0);
    assert!(!is_installed::<A>());
}

/// Mutant: delete the `debug_assert!` in `insert` -> no panic.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "nested on the same thread")]
fn installing_twice_on_one_thread_panics() {
    let (tx, _rx) = channel();
    let _outer = install::<A>(tx.clone());
    let _inner = install::<A>(tx);
}

/// Mutant: key `install` by `TypeId::of::<()>()` for every probe -> `B`'s install trips the
/// nesting assert.
#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
fn capturing_leaves_the_arming_threads_probe_installed() {
    let (tx, rx) = channel();
    let _guard = install::<A>(tx);
    drop(capture());
    notify::<A>(3);
    assert_eq!(rx.try_iter().collect::<Vec<_>>(), [3]);
}

/// A rejected nested install leaves the outer owner's channel installed, in debug (the install
/// panics) and in release (it is a no-op whose guard removes nothing).
///
/// Mutant: let `insert` overwrite an occupied slot -> the outer channel stops receiving.
/// Mutant: let a guard that inserted nothing remove the id -> the outer channel stops receiving
/// once the inner guard drops (release only; in debug the inner guard is never built).
#[skuld::test]
fn a_rejected_nested_install_leaves_the_outer_channel_receiving() {
    let (outer_tx, outer_rx) = channel();
    let (inner_tx, inner_rx) = channel();
    let _outer = install::<A>(outer_tx);
    let nested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(install::<A>(inner_tx))));
    assert_eq!(nested.is_err(), cfg!(debug_assertions));
    notify::<A>(5);
    assert_eq!(outer_rx.try_iter().collect::<Vec<_>>(), [5]);
    assert_eq!(inner_rx.try_iter().count(), 0);
}

/// A reinstall that hits an occupied slot must uninstall what it inserted, and only that: the
/// prior owner's entry stays. It panics in debug; in release it skips the occupied slot.
///
/// Mutant: build the `RelayGuard` after the insert loop -> `A` stays installed after the panic.
/// Mutant: record an id before its insert succeeds -> `B`'s original entry is removed.
#[skuld::test]
fn a_reinstall_onto_an_occupied_slot_touches_only_what_it_inserted() {
    let (a_tx, a_rx) = channel::<u8>();
    let (b_relay_tx, b_relay_rx) = channel::<&'static str>();
    let (b_orig_tx, b_orig_rx) = channel::<&'static str>();
    let relay = Relay(vec![
        (TypeId::of::<A>(), Box::new(a_tx) as Box<dyn Entry>),
        (TypeId::of::<B>(), Box::new(b_relay_tx) as Box<dyn Entry>),
    ]);
    std::thread::scope(|s| {
        s.spawn(move || {
            let _b = install::<B>(b_orig_tx);
            let reinstalled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| relay.reinstall()));
            assert_eq!(reinstalled.is_err(), cfg!(debug_assertions));
            drop(reinstalled);
            assert!(!is_installed::<A>(), "the inserted entry must be uninstalled");
            notify::<B>("original");
        });
    });
    assert_eq!(a_rx.try_iter().count(), 0);
    assert_eq!(b_relay_rx.try_iter().count(), 0);
    assert_eq!(b_orig_rx.try_iter().collect::<Vec<_>>(), ["original"]);
}

/// A slot whose entry is not `P`'s sender is a broken contract, not an absent probe.
///
/// Mutant: make `current` swallow a failed downcast -> it returns `None` instead of panicking.
#[skuld::test]
fn a_slot_holding_the_wrong_sender_type_panics() {
    let (wrong_tx, _wrong_rx) = channel::<&'static str>();
    assert!(insert(TypeId::of::<A>(), Box::new(wrong_tx)));
    let current = std::panic::catch_unwind(current::<A>);
    SLOTS.with(|slots| slots.borrow_mut().remove(&TypeId::of::<A>()));
    assert!(current.is_err(), "a mistyped slot must panic, not read as absent");
}
