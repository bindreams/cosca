//! The drain wait of an abandoned spawn's leaf, and of a dropped one, warns once when it is slow
//! (principle 2). The leaf is a [`FakeLeaf`] whose `cgroup.events` says a member still runs; the member is let go from the
//! hook that runs right after the warn, or, for a wait that never warned, from the one that runs
//! when it is about to block, so a missing warn fails the count below instead of hanging.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use super::leaf_tests::spawn_placing;
use super::CgroupLeaf;
use crate::child::owned::teardown::Past;
use crate::containment::cgroup::fault;
use crate::containment::cgroup::test_support::{handle_of, pidfd_of, FakeLeaf};
use crate::containment::Prepared;

const DRAIN_WARN: &str = "still waiting for it to drain";

/// Runs `end`, which tears down the leaf `fake` stands for, whose member `fake` keeps populated.
/// Answers the drain warns out at the member's release, and the levels of all of them.
fn drain_warns_at_release(fake: &FakeLeaf, end: impl FnOnce()) -> (Option<usize>, Vec<log::Level>) {
    crate::log_capture::install();
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&path, &events));
    let mark = crate::log_capture::mark();
    let warns_at_release = Rc::new(Cell::new(None));
    let _after_warn = fault::set_after_drain_warn({
        let (events, warns_at_release) = (fake.events.clone(), Rc::clone(&warns_at_release));
        move || {
            warns_at_release.set(Some(crate::log_capture::records_since(mark, DRAIN_WARN).len()));
            FakeLeaf::set_populated(&events, false);
        }
    });
    let _backstop = fault::set_before_drain_block({
        let (events, warns_at_release) = (fake.events.clone(), Rc::clone(&warns_at_release));
        move || {
            if warns_at_release.get().is_none() {
                warns_at_release.set(Some(crate::log_capture::records_since(mark, DRAIN_WARN).len()));
            }
            FakeLeaf::set_populated(&events, false);
        }
    });

    end();

    fault::take_rmdir_hook();
    assert!(!fake.leaf.exists(), "the drained leaf is removed");
    (
        warns_at_release.get(),
        crate::log_capture::levels_since(mark, DRAIN_WARN),
    )
}

/// Abandons a leaf (warning past `Duration::ZERO`) its child entered, whose member `FakeLeaf` keeps
/// populated; see [`drain_warns_at_release`].
#[allow(
    clippy::zombie_processes,
    reason = "the abandonment reaps the child through its pidfd; waiting by its number here could reach a reused pid"
)]
fn abandoned_drain_warns_at_release(name: &str, child_argv: &[&str], front: bool) -> (Option<usize>, Vec<log::Level>) {
    let fake = FakeLeaf::new(name, true);
    let leaf = CgroupLeaf::for_test_warning_after(fake.leaf.clone(), Some(Duration::ZERO));
    // Placed through `/dev/null`: the child reports `Placed`, so the leaf is entered.
    let child = spawn_placing(
        &leaf,
        child_argv,
        false,
        std::process::Stdio::piped(),
        std::process::Stdio::null(),
    );
    let pidfd = pidfd_of(child.id());
    drain_warns_at_release(&fake, || {
        let mut prepared = Prepared {
            mode: Some(crate::containment::ContainMode::Strongest),
            is_root: true,
            cgroup_leaf: Some(leaf),
        };
        prepared.abandon_before_verdict(front, Some((pidfd, Past::Clean)));
    })
}

/// A child that named itself and entered its leaf: the leaf is killed through, the child is torn
/// down through its handle, and the leaf is drained.
///
/// Mutant: `abandon_before_verdict` hands `remove_killing_through` a `NoWarn`. The leaf here is built
/// with its threshold; that `prepare` gives it one is `dispatch_tests`' row.
#[skuld::test]
fn an_abandoned_childs_leaf_drained_slowly_warns_once() {
    let (at_release, levels) = abandoned_drain_warns_at_release("cosca-abandoned-slow-drain", &["cat"], false);
    assert_eq!(
        at_release,
        Some(1),
        "one warn for the leaf, out before its member was let go"
    );
    assert_eq!(levels, [log::Level::Warn], "exactly one warn, at warn");
}

/// An elevation front that entered its leaf: the leaf is killed through and drained before the
/// front is waited for.
///
/// Mutant: `abandon_before_verdict` hands `remove_killing_through` a `NoWarn`.
#[skuld::test]
fn an_abandoned_fronts_leaf_drained_slowly_warns_once() {
    let (at_release, levels) = abandoned_drain_warns_at_release("cosca-abandoned-front-slow-drain", &["true"], true);
    assert_eq!(
        at_release,
        Some(1),
        "one warn for the leaf, out before its member was let go"
    );
    assert_eq!(levels, [log::Level::Warn], "exactly one warn, at warn");
}

/// A leaf its child entered (the verdict is taken), dropped while its member still runs, waits for
/// the drain through the warn its spawn's policy gave it at creation.
///
/// Mutant: the leaf's `Drop` waits with a `NoWarn`. The leaf here is built with its threshold; that
/// `prepare` gives it one is `dispatch_tests`' row.
#[skuld::test]
fn a_dropped_leafs_slow_drain_warns_once() {
    let fake = FakeLeaf::new("cosca-dropped-slow-drain", true);
    let mut leaf = CgroupLeaf::for_test_warning_after(fake.leaf.clone(), Some(Duration::ZERO));
    // SAFETY: the slot's channel lives as long as `leaf`.
    unsafe { leaf.placement_slot().report_placed_for_test() };
    // The verdict needs a live pid: this process's own stands in for the child.
    leaf.take_placement(handle_of(std::process::id(), &pidfd_of(std::process::id())))
        .expect("the child reported Placed");

    let (at_release, levels) = drain_warns_at_release(&fake, || drop(leaf));

    assert_eq!(
        at_release,
        Some(1),
        "one warn for the leaf, out before its member was let go"
    );
    assert_eq!(levels, [log::Level::Warn], "exactly one warn, at warn");
}
