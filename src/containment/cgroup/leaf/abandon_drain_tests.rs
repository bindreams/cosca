//! The drain wait of an abandoned spawn's leaf warns once when it is slow (principle 2). The leaf is
//! a [`FakeLeaf`] whose `cgroup.events` says a member still runs; the member is let go from the
//! hook that runs right after the warn, or, for a wait that never warned, from the one that runs
//! when it is about to block, so a missing warn fails the count below instead of hanging.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use super::leaf_tests::spawn_placing;
use super::CgroupLeaf;
use crate::containment::cgroup::fault;
use crate::containment::cgroup::test_support::FakeLeaf;
use crate::containment::Prepared;

const DRAIN_WARN: &str = "still waiting for it to drain";

/// Abandons, through [`Prepared::abandon_before_verdict`] with a zero threshold, a leaf its child
/// entered and whose member `FakeLeaf` keeps populated; `front` says the child is an elevation
/// front. Answers how many drain warns were out when the member was let go, and the levels of all
/// of them.
#[allow(
    clippy::zombie_processes,
    reason = "the abandonment reaps the child through its pidfd; waiting by its number here could reach a reused pid"
)]
fn drain_warns_at_release(name: &str, child_argv: &[&str], front: bool) -> (Option<usize>, Vec<log::Level>) {
    crate::log_capture::install();
    let fake = FakeLeaf::new(name, true);
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&path, &events));
    let leaf = CgroupLeaf::for_test_at(fake.leaf.clone());
    // Placed through `/dev/null`: the child reports `Placed`, so the leaf is entered.
    let _child = spawn_placing(
        &leaf,
        child_argv,
        false,
        std::process::Stdio::piped(),
        std::process::Stdio::null(),
    );
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

    let mut prepared = Prepared {
        mode: Some(crate::containment::ContainMode::Strongest),
        is_root: true,
        cgroup_leaf: Some(leaf),
        teardown_warn_after: Some(Duration::ZERO),
    };
    prepared.abandon_before_verdict(front, None);

    fault::take_rmdir_hook();
    assert!(!fake.leaf.exists(), "the drained leaf is removed");
    (
        warns_at_release.get(),
        crate::log_capture::levels_since(mark, DRAIN_WARN),
    )
}

/// A child that named itself and entered its leaf: killed through its handle, then the leaf is
/// killed through and drained.
///
/// Mutants: `abandon_before_verdict` hands `remove_killing_through` a `NoWarn`; the `Prepared` hands
/// the leaf no threshold.
#[skuld::test]
fn an_abandoned_childs_leaf_drained_slowly_warns_once() {
    let (at_release, levels) = drain_warns_at_release("cosca-abandoned-slow-drain", &["cat"], false);
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
/// Mutant: `abandon_front` hands `remove_killing_through` a `NoWarn`.
#[skuld::test]
fn an_abandoned_fronts_leaf_drained_slowly_warns_once() {
    let (at_release, levels) = drain_warns_at_release("cosca-abandoned-front-slow-drain", &["true"], true);
    assert_eq!(
        at_release,
        Some(1),
        "one warn for the leaf, out before its member was let go"
    );
    assert_eq!(levels, [log::Level::Warn], "exactly one warn, at warn");
}
