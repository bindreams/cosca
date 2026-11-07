//! The drain wait of a dropped leaf warns once when it is slow (principle 2). The leaf is a
//! [`FakeLeaf`] whose `cgroup.events` says a member still runs; the member is let go from the hook
//! that runs right after the warn, or, for a wait that never warned, from the one that runs when it
//! is about to block, so a missing warn fails the count below instead of hanging.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use super::CgroupLeaf;
use crate::containment::cgroup::fault;
use crate::containment::cgroup::test_support::{handle_of, pidfd_of, FakeLeaf};

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
