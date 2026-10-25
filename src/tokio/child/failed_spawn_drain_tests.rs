//! The tree drain of a failed async spawn's cleanup warns once, naming the leaf, when it passes
//! 1 s, and goes on waiting (principle 2).

use std::cell::Cell;
use std::rc::Rc;

use super::child_drop_tests::linux;
use crate::containment::cgroup::fault as leaf_fault;
use crate::containment::cgroup::test_support::FakeLeaf;
use crate::test_groups::{cgroup, Group};

/// `finish_elevated` after a failed elevation write kills the tree and waits for its leaf to drain
/// (`Child::block_until_members_drained`). The fake leaf's member is released from the hook that
/// runs right after the warn, which records how many warns were out by then.
///
/// Mutant: the drain wait's warn call is removed (the hook still runs, and finds no warn).
#[skuld::test]
async fn a_failed_elevation_writes_drain_warns_once_past_1s() {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    let mut child = cmd.spawn().expect("spawn");
    let _stdin = child.stdin().expect("piped stdin");

    // The cleanup runs on a thread of its own, as a failed spawn's does outside a runtime's tasks.
    let (failed, warns_at_release, levels, removed) = std::thread::scope(|s| {
        s.spawn(move || {
            let _warn = crate::tokio::child::fault::warn_slow_teardowns();
            let name = "cosca-failed-write-slow-drain";
            let (fake, leaf) = linux::fake_leaf(name, true);
            let child = linux::contained_by(child, leaf);
            let mark = crate::log_capture::mark();
            let warns_at_release = Rc::new(Cell::new(None));
            let _after_warn = leaf_fault::set_after_drain_warn({
                let (events, warns_at_release) = (fake.events.clone(), Rc::clone(&warns_at_release));
                move || {
                    warns_at_release.set(Some(
                        crate::log_capture::records_since(mark, "still waiting for it to drain").len(),
                    ));
                    FakeLeaf::set_populated(&events, false);
                }
            });
            let failed =
                crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
                    .map(drop)
                    .is_err();
            leaf_fault::take_rmdir_hook();
            (
                failed,
                warns_at_release.get(),
                crate::log_capture::levels_since(mark, "still waiting for it to drain"),
                !fake.leaf.exists(),
            )
        })
        .join()
        .expect("the cleanup")
    });

    assert!(failed, "the failed write fails the spawn");
    assert_eq!(
        warns_at_release,
        Some(1),
        "one warn for the leaf, out before its member was released"
    );
    assert_eq!(levels, [log::Level::Warn], "exactly one warn, at warn");
    assert!(removed, "the drained leaf is removed");
}

/// A spawn that succeeds hands its leaf to the handle, whose armed drop warns of a slow drain
/// itself: the leaf must not also warn from its own `Drop`, which would make two warns of one wait.
///
/// Mutant: a successful spawn leaves the failed-spawn warn set on its leaf.
#[skuld::test]
async fn a_successful_spawn_leaves_its_leaf_to_the_armed_drops_warn(#[fixture(cgroup)] _group: &Group) {
    let _warn = crate::tokio::child::fault::warn_slow_teardowns();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.contain_with(crate::ContainMode::Strongest);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    let mut child = cmd.spawn().expect("spawn");
    let _stdin = child.stdin().expect("piped stdin");
    let crate::containment::Attached::Cgroup(leaf) = &child.os.attached else {
        panic!("expected a cgroup leaf, got {:?}", child.os.attached);
    };
    assert_eq!(leaf.drain_warn_after_for_test(), None);
}
