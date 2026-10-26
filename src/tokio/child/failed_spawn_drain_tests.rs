//! The tree drain of a failed async spawn's cleanup warns once, naming the leaf, when it passes
//! 1 s, and goes on waiting (principle 2).

use std::cell::Cell;
use std::rc::Rc;

use super::child_drop_tests::linux;
use crate::containment::cgroup::fault as leaf_fault;
use crate::containment::cgroup::test_support::FakeLeaf;

/// `finish_elevated` after a failed elevation write kills the tree and waits for its leaf to drain
/// (`Child::block_until_members_drained`). The fake leaf's member is released from the hook that
/// runs right after the warn, which records how many warns were out by then.
///
/// A wait that blocks with no warn releases the member too, so a wait that never warned fails the
/// assertion on the warns out by then instead of hanging.
///
/// Mutants: the drain wait's warn call is removed (the hook still runs, and finds no warn);
/// `block_until_members_drained` waits with `NoWarn` (the blocking wait's hook finds no warn).
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
            let _backstop = leaf_fault::set_before_drain_block({
                let (events, warns_at_release) = (fake.events.clone(), Rc::clone(&warns_at_release));
                move || {
                    if warns_at_release.get().is_none() {
                        warns_at_release.set(Some(
                            crate::log_capture::records_since(mark, "still waiting for it to drain").len(),
                        ));
                    }
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
