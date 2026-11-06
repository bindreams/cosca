//! The tree drain of a failed async spawn's cleanup warns once, naming the leaf, when it passes
//! 1 s, and goes on waiting (principle 2).

use std::cell::Cell;

use crate::test_child::Console;
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
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    let mut child = cmd.spawn().expect("spawn");
    // The cleanup's thread arms the release: the hook is thread-local.
    let stdin = child.stdin().expect("piped stdin");

    // The cleanup runs on a thread of its own, as a failed spawn's does outside a runtime's tasks.
    let (failed, warns_at_release, levels, removed) = std::thread::scope(|s| {
        s.spawn(move || {
            let _warn = crate::tokio::child::fault::warn_slow_teardowns();
            // Released once the cleanup's root kill returned, before its reap.
            let teardown = crate::child::spawn::fault::release_between_kill_and_wait(stdin);
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
            teardown.assert_killed();
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

/// A drain watch that fails after a kill that landed does not make the kill a failure: the error
/// says the tree was killed and the watch could not be followed, and the one warn says the same.
///
/// Mutant: the cleanup makes the watch's failure the kill's outcome (the tree "could not be killed").
#[skuld::test]
async fn a_drain_watch_that_fails_after_a_landed_kill_is_reported_beside_it() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");

    let (detail, warns) = std::thread::scope(|s| {
        s.spawn(move || {
            let teardown = crate::child::spawn::fault::release_between_kill_and_wait(stdin);
            let (fake, leaf) = linux::fake_leaf("cosca-failed-write-unwatchable-drain", true);
            let child = linux::contained_by(child, leaf);
            // The kill lands; then the file the drain watch reads is garbage.
            let _corrupted = leaf_fault::set_after_kill_write({
                let events = fake.events.clone();
                move || std::fs::write(&events, "garbage\n").expect("corrupt cgroup.events")
            });
            let mark = crate::log_capture::mark();
            let (err, _fate) =
                crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
                    .expect_err("a failed write fails the spawn")
                    .expect_may_have_started_with();
            teardown.assert_killed();
            (
                err.to_string(),
                crate::log_capture::records_since_on_current_thread(
                    mark,
                    "tree teardown after a failed password write",
                ),
            )
        })
        .join()
        .expect("the cleanup")
    });

    assert!(detail.contains("its drain could not be watched"), "{detail}");
    assert!(!detail.contains("could not be killed"), "the kill landed: {detail}");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].1.contains("its drain could not be watched"), "{warns:?}");
}
