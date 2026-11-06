//! The tree drain of a failed async spawn's cleanup warns once, naming the leaf, when it passes
//! 1 s, and goes on waiting (principle 2).

use std::cell::{Cell, RefCell};

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

/// A drain that could not be watched is not a settled tree: the cleanup leaves the handle armed, so
/// its drop writes `cgroup.kill` again and waits for the drain again. The drop's wait is reached
/// (the leaf's `cgroup.events` is readable again by then, and populated until the wait is about to
/// block), and the drained leaf is removed.
///
/// Mutants: the cleanup disarms the handle once the kill landed, whether or not its drain was
/// watched (no second kill write); the armed drop gives the leaf up without waiting for its drain
/// (the wait is never reached).
#[skuld::test]
async fn a_drain_watch_that_fails_leaves_the_handle_armed_to_watch_it_again() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");

    let (kill_written_by_the_drop, waited_for_the_drain, removed) = std::thread::scope(|s| {
        s.spawn(move || {
            let teardown = crate::child::spawn::fault::release_between_kill_and_wait(stdin);
            let (fake, leaf) = linux::fake_leaf("cosca-failed-write-rearmed-drain", true);
            let child = linux::contained_by(child, leaf);
            let waited = Rc::new(Cell::new(false));
            // Hooks armed from inside a hook: kept until the end.
            let armed = Rc::new(RefCell::new(Vec::new()));
            // The first kill lands; then the file the drain watch reads is garbage. The drop's kill
            // makes it readable again, populated until the drop's wait is about to block.
            let _corrupted = leaf_fault::set_after_kill_write({
                let (events, kill) = (fake.events.clone(), fake.kill.clone());
                let (waited, armed) = (Rc::clone(&waited), Rc::clone(&armed));
                move || {
                    std::fs::write(&events, "garbage\n").expect("corrupt cgroup.events");
                    // Only a later write of `cgroup.kill` shows.
                    std::fs::write(&kill, b"").expect("clear cgroup.kill");
                    let repaired = leaf_fault::set_after_kill_write({
                        let (events, waited, armed) = (events.clone(), Rc::clone(&waited), Rc::clone(&armed));
                        move || {
                            std::fs::write(&events, "populated 1\nfrozen 0\n").expect("repair cgroup.events");
                            let released = leaf_fault::set_before_drain_block(move || {
                                waited.set(true);
                                FakeLeaf::set_populated(&events, false);
                            });
                            armed.borrow_mut().push(released);
                        }
                    });
                    armed.borrow_mut().push(repaired);
                }
            });
            let failed =
                crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
                    .map(drop)
                    .is_err();
            assert!(failed, "the failed write fails the spawn");
            leaf_fault::take_rmdir_hook();
            teardown.assert_killed();
            (!fake.kill_written().is_empty(), waited.get(), !fake.leaf.exists())
        })
        .join()
        .expect("the cleanup")
    });

    assert!(kill_written_by_the_drop, "the armed drop kills the leaf again");
    assert!(waited_for_the_drain, "the armed drop waits for the leaf's drain again");
    assert!(removed, "the drained leaf is removed");
}

/// A drain watch that failed is reported by the cleanup as its own kind of failure: the armed
/// drop's own failure to kill the tree is not a repeat of it, and warns.
///
/// Mutant: the cleanup files the drain watch's failure as the tree's kill failure, so the drop's
/// report of a failed kill counts as already warned of.
#[skuld::test]
async fn a_drain_watch_that_fails_does_not_hide_the_armed_drops_own_failed_kill() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");

    let levels = std::thread::scope(|s| {
        s.spawn(move || {
            let teardown = crate::child::spawn::fault::release_between_kill_and_wait(stdin);
            let (fake, leaf) = linux::fake_leaf("cosca-failed-write-drain-then-kill", true);
            let child = linux::contained_by(child, leaf);
            let drop_kill_fails = Rc::new(RefCell::new(None));
            // The first kill lands; then the file the drain watch reads is garbage, and the next
            // kill (the drop's) is refused.
            let _corrupted = leaf_fault::set_after_kill_write({
                let (events, drop_kill_fails) = (fake.events.clone(), Rc::clone(&drop_kill_fails));
                move || {
                    std::fs::write(&events, "garbage\n").expect("corrupt cgroup.events");
                    *drop_kill_fails.borrow_mut() = Some(leaf_fault::fail_next_kill_write());
                }
            });
            let mark = crate::log_capture::mark();
            let failed =
                crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
                    .map(drop)
                    .is_err();
            assert!(failed, "the failed write fails the spawn");
            leaf_fault::take_rmdir_hook();
            teardown.assert_killed();
            crate::log_capture::records_since_on_current_thread(mark, "contained-tree teardown did not fully succeed")
                .into_iter()
                .map(|(level, _)| level)
                .collect::<Vec<_>>()
        })
        .join()
        .expect("the cleanup")
    });

    assert_eq!(
        levels,
        [log::Level::Warn],
        "the drop's own failed kill is a warn of its own"
    );
}
