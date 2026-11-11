//! A tree call on a group whose root this handle reaped, whose pid names no process: it sends
//! nothing by the number. After this handle killed the tree there is nothing left to skip, so the
//! call answers as the drop does and warns of nothing; after a skip the tree stays unkilled, and a
//! terminate never marks it.

use std::time::Duration;

use crate::containment::unix::fault::{record_kill_group, KillGroupRecorder};
use crate::identity::Resolved;
use crate::log_capture::warns_since;
use crate::test_child::reaped_elsewhere::{kill_own_child, session_sleep};

/// A session child whose root this handle reaped, with its pid reading as naming no process, and the
/// guards that keep that so.
struct Reaped {
    child: crate::Child,
    killed: KillGroupRecorder,
    _gone: crate::child::fault::ForcedRootReads,
    #[cfg(target_os = "linux")]
    _old_kernel: crate::containment::unix::fault::Refused,
}

/// [`Reaped`] over a tree the handle `killed` before the reap, or whose root died of the test's own
/// signal.
fn reaped(kill_tree_first: bool) -> Reaped {
    reaped_reading(kill_tree_first, Resolved::Gone)
}

/// [`reaped`], with the root's pid reading as `read`.
fn reaped_reading(kill_tree_first: bool, read: Resolved<crate::identity::ProcessId>) -> Reaped {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let killed = record_kill_group();
    let child = session_sleep().spawn().expect("spawn");
    if kill_tree_first {
        // The recorder takes the group's kill; the handle backstop ends the root.
        child.kill_tree().expect("kill the tree");
    } else {
        kill_own_child(child.pid());
    }
    child.wait().expect("this handle reaps the root");
    Reaped {
        child,
        killed,
        _gone: crate::child::fault::force_root_reads(read),
        #[cfg(target_os = "linux")]
        _old_kernel,
    }
}

#[skuld::test]
fn kill_tree_after_a_kill_tree_and_the_own_reap_is_ok_and_warns_nothing() {
    let setup = reaped(true);
    let sent_before = setup.killed.killed().len();
    let mark = crate::log_capture::mark();

    setup.child.kill_tree().expect("the tree is already killed");

    assert_eq!(warns_since(mark, ""), Vec::<String>::new());
    assert_eq!(
        setup.killed.killed().len(),
        sent_before,
        "nothing is sent by the number"
    );
}

/// A pid that cannot be read after the own reap is skipped like one that names no process, so a tree
/// the handle killed has nothing left for the skip to leave undone.
#[skuld::test]
fn kill_tree_after_a_kill_tree_and_the_own_reap_with_an_unreadable_pid_is_ok_and_warns_nothing() {
    let setup = reaped_reading(true, Resolved::Unknown);
    let sent_before = setup.killed.killed().len();
    let mark = crate::log_capture::mark();

    setup.child.kill_tree().expect("the tree is already killed");

    assert_eq!(warns_since(mark, ""), Vec::<String>::new());
    assert_eq!(
        setup.killed.killed().len(),
        sent_before,
        "nothing is sent by the number"
    );
}

/// A root some other reaper reaped after this handle killed the tree is not the own reap: its skip
/// is no moot one, so the call fails and warns.
///
/// Mutant: a skip is moot whatever reaped the root.
#[skuld::test]
fn kill_tree_after_a_kill_tree_and_a_foreign_reap_still_skips_and_warns() {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let _killed = record_kill_group();
    let child = session_sleep().spawn().expect("spawn");
    // The recorder takes the group's kill; the handle backstop ends the root.
    child.kill_tree().expect("kill the tree");
    crate::test_child::reaped_elsewhere::reap_behind(child.pid());
    let mark = crate::log_capture::mark();

    child
        .kill_tree()
        .expect_err("a root reaped elsewhere is not the handle's own reap");

    assert_eq!(warns_since(mark, "").len(), 1);
}

#[skuld::test]
fn terminate_tree_after_a_kill_tree_and_the_own_reap_is_ok_and_warns_nothing() {
    let setup = reaped(true);
    let mark = crate::log_capture::mark();

    setup.child.terminate_tree().expect("the tree is already killed");

    assert_eq!(warns_since(mark, ""), Vec::<String>::new());
}

#[skuld::test]
fn graceful_shutdown_tree_after_a_kill_tree_and_the_own_reap_is_ok_and_warns_nothing() {
    let setup = reaped(true);
    let mark = crate::log_capture::mark();

    setup
        .child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect("the tree is already killed, and the status is this handle's own");

    assert_eq!(warns_since(mark, ""), Vec::<String>::new());
}

/// A kill that skipped what the pid names is not a kill: the tree stays unkilled, so the drop that
/// follows warns of it, once.
#[skuld::test]
fn a_skipped_kill_tree_leaves_the_tree_unkilled_so_the_drop_warns_once() {
    let setup = reaped(false);
    setup
        .child
        .kill_tree()
        .expect_err("a pid that names no process is not assessable");

    let mark = crate::log_capture::mark();
    drop(setup.child);

    let warns = warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains(crate::child::drop_report::END_THEM_BEFORE_WAIT),
        "{warns:?}"
    );
}

/// A cooperative signal is not a kill: a `terminate_tree` that skipped what the pid names does not
/// mark the tree killed, so `kill_tree` still skips and says so, and the drop still warns.
#[skuld::test]
fn terminate_tree_after_the_own_reap_does_not_mark_the_tree_killed() {
    let setup = reaped(false);
    setup
        .child
        .terminate_tree()
        .expect_err("a pid that names no process is not assessable");
    setup
        .child
        .kill_tree()
        .expect_err("the tree was never killed, so the skip still answers");

    let mark = crate::log_capture::mark();
    drop(setup.child);

    let warns = warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
}
