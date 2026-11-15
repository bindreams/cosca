//! A tree call on a group whose root some other reaper reaped, after this handle killed the tree: the
//! skip is no moot one.

use crate::containment::unix::fault::record_kill_group;
use crate::log_capture::warns_since;
use crate::test_child::reaped_elsewhere::session_cat;
use crate::test_groups::{stray_signal, Group};

/// A root some other reaper reaped after this handle killed the tree: its skip is no moot one, so the
/// call fails and warns.
///
/// Mutant: a skip is moot whatever reaped the root.
#[skuld::test]
fn kill_tree_after_a_kill_tree_and_a_foreign_reap_still_skips_and_warns(#[fixture(stray_signal)] _stray: &Group) {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let _killed = record_kill_group();
    let mut child = session_cat().spawn().expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    // The recorder takes the group's kill; the handle backstop ends the root.
    child.kill_tree().expect("kill the tree");
    // Released only after the kill: a kill that never came ends the root with status 0, which fails
    // here instead of leaving the reap to block.
    drop(stdin);
    let status = crate::test_child::reaped_elsewhere::reap_behind_status(child.pid());
    crate::test_child::assert_killed("the session root", status);
    let mark = crate::log_capture::mark();

    child
        .kill_tree()
        .expect_err("a root reaped elsewhere is not the handle's own reap");

    assert_eq!(warns_since(mark, "").len(), 1);
}
