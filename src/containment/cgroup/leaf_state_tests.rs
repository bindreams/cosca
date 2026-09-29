//! `proc_state` reads a child's state only through the checked `/proc` view.

use super::proc_state;
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};
use crate::test_child::namespaces as ns;
use crate::test_child::{fixture_path, member_command};

#[test]
fn a_live_process_has_a_state_under_the_ordinary_view() {
    assert!(proc_state(std::process::id()).is_some());
}

/// Mutant: "read `/proc/{pid}/stat` by path whatever the view".
#[test]
fn no_state_is_read_when_the_view_is_diverged_or_unassessable() {
    for view in [ForcedView::Diverged, ForcedView::Unassessable] {
        let _forced = force_proc_view_once(view);
        assert_eq!(proc_state(std::process::id()), None, "{view:?}");
    }
}

/// pid 1 of a new pid namespace whose `/proc` is still the outer one: `/proc/1` is the outer
/// init, whose state says nothing about this process. Mutant: "read by path".
#[test]
fn namespaces_an_outer_procfs_gives_no_state() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_state_outer));
}

#[test]
fn fixture_state_outer() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_state_inner));
}

#[test]
fn fixture_state_inner() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    assert_eq!(proc_state(1), None);
}

/// A file mounted over a child's `stat` is not read. Mutant: "read by path" — the fake record's
/// state letter comes back.
#[test]
fn namespaces_a_stat_mounted_over_gives_no_state() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_state_overmount));
}

#[test]
fn fixture_state_overmount() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let mut child = {
        let _guard = crate::child::spawn::spawn_lock();
        member_command(0).spawn().expect("spawn the member")
    };
    crate::test_child::await_member_ready(&mut child);
    let pid = child.id();
    assert!(proc_state(pid).is_some(), "the member has a state before the mount");
    let scratch = tempfile::tempdir().expect("tempdir");
    let fake = scratch.path().join("stat");
    let zeros = ["0"; 16].join(" ");
    std::fs::write(&fake, format!("{pid} (fake) Z 1 1 {zeros} 1 0\n")).expect("write the fake stat");
    ns::bind_over(&fake, std::path::Path::new(&format!("/proc/{pid}/stat")));
    assert_eq!(proc_state(pid), None);

    _ = child.kill();
    _ = child.wait();
}
