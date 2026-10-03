//! `members` against REAL namespace layouts, in re-exec'd children (see `test_child::namespaces`
//! for the group's gating).

use super::members;
use crate::test_child::namespaces as ns;
use crate::test_child::{await_member_ready, fixture_path, member_command};

/// pid 1 of a new pid namespace whose `/proc` is still the outer one: its listing names the
/// outer namespace's processes, whose pgids mean nothing to this caller. Mutant: "scan `/proc`
/// whatever the view" — the outer processes whose pgid is 1 are returned.
#[skuld::test]
fn namespaces_an_outer_procfs_lists_no_group() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_group_outer));
}

#[skuld::test]
fn fixture_group_outer() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_group_inner));
}

#[skuld::test]
fn fixture_group_inner() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    let err = members(1).expect_err("an outer procfs must not be scanned");
    assert!(err.to_string().contains("outer pid namespace"), "{err}");
}

/// A file mounted over a member's `stat` is a mount below `/proc`, which no read crosses: the
/// listing is an error, never an exclusion. Mutant: "read `stat` with a plain `openat`" — the fake
/// record (another pgid) is read and the live member is silently excluded.
#[skuld::test]
fn namespaces_a_stat_mounted_over_a_member_is_an_error_not_an_exclusion() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_group_stat_overmount));
}

#[skuld::test]
fn fixture_group_stat_overmount() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn the member");
    await_member_ready(&mut child);
    let pid = child.id();
    let scratch = tempfile::tempdir().expect("tempdir");
    let fake = scratch.path().join("stat");
    let zeros = ["0"; 16].join(" ");
    std::fs::write(&fake, format!("{pid} (fake) S 1 999 {zeros} 1 0\n")).expect("write the fake stat");
    ns::bind_over(&fake, std::path::Path::new(&format!("/proc/{pid}/stat")));

    let err = members(pid as i32).expect_err("a stat behind a mount must not be read or skipped");
    assert!(err.to_string().contains("mount"), "{err}");

    _ = child.kill();
    _ = child.wait();
}
