//! `process_parents` against REAL namespace layouts, in re-exec'd children (see
//! `test_child::namespaces` for the group's gating).

use super::process_parents;
use crate::test_child::namespaces as ns;
use crate::test_child::{await_member_ready, fixture_path, member_command};

/// pid 1 of a new pid namespace whose `/proc` is still the outer one: the snapshot is
/// `Unassessable`, neither the outer namespace's processes nor an empty list. Mutants: "scan
/// `/proc` whatever the view"; "return an empty snapshot".
#[test]
fn namespaces_an_outer_procfs_is_unassessable() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_enumerate_outer));
}

#[test]
fn fixture_enumerate_outer() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_enumerate_inner));
}

#[test]
fn fixture_enumerate_inner() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    match process_parents() {
        Err(crate::error::Error::Unassessable { detail, .. }) => {
            assert!(detail.contains("outer pid namespace"), "{detail}")
        }
        other => panic!("an outer procfs must be Unassessable, got {other:?}"),
    }
}

/// A file mounted over a process's `stat` is not read: the process is omitted, not listed with
/// the fake parent. Mutant: "read `stat` with a plain `openat`".
#[test]
fn namespaces_a_stat_mounted_over_is_omitted_not_read() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_enumerate_stat_overmount));
}

#[test]
fn fixture_enumerate_stat_overmount() {
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
    std::fs::write(&fake, format!("{pid} (fake) S 4242 999 {zeros} 1 0\n")).expect("write the fake stat");
    ns::bind_over(&fake, std::path::Path::new(&format!("/proc/{pid}/stat")));

    let snapshot = process_parents().expect("the /proc view is this namespace's");
    assert!(
        !snapshot.iter().any(|&(p, _)| p == pid),
        "a stat behind a mount must be omitted, got {:?}",
        snapshot.iter().find(|&&(p, _)| p == pid)
    );
    assert!(snapshot.contains(&(std::process::id(), std::os::unix::process::parent_id())));

    _ = child.kill();
    _ = child.wait();
}
