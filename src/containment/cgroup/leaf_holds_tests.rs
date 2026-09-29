//! `CgroupLeaf::holds` and `holds_via`: what a read through the checked `/proc` returns, and what
//! it refuses.

use std::error::Error as _;
use std::io;

use super::CgroupLeaf;
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};
use crate::identity::ProcDir;

/// A leaf with a unified-hierarchy path but no cgroupfs behind it: `holds` never touches the leaf.
fn pathed_leaf(dir: &tempfile::TempDir) -> CgroupLeaf {
    let path = dir.path().join("cosca-holds");
    std::fs::create_dir(&path).expect("create the stand-in leaf");
    let mut leaf = CgroupLeaf::for_test_at(path);
    leaf.cgroup_path = Some("/cosca-holds".into());
    leaf
}

/// No pid namespace has a process numbered past `PID_MAX_LIMIT` (2^22), so `{pid}/cgroup` is
/// absent from every `/proc`, whatever else is running.
const ABSENT_PID: u32 = (1 << 22) + 1;

/// A read the checked directory cannot make is an error carrying the OS's errno, not `Ok(false)`:
/// "no such process" must not read as "not in the leaf".
///
/// Mutant: `holds_via` maps a failed read to `Ok(false)`.
#[test]
fn holds_via_an_absent_pid_is_the_reads_own_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf = pathed_leaf(&dir);
    let proc_dir = ProcDir::open().expect("this test's /proc is its own");
    let err = leaf
        .holds_via(&proc_dir, ABSENT_PID)
        .expect_err("an absent pid has no cgroup file");
    assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "{err}");
}

/// A view with no OS error behind it (forced) keeps the kind `Other` and has no source.
#[test]
fn holds_under_an_unassessable_view_without_an_os_error_has_no_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf = pathed_leaf(&dir);
    let _forced = force_proc_view_once(ForcedView::Unassessable);
    let err = leaf
        .holds(std::process::id())
        .expect_err("an unassessable view is an error");
    assert_eq!(err.kind(), io::ErrorKind::Other, "{err}");
    assert!(err.source().is_none(), "{err}");
}

/// A `Diverged` view is an error naming the outer pid namespace.
///
/// Mutant: `holds` reads without the view check.
#[test]
fn holds_under_a_diverged_view_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf = pathed_leaf(&dir);
    let _forced = force_proc_view_once(ForcedView::Diverged);
    let err = leaf.holds(std::process::id()).expect_err("a diverged view is an error");
    assert!(err.to_string().contains("outer pid namespace"), "{err}");
}

/// A member in a cgroup nested under the leaf is in the leaf.
///
/// Mutant: `holds_via` compares the member's path to the leaf's for equality.
#[test]
fn cgroup_holds_via_counts_a_member_nested_under_the_leaf() {
    use crate::containment::cgroup::test_support::occupied_leaf;
    use crate::containment::TreeDrain;
    if !crate::test_enablement::require_group("CGROUP") {
        return;
    }
    let (leaf, mut member, _own) = occupied_leaf();
    let pid = member.id();
    let nested = leaf.leaf_path.join("nested");
    std::fs::create_dir(&nested).expect("create the nested cgroup");
    std::fs::write(nested.join("cgroup.procs"), pid.to_string()).expect("move the member into it");
    let proc_dir = ProcDir::open().expect("this test's /proc is its own");
    let text = proc_dir
        .read_to_string(&format!("{pid}/cgroup"))
        .expect("read the member's cgroup");
    assert!(
        text.trim_end().ends_with("/nested"),
        "the member must be nested: {text:?}"
    );

    assert!(leaf.holds_via(&proc_dir, pid).expect("read the membership"));

    leaf.hard_kill().expect("kill through the leaf");
    assert_eq!(leaf.wait_drained(None).expect("drain"), TreeDrain::AllMembersExited);
    member.wait().expect("reap the member");
}
