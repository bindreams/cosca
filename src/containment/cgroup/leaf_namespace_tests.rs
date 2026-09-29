//! `CgroupLeaf::holds` against REAL mount namespaces, in re-exec'd children (see
//! `test_child::namespaces` for the group's gating). These also need a delegated cgroup, so
//! they fail loudly, not skip, without `COSCA_TEST_CGROUP`.

use std::os::unix::process::CommandExt;

use crate::containment::TreeDrain;
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;

const OVERMOUNT_MARKER: &str = "COSCA_FIXTURE_LEAF_OVERMOUNT";
const FORCED_SAME_MARKER: &str = "COSCA_FIXTURE_LEAF_FORCED_SAME";

fn require_cgroup() {
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
}

/// A child placed in a fresh leaf by its own pre-exec, plus the leaf, ready for a verdict that
/// cannot wait (no pidfd, leaf busy) and so must decide by reading the child's `cgroup` file.
fn occupied_leaf() -> (
    crate::containment::cgroup::CgroupLeaf,
    std::process::Child,
    crate::containment::cgroup::ReportChannel,
) {
    let leaf = crate::containment::cgroup::try_create_leaf().expect("a delegated cgroup v2 leaf");
    let own = crate::containment::cgroup::ReportChannel::new().expect("open the member's channel");
    let (procs_fd, slot) = (leaf.procs_fd(), own.slot());
    let mut cmd = std::process::Command::new("/bin/sleep");
    cmd.arg("300");
    // SAFETY: the closure runs between fork and exec, and performs only async-signal-safe calls
    // on descriptors `leaf` and `own` keep open across the spawn.
    unsafe { cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot)) };
    let member = cmd.spawn().expect("spawn the member");
    (leaf, member, own)
}

/// The membership read goes through the `/proc` dirfd that the view check produced, not through
/// `/proc` looked up by path again. Between the check and the read, a tmpfs is mounted over
/// `/proc` whose `{pid}/cgroup` puts the member OUTSIDE the leaf; the read must still see the
/// real `/proc`, where the member is in the leaf.
///
/// Mutant: "read `/proc/{pid}/cgroup` by absolute path" — the fake file wins, the member reads as
/// not in the leaf, and the spawn fails instead of being contained.
#[test]
fn namespaces_cgroup_membership_is_read_through_the_checked_proc_dirfd() {
    if !ns::enabled() {
        return;
    }
    require_cgroup();
    ns::run(fixture_path!(fixture_leaf_overmount), OVERMOUNT_MARKER);
}

#[test]
fn fixture_leaf_overmount() {
    if !ns::is_child(OVERMOUNT_MARKER) {
        return;
    }
    ns::enter_private_mount_ns();
    let (mut leaf, mut member, _own) = occupied_leaf();
    let pid = member.id();
    let _hook = crate::containment::cgroup::fault::between_view_and_membership_read(move || {
        ns::mount_tmpfs(std::path::Path::new("/proc"));
        let dir = std::path::PathBuf::from(format!("/proc/{pid}"));
        std::fs::create_dir(&dir).expect("mkdir the fake pid dir");
        std::fs::write(dir.join("cgroup"), "0::/somewhere/else\n").expect("write the fake cgroup");
    });
    crate::containment::cgroup::fault::set_force_pidfd_failure(true);
    let verdict = leaf.take_placement(pid);
    assert!(matches!(verdict, Ok(Ok(()))), "got {verdict:?}");
    assert!(leaf.entered, "the member is in the leaf");

    leaf.hard_kill().expect("kill through the leaf");
    assert_eq!(leaf.wait_drained(None).expect("drain"), TreeDrain::AllMembersExited);
    member.wait().expect("reap the member");
}

/// A forced `Same` view opens the real `/proc` (so it carries a usable dirfd) and the read
/// works: the seam cannot make `holds` panic.
///
/// Mutant: "a forced `Same` carries no dirfd, and `holds` `expect`s one".
#[test]
fn namespaces_cgroup_a_forced_same_view_reads_the_real_proc() {
    if !ns::enabled() {
        return;
    }
    require_cgroup();
    ns::run(fixture_path!(fixture_leaf_forced_same), FORCED_SAME_MARKER);
}

#[test]
fn fixture_leaf_forced_same() {
    if !ns::is_child(FORCED_SAME_MARKER) {
        return;
    }
    let (mut leaf, mut member, _own) = occupied_leaf();
    let _view =
        crate::identity::proc_view_fault::force_proc_view_once(crate::identity::proc_view_fault::ForcedView::Same);
    crate::containment::cgroup::fault::set_force_pidfd_failure(true);
    let verdict = leaf.take_placement(member.id());
    assert!(matches!(verdict, Ok(Ok(()))), "got {verdict:?}");

    leaf.hard_kill().expect("kill through the leaf");
    assert_eq!(leaf.wait_drained(None).expect("drain"), TreeDrain::AllMembersExited);
    member.wait().expect("reap the member");
}
