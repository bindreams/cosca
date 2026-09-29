//! `CgroupLeaf::holds_via` and `holds` against REAL mount namespaces, in re-exec'd children (see
//! `test_child::namespaces` for the group's gating). They need a delegated cgroup too.

use crate::containment::cgroup::test_support::occupied_leaf;
use crate::containment::TreeDrain;
use crate::identity::ProcDir;
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;

/// Whether to run: the `CGROUP` group is on, as well as the `NAMESPACES` one.
fn enabled() -> bool {
    ns::enabled() && crate::test_enablement::require_group("CGROUP")
}

/// `holds_via` reads through the `/proc` dirfd it is given. The dirfd is opened, THEN a tmpfs is
/// mounted over `/proc` whose `{pid}/cgroup` puts the member outside the leaf: the read must
/// still see the real `/proc`, where the member is in the leaf.
///
/// Mutant: `holds_via` reads `/proc/{pid}/cgroup` by absolute path.
#[test]
fn namespaces_cgroup_membership_is_read_through_the_given_proc_dirfd() {
    if !enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_leaf_overmount));
}

#[test]
fn fixture_leaf_overmount() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let (leaf, mut member, _own) = occupied_leaf();
    let pid = member.id();
    let proc_dir = ProcDir::open().expect("this fixture's /proc is its own");

    ns::mount_tmpfs(std::path::Path::new("/proc"));
    let fake = std::path::PathBuf::from(format!("/proc/{pid}"));
    std::fs::create_dir(&fake).expect("mkdir the fake pid dir");
    std::fs::write(fake.join("cgroup"), "0::/somewhere/else\n").expect("write the fake cgroup");
    assert_eq!(
        std::fs::read_to_string(fake.join("cgroup")).expect("read by path"),
        "0::/somewhere/else\n",
        "by path, /proc is now the fake"
    );

    assert!(
        leaf.holds_via(&proc_dir, pid).expect("read through the dirfd"),
        "the member is in the leaf"
    );

    leaf.hard_kill().expect("kill through the leaf");
    assert_eq!(leaf.wait_drained(None).expect("drain"), TreeDrain::AllMembersExited);
    member.wait().expect("reap the member");
}

/// A `/proc` the OS refuses to open is an error that keeps the OS error as its `source`: the kind
/// and the raw errno both survive `holds`.
///
/// Mutant: `holds` keeps only the source's kind.
#[test]
fn namespaces_cgroup_holds_keeps_the_os_error_behind_an_unopenable_proc() {
    if !enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_leaf_no_proc));
}

#[test]
fn fixture_leaf_no_proc() {
    if !ns::is_child() {
        return;
    }
    let (leaf, mut member, _own) = occupied_leaf();
    let pid = member.id();
    let empty = tempfile::tempdir().expect("tempdir");
    ns::chroot_into(empty.path());

    let err = leaf.holds(pid).expect_err("a missing /proc has no membership to read");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
    let source = err
        .get_ref()
        .and_then(|inner| inner.source())
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .unwrap_or_else(|| panic!("the OS error must be the source: {err:?}"));
    assert_eq!(source.raw_os_error(), Some(libc::ENOENT), "{source}");

    leaf.hard_kill().expect("kill through the leaf");
    assert_eq!(leaf.wait_drained(None).expect("drain"), TreeDrain::AllMembersExited);
    member.wait().expect("reap the member");
}
