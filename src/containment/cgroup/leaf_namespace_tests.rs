//! `CgroupLeaf::holds_via` and `holds` against REAL mount namespaces, in re-exec'd children (see
//! `test_child::namespaces` for the group's gating). They need a delegated cgroup too.

use crate::containment::cgroup::test_support::occupied_leaf;
use crate::containment::TreeDrain;
use crate::identity::ProcDir;
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;

/// The mount point `fixture_cleanup_over_mount` puts a tmpfs on, under the chroot root.
const MOUNT_POINT_ENV: &str = "COSCA_FIXTURE_MOUNT_POINT";

/// The empty directory `fixture_leaf_no_proc` chroots into, made and removed by its driver.
const CHROOT_ROOT_ENV: &str = "COSCA_FIXTURE_CHROOT_ROOT";

/// Whether to run: the `CGROUP` group is on, as well as the `NAMESPACES` one.
fn enabled() -> bool {
    ns::enabled() && crate::test_support::require_group("CGROUP")
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
    // `TMPDIR` is `scratch`, so anything the fixture leaves in the temp dir is caught below.
    let dirs = ns::ChrootScratch::new();
    ns::run_with_env(
        fixture_path!(fixture_leaf_no_proc),
        &[
            ("TMPDIR", dirs.scratch()),
            (CHROOT_ROOT_ENV, dirs.root()),
            (ns::SKULD_DB_DIR_ENV, dirs.db_dir()),
        ],
    );
    dirs.finish().unwrap_or_else(|e| panic!("{e}"));
}

/// The cleanup never deletes recursively: with a mount inside the chroot root it fails, naming
/// what is there, and what the mount holds survives.
///
/// Mutant: `ChrootScratch::finish` removes recursively.
#[test]
fn namespaces_a_failed_chroot_cleanup_never_deletes_through_a_mount() {
    if !ns::enabled() {
        return;
    }
    let dirs = ns::ChrootScratch::new();
    let mnt = dirs.root().join("mnt");
    std::fs::create_dir(&mnt).expect("mkdir the mount point");
    ns::run_with_env(
        fixture_path!(fixture_cleanup_over_mount),
        &[(CHROOT_ROOT_ENV, dirs.root()), (MOUNT_POINT_ENV, &mnt)],
    );
    // The mount lived in the child's namespace: here `mnt` is an empty directory again.
    let (scratch, root) = (dirs.scratch().to_owned(), dirs.root().to_owned());
    let err = dirs.finish().expect_err("a root holding a directory is not removable");
    assert!(err.contains("mnt"), "{err}");
    assert!(mnt.is_dir(), "the cleanup removed {mnt:?}");
    std::fs::remove_dir(&mnt).expect("remove the mount point");
    std::fs::remove_dir(&root).expect("remove the chroot root");
    std::fs::remove_dir(&scratch).expect("remove the scratch directory");
}

#[test]
fn fixture_cleanup_over_mount() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let root = std::env::var_os(CHROOT_ROOT_ENV).expect("the driver names the chroot root");
    let mnt = std::path::PathBuf::from(std::env::var_os(MOUNT_POINT_ENV).expect("the driver names the mount"));
    ns::mount_tmpfs(&mnt);
    let evidence = mnt.join("evidence");
    std::fs::write(&evidence, b"x").expect("write through the mount");

    let err = ns::remove_chroot_root(std::path::Path::new(&root)).expect_err("a root holding a mount is not removable");
    assert!(err.contains("mnt"), "{err}");
    assert!(evidence.is_file(), "the cleanup reached through the mount");
}

#[test]
fn fixture_leaf_no_proc() {
    if !ns::is_child() {
        return;
    }
    let (leaf, mut member, _own) = occupied_leaf();
    let pid = member.id();
    let root = std::env::var_os(CHROOT_ROOT_ENV).expect("the driver names the chroot root");
    let db_dir = std::env::var_os(ns::SKULD_DB_DIR_ENV).expect("the driver names the skuld DB directory");
    // Skuld checks the DB's path at the end of this test, after the chroot.
    ns::enter_private_mount_ns();
    ns::bind_into_root(std::path::Path::new(&root), std::path::Path::new(&db_dir));
    ns::chroot_into(std::path::Path::new(&root));

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
