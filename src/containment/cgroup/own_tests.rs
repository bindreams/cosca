use super::*;
use crate::test_groups::{unprivileged, Group};

/// [`offered_cgroup`] over an explicit `/proc/self/cgroup` read and cgroup filesystem mount.
fn offered_in(file: io::Result<String>, root: &Path) -> Result<Option<OwnCgroup>, LeafError> {
    offered_from(find_in(file, root))
}

/// An own cgroup `name` under `root`: its directory, and the `cgroup.procs` a cgroup always shows.
fn make_own_cgroup(root: &Path, name: &str) -> PathBuf {
    let own = root.join(name);
    std::fs::create_dir_all(&own).expect("create the own cgroup");
    std::fs::write(own.join("cgroup.procs"), "").expect("create cgroup.procs");
    own
}

/// What a failed leaf creation left in the own cgroup besides its `cgroup.procs`.
fn left_in(own: &Path) -> Vec<std::ffi::OsString> {
    std::fs::read_dir(own)
        .expect("read the own cgroup")
        .map(|entry| entry.expect("read an entry").file_name())
        .filter(|name| name != "cgroup.procs")
        .collect()
}

/// A host with no `/proc/self/cgroup` offers no cgroup; a read that fails any other way is an error.
#[skuld::test]
fn a_missing_proc_self_cgroup_offers_no_cgroup_and_another_read_error_is_an_error() {
    let root = tempfile::tempdir().expect("tempdir");

    let offered = offered_in(Err(io::ErrorKind::NotFound.into()), root.path());
    assert!(matches!(offered, Ok(None)), "{offered:?}");

    let offered = offered_in(Err(io::ErrorKind::PermissionDenied.into()), root.path());
    assert!(
        matches!(offered, Err(LeafError::ReadProcSelfCgroup(ref e)) if e.kind() == io::ErrorKind::PermissionDenied),
        "{offered:?}"
    );
}

/// A cgroup v1 host has no `0::` line: no cgroup is offered, and that is no error.
#[skuld::test]
fn a_file_without_a_unified_line_offers_no_cgroup() {
    let root = tempfile::tempdir().expect("tempdir");

    let offered = offered_in(
        Ok("12:cpu,cpuacct:/user\n1:name=systemd:/user\n".to_owned()),
        root.path(),
    );

    assert!(matches!(offered, Ok(None)), "{offered:?}");
}

/// The own cgroup the file names is the directory a leaf is made under.
#[skuld::test]
fn the_own_cgroup_the_file_names_is_the_directory_a_leaf_is_made_under() {
    let root = tempfile::tempdir().expect("tempdir");
    let own = make_own_cgroup(root.path(), "user.slice/session.scope");

    let offered = offered_in(Ok("0::/user.slice/session.scope\n".to_owned()), root.path());

    let Ok(Some(offered)) = offered else {
        panic!("{offered:?}");
    };
    assert_eq!(offered.dir(), own);
    assert_eq!(offered.rel_path(), "/user.slice/session.scope");
}

/// The own cgroup under a temp directory, as the file names it: a directory whose new leaf has no
/// `cgroup.kill`, as on a kernel before 5.14.
fn offered_under(root: &Path) -> Result<Option<OwnCgroup>, LeafError> {
    make_own_cgroup(root, "own");
    offered_in(Ok("0::/own\n".to_owned()), root)
}

/// An own cgroup the filesystem does not show is the host not offering it (step 1 of
/// [`leaf_if_offered`], `ENOENT`): a process group, no error.
#[skuld::test]
fn an_own_cgroup_the_filesystem_does_not_show_is_a_process_group_for_strongest() {
    let root = tempfile::tempdir().expect("tempdir");
    let offered = offered_in(Ok("0::/not/here\n".to_owned()), root.path());

    let leaf = leaf_if_offered(offered, None);

    assert!(matches!(leaf, Ok(None)), "{leaf:?}");
}

/// An own cgroup with no `cgroup.procs` cannot be opened for the placement write: the same, and
/// no leaf is made.
#[skuld::test]
fn an_own_cgroup_without_a_cgroup_procs_is_a_process_group_for_strongest() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(root.path().join("own")).expect("create the own cgroup");
    let offered = offered_in(Ok("0::/own\n".to_owned()), root.path());

    let leaf = leaf_if_offered(offered, None);

    assert!(matches!(leaf, Ok(None)), "{leaf:?}");
    assert!(left_in(&root.path().join("own")).is_empty());
}

/// A leaf with no `cgroup.procs` of its own fails the spawn, the leaf removed: `ENOENT` at the
/// leaf's `cgroup.procs` (step 3) is no refusal. A temp directory cannot show one (`cgroup.kill` is
/// the fact it lacks, which the seam supplies), and this is the one outcome that tells "went on to
/// step 3" from a refusal on a directory the mode bits bind or do not.
#[skuld::test]
fn a_leaf_whose_cgroup_procs_is_missing_fails_strongest_and_leaves_no_leaf() {
    let root = tempfile::tempdir().expect("tempdir");
    let offered = offered_under(root.path());
    crate::containment::cgroup::fault::set_force_kill_supported(true);

    let leaf = leaf_if_offered(offered, None);

    let Err(error) = leaf else {
        panic!("a leaf with no cgroup.procs must fail the spawn: {leaf:?}");
    };
    assert!(
        matches!(error, crate::error::Error::Containment { ref detail, .. } if detail.contains("cgroup.procs")),
        "{error:?}"
    );
    assert!(left_in(&root.path().join("own")).is_empty(), "the leaf is removed");
}

/// What the setup calls say of an own cgroup the mode bits bind this process on: a missing
/// permission is a refusal the kernel gives for real, so the host offers none (step 1 or 2) and no
/// leaf is left. A directory this process may write goes on to the leaf's own `cgroup.procs`, which
/// a temp directory lacks: `ENOENT` there is an error. Declares what it needs: a process the mode
/// bits bind, which root is not, so it drops the module's `cgroup` label (the lane runs as root) and
/// only the `unprivileged` group selects it.
#[skuld::test(labels = [])]
fn a_cgroup_this_process_may_not_use_is_a_process_group_for_strongest(#[fixture(unprivileged)] _group: &Group) {
    use std::os::unix::fs::PermissionsExt;

    assert!(
        !nix::unistd::geteuid().is_root(),
        "the mode bits do not bind root: run as an unprivileged user, or set COSCA_TEST_UNPRIVILEGED=0 to opt out"
    );
    // (the directory's mode, `cgroup.procs`'s mode, the host offers the cgroup)
    let cases = [
        (0o700, 0o644, true),
        // A read-only parent: `mkdir` is refused (`EACCES`).
        (0o500, 0o644, false),
        // No search: the own `cgroup.procs` cannot be reached.
        (0o600, 0o644, false),
        // The own `cgroup.procs` cannot be opened for writing.
        (0o700, 0o444, false),
    ];
    for (dir_mode, procs_mode, offered) in cases {
        let root = tempfile::tempdir().expect("tempdir");
        let own = make_own_cgroup(root.path(), "own");
        std::fs::set_permissions(own.join("cgroup.procs"), PermissionsExt::from_mode(procs_mode)).expect("chmod file");
        std::fs::set_permissions(&own, PermissionsExt::from_mode(dir_mode)).expect("chmod dir");
        crate::containment::cgroup::fault::set_force_kill_supported(true);

        let leaf = leaf_if_offered(offered_in(Ok("0::/own\n".to_owned()), root.path()), None);

        // Restored, so the temp directory can be removed.
        std::fs::set_permissions(&own, PermissionsExt::from_mode(0o700)).expect("restore dir");
        crate::containment::cgroup::fault::take_force_kill_supported();
        match (offered, &leaf) {
            (false, Ok(None)) => {}
            (true, Err(_)) => {}
            _ => panic!("directory {dir_mode:o}, cgroup.procs {procs_mode:o}: {leaf:?}"),
        }
        assert!(
            left_in(&own).is_empty(),
            "directory {dir_mode:o}, cgroup.procs {procs_mode:o}: a leaf is left"
        );
    }
}

/// A host whose leaf shows no `cgroup.kill` (a kernel before 5.14) offers no cgroup that can kill a
/// tree: a `Strongest` spawn gets a process group, no error, and the leaf it made is removed. The
/// own cgroup's own directory could not say so: the hierarchy's root never shows `cgroup.kill`.
#[skuld::test]
fn a_leaf_without_cgroup_kill_is_a_process_group_for_strongest_and_leaves_no_leaf() {
    let root = tempfile::tempdir().expect("tempdir");
    let offered = offered_under(root.path());

    let leaf = leaf_if_offered(offered, None);

    assert!(matches!(leaf, Ok(None)), "a process group, not an error and not a leaf");
    let left = left_in(&root.path().join("own"));
    assert!(left.is_empty(), "the failed leaf is removed: {left:?}");
}

/// Every other failure to set up a cgroup the host offers fails the spawn: here the `cgroup.kill`
/// lookup fails with something other than absence.
#[skuld::test]
fn a_failed_leaf_step_other_than_a_missing_cgroup_kill_fails_strongest() {
    let root = tempfile::tempdir().expect("tempdir");
    let offered = offered_under(root.path());
    crate::containment::cgroup::fault::set_force_kill_check_errno(libc::EACCES);

    let leaf = leaf_if_offered(offered, None);

    let Err(error) = leaf else {
        panic!("a failed cgroup.kill lookup must fail the spawn");
    };
    assert!(
        matches!(error, crate::error::Error::Containment { ref detail, .. } if detail.contains("cgroup.kill")),
        "{error:?}"
    );
}

/// A leaf directory that was made but cannot be held fails the spawn with the errno the kernel
/// gave (`EMFILE`, which is no refusal), and the leaf is removed. The seam stands for an error the
/// kernel gives on demand for no real directory (`EAGAIN` of `cgroup.max.depth` is another).
#[skuld::test]
fn a_leaf_that_cannot_be_held_fails_strongest_and_leaves_no_leaf() {
    let root = tempfile::tempdir().expect("tempdir");
    let offered = offered_under(root.path());
    crate::containment::cgroup::fault::set_force_leaf_open_failure(true);

    let leaf = leaf_if_offered(offered, None);

    let Err(error) = leaf else {
        panic!("a leaf that cannot be held must fail the spawn: {leaf:?}");
    };
    assert_eq!(crate::error::first_os_code(&error), Some(libc::EMFILE), "{error:?}");
    assert!(left_in(&root.path().join("own")).is_empty(), "the leaf is removed");
}
