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

/// The own cgroup is offered when its directory is writable, and it names that directory: the one a
/// leaf is made under.
#[skuld::test]
fn a_writable_own_cgroup_is_offered_as_the_directory_a_leaf_is_made_under() {
    let root = tempfile::tempdir().expect("tempdir");
    let own = make_own_cgroup(root.path(), "user.slice/session.scope");

    let offered = offered_in(Ok("0::/user.slice/session.scope\n".to_owned()), root.path());

    let Ok(Some(offered)) = offered else {
        panic!("{offered:?}");
    };
    assert_eq!(offered.dir(), own);
    assert_eq!(offered.rel_path(), "/user.slice/session.scope");
}

/// An own cgroup the filesystem does not show cannot be written, so none is offered.
#[skuld::test]
fn an_own_cgroup_that_cannot_be_written_offers_no_cgroup() {
    let root = tempfile::tempdir().expect("tempdir");

    let offered = offered_in(Ok("0::/not/here\n".to_owned()), root.path());

    assert!(matches!(offered, Ok(None)), "{offered:?}");
}

/// The own cgroup under a temp directory, offered: a writable directory, whose new leaf has no
/// `cgroup.kill`, as on a kernel before 5.14.
fn offered_under(root: &Path) -> Result<Option<OwnCgroup>, LeafError> {
    make_own_cgroup(root, "own");
    offered_in(Ok("0::/own\n".to_owned()), root)
}

/// What the check of an access says of it: a refusal, or a path that is not there, is "not
/// offered", and nothing else is. `ENOSYS` is its own error, which says why.
#[skuld::test]
fn only_a_refusal_or_a_missing_path_means_a_cgroup_is_not_offered() {
    let path = Path::new("/sys/fs/cgroup/own");

    assert!(matches!(grants(Ok(()), path), Ok(true)));
    for refused in [Errno::ACCESS, Errno::PERM, Errno::ROFS, Errno::NOENT] {
        assert!(matches!(grants(Err(refused), path), Ok(false)), "{refused}");
    }
    for failed in [
        Errno::IO,
        Errno::NOMEM,
        Errno::LOOP,
        Errno::INVAL,
        Errno::FAULT,
        Errno::NAMETOOLONG,
        Errno::NOTDIR,
    ] {
        let answer = grants(Err(failed), path);
        assert!(
            matches!(answer, Err(LeafError::CheckAccess { ref source, .. }) if source.raw_os_error() == Some(failed.raw_os_error())),
            "{failed}: {answer:?}"
        );
    }
    let answer = grants(Err(Errno::NOSYS), path);
    assert!(
        matches!(answer, Err(LeafError::CheckAccessUnavailable { ref source, .. }) if source.raw_os_error() == Some(libc::ENOSYS)),
        "{answer:?}"
    );
}

/// A check that failed fails a `Strongest` spawn, naming the path and keeping the OS error as its
/// source: it is no host that offers nothing.
#[skuld::test]
fn a_failed_access_check_fails_a_strongest_spawn() {
    let path = Path::new("/sys/fs/cgroup/own");
    let failed = grants(Err(Errno::IO), path).expect_err("an I/O error is no answer");

    let error = leaf_if_offered(Err(failed), None).expect_err("a failed check fails the spawn");

    let crate::error::Error::Containment { detail, source } = &error else {
        panic!("{error:?}");
    };
    assert!(detail.contains(&*path.to_string_lossy()), "{detail:?}");
    assert!(
        matches!(source.as_deref(), Some(crate::error::Error::Io(e)) if e.raw_os_error() == Some(libc::EIO)),
        "{source:?}"
    );
}

/// A directory the own cgroup lets this process write, but whose `cgroup.procs` is absent, is not
/// offered: moving the child writes that file.
#[skuld::test]
fn an_own_cgroup_without_a_cgroup_procs_offers_no_cgroup() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(root.path().join("own")).expect("create the own cgroup");

    let offered = offered_in(Ok("0::/own\n".to_owned()), root.path());

    assert!(matches!(offered, Ok(None)), "{offered:?}");
}

/// The own cgroup is offered only when this process may write and search its directory and write
/// its `cgroup.procs`: each missing permission means no cgroup. Declares what it needs: a process
/// the mode bits bind, which root is not, so it drops the module's `cgroup` label (the lane runs as
/// root) and only the `unprivileged` group selects it.
#[skuld::test(labels = [])]
fn a_cgroup_this_process_may_not_fully_use_is_not_offered(#[fixture(unprivileged)] _group: &Group) {
    use std::os::unix::fs::PermissionsExt;

    assert!(
        !nix::unistd::geteuid().is_root(),
        "the mode bits do not bind root: run as an unprivileged user, or set COSCA_TEST_UNPRIVILEGED=0 to opt out"
    );
    // (the directory's mode, `cgroup.procs`'s mode, offered)
    let cases = [
        (0o700, 0o644, true),
        (0o500, 0o644, false),
        (0o600, 0o644, false),
        (0o700, 0o444, false),
    ];
    for (dir_mode, procs_mode, want) in cases {
        let root = tempfile::tempdir().expect("tempdir");
        let own = make_own_cgroup(root.path(), "own");
        std::fs::set_permissions(own.join("cgroup.procs"), PermissionsExt::from_mode(procs_mode)).expect("chmod file");
        std::fs::set_permissions(&own, PermissionsExt::from_mode(dir_mode)).expect("chmod dir");

        let offered = offered_in(Ok("0::/own\n".to_owned()), root.path());

        // Restored, so the temp directory can be removed.
        std::fs::set_permissions(&own, PermissionsExt::from_mode(0o700)).expect("restore dir");
        assert_eq!(
            matches!(offered, Ok(Some(_))),
            want,
            "directory {dir_mode:o}, cgroup.procs {procs_mode:o}: {offered:?}"
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
    let left: Vec<_> = std::fs::read_dir(root.path().join("own"))
        .expect("read the own cgroup")
        .map(|entry| entry.expect("read an entry").file_name())
        .filter(|name| name != "cgroup.procs")
        .collect();
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
