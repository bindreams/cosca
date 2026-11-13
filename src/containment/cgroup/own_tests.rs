use super::*;

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
    let own = root.path().join("user.slice").join("session.scope");
    std::fs::create_dir_all(&own).expect("create the own cgroup");

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
    std::fs::create_dir(root.join("own")).expect("create the own cgroup");
    offered_in(Ok("0::/own\n".to_owned()), root)
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
