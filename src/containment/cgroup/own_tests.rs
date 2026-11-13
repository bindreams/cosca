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
