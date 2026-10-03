//! Unit tests for [`super::check_path_traversable_by`].
//!
//! Each mode is chosen so the owner class (checked when the test runs unprivileged and owns what
//! it builds) and the other class (checked when the test runs as root and the child drops to
//! `UNPRIVILEGED`) give the same answer: `0o101` and `0o701` grant `x` to both, `0o404` to neither.

use super::{check_path_traversable_by as check, TraversalError};
use crate::test_child::RestoreMode;
use std::os::unix::fs::PermissionsExt as _;

fn chmod(path: &std::path::Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Built directly under `/tmp`, the one path guaranteed searchable end to end: under an
/// unsearchable ambient `TMPDIR`, an `Err` test would pass for that ancestor's sake, not its own
/// mode. Mode `0o755` so the root case's dropped identity can enter it.
fn scratch_dir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .tempdir_in("/tmp")
        .expect("tempdir directly under /tmp");
    chmod(dir.path(), 0o755);
    dir
}

fn assert_denied_with_eacces(r: Result<(), TraversalError>) {
    match r {
        Err(TraversalError::Denied { errno, .. }) => assert_eq!(errno, libc::EACCES),
        other => panic!("expected Denied(EACCES), got {other:?}"),
    }
}

#[skuld::test]
fn a_reachable_directory_is_ok() {
    let dir = scratch_dir();
    let r = check(dir.path());
    assert!(r.is_ok(), "{r:?}");
}

#[skuld::test]
fn search_only_for_owner_and_other_is_ok() {
    let dir = scratch_dir();
    let _restore = RestoreMode::new(dir.path(), 0o755);
    chmod(dir.path(), 0o101);
    let r = check(dir.path());
    assert!(r.is_ok(), "{r:?}");
}

#[skuld::test]
fn world_searchable_only_is_ok() {
    let dir = scratch_dir();
    let _restore = RestoreMode::new(dir.path(), 0o755);
    chmod(dir.path(), 0o701);
    let r = check(dir.path());
    assert!(r.is_ok(), "{r:?}");
}

/// Readable, but no `x` bit anywhere: a read check would pass it, `access(X_OK)` refuses it.
#[skuld::test]
fn read_only_with_no_execute_bit_is_denied() {
    let dir = scratch_dir();
    let _restore = RestoreMode::new(dir.path(), 0o755);
    chmod(dir.path(), 0o404);
    assert_denied_with_eacces(check(dir.path()));
}

/// The kernel follows a symlink at an intermediate component, so `real`'s mode governs
/// `link/inner`, not the link's own permissive mode. A hand-rolled check of the link's bits would
/// pass it. The positive control shows the path resolves before `real` is locked.
#[skuld::test]
fn a_symlinked_ancestor_is_denied_by_the_kernel_not_modelled() {
    let base = scratch_dir();
    let real = base.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::create_dir(real.join("inner")).unwrap();
    let link = base.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let target = link.join("inner");
    let r = check(&target);
    assert!(r.is_ok(), "positive control: {r:?}");

    let _restore = RestoreMode::new(&real, 0o755);
    chmod(&real, 0o000);
    assert_denied_with_eacces(check(&target));
}
