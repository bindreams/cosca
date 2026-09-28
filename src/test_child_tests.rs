//! Unit tests for [`super::fixture_command`]'s env setup — properties that do not need a real
//! re-exec, so they run as plain assertions on the built `std::process::Command` rather than as
//! fixtures of their own.

/// A re-exec'd fixture must run in libtest's default (buffered, replay-on-failure) capture mode
/// regardless of what the OUTER `cargo test`/`cargo nextest` invocation was run under — the
/// injected-failure drivers (`resolve_base_tests.rs`, `exact_posix_tests.rs`) read a failing
/// fixture's panic message back from its captured stdout, which only libtest's own buffering
/// produces. `RUST_TEST_NOCAPTURE=1` in the AMBIENT environment (the outer invocation's own) would
/// otherwise be inherited by the child via `std::process::Command`'s default env-inheritance,
/// making the child libtest process print an unbuffered failing test's panic straight to its real
/// stderr instead — invisible to a driver that only reads the child's stdout. Measured: with
/// `RUST_TEST_NOCAPTURE=1` set in the process running `cargo test`, the injected-failure driver
/// failed before this fix and passes after it.
///
/// `Command::get_envs` surfaces an `.env_remove(...)` call as `(key, None)` — distinct from the
/// var being merely absent from this list (inherited, whatever the ambient value is) — so this
/// checks the REMOVAL is explicit, not that the var merely isn't set to some other value here.
#[test]
fn fixture_command_removes_rust_test_nocapture_from_its_env() {
    let cmd = super::fixture_command("some::fully::qualified::fixture");
    let removed = cmd
        .get_envs()
        .any(|(key, value)| key == std::ffi::OsStr::new("RUST_TEST_NOCAPTURE") && value.is_none());
    assert!(
        removed,
        "RUST_TEST_NOCAPTURE must be explicitly env_remove'd, not merely unset here"
    );
}

/// Unit tests for [`super::check_path_traversable_by`] — the non-Linux precondition
/// [`super::run_fixture`] fails loudly on, rather than tries to fix, for a root driver whose
/// ambient `TMPDIR` (or exec path — see [`super::copy_exe_to_traversable_scratch`]) the post-drop
/// identity could not otherwise reach.
#[cfg(all(unix, not(target_os = "linux")))]
mod check_path_traversable_by_tests {
    use std::os::unix::fs::PermissionsExt as _;

    fn check(path: &std::path::Path, uid: libc::uid_t) -> Result<(), String> {
        super::super::check_path_traversable_by(path, uid, uid)
    }

    #[test]
    fn a_directory_owned_by_the_dropped_uid_is_traversable_regardless_of_other_bits() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let this_uid = unsafe { libc::geteuid() };
        assert!(check(dir.path(), this_uid).is_ok());
    }

    #[test]
    fn a_world_searchable_directory_owned_by_someone_else_is_traversable() {
        // Directly under `/tmp`, not `tempfile::tempdir()`'s ambient `TMPDIR`: checking a
        // FOREIGN uid's access must not depend on the REAL system `TMPDIR`'s own ancestors (a
        // per-user macOS `TMPDIR` is itself `0700`) also happening to be world-traversable — only
        // `/tmp` itself is guaranteed to be.
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o701)).unwrap();
        let some_other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        assert!(check(dir.path(), some_other_uid).is_ok());
    }

    #[test]
    fn a_0700_directory_owned_by_someone_else_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let some_other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        let err = check(dir.path(), some_other_uid).unwrap_err();
        assert!(err.contains("does not grant"), "{err}");
    }

    /// The whole point of walking ancestors rather than checking only the leaf: a `TMPDIR` (or
    /// exec path) that is itself wide open is still unreachable if something ABOVE it refuses
    /// entry — reproducing #200's own F3 finding (a `chmod 0750` `$HOME` blocking a leaf `TMPDIR`
    /// underneath it that was, on its own, perfectly traversable).
    #[test]
    fn a_traversable_leaf_under_an_unreachable_ancestor_is_refused() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let leaf = root.path().join("leaf");
        std::fs::create_dir(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o701)).unwrap();
        let some_other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        let err = check(&leaf, some_other_uid).unwrap_err();
        assert!(err.contains(root.path().to_str().unwrap()), "{err}");
    }

    /// The kernel always follows a symlink at an intermediate path component — there is no way to
    /// opt out of that for anything but the FINAL component (`O_NOFOLLOW`) — so a check reporting
    /// on the symlink's OWN (conventionally always-permissive) mode instead of its target's would
    /// silently pass something the real path resolution would refuse. `/tmp` on macOS is exactly
    /// this shape (`-> /private/tmp`); this test does not rely on that coincidence, building its
    /// own symlink over a deliberately restrictive target instead.
    #[test]
    fn a_symlink_ancestor_is_checked_against_its_target_not_its_own_mode() {
        let base = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let real_target = base.path().join("real");
        std::fs::create_dir(&real_target).unwrap();
        std::fs::set_permissions(&real_target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inner = real_target.join("inner");
        std::fs::create_dir(&inner).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o701)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real_target, &link).unwrap();

        let some_other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        let err = check(&link.join("inner"), some_other_uid).unwrap_err();
        assert!(err.contains("0700") || err.contains("700"), "{err}");
    }

    #[test]
    fn group_membership_grants_search_via_group_bits() {
        // Directly under `/tmp` — see the world-searchable test above for why.
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o710)).unwrap();
        let meta = std::fs::metadata(dir.path()).unwrap();
        use std::os::unix::fs::MetadataExt as _;
        let some_other_uid = meta.uid().wrapping_add(1);
        assert!(super::super::check_path_traversable_by(dir.path(), some_other_uid, meta.gid()).is_ok());
    }

    #[test]
    fn a_leaf_file_needs_read_and_execute_not_just_search() {
        // Directly under `/tmp` — see the world-searchable test above for why.
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o701)).unwrap();
        let file = dir.path().join("exe");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o701)).unwrap(); // x only, no r
        let some_other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        let err = check(&file, some_other_uid).unwrap_err();
        assert!(err.contains("read+execute"), "{err}");

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o705)).unwrap(); // r+x
        assert!(check(&file, some_other_uid).is_ok());
    }
}
