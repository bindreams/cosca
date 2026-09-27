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

/// Unit tests for [`super::check_traversable_by`] — the non-Linux precondition
/// [`super::run_fixture`] fails loudly on, rather than tries to fix, for a root driver whose
/// ambient `TMPDIR` the post-drop identity could not otherwise reach.
#[cfg(all(unix, not(target_os = "linux")))]
mod check_traversable_by_tests {
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn a_directory_owned_by_the_dropped_uid_is_traversable_regardless_of_other_bits() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let this_uid = unsafe { libc::geteuid() };
        assert!(super::super::check_traversable_by(dir.path(), this_uid).is_ok());
    }

    #[test]
    fn a_world_searchable_directory_owned_by_someone_else_is_traversable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o701)).unwrap();
        let some_other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        assert!(super::super::check_traversable_by(dir.path(), some_other_uid).is_ok());
    }

    #[test]
    fn a_0700_directory_owned_by_someone_else_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let some_other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        let err = super::super::check_traversable_by(dir.path(), some_other_uid).unwrap_err();
        assert!(err.contains("not traversable"), "{err}");
    }
}
