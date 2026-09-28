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
///
/// The function now acts and fails (forks, drops to `UNPRIVILEGED`, `open`s the path, reports the
/// real errno) rather than modelling permission bits in Rust — see its own doc for why. That
/// means a REAL denial can only be observed by a process that can actually BECOME a different,
/// unprivileged identity, which needs root. Both tests below run unconditionally and assert
/// something true in either environment: as root, the fork really drops to `UNPRIVILEGED` and the
/// kernel really denies it; as a non-root, already-unprivileged caller, the drop is the
/// documented no-op (same shape as [`crate::test_privilege::drop_root_uid`]'s own), so the check
/// runs as the CURRENT identity — which owns the directories these tests build, and so can always
/// reach them, `0700` or not. Neither branch skips the check; each asserts the outcome that
/// identity actually produces.
#[cfg(all(unix, not(target_os = "linux")))]
mod check_path_traversable_by_tests {
    use std::os::unix::fs::PermissionsExt as _;

    fn check(path: &std::path::Path) -> Result<(), String> {
        super::super::check_path_traversable_by(path)
    }

    #[test]
    fn a_reachable_directory_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check(dir.path()).is_ok());
    }

    /// The reviewer's own repro shape: `real` (`0700`) sits behind a symlink, so a check that
    /// only inspected the symlink's own (conventionally always-permissive) mode — rather than
    /// letting the kernel resolve through it, as `open` does — would miss the denial entirely.
    #[test]
    fn a_symlinked_ancestor_is_denied_by_the_kernel_not_modelled() {
        let base = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inner = real.join("inner");
        std::fs::create_dir(&inner).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let result = check(&link.join("inner"));
        if unsafe { libc::geteuid() } == 0 {
            // Root: the fork really becomes UNPRIVILEGED, which does not own `real` — denied.
            let err = result.unwrap_err();
            assert!(err.contains("link"), "{err}");
        } else {
            // Not root: the drop no-ops, so the check runs as THIS test's own identity — which
            // owns `real`, and so can always enter its own `0700` directory. Still exercises the
            // same fork+open path through the symlink, just without an identity that gets denied.
            assert!(result.is_ok(), "{result:?}");
        }
    }
}
