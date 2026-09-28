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
/// The function now acts and fails (forks, drops to `UNPRIVILEGED`, `access(path, X_OK)`s it,
/// reports the real errno) rather than modelling permission bits in Rust — see its own doc for
/// why. That drop only really happens as root: as a non-root, already-unprivileged caller, it
/// no-ops (same shape as [`crate::test_privilege::drop_root_uid`]'s own), so the check runs as
/// the CURRENT identity — which owns every directory these tests build.
///
/// Most tests below are written to be IDENTITY-INDEPENDENT: their mode is chosen so the owner
/// class (what a non-root run checks, since the test process owns what it builds) and the other
/// class (what a root run checks, since `UNPRIVILEGED` is neither the owner nor, after
/// `setgroups(0, ..)`, in the owning group) agree on the answer — `0o101` and `0o701` both give
/// the `x` bit to owner AND other, so both are `Ok` either way; `0o404` gives NEITHER class `x`,
/// so both are `Err` either way. `a_symlinked_ancestor_is_denied_by_the_kernel_not_modelled`
/// instead sets `real` to `0o000` specifically so NEITHER class has `x` there either — the same
/// identity-independent trick, applied to the symlink-following regression itself, so the denial
/// is asserted unconditionally rather than only under a `geteuid() == 0` branch (which no CI lane
/// exercised: `resolve_root_lane_macos`'s own `-E` filter did not select this module).
#[cfg(all(unix, not(target_os = "linux")))]
mod check_path_traversable_by_tests {
    use std::os::unix::fs::PermissionsExt as _;

    fn check(path: &std::path::Path) -> Result<(), String> {
        super::super::check_path_traversable_by(path)
    }

    fn chmod(path: &std::path::Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Every test in this module builds directly under `/tmp`, never under
    /// `tempfile::tempdir()`'s own ambient `TMPDIR` — the ONE thing every platform this crate
    /// targets guarantees world-traversable end to end (see `copy_exe_to_traversable_scratch`'s
    /// own doc for the identical reasoning). Under `sudo -E` on macOS specifically, the ambient
    /// `TMPDIR` stays the CALLING (unprivileged) user's own per-app-container directory —
    /// `chmod 0700`, owned by neither root nor `UNPRIVILEGED` — so a test built under it would be
    /// refused by that ANCESTOR regardless of whatever mode the test itself sets on its own leaf,
    /// making an `Err`-expecting test pass for the WRONG reason (a `read_only_with_no_execute_bit`
    /// case built there once did: it passed vacuously, denied by the ambient ancestor rather than
    /// by its own intended mode) and an `Ok`-expecting one fail outright.
    fn scratch_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .tempdir_in("/tmp")
            .expect("tempdir directly under /tmp")
    }

    #[test]
    fn a_reachable_directory_is_ok() {
        let dir = scratch_dir();
        chmod(dir.path(), 0o755);
        let r = check(dir.path());
        assert!(r.is_ok(), "{r:?}");
    }

    /// `0o101`: owner `--x`, other `--x` — search-only for both classes `check_path_traversable_by`
    /// can end up testing, identity-independent (see the module doc).
    #[test]
    fn search_only_for_owner_and_other_is_ok() {
        let dir = scratch_dir();
        chmod(dir.path(), 0o101);
        let r = check(dir.path());
        assert!(r.is_ok(), "{r:?}");
    }

    /// `0o404`: owner `r--`, other `r--` — read, but no execute/search bit anywhere. The exact
    /// shape `open(O_RDONLY)` (this function's earlier, wrong mechanism) would have falsely
    /// PASSED, and the exact shape a root-owned `0711`/`0701` directory — search-only, no read —
    /// would have falsely REFUSED under it. `access(path, X_OK)` gets both right; this case pins
    /// the refusal half.
    #[test]
    fn read_only_with_no_execute_bit_is_err() {
        let dir = scratch_dir();
        chmod(dir.path(), 0o404);
        let r = check(dir.path());
        assert!(r.is_err(), "{r:?}");
    }

    /// `0o701`: owner `rwx`, other `--x` — restored from the pre-rewrite suite (then testing an
    /// arbitrary "some other uid" directly against the modelled bits; now identity-independent
    /// the same way as the two cases above, since owner and other both carry `x`).
    #[test]
    fn world_searchable_only_is_ok() {
        let dir = scratch_dir();
        chmod(dir.path(), 0o701);
        let r = check(dir.path());
        assert!(r.is_ok(), "{r:?}");
    }

    /// The reviewer's own repro shape: `real` sits behind a symlink, so a check that only
    /// inspected the symlink's own (conventionally always-permissive) mode — rather than letting
    /// the kernel resolve through it, as `access` does — would miss the denial entirely. `real` is
    /// `0o000`, not `0o700`: identity-independent (see the module doc), so this asserts `Err`
    /// unconditionally, with no `geteuid()` branch — no CI lane exercised the root branch here
    /// before (`resolve_root_lane_macos`'s `-E` filter selected `resolve_base_tests`/
    /// `exact_posix_tests` only, never this module), so a version that only checked under
    /// `geteuid() == 0` was never actually run as root anywhere in CI.
    #[test]
    fn a_symlinked_ancestor_is_denied_by_the_kernel_not_modelled() {
        let base = scratch_dir();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let inner = real.join("inner");
        std::fs::create_dir(&inner).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Locked last: creating `inner` under `real` needs the OWNER's own write+execute first —
        // mode bits bind the owner too, not just other callers.
        chmod(&real, 0o000);

        let r = check(&link.join("inner"));
        assert!(r.is_err(), "{r:?}");
        let err = r.unwrap_err();
        assert!(err.contains("link"), "{err}");
    }
}
