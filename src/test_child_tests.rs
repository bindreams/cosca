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
