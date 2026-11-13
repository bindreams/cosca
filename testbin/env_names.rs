//! The env vars the testbin reads that tests set, shared by `testbin/main.rs` and `tests/common`.

/// Set (to a mode name) in the environment to select the testbin's mode instead of argv[1], so a
/// test that shifts argv cannot change what the testbin does.
pub const TESTBIN_MODE_ENV: &str = "COSCA_TESTBIN_MODE";

/// Set (to `uid:gid`) in a root testbin's environment to name the ids it drops to before the fake
/// `pkexec` mode runs: ids the test checked its user namespace maps.
#[cfg(unix)]
pub const DROP_TO_ENV: &str = "COSCA_TESTCFG_DROP_TO";
