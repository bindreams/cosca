//! The env var shared by the testbin's `drop_root` (in `main.rs`) and `tests/elevation_pkexec_version.rs`.

/// Set (to `uid:gid`) in a root testbin's environment to name the ids it drops to before the fake
/// `pkexec` mode runs: ids the test checked its user namespace maps.
pub const DROP_TO_ENV: &str = "COSCA_TESTCFG_DROP_TO";
