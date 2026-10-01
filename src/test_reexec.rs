//! The one place that decides how a test re-executes its own test binary.
//!
//! Skuld reads `SKULD_LABELS` and `SKULD_NEXTEST_METADATA_PATH` from its environment. A child that
//! inherits `SKULD_LABELS` selects the labelled tests only, so a fixture without the driver's
//! label lists zero tests and exits 0; one that inherits `SKULD_NEXTEST_METADATA_PATH` overwrites
//! the caller's metadata file. Every re-exec removes both ([`command`], or [`scrub_env`] for a
//! command type that is not `std`'s).
//!
//! Skuld's output capture is fd-level and drops a passing test's bytes, so a child whose stdout or
//! stderr the driver reads also runs with [`NOCAPTURE`] ([`fixture_args`] includes it).
//!
//! Also mounted by `#[path]` into `tests/common` (as a sibling of `test_own_process`), so it
//! names nothing of its crate.

/// The skuld variables a re-exec'd child must not inherit.
pub const SCRUBBED_ENV: [&str; 2] = ["SKULD_LABELS", "SKULD_NEXTEST_METADATA_PATH"];

/// Keeps skuld from capturing the child's output.
pub const NOCAPTURE: &str = "--nocapture";

/// `Command::new(program)` for re-executing a test binary, without the [`SCRUBBED_ENV`] variables.
///
/// A raw `tokio::process::Command` takes this value through `From`.
pub fn command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    scrub_env(|var| _ = command.env_remove(var));
    command
}

/// Calls `remove` with each [`SCRUBBED_ENV`] variable, for a `cosca::Command` or
/// `crate::tokio::Command`, which cannot be built by [`command`].
pub fn scrub_env(mut remove: impl FnMut(&str)) {
    for var in SCRUBBED_ENV {
        remove(var);
    }
}

/// The argv (after the program name) that runs exactly one fixture, single-threaded, uncaptured.
pub fn fixture_args(fixture: &str) -> [&str; 4] {
    ["--test-threads=1", "--exact", fixture, NOCAPTURE]
}
