//! The one way a test builds the command that re-executes its own test binary.
//!
//! Skuld reads `SKULD_LABELS` and `SKULD_NEXTEST_METADATA_PATH` from its environment. A child that
//! inherits `SKULD_LABELS` selects the labelled tests only, so a fixture without the driver's
//! label lists zero tests and exits 0; one that inherits `SKULD_NEXTEST_METADATA_PATH` overwrites
//! the caller's metadata file. [`command`] removes both.
//!
//! Skuld's output capture is fd-level and drops a passing test's bytes, so a child whose stdout or
//! stderr the driver reads must also run with `--nocapture`.
//!
//! Also mounted by `#[path]` into `tests/common` (as a sibling of `test_own_process`), so it
//! names nothing of its crate.

/// The skuld variables a re-exec'd child must not inherit.
pub const SCRUBBED_ENV: [&str; 2] = ["SKULD_LABELS", "SKULD_NEXTEST_METADATA_PATH"];

/// `Command::new(program)` for re-executing a test binary, without the [`SCRUBBED_ENV`] variables.
///
/// For a `cosca::Command` or tokio launcher, which cannot take this value, remove
/// [`SCRUBBED_ENV`] from it instead (tokio: `tokio::process::Command::from(command(program))`).
pub fn command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    for var in SCRUBBED_ENV {
        command.env_remove(var);
    }
    command
}
