//! `cosca`: unified cross-platform subprocess management.
//!
//! Build a process with [`Command`] (stdio, env, tree containment, elevation),
//! spawn it into an owned [`Child`], or attach to an already-running process by
//! pid via [`Process`]. Sync by default; async counterparts live in the `tokio`
//! module behind the `tokio` feature.

pub mod containment;
pub mod elevation;
pub mod error;
pub mod graceful;
pub mod identity;
pub mod quote;
pub mod stdio;
pub use containment::{ContainMode, Containment};
pub use elevation::{Auth, Backend, ElevatedStdio, ElevatedVia, ElevationReport, EnvSanitizer, Privilege, Secret};
pub use graceful::GracefulMechanism;
pub use stdio::{Fd, Stdio};

mod child;
pub use child::Child;

/// Test-only: the same process-wide lock production spawns take internally
/// (`child::spawn::spawn_lock`), exposed so this crate's OWN integration tests
/// (`tests/*.rs`, a separate compilation unit that cannot name a `pub(crate)` item) can
/// serialize a raw `std::process::Command` spawn against it too — closing the same
/// fork-bystander-inherits-a-live-marker window `containment::fdmarker`'s module docs
/// describe, for a raw spawn that bypasses `cosca::Command` entirely. `#[doc(hidden)]`: not
/// public API, present only for this crate's own `tests/` binaries to link against.
#[doc(hidden)]
pub fn test_spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    child::spawn::spawn_lock()
}

mod command;
pub use command::Command;

mod wait;

#[cfg(test)]
mod log_capture;

#[cfg(test)]
mod test_child;

pub mod process;
pub use process::{Process, Recursive};

#[cfg(feature = "tokio")]
pub mod tokio;

pub use std::process::ExitStatus;

/// Captured result of a finished process.
#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Start building a command from an argument vector.
pub fn run<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut c = Command::new();
    c.args(args);
    c
}

/// Start building a command from a single command-line string.
pub fn run_line(line: impl Into<std::ffi::OsString>) -> Command {
    let mut c = Command::new();
    c.commandline(line);
    c
}
