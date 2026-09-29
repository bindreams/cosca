//! `cosca`: unified cross-platform subprocess management.
//!
//! Build a process with [`Command`] (stdio, env, tree containment, elevation),
//! spawn it into an owned [`Child`], or attach to an already-running process by
//! pid via [`Process`]. Sync by default; async counterparts live in the `tokio`
//! module behind the `tokio` feature.

// `SpawnLockGuard` is `#[must_use]`, but only this lint keeps `let _ = spawn_lock();` (a lock released
// at once) flagged, as rustc's `let_underscore_lock` did when the guard was a `MutexGuard`. Discard a
// result on purpose with `_ = expr;`.
#![warn(clippy::let_underscore_must_use)]

pub mod containment;
pub mod elevation;
pub mod error;
pub mod graceful;
pub mod identity;
pub mod quote;
pub mod stdio;
#[cfg(windows)]
pub use containment::Job;
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
///
/// Returns a guard: hold it for the raw spawn. Re-taking the lock on the same thread (a
/// `cosca::Command::spawn` under it, say) panics under `debug_assertions` instead of deadlocking.
#[doc(hidden)]
pub fn test_spawn_lock() -> TestSpawnLockGuard {
    TestSpawnLockGuard(child::spawn::spawn_lock())
}

/// Holds [`test_spawn_lock`]'s lock until dropped.
#[doc(hidden)]
#[must_use = "if unused the spawn lock is released immediately; bind the guard for the whole window"]
pub struct TestSpawnLockGuard(#[allow(dead_code, reason = "held only for its Drop")] child::spawn::SpawnLockGuard);

mod command;
// Off Windows only the `Exact` completion (`resolve::exact`) is consumed, so the lib build sees
// the search policy as dead. The module is deliberately NOT cfg-gated: keeping it platform-independent is what makes
// its policy testable from a POSIX host, which is where most of this work happens. The allow
// goes away when the POSIX and default spawn paths route through it too.
#[cfg_attr(not(windows), allow(dead_code))]
mod resolve;
pub use command::Command;

mod wait;

#[cfg(test)]
mod log_capture;

#[cfg(test)]
mod oneshot_hook;

#[cfg(test)]
mod test_child;

#[cfg(all(test, unix))]
mod test_privilege;

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
