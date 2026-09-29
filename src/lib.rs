//! `cosca`: unified cross-platform subprocess management.
//!
//! Build a process with [`Command`] (stdio, env, tree containment, elevation),
//! spawn it into an owned [`Child`], or attach to an already-running process by
//! pid via [`Process`]. Sync by default; async counterparts live in the `tokio`
//! module behind the `tokio` feature.
//!
//! # Platform requirements
//!
//! **Linux 5.6 or newer**, with `pidfd_open` and `openat2` not blocked by a seccomp profile.
//! Each requirement comes from a different syscall:
//!
//! - `pidfd_open` needs 5.3, and cosca requires a pidfd for every child it spawns. A refusal is
//!   [`Error::Unsupported`](error::Error::Unsupported); a transient failure such as `EMFILE` is
//!   [`Error::Io`](error::Error::Io) naming the syscall. `main` does not require a pidfd
//!   at spawn yet ([#341](https://github.com/bindreams/cosca/issues/341)).
//! - `waitid(P_PIDFD)` needs 5.4, and is what a pidfd-based reap needs. On `main` only the cgroup
//!   leaf reaps that way; an owned child's waits and reaps still go by pid
//!   ([#341](https://github.com/bindreams/cosca/issues/341)).
//! - `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS` needs 5.6. The
//!   checked `/proc` view uses it to read a process's identity. A refusal is
//!   [`Error::Unsupported`](error::Error::Unsupported) naming `openat2`, from a spawn or from a
//!   by-pid identity read, wait or kill. [`ProcessId::current`](identity::ProcessId::current)
//!   needs only a readable `/proc/self/stat`.
//!
//! [`Containment::CgroupV2`] additionally needs `cgroup.kill` (Linux 5.14); without it `CgroupV2`
//! is not used and containment falls back as documented on [`Containment`]. It also assumes kernel
//! commit `b69bb476dee9` ("cgroup: fix race between fork and cgroup.kill"), in mainline from 6.14
//! or in a stable kernel that carries it. cosca does not probe for it; the cost of its absence is
//! described under [`Command::kill_on_drop`].

// `SpawnLockGuard` is `#[must_use]`, but only this lint keeps `let _ = spawn_lock();` (a lock released
// at once) flagged, as rustc's `let_underscore_lock` did when the guard was a `MutexGuard`. Discard a
// result on purpose with `_ = expr;`. Crate-level, not in `[lints]`, which would extend it to the
// tests and test binaries.
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

// Lets `tests/common/locked.rs`, which names `cosca::test_spawn_lock`, compile into the lib's tests.
#[cfg(test)]
extern crate self as cosca;

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
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "off-windows only resolve::exact is consumed, so the lib build sees the search policy as dead"
    )
)]
mod resolve;
pub use command::Command;

mod wait;

#[cfg(test)]
mod log_capture;

#[cfg(test)]
mod graceful_hooks;

#[cfg(test)]
mod oneshot_hook;

#[cfg(test)]
mod relayed_probe;

#[cfg(test)]
mod test_child;

#[cfg(all(test, unix))]
mod test_privilege;

#[cfg(all(test, unix))]
mod test_own_process;
#[cfg(all(test, unix))]
mod test_own_process_tests;
#[cfg(all(test, unix))]
mod test_stdio;
#[cfg(all(test, unix))]
mod test_stdio_tests;
#[cfg(all(test, target_os = "macos"))]
mod test_support;

#[cfg(test)]
mod test_spawn;

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
