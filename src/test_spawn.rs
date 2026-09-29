//! Spawn helpers for tests that drive a raw `std::process::Command` (or tokio's) directly.
//!
//! A raw spawn forks without going through `cosca::Command`, so it must take
//! [`spawn_lock`](crate::child::spawn::spawn_lock) itself. Otherwise a fork that never `exec`s
//! (the `cgroup` tests' `fork_running`) can land inside the spawn and inherit its transient
//! descriptors: the CLOEXEC exec-error pipe write end, or a `Stdio::piped()` child-side end. Its
//! copy stays open until that fork exits, so the spawn (which reads the exec-error pipe to EOF)
//! and any reader of the piped stream block until then.
//!
//! Never call these while already holding `spawn_lock`, or from a `cosca::Command` spawn: the lock
//! is not reentrant, and re-entry panics.

use std::io;
use std::process::{Child, Command};
#[cfg(unix)]
use std::process::{ExitStatus, Output, Stdio};

/// Holds `spawn_lock` for one spawn.
struct Held {
    _guard: crate::child::spawn::SpawnLockGuard,
}

impl Held {
    fn take() -> Self {
        Self {
            _guard: crate::child::spawn::spawn_lock(),
        }
    }
}

/// Whether the calling thread holds `spawn_lock`. In a `pre_exec` closure, whether the fork
/// happened under the lock: a plain read of a const-initialised thread-local, async-signal-safe.
#[cfg(unix)]
pub(crate) fn held_by_this_thread() -> bool {
    crate::child::spawn::spawn_lock_held_by_this_thread()
}

/// [`Command::spawn`] under `spawn_lock`.
pub(crate) fn spawn(cmd: &mut Command) -> io::Result<Child> {
    let _held = Held::take();
    cmd.spawn()
}

/// [`Command::output`] with `spawn_lock` held for the spawn only. Like `output` it captures
/// stdout and stderr and gives the child a null stdin, but it OVERRIDES whatever the caller set
/// for those three: `output` cannot be split into its spawn and its wait, and a stdio setting
/// cannot be told apart from the default.
#[cfg(unix)]
pub(crate) fn output(cmd: &mut Command) -> io::Result<Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    spawn(cmd)?.wait_with_output()
}

/// [`Command::status`] under `spawn_lock` for the spawn only; the wait runs unlocked.
#[cfg(unix)]
pub(crate) fn status(cmd: &mut Command) -> io::Result<ExitStatus> {
    spawn(cmd)?.wait()
}

/// `tokio::process::Command::spawn` under `spawn_lock`.
#[cfg(all(unix, feature = "tokio"))]
pub(crate) fn spawn_tokio(cmd: &mut ::tokio::process::Command) -> io::Result<::tokio::process::Child> {
    let _held = Held::take();
    cmd.spawn()
}

#[cfg(test)]
#[path = "test_spawn_tests.rs"]
mod tests;
