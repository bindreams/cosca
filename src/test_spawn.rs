//! Spawn helpers for tests that drive a raw `std::process::Command` (or tokio's) directly.
//!
//! A raw spawn forks without going through `cosca::Command`, so it must take
//! [`spawn_lock`](crate::child::spawn::spawn_lock) itself. Otherwise a fork that never `exec`s
//! can land inside the spawn and inherit its transient descriptors: the CLOEXEC exec-error pipe write end, or a `Stdio::piped()` child-side end. Its
//! copy stays open until that fork exits, so the spawn (which reads the exec-error pipe to EOF)
//! and any reader of the piped stream block until then.
//!
//! Never call these while already holding `spawn_lock`, or from a `cosca::Command` spawn: the lock
//! is not reentrant, and re-entry panics.

use std::io;
use std::process::{Child, Command, ExitStatus, Output, Stdio};

thread_local! {
    static BETWEEN_SPAWN_AND_WAIT: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
}

/// Run `hook` once on this thread in the next sync or tokio `output_captured`/`status`, after the
/// spawn returned and before the wait. A test asserts there that the lock is not held, so a helper
/// that holds it across the wait fails an assertion instead of deadlocking.
#[cfg_attr(not(unix), allow(dead_code, reason = "only the unix helper tests arm it"))]
pub(crate) fn set_between_spawn_and_wait(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&BETWEEN_SPAWN_AND_WAIT, hook)
}

fn run_between_spawn_and_wait() {
    crate::oneshot_hook::fire(&BETWEEN_SPAWN_AND_WAIT);
}

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

/// Whether the calling thread holds `spawn_lock`. Async-signal-safe, so callable from `pre_exec`
/// to learn whether the fork ran under the lock.
#[cfg(unix)]
pub(crate) fn held_by_this_thread() -> bool {
    crate::child::spawn::spawn_lock_held_by_this_thread()
}

/// [`Command::spawn`] under `spawn_lock`.
pub(crate) fn spawn(cmd: &mut Command) -> io::Result<Child> {
    let _held = Held::take();
    #[allow(clippy::disallowed_methods, reason = "`_held` is spawn_lock")]
    cmd.spawn()
}

/// [`Command::output`] with `spawn_lock` held for the spawn only. Like `output`, it overrides
/// stdin (null) and stdout/stderr (piped), discarding any caller setting.
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "the ban names it; only unix lib tests call it so far")
)]
pub(crate) fn output_captured(cmd: &mut Command) -> io::Result<Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = spawn(cmd)?;
    run_between_spawn_and_wait();
    child.wait_with_output()
}

/// [`Command::status`] under `spawn_lock` for the spawn only; the wait runs unlocked.
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "the ban names it; only unix lib tests call it so far")
)]
pub(crate) fn status(cmd: &mut Command) -> io::Result<ExitStatus> {
    let mut child = spawn(cmd)?;
    run_between_spawn_and_wait();
    child.wait()
}

/// `tokio::process::Command::spawn` under `spawn_lock`.
#[cfg(feature = "tokio")]
pub(crate) fn spawn_tokio(cmd: &mut ::tokio::process::Command) -> io::Result<::tokio::process::Child> {
    let _held = Held::take();
    #[allow(clippy::disallowed_methods, reason = "`_held` is spawn_lock")]
    cmd.spawn()
}

/// The tokio twin of [`output_captured`], with the same stdio override.
#[cfg(feature = "tokio")]
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "the ban names it; only unix lib tests call it so far")
)]
pub(crate) async fn output_captured_tokio(cmd: &mut ::tokio::process::Command) -> io::Result<Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = spawn_tokio(cmd)?;
    run_between_spawn_and_wait();
    child.wait_with_output().await
}

/// The tokio twin of [`status`].
#[cfg(feature = "tokio")]
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "the ban names it; only unix lib tests call it so far")
)]
pub(crate) async fn status_tokio(cmd: &mut ::tokio::process::Command) -> io::Result<ExitStatus> {
    let mut child = spawn_tokio(cmd)?;
    run_between_spawn_and_wait();
    child.wait().await
}

#[cfg(test)]
#[path = "test_spawn_tests.rs"]
mod tests;
