//! Async spawn: the sync spawn, run whole on tokio's blocking pool, told the async policy (see
//! [`async_policy`]), whose child the async [`Child`] holds. Every platform, elevation and
//! containment arm is the sync spawn's, and so is every wait in it: none runs on a runtime thread.

use crate::child::spawn::SpawnFailure;
use crate::command::Command;
use crate::error::ChildFate;

use super::child::{async_policy, Child};
use super::wait::{Hop, Unjoined};

/// Spawn `cmd` and apply its `kill_on_drop`: the sync spawn, on the pool. The child's last step
/// happens there too, so a future dropped before it ends leaves a child that is dropped as
/// `kill_on_drop` says.
///
/// Every failure says whether the program could have started; see [`SpawnFailure`].
pub(crate) async fn spawn(cmd: &mut Command) -> Result<Child, SpawnFailure> {
    let policy = async_policy();
    on_pool(cmd, "cosca::tokio::Command::spawn", move |cmd| {
        crate::child::spawn::spawn_uncommitted(cmd, policy)?.commit_kill_on_drop()
    })
    .await
    .map_err(spawn_failure)?
    .map(Child::from_sync)
}

/// What a spawn's hop onto the pool failing says of the program.
pub(super) fn spawn_failure(unjoined: Unjoined) -> SpawnFailure {
    match unjoined {
        Unjoined::NotRun(e) => SpawnFailure::NotStarted(e),
        // Nothing shows the task did not start the program, and nothing says what became of a child.
        Unjoined::Unknown(e) => SpawnFailure::started(e, ChildFate::Unknown, None),
    }
}

/// Run `run` on `cmd` on the blocking pool, and give `cmd` back as `run` leaves it.
///
/// The command is moved into the task when the future is first polled, and moved back when the task
/// ends. A future dropped before that, a panic, and a task the runtime's shutdown cancels all leave
/// `cmd` as [`Command::new`] makes it; a dropped future's task still runs to its end, dropping what
/// it made. With no runtime nothing is moved and `cmd` is as it was; when the runtime's shutdown
/// cancels the task before it ran, `run` did not run: the error says so (see [`Hop`]).
pub(super) async fn on_pool<R: Send + 'static>(
    cmd: &mut Command,
    what: &'static str,
    run: impl FnOnce(&mut Command) -> R + Send + 'static,
) -> Result<R, Unjoined> {
    let hop = Hop::enter(what)?;
    let mut moved = std::mem::take(cmd);
    let (moved, made) = hop
        .run(move || {
            let made = run(&mut moved);
            (moved, made)
        })
        .await?;
    *cmd = moved;
    Ok(made)
}

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/slow_teardown_tests.rs"]
mod slow_teardown_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "spawn/slow_teardown_macos_tests.rs"]
mod slow_teardown_macos_tests;

#[cfg(all(test, windows))]
#[path = "spawn/slow_teardown_windows_tests.rs"]
mod slow_teardown_windows_tests;
