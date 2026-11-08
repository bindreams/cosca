//! Async spawn: the sync spawn, told the async policy (see [`async_policy`]), whose child the async
//! [`Child`] holds. Every platform, elevation and containment arm is the sync spawn's.

use crate::child::spawn::SpawnFailure;
use crate::command::Command;
use crate::error::Error;

use super::child::{async_policy, Child};

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, SpawnFailure> {
    spawn_uncommitted(cmd)?.commit_kill_on_drop()
}

/// [`spawn`] up to the handle it returns, whose containment resource still tears the tree down
/// on drop whatever `kill_on_drop` says.
///
/// Every failure says whether the program could have started; see [`SpawnFailure`].
pub(super) fn spawn_uncommitted(cmd: &mut Command) -> Result<Child, SpawnFailure> {
    // The async waits need a running reactor, and a handle without one cannot wait: reject the
    // no-runtime case up front, as a typed Err on every platform.
    if ::tokio::runtime::Handle::try_current().is_err() {
        return Err(SpawnFailure::NotStarted(Error::Io(std::io::Error::other(
            "cosca::tokio::Command must be spawned from within a Tokio runtime",
        ))));
    }
    #[cfg(unix)]
    require_io_driver()?;
    crate::child::spawn::spawn_uncommitted(cmd, async_policy()).map(Child::from_sync)
}

/// Panics, before the program starts, on a runtime without the IO driver: the child's waits and
/// pipes register with the reactor, and tokio panics at a registration on such a runtime, so a
/// handle that could never wait is not made. A pipe's end stands for the registration, and is
/// deregistered as it drops.
#[cfg(unix)]
fn require_io_driver() -> Result<(), SpawnFailure> {
    let (probe, _write_end) = std::io::pipe().map_err(|e| SpawnFailure::NotStarted(Error::Io(e)))?;
    // The panic is the answer; a registration that fails any other way is the wait's to report.
    _ = ::tokio::io::unix::AsyncFd::new(probe);
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/slow_teardown_tests.rs"]
mod slow_teardown_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "spawn/slow_teardown_macos_tests.rs"]
mod slow_teardown_macos_tests;

#[cfg(all(test, windows))]
#[path = "spawn/slow_teardown_windows_tests.rs"]
mod slow_teardown_windows_tests;
