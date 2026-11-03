//! Async mirror of the foreign [`Process`](crate::Process). Introspection delegates
//! synchronously; only the death-watch and the graceful pair are async (`tokio::wait`).
//! NO stdio (its pipes belong to its real parent); every operation re-verifies identity; nothing here
//! reaps (the real parent collects the zombie).

use std::time::Duration;

use crate::error::Error;
use crate::identity::{ProcessId, RawPid};

#[path = "process/graceful.rs"]
mod graceful;

/// An async handle on an open process. See [`Process`](crate::Process); the waits are async.
#[derive(Debug)]
pub struct Process {
    inner: crate::process::Process,
}

impl From<crate::process::Process> for Process {
    fn from(inner: crate::process::Process) -> Process {
        Process { inner }
    }
}

impl Process {
    /// Open the process `id` names (see [`Process::open`](crate::Process::open)).
    pub fn open(id: ProcessId) -> Result<Option<Process>, Error> {
        Ok(crate::process::Process::open(id)?.map(Process::from))
    }

    /// Open the process holding `pid` now (see [`Process::open_pid`](crate::Process::open_pid)).
    pub fn open_pid(pid: RawPid) -> Result<Option<Process>, Error> {
        Ok(crate::process::Process::open_pid(pid)?.map(Process::from))
    }

    /// An open handle on this process itself (see [`Process::current`](crate::Process::current)).
    pub fn current() -> Result<Process, Error> {
        crate::process::Process::current().map(Process::from)
    }

    /// The stable identity (`(pid, start_token)`).
    pub fn id(&self) -> ProcessId {
        self.inner.id()
    }

    /// Whether the process is still running, read through the handle (see
    /// [`Process::is_alive`](crate::Process::is_alive)).
    pub fn is_alive(&self) -> crate::identity::Liveness {
        self.inner.is_alive()
    }

    /// Resolve when the process exits. Death-watch — yields no `ExitStatus` (only the real
    /// parent gets one). Non-reaping and signal-free; `Err` only on a watch failure. Dropping the future cancels the watch on every
    /// platform (the Windows watcher is released via its cancel event).
    ///
    /// # Runtime
    ///
    /// Needs a runtime with the IO driver enabled on Unix (the `#[tokio::main]` /
    /// `#[tokio::test]` defaults) — missing it, tokio panics rather than returning a typed
    /// error. On Windows the watch runs on the blocking pool (one thread per in-flight wait).
    pub async fn wait(&self) -> Result<(), Error> {
        let exited = crate::tokio::drive::exited_held(self.inner.os(), None).await?;
        debug_assert!(exited);
        Ok(())
    }

    /// Wait up to `timeout` for the process to exit. `Ok(true)` = exited; `Ok(false)` =
    /// still alive at expiry. `Duration::ZERO` polls once. Non-reaping; cancellation and
    /// runtime requirements as on [`wait`](Process::wait) (Unix additionally needs the time
    /// driver). Errors as for [`wait`](Process::wait).
    pub async fn wait_timeout(&self, timeout: Duration) -> Result<bool, Error> {
        crate::tokio::drive::exited_held(self.inner.os(), Some(timeout)).await
    }

    /// Hard-kill the process (see [`Process::kill`](crate::Process::kill) for
    /// the per-OS race-freedom contract).
    pub fn kill(&self) -> Result<(), Error> {
        self.inner.kill()
    }

    /// Send `SIGTERM` (signal-only, bound to the opened process). Unix only; Windows returns
    /// `Unsupported`.
    pub fn terminate(&self) -> Result<(), Error> {
        self.inner.terminate()
    }

    /// Best-effort hard identity-walk sweep of the tree (all platforms; the `TreeWalk`
    /// contract — see [`Process::kill_tree`](crate::Process::kill_tree)).
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.inner.kill_tree()
    }

    /// Best-effort graceful (`SIGTERM`) identity-walk sweep. Unix only; Windows returns
    /// `Unsupported` (see [`Process::terminate_tree`](crate::Process::terminate_tree)).
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.inner.terminate_tree()
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod process_tests;
