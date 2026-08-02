//! Async mirror of the foreign [`Process`](crate::Process). Introspection delegates
//! synchronously; only the death-watch and the graceful pair are async (`tokio::wait`).
//! NO stdio (its pipes belong to its real parent); every operation re-verifies identity; nothing here
//! reaps (the real parent collects the zombie).

use std::time::Duration;

use crate::error::Error;
use crate::identity::{ProcessId, RawPid};
use crate::process::Recursive;

#[path = "process/graceful.rs"]
mod graceful;

/// An async handle to a foreign process identified by `(pid, start_token)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Process {
    inner: crate::process::Process,
}

impl From<crate::process::Process> for Process {
    fn from(inner: crate::process::Process) -> Process {
        Process { inner }
    }
}

impl Process {
    /// Resolve a foreign process by a saved identity. `None` if that exact identity is
    /// gone or the pid was recycled.
    pub fn from_id(id: ProcessId) -> crate::identity::Resolved<Process> {
        crate::process::Process::from_id(id).map(Process::from)
    }

    /// Resolve the process currently holding `pid`. `None` if no live process has it.
    pub fn from_pid(pid: RawPid) -> crate::identity::Resolved<Process> {
        crate::process::Process::from_pid(pid).map(Process::from)
    }

    /// This process's own handle. Infallible.
    pub fn current() -> Process {
        Process::from(crate::process::Process::current())
    }

    /// The stable identity (`(pid, start_token)`).
    pub fn id(&self) -> ProcessId {
        self.inner.id()
    }

    /// Whether the process is still running (zombie-exclusive; see [`ProcessId::is_alive`]).
    pub fn is_alive(&self) -> crate::identity::Liveness {
        self.inner.is_alive()
    }

    /// The parent process, by identity (see [`Process::parent`](crate::Process::parent) for
    /// the identity-guard contract).
    pub fn parent(&self) -> Option<Process> {
        self.inner.parent().map(Process::from)
    }

    /// The process's children (see [`Process::children`](crate::Process::children)).
    pub fn children(&self, recursive: Recursive) -> Vec<Process> {
        self.inner.children(recursive).into_iter().map(Process::from).collect()
    }

    /// Resolve when the process exits. Death-watch — yields no `ExitStatus` (only the real
    /// parent gets one). Non-reaping and signal-free; `Err` only on a watch failure (incl.
    /// `Unsupported` on Linux < 5.3). Dropping the future cancels the watch on every
    /// platform (the Windows watcher is released via its cancel event).
    ///
    /// # Runtime
    ///
    /// Needs a runtime with the IO driver enabled on Unix (the `#[tokio::main]` /
    /// `#[tokio::test]` defaults) — missing it, tokio panics rather than returning a typed
    /// error. On Windows the watch runs on the blocking pool (one thread per in-flight wait).
    pub async fn wait(&self) -> Result<(), Error> {
        crate::tokio::wait::wait_exit(self.inner.id()).await
    }

    /// Wait up to `timeout` for the process to exit. `Ok(true)` = exited; `Ok(false)` =
    /// still alive at expiry. `Duration::ZERO` polls once. Non-reaping; cancellation and
    /// runtime requirements as on [`wait`](Process::wait) (Unix additionally needs the time
    /// driver).
    pub async fn wait_timeout(&self, timeout: Duration) -> Result<bool, Error> {
        crate::tokio::wait::grace_wait(self.inner.id(), timeout).await
    }

    /// Hard-kill the process by identity (see [`Process::kill`](crate::Process::kill) for
    /// the per-OS race-freedom contract).
    pub fn kill(&self) -> Result<(), Error> {
        self.inner.kill()
    }

    /// Send `SIGTERM` (signal-only, identity-bound). Unix only; Windows returns
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
