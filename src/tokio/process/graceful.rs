//! Async foreign graceful shutdown — mirrors the sync `Process` graceful methods on the
//! reactor-native grace-wait. No reap anywhere (the real parent collects the zombie).

use std::time::Duration;

use super::Process;
use crate::error::Error;

impl Process {
    /// Cooperative-then-forced lone shutdown of the foreign process: `SIGTERM`, wait up to
    /// `grace`, then `SIGKILL` if it has not exited. No `ExitStatus`. Escalation proceeds
    /// even if `SIGTERM` is ignored. Unix only; Windows returns `Unsupported`. `grace` is
    /// relative; `ZERO` polls once, then escalates.
    ///
    /// A watch failure surfaces only after the kill runs; a kill error wins over it.
    /// Dropping this future mid-grace cancels the watch and performs no further signalling.
    ///
    /// # Runtime
    ///
    /// Needs the IO **and** time drivers on Unix (the `#[tokio::main]`/`#[tokio::test]`
    /// defaults) — missing either, tokio panics rather than returning a typed error.
    pub async fn graceful_shutdown(&self, grace: Duration) -> Result<(), Error> {
        self.terminate()?;
        #[cfg(test)]
        crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterTerminate);
        crate::graceful::after_grace(self.wait_timeout(grace).await, || self.kill())
    }

    /// Cooperative-then-forced shutdown of the foreign process's tree: `SIGTERM`-walk, wait
    /// up to `grace` for the **root** to exit, then a hard identity-walk sweep. Best-effort
    /// (the `TreeWalk` contract); no `ExitStatus`. Unix only (Windows `terminate_tree` is
    /// `Unsupported`).
    ///
    /// A grace-watch failure does not strand the tree: the hard sweep still runs, and the
    /// watch error is surfaced afterward; a sweep failure would win over it. Dropping this
    /// future mid-grace cancels the watch and performs no further signalling. Runtime
    /// requirements as on [`graceful_shutdown`](Process::graceful_shutdown).
    pub async fn graceful_shutdown_tree(&self, grace: Duration) -> Result<(), Error> {
        self.terminate_tree()?; // SIGTERM-walk (Windows: Unsupported, early return)
        #[cfg(test)]
        crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterTerminate);
        crate::graceful::after_tree_grace(self.wait_timeout(grace).await, || self.kill_tree())
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
