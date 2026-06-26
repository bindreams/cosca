//! `Child` graceful shutdown — the soft-then-hard escalation trio. A submodule of `child`
//! so it can reach `Child`'s private `shared`/`id`.

use std::process::ExitStatus;
use std::time::Duration;

use super::Child;
use crate::error::Error;

impl Child {
    /// Send `SIGTERM` to the (lone) child — a cooperative request to exit. Signal-only: does
    /// not wait or reap. Identity-bound, so it cannot race a concurrent reap onto a recycled
    /// pid. Unix only — Windows has no per-process graceful signal and returns `Unsupported`
    /// (use [`graceful_shutdown_tree`](Child::graceful_shutdown_tree) for a contained child).
    pub fn terminate(&self) -> Result<(), Error> {
        crate::wait::terminate(self.id)
    }

    /// Cooperative-then-forced lone shutdown: `SIGTERM`, wait up to `grace` for the child to
    /// exit, then `SIGKILL` if it has not — reaping either way and returning its `ExitStatus`.
    /// The status's terminating signal distinguishes a graceful exit from a forced one.
    /// Escalation proceeds even if the child ignores `SIGTERM`. Unix only; Windows returns
    /// `Unsupported`. `grace` is relative; `Duration::ZERO` signals, polls once, then escalates.
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<ExitStatus, Error> {
        crate::wait::terminate(self.id)?; // SIGTERM (Windows: Unsupported, early return)
        if let Some(status) = self.wait_timeout(grace)? {
            return Ok(status); // exited within grace
        }
        self.shared.kill().map_err(Error::Io)?;
        self.wait()
    }

    /// Cooperative-then-forced shutdown of the contained tree: send the group its graceful
    /// signal (`SIGTERM` via `killpg`/cgroup, or `CTRL_BREAK` to the job/console group), wait
    /// up to `grace` for the **root** to exit, then hard-sweep any survivors and reap the root.
    /// Returns the root's `ExitStatus`. Requires an actionable containment mechanism (errors
    /// `Unsupported` otherwise — use [`graceful_shutdown`](Child::graceful_shutdown) for a lone
    /// child). Works on all platforms.
    ///
    /// The grace-wait is **non-reaping** (watches the root's exit without collecting it), so the
    /// subsequent hard sweep runs while the root's pid — and thus the `killpg` group id — is
    /// still valid; reaping first could let `killpg` hit a recycled group. The sweep is
    /// unconditional but a no-op once the tree has drained, so a graceful exit's status is
    /// preserved (the lone backstop no-ops on the already-dead root).
    pub fn graceful_shutdown_tree(&self, grace: Duration) -> Result<ExitStatus, Error> {
        // Fail fast before sending any signal. terminate_tree/kill_tree re-check this guard
        // internally; the redundancy is intentional so an uncontained child errors up front.
        self.require_contained()?;
        self.terminate_tree()?; // group SIGTERM / CTRL_BREAK (signal-only)
        let _ = crate::wait::block_until_exit(self.id, Some(grace))?; // NON-reaping grace-wait on root
        self.kill_tree()?;
        self.wait()
    }
}
