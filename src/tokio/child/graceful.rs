//! Async `Child` graceful shutdown — the soft-then-hard escalation trio, mirroring the
//! sync `Child` counterparts.

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
        crate::wait::terminate(self.id())
    }

    /// Cooperative-then-forced lone shutdown: `SIGTERM`, wait up to `grace` for the child to
    /// exit, then `SIGKILL` if it has not — reaping either way and returning its `ExitStatus`.
    /// The status's terminating signal distinguishes a graceful exit from a forced one —
    /// best-effort at the boundary: a child that exits of its own accord between the grace
    /// elapsing and the `SIGKILL` landing reports its own status.
    /// Escalation proceeds even if the child ignores `SIGTERM`. Unix only; Windows returns
    /// `Unsupported`. `grace` is relative; `Duration::ZERO` signals, polls once, then escalates.
    ///
    /// Dropping this future mid-grace cancels the exit watch (the `AsyncFd` deregisters and
    /// the fd closes) and performs no further signalling — the child stays owned, and
    /// `Drop`'s teardown still applies.
    ///
    /// A watch failure never skips the kill and reap; it surfaces only after they run, and a
    /// kill/reap error takes precedence (the child then stays owned — `Drop`'s teardown
    /// applies).
    ///
    /// # Runtime
    ///
    /// Needs a runtime with the IO **and** time drivers enabled (the `#[tokio::main]` /
    /// `#[tokio::test]` defaults) — on a hand-built runtime missing either, tokio panics
    /// rather than returning a typed error.
    pub async fn graceful_shutdown(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        crate::wait::terminate(self.id())?;
        // A watch failure must not strand the child between the soft signal and the
        // escalation — kill and reap still run (grace unobservable => escalate now); the
        // watch error surfaces only after they succeed (a kill/reap error wins — deliberate
        // subsumption, mirroring kill_tree's both-fail disposition).
        let watch = crate::tokio::wait::grace_wait(self.id(), grace).await;
        if !matches!(watch, Ok(true)) {
            if let Err(e) = &watch {
                log::debug!(
                    "graceful_shutdown({id}): watch error before escalation (subsumed if it also fails): {e}",
                    id = self.id().pid()
                );
            }
            self.kill()?; // escalate; an Err returns HERE, subsuming any watch Err
        }
        let status = self.wait().await?;
        watch?;
        Ok(status)
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
    ///
    /// Dropping this future mid-grace cancels the exit watch (on all platforms — the Windows
    /// watcher is released via its cancel event) and performs no further signalling — the
    /// child stays owned, and `Drop`'s teardown still applies.
    ///
    /// A watch failure never skips the sweep and reap; a sweep error wins over it — and over
    /// a graceful root exit (survivors may remain; the root is still reaped first when its
    /// exit was observed, otherwise the child stays owned for `Drop`).
    ///
    /// # Runtime
    ///
    /// On Unix, needs a runtime with the IO **and** time drivers enabled (the
    /// `#[tokio::main]` / `#[tokio::test]` defaults) — missing either, tokio panics rather
    /// than returning a typed error. On Windows the grace-wait runs on the blocking pool:
    /// each in-flight call occupies one blocking-pool thread for up to `grace` — size the
    /// pool accordingly for many long concurrent shutdowns.
    pub async fn graceful_shutdown_tree(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        // terminate_tree's own require_contained guard fires before any signal, so an
        // uncontained child errors up front.
        self.terminate_tree()?;
        // Watch-Err ordering: sweep + reap first, then surface (see graceful_shutdown above).
        let watch = crate::tokio::wait::grace_wait(self.id(), grace).await;
        // The sweep is unconditional — a gracefully-exited root does NOT mean the descendants
        // drained (the survivor-sweep scenario). A sweep Err subsumes any watch Err; it must
        // propagate before the reap on a LIVE root (waiting unswept would hang), but once the
        // root's exit was observed, the reap runs first so no zombie is stranded.
        if let Err(e) = &watch {
            log::debug!(
                "graceful_shutdown_tree({id}): watch error before escalation (subsumed if it also fails): {e}",
                id = self.id().pid()
            );
        }
        if let Err(sweep) = self.kill_tree() {
            if matches!(watch, Ok(true)) {
                // The root is a zombie — this reap cannot hang (which is why it is gated on the
                // observed exit). The sweep Err stays the verdict: the status, and even a distinct
                // reap Err (a wait failure on the zombie), are subsumed — live survivors are the
                // actionable failure, and the child stays owned for Drop's teardown.
                let _ = self.wait().await;
            }
            return Err(sweep);
        }
        let status = self.wait().await?;
        watch?;
        Ok(status)
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
