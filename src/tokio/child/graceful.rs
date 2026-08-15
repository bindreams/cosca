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
    /// **Windows: what this actually signals, and what the grace costs.** `CTRL_BREAK` goes
    /// to the root's **process group** only. A nested contained descendant leads its own
    /// group and never receives it — so it does not exit during the grace, idles through the
    /// whole window, and is then killed by the sweep. The call reports no error either way:
    /// on Windows the grace is spent regardless of how much of the tree the signal reached.
    /// Size it accordingly, and treat [`kill_tree`](Child::kill_tree) as the only op that
    /// reaches every member.
    ///
    /// **The caller must also have a console.** The event is deliverable only within the
    /// *calling* process's console, so a GUI-subsystem binary, a service, or anything spawned
    /// detached fails up front: no signal is sent, no grace is waited, and the tree is left
    /// running for the caller to `kill_tree` (which needs no console). The cause is
    /// classified best-effort — usually [`Error::NoConsole`](crate::error::Error::NoConsole),
    /// but a raw `Error::Io` when the crate cannot confirm it — so treat **any** error here
    /// as "not delivered, tree still running".
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
    /// **A refused or unconfirmed graceful signal never skips the grace wait and hard sweep
    /// either.** If the initial group signal reaches a live member that refuses it, or a
    /// member's post-signal state cannot be confirmed
    /// ([`Error::Containment`](crate::error::Error::Containment) or
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) with no I/O `source` — see
    /// [`terminate_tree`](Child::terminate_tree)), the grace is still waited and the sweep
    /// still runs, so a member that only needed the follow-up `SIGKILL` does not strand the
    /// rest of the tree. A subsequent successful sweep is fresher, positive proof the group
    /// cleared, which supersedes the earlier refusal: it is logged and discarded, and this
    /// call reports `Ok`. It resurfaces only indirectly, as the sweep's own error, if the
    /// sweep then fails too. A genuine listing-mechanism failure (an `Unassessable` with an
    /// I/O `source`) is not held — like `NoConsole`/`Unsupported`/`Io`, it returns
    /// immediately: no signal is confirmed sent, so there is nothing for a grace wait or
    /// sweep to act on yet.
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
        #[cfg(test)]
        let term_result = match fault::take_force_terminate() {
            fault::Forced::None => self.terminate_tree(),
            kind => Err(fault::forced_terminate_error(kind)),
        };
        #[cfg(not(test))]
        let term_result = self.terminate_tree();

        // Hold-and-continue ONLY for the error shapes #61's fix can produce as ORDINARY
        // outcomes — see the sync `src/child/graceful.rs` twin's identical match for the full
        // rationale.
        let term = match term_result {
            Ok(()) => Ok(()),
            Err(e @ Error::Containment { .. }) | Err(e @ Error::Unassessable { source: None, .. }) => {
                log::debug!(
                    "graceful_shutdown_tree({id}): terminate_tree refused; the sweep's own outcome decides what surfaces: {e}",
                    id = self.id().pid()
                );
                Err(e)
            }
            Err(e) => return Err(e), // unchanged pre-existing behavior: no signal sent, no grace, no sweep
        };

        // Watch-Err ordering: sweep + reap first, then surface (see graceful_shutdown above).
        let watch = crate::tokio::wait::grace_wait(self.id(), grace).await;
        // The sweep is unconditional — a gracefully-exited root does NOT mean the descendants
        // drained (the survivor-sweep scenario). A sweep Err subsumes any watch or terminate Err;
        // it must propagate before the reap on a LIVE root (waiting unswept would hang), but once
        // the root's exit was observed, the reap runs first so no zombie is stranded.
        if let Err(e) = &watch {
            log::debug!(
                "graceful_shutdown_tree({id}): watch error before escalation (subsumed if it also fails): {e}",
                id = self.id().pid()
            );
        }
        if let Err(sweep) = self.kill_tree() {
            if matches!(watch, Ok(true)) {
                // Best-effort reap so an observed-exited root isn't left a zombie; `sweep`
                // (below) is already the error this call reports, so a failure here is
                // secondary — but every other discarded error in this module is still logged,
                // and a silent one here would obscure a second, independent failure mode.
                if let Err(e) = self.wait().await {
                    log::debug!(
                        "graceful_shutdown_tree({id}): best-effort reap after a swept, exited root also failed: {e}",
                        id = self.id().pid()
                    );
                }
            }
            return Err(sweep);
        }
        let status = self.wait().await?;
        watch?;
        // The sweep just returned `Ok`: positive, freshly-measured proof the group cleared,
        // superseding whatever `term` held. Discard it here rather than returning it — an
        // already-disproved refusal must never outrank the evidence that disproved it.
        if let Err(e) = &term {
            log::debug!(
                "graceful_shutdown_tree({id}): sweep succeeded; discarding the superseded terminate_tree refusal: {e}",
                id = self.id().pid()
            );
        }
        Ok(status)
    }
}

/// Test-only fault-injection seam for a forced `terminate_tree` failure inside
/// `graceful_shutdown_tree`, mirroring `crate::wait::fault`'s shape. Duplicated (not shared)
/// with `crate::child::graceful::fault` — see this crate's `#61` implementation plan, Task 7,
/// "Structural note", for why: `mod graceful;` is private in both `src/child.rs` and
/// `src/tokio/child.rs`, so a seam here is not nameable from the sync tree without widening
/// that visibility, which is out of scope here.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    /// Which `terminate_tree` failure to fabricate on the next call, on this thread.
    /// `Containment` and `UnassessablePerMember` exercise the hold-and-continue path this
    /// task adds — both ORDINARY #61 outcomes, a signal was attempted. `Unsupported` and
    /// `UnassessableMechanism` exercise fail-fast paths: `Unsupported` models the
    /// PRE-EXISTING console-less-caller shape (`NoConsole`/`Unsupported`) this task must not
    /// touch; `UnassessableMechanism` models `Error::Unassessable { source: Some(_), .. }` —
    /// `group::state`'s own listing failure, `crate::child::is_teardown_mechanism_failure`'s
    /// classification for the identical shape reaching `Child::drop` — which this task's
    /// `graceful_shutdown_tree` match must treat the SAME way (fail-fast), not fold into the
    /// per-member `Unassessable{source: None}` hold-and-continue case.
    #[derive(Clone, Copy, PartialEq, Eq, Default)]
    pub(crate) enum Forced {
        #[default]
        None,
        Containment,
        UnassessablePerMember,
        UnassessableMechanism,
        Unsupported,
    }
    thread_local! {
        static FORCE_TERMINATE: Cell<Forced> = const { Cell::new(Forced::None) };
    }
    pub(crate) fn set_force_terminate(kind: Forced) {
        FORCE_TERMINATE.with(|f| f.set(kind));
    }
    pub(crate) fn take_force_terminate() -> Forced {
        FORCE_TERMINATE.with(|f| f.replace(Forced::None))
    }
    // No `armed()` here — see the sync twin's identical note.
    pub(crate) fn forced_terminate_error(kind: Forced) -> crate::error::Error {
        match kind {
            Forced::None => unreachable!("forced_terminate_error called with Forced::None"),
            Forced::Containment => crate::error::Error::Containment {
                detail: "forced term_group refusal (test seam)".into(),
            },
            Forced::UnassessablePerMember => crate::error::Error::Unassessable {
                detail: "forced per-member unconfirmed state (test seam) — group::decide's shape".into(),
                source: None,
            },
            Forced::UnassessableMechanism => crate::error::Error::Unassessable {
                detail: "forced listing-mechanism failure (test seam) — group::state's shape".into(),
                source: Some(std::io::Error::other("forced (test seam)")),
            },
            Forced::Unsupported => crate::error::Error::Unsupported {
                op: "terminate_tree".into(),
                platform: "test",
                detail: "forced (test seam) — models NoConsole/Unsupported, NOT a #61 refusal".into(),
            },
        }
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
