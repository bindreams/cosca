//! Async `Child` graceful shutdown — the soft-then-hard escalation trio, mirroring the
//! sync `Child` counterparts.

use std::process::ExitStatus;
use std::time::Duration;

use super::Child;
use crate::error::Error;

/// The `crate::wait::fault` grace-watch seam, consumed HERE rather than inside a specific
/// backend so it applies uniformly to whichever watch `graceful_shutdown_tree` actually
/// performs — root-only ([`crate::tokio::wait::grace_wait`]) or whole-tree
/// ([`crate::tokio::wait::wait_tree_drained_dispatch`]). Outside test builds the seam module
/// does not exist at all, so this compiles to a constant `None`. Duplicated (not shared) with
/// the sync `crate::child::graceful` twin — see this module's own fault-seam doc comment for
/// why a shared seam is not nameable across the sync/async trees.
#[cfg(test)]
fn take_forced_watch_error() -> Option<Error> {
    crate::wait::fault::take_force_watch_error().then(crate::wait::fault::forced_watch_error)
}
#[cfg(not(test))]
fn take_forced_watch_error() -> Option<Error> {
    None
}

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
    /// up to `grace`, then hard-sweep any survivors and reap the root. Returns the root's
    /// `ExitStatus`. Requires an actionable containment mechanism (errors `Unsupported`
    /// otherwise — use [`graceful_shutdown`](Child::graceful_shutdown) for a lone child).
    /// Works on all platforms.
    ///
    /// **What the grace-wait watches depends on the mechanism.** On one with a real kernel
    /// drain edge ([`Containment::can_observe_drain`](crate::containment::Containment::can_observe_drain)
    /// — cgroup v2, a Windows job object, the macOS fd marker), the whole `grace` is spent
    /// watching the *entire tree* drain, and the hard sweep below runs only if `grace` elapses
    /// before the tree does — never on a tree that already cleared on its own. On every other
    /// mechanism (`ProcessGroup`, `Session`, `TreeWalk`) there is no kernel edge to observe
    /// descendants draining, so the wait watches the **root only** and the sweep always runs
    /// afterward regardless of what it saw, exactly as before this distinction existed.
    ///
    /// **Windows: what this actually signals, and what the grace costs.** `CTRL_BREAK` goes
    /// to the root's **process group** only. A nested contained descendant leads its own
    /// group and never receives it — so it does not exit during the grace, idles through the
    /// whole window, and is then killed by the sweep (a job object *is* drain-observable, so
    /// this shows up as `grace` fully elapsing rather than draining early, not as a skipped
    /// wait). The call reports no error either way: on Windows the grace is spent regardless
    /// of how much of the tree the signal reached. Size it accordingly, and treat
    /// [`kill_tree`](Child::kill_tree) as the only op that reaches every member.
    ///
    /// **The caller must also have a console.** The event is deliverable only within the
    /// *calling* process's console, so a GUI-subsystem binary, a service, or anything spawned
    /// detached fails up front: no signal is sent, no grace is waited, and the tree is left
    /// running for the caller to `kill_tree` (which needs no console). The cause is
    /// classified best-effort — usually [`Error::NoConsole`](crate::error::Error::NoConsole),
    /// but a raw `Error::Io` when the crate cannot confirm it — so treat **any** error here
    /// as "not delivered, tree still running".
    ///
    /// The grace-wait is **non-reaping** (watches exit without collecting it), so a subsequent
    /// hard sweep runs while the root's pid — and thus the `killpg` group id — is still valid;
    /// reaping first could let `killpg` hit a recycled group. A skipped or no-op sweep alike
    /// preserve a graceful exit's status (the lone backstop no-ops on an already-dead root).
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
        //
        // `drained`: whether the sweep below is skippable. On a drain-observable mechanism
        // this is positive kernel-confirmed proof the WHOLE tree exited, so the sweep would be
        // pure overhead — skip it. On every other mechanism there is no such edge, so `drained`
        // stays `false` unconditionally and the sweep always runs, exactly as before this
        // distinction existed. `root_exited`: whether the root specifically was observed to
        // have exited (a drained tree implies it; otherwise it is the root-only watch's own
        // result) — used only below, to decide whether a best-effort reap is safe after a
        // sweep failure.
        let (drained, root_exited, watch_err) = if let Some(e) = take_forced_watch_error() {
            (false, false, Some(e))
        } else if self.containment().can_observe_drain() {
            match crate::tokio::wait::wait_tree_drained_dispatch(&self.attached, crate::wait::deadline_from(grace))
                .await
            {
                Ok(crate::containment::TreeDrain::AllMembersExited) => (true, true, None),
                Ok(crate::containment::TreeDrain::MembersRemain) => (false, false, None),
                Err(e) => (false, false, Some(e)),
            }
        } else {
            // NON-reaping grace-wait on the root only.
            match crate::tokio::wait::grace_wait(self.id(), grace).await {
                Ok(exited) => (false, exited, None),
                Err(e) => (false, false, Some(e)),
            }
        };
        if let Some(e) = &watch_err {
            log::debug!(
                "graceful_shutdown_tree({id}): watch error before escalation (subsumed if it also fails): {e}",
                id = self.id().pid()
            );
        }
        // A sweep Err subsumes any watch or terminate Err; it must propagate before the reap on
        // a LIVE root (waiting unswept would hang), but once the root's exit was observed, the
        // reap runs first so no zombie is stranded.
        if !drained {
            // The `#[cfg(test)]` arm lets a test PROVE the sweep is skipped when `drained`,
            // not merely that it would have no-op'd: forcing this call to fail and then
            // observing `Ok` from the whole function is only possible if this branch was
            // never entered at all.
            #[cfg(test)]
            let sweep_result = if fault::take_force_kill_tree_error() {
                Err(fault::forced_kill_tree_error())
            } else {
                self.kill_tree()
            };
            #[cfg(not(test))]
            let sweep_result = self.kill_tree();
            if let Err(sweep) = sweep_result {
                if root_exited {
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
        }
        let status = self.wait().await?;
        if let Some(e) = watch_err {
            return Err(e);
        }
        // The tree is confirmed clear here — either the drain watch observed the whole tree
        // directly (`drained`), or the sweep just returned `Ok`: either way, positive,
        // freshly-measured proof superseding whatever `term` held. Discard it here rather than
        // returning it — an already-disproved refusal must never outrank the evidence that
        // disproved it.
        if let Err(e) = &term {
            log::debug!(
                "graceful_shutdown_tree({id}): tree confirmed clear; discarding the superseded terminate_tree refusal: {e}",
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
        static FORCE_KILL_TREE_ERROR: Cell<bool> = const { Cell::new(false) };
    }
    pub(crate) fn set_force_terminate(kind: Forced) {
        FORCE_TERMINATE.with(|f| f.set(kind));
    }
    pub(crate) fn take_force_terminate() -> Forced {
        FORCE_TERMINATE.with(|f| f.replace(Forced::None))
    }

    /// Force the next `kill_tree` call inside `graceful_shutdown_tree` on THIS thread — the
    /// sweep, not `terminate_tree` — to fail, so a test can prove it was skipped (`drained`)
    /// rather than merely no-op'd on an already-empty group.
    pub(crate) fn set_force_kill_tree_error(on: bool) {
        FORCE_KILL_TREE_ERROR.with(|f| f.set(on));
    }
    pub(crate) fn take_force_kill_tree_error() -> bool {
        FORCE_KILL_TREE_ERROR.with(|f| f.replace(false))
    }
    pub(crate) fn kill_tree_armed() -> bool {
        FORCE_KILL_TREE_ERROR.with(|f| f.get())
    }
    pub(crate) fn forced_kill_tree_error() -> crate::error::Error {
        crate::error::Error::Io(std::io::Error::other("forced kill_tree failure (test seam)"))
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
