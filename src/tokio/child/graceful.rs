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
    /// Send the child its cooperative shutdown signal — a request to exit, not an order.
    /// Signal-only: does not wait or reap.
    ///
    /// Which signal, and how far it goes, is per child: read it from
    /// [`graceful_mechanism`](Child::graceful_mechanism). On Unix it is an identity-bound
    /// `SIGTERM` to this process alone, so it cannot race a concurrent reap onto a recycled pid.
    /// On Windows it is `CTRL_BREAK` to the child's own **console process group** — every child
    /// spawned with [`contain`](crate::tokio::Command::contain), including a nested
    /// [`Delegated`](crate::Containment::Delegated) one. A child that leads no group of its own
    /// (an uncontained Windows spawn) is refused with `Unsupported`; `kill` is the
    /// always-available alternative.
    ///
    /// **Windows blast radius.** The event reaches the child's whole console group, so an
    /// ordinary descendant that stayed in that group is signalled too, while a nested
    /// *contained* descendant — which leads a group of its own — is not.
    ///
    /// **The caller must hold a console** ([`Error::NoConsole`](crate::error::Error::NoConsole)
    /// otherwise: a GUI-subsystem binary, a service, or a detached spawn cannot deliver console
    /// control events). A child that owns its own console instead needs a process attached to
    /// *that* console to signal it — it is not beyond a polite shutdown, just beyond this
    /// process's reach.
    ///
    /// **Success does not prove delivery on Windows.** Windows reports success for an event
    /// aimed at a group in another console and delivers nothing, and this process cannot rule
    /// that case out: absence from its console list is equally the answer for a healthy child.
    /// Each such call also leaves a dead entry in the caller's console process list.
    ///
    /// **Every error means nothing was sent and nothing was killed.**
    ///
    /// **Windows, before the child has run.** Between the spawn returning and the child
    /// executing its first instructions it has not yet registered with any console; an event
    /// delivered in that window ends it during loader init rather than through its own handler.
    /// That is an abrupt end, not a failed one, and it is reported `Ok`. A caller that has
    /// observed anything from the child — a byte of output, a handshake, an exit-status check —
    /// is past the window and gets a real cooperative signal; a caller that wants the child gone
    /// before it has run at all should use [`kill`](Child::kill), which is honest about being
    /// forced.
    ///
    /// **Windows, after the exit has been observed.** A console control event is addressed by
    /// pid alone, and this handle stops pinning the child's pid the moment `wait`/`try_wait`
    /// reports the exit — the async backend releases the process handle there, so the OS may
    /// reissue the pid to an unrelated group leader. From that point the call is refused
    /// ([`Error::Unassessable`](crate::error::Error::Unassessable)) rather than fired at a bare
    /// pid. The sync [`Child`](crate::Child) pins for its whole life and answers `Ok`.
    pub fn terminate(&self) -> Result<(), Error> {
        #[cfg(windows)]
        if !self.proc.pins_pid() {
            return Err(Error::Unassessable {
                detail: format!(
                    "this handle no longer pins pid {pid}: the async backend released the \
                     child's process handle when its exit was observed, so the pid may since \
                     name an unrelated process. A console control event is addressed by pid \
                     alone, so nothing was sent — and the child is already gone.",
                    pid = self.id().pid()
                ),
                source: None,
            });
        }
        crate::graceful::signal(self.graceful_mechanism(), self.id())
    }

    /// Cooperative-then-forced lone shutdown: [`terminate`](Child::terminate), wait up to
    /// `grace` for the child to exit, then hard-kill it if it has not — reaping either way and
    /// returning its `ExitStatus`. The status distinguishes a graceful exit from a forced one —
    /// best-effort at the boundary: a child that exits of its own accord between the grace
    /// elapsing and the kill landing reports its own status. Escalation proceeds even if the
    /// child ignores the cooperative signal. `grace` is relative; `Duration::ZERO` signals,
    /// polls once, then escalates.
    ///
    /// Every caveat on [`terminate`](Child::terminate) applies to the cooperative half, and a
    /// cooperative-signal error propagates immediately: no grace is waited, nothing is killed,
    /// and the child is left running for the caller to `kill`.
    ///
    /// **Windows: the two halves have different radii.** The cooperative half reaches the
    /// child's whole console group; the forced half reaches only the child. So a descendant
    /// that stayed in the child's group can be left told-to-exit but not killed: if the child
    /// itself exits within `grace`, this returns `Ok` while that descendant — possibly hung
    /// mid-shutdown — keeps running, with no hard backstop and no error. For a leaf child, the
    /// common case, the two radii are identical. Two routes give matched radii: the tree
    /// variants on a contained root ([`graceful_shutdown_tree`](Child::graceful_shutdown_tree)
    /// plus [`kill_tree`](Child::kill_tree)), or each level shutting down its own children,
    /// which works because a child that owns a console can politely signal its own
    /// group-leading children.
    ///
    /// **Neither route is available to the holder of a nested contained child.** Its `_tree`
    /// ops are `Unsupported` by design, and the root that owns its teardown lives in the
    /// intermediate process that spawned it. What that holder can do is exactly this call: the
    /// cooperative half reaches the nested child's own group and the forced half reaches the
    /// child. Anything below it that left that group is the intermediate's business — and if the
    /// intermediate is itself contained by *its* holder, `kill_tree` there is the backstop.
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
        self.terminate()?; // an error here returns before any grace wait or kill
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
    /// [`kill_tree`](Child::kill_tree) as the only op that reaches every member FROM THIS
    /// HANDLE. The layers the group signal skips are not beyond a polite shutdown: the holder
    /// of a nested descendant's own `Child` can drain it with
    /// [`graceful_shutdown`](Child::graceful_shutdown) before this root is torn down, and a
    /// chain in which each level shuts down its own children drains completely, because a
    /// child that owns a console can politely signal its own group-leading children.
    ///
    /// **And success here does not prove the event was delivered.** A root that shares no
    /// console with the caller is reported as success and reaches nobody.
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
        // `drained`: whether the sweep below is skippable. Only `TreeDrain::AllMembersExited`
        // (`permits_skipping_sweep`) makes it true — positive kernel-confirmed proof the WHOLE
        // tree exited, from a mechanism a live process cannot leave without exiting, so the
        // sweep would be pure overhead. `AllMarkersClosed` (the macOS marker's advisory pipe
        // EOF — see `TreeDrain`'s own doc) is NOT that proof: a live process can close its own
        // copy of the marker descriptor and remain alive, undetectable by this edge alone, so
        // it falls into the same "always sweep" bucket as `MembersRemain` and every mechanism
        // with no drain edge at all. `root_exited`: whether the root specifically was observed
        // to have exited. A skipped-sweep tree implies it. On the root-only-watch mechanism
        // (the `else` arm below) it is that watch's own result. Everywhere else it comes from a
        // fresh, non-blocking, zero-duration probe of the root alone, immediately below — a
        // tree-wide verdict that isn't sufficient to skip the sweep says nothing about the root
        // specifically (only some OTHER member may still be alive), and the probe costs nothing
        // extra since `grace` was already fully spent by the tree-drain watch that just
        // returned it. Used only below, to decide whether a
        // best-effort reap is safe after a sweep failure.
        let (drained, root_exited, watch_err) = if let Some(e) = take_forced_watch_error() {
            (false, false, Some(e))
        } else if self.containment().can_observe_drain() {
            match crate::tokio::wait::wait_tree_drained_dispatch(&self.attached, crate::wait::deadline_from(grace))
                .await
            {
                Ok(verdict) if verdict.permits_skipping_sweep() => (true, true, None),
                // Not sufficient proof alone to skip the sweep (see the doc above) — fall back
                // to the fresh, non-blocking, zero-duration root probe described there.
                Ok(_) => match crate::tokio::wait::grace_wait(self.id(), Duration::ZERO).await {
                    Ok(exited) => (false, exited, None),
                    Err(e) => (false, false, Some(e)),
                },
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

    /// RAII disarm for `FORCE_KILL_TREE_ERROR` — see the sync twin's identical guard for the
    /// full rationale (a test harness thread is reused across test functions, so a seam armed
    /// but never consumed must still be cleared even if this test's own assertions panic first).
    #[must_use]
    pub(crate) struct ArmedKillTreeError;
    impl ArmedKillTreeError {
        pub(crate) fn arm() -> Self {
            set_force_kill_tree_error(true);
            Self
        }
    }
    impl Drop for ArmedKillTreeError {
        fn drop(&mut self) {
            set_force_kill_tree_error(false);
        }
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
