//! Async `Child` graceful shutdown — the soft-then-hard escalation trio, mirroring the
//! sync `Child` counterparts.

use std::process::ExitStatus;
use std::time::Duration;

use super::Child;
#[cfg(test)]
use crate::child::graceful::fault;
use crate::child::graceful::{take_forced_watch_error, SignalTreeCooperativelyOutcome};
use crate::error::Error;

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
    /// **Every error means nothing was sent and nothing was killed.** On Linux that includes a
    /// refused `pidfd_open`, which is `Unsupported` (see [`Error::Unsupported`](crate::error::Error::Unsupported)).
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
    /// pid alone. This handle pins the child's pid for its whole life, as the sync
    /// [`Child`](crate::Child) does, so the call answers `Ok` before and after the exit has been
    /// observed, and never reaches a reissued pid. A mechanism that addresses no pid keeps its
    /// own answer: an uncontained Windows child is `Unsupported` before and after the reap alike,
    /// because nothing was ever going to be sent to a pid in the first place.
    ///
    /// **A macOS graphically-elevated child** is refused, as for the sync
    /// [`Child::terminate`](crate::Child::terminate).
    ///
    /// **macOS, a root launchd holds** is refused with nothing sent, and an `Unknown` root is signalled
    /// through the handle, as for the sync [`Child::kill`](crate::Child::kill).
    pub fn terminate(&self) -> Result<(), Error> {
        self.inner.terminate()
    }

    /// Whether the child has exited by the time `timeout` is over (`None`: until it does), looked at
    /// through the held handle. Non-reaping, so the pid stays pinned.
    async fn exited_through_handle(&self, timeout: Option<Duration>) -> Result<bool, Error> {
        crate::tokio::drive::exited_held(self.inner.proc.os_process(), timeout).await
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
    /// An untaken stdin pipe stays open through the grace: unlike [`wait`](Child::wait), the grace
    /// does not close it, so the signal, not an EOF on stdin, is what ends the child. The reap
    /// after the exit or the kill closes it.
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
    ///
    /// **macOS, a root launchd holds** is refused by the cooperative half, as for the sync
    /// [`Child::kill`](crate::Child::kill). A root orphaned during the grace is not killed: the
    /// escalation returns [`Error::Unassessable`](crate::error::Error::Unassessable) saying the kill
    /// sent nothing though the `SIGTERM` was sent.
    pub async fn graceful_shutdown(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        self.terminate()?;
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::AfterTerminate);
        // A watch failure must not strand the child between the soft signal and the escalation —
        // kill and reap still run (grace unobservable => escalate now); the watch error surfaces
        // only after they succeed (a kill/reap error wins — deliberate subsumption, mirroring
        // kill_tree's both-fail disposition).
        let watch = self.exited_through_handle(Some(grace)).await;
        if !matches!(watch, Ok(true)) {
            if let Err(e) = &watch {
                log::debug!(
                    "graceful_shutdown({id}): watch error before escalation (subsumed if it also fails): {e}",
                    id = self.pid()
                );
            }
            #[cfg(test)]
            fault::run_hook(fault::HookPoint::BeforeEscalation);
            // A root orphaned during the grace is no longer ours to kill. Read once: the gated send
            // does not read the state again.
            #[cfg(unix)]
            {
                self.inner.refuse_unpinned("kill", Some("the SIGTERM"))?;
                let gate = self.inner.kill_gate();
                self.inner.kill_sent_gated("graceful_shutdown", gate)?;
            }
            #[cfg(not(unix))]
            self.kill()?; // escalate; an Err returns HERE, subsuming any watch Err
        }
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::BeforeReap);
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
    /// afterward regardless of what it saw.
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
    /// console with the caller is reported as success and reaches nobody — including a root
    /// spawned with [`no_window`](crate::Command::no_window) or
    /// `detached()`, which gets a console of its own. Such a root is
    /// reported as [`GracefulMechanism::OtherConsoleGroup`](crate::GracefulMechanism::OtherConsoleGroup)
    /// by [`graceful_mechanism`](Child::graceful_mechanism): that is what cosca recorded about
    /// the *route* from this process, never an authority on whether a signal will arrive. It is
    /// also not "this child cannot be shut down politely" — a process attached to the child's own
    /// console can deliver the event. The cooperative op returns `Ok` and delivers nothing; the
    /// forced ops ([`kill`](Child::kill) / [`kill_tree`](Child::kill_tree), and the escalation
    /// half of [`graceful_shutdown_tree`](Child::graceful_shutdown_tree)) are unaffected.
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
    /// A refused Linux `pidfd_open` while watching the root is `Unsupported` (see [`Error::Unsupported`](crate::error::Error::Unsupported)); it is a
    /// watch failure, so the sweep still runs.
    ///
    /// An untaken stdin pipe stays open through the grace, as for
    /// [`graceful_shutdown`](Child::graceful_shutdown): the signal, not an EOF on stdin, is what
    /// ends the root.
    ///
    /// # Runtime
    ///
    /// On Unix, needs a runtime with the IO **and** time drivers enabled (the
    /// `#[tokio::main]` / `#[tokio::test]` defaults) — missing either, tokio panics rather
    /// than returning a typed error. On Windows the grace-wait runs on the blocking pool:
    /// each in-flight call occupies one blocking-pool thread for up to `grace` — size the
    /// pool accordingly for many long concurrent shutdowns.
    ///
    /// **A root reaped by something else** (see [`kill_tree`](Child::kill_tree)):
    ///
    /// - On Linux 6.9+ a process group that still has a member gets the `SIGTERM` through the
    ///   root's pidfd, then the sweep at once: the grace watches only the root, which is gone. One
    ///   with none left has nothing to shut down. Either way, once the tree is down the call
    ///   returns [`Error::Unassessable`](crate::error::Error::Unassessable) saying so: the root's
    ///   exit status went to the other reaper.
    /// - Otherwise nothing goes out by the root's number, and the call ends with one `warn` and
    ///   [`Error::Unassessable`](crate::error::Error::Unassessable), with no sweep. A macOS fd
    ///   marker's holders, named by the pipe they hold, still get the `SIGTERM`, the grace, and a
    ///   kill of any left, whose error is returned if it fails; any other mechanism ends at once,
    ///   with no grace.
    ///
    /// On Linux, a root whose handle cannot say whether it was reaped still gets the `SIGTERM`
    /// through its pidfd, which names it exactly, then the grace, and a kill through the pidfd if
    /// it is still running; nothing goes out by its number, and the call ends the same way. On 6.9+
    /// its group is shut down as usual while it has a member, and the call then returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable): no status is collected. After
    /// this handle's own reap, with another process at the pid, the group is empty: only the holders
    /// get the `SIGTERM`, and the call goes on as usual. The `SIGTERM` and the sweep each decide on a
    /// look of their own at the root, and each send by the group's number after it is checked as for
    /// `kill_tree`.
    ///
    /// **macOS, a root the handle cannot vouch for** is signalled as for
    /// [`terminate_tree`](Child::terminate_tree) and swept as for [`kill_tree`](Child::kill_tree). A
    /// mechanism with no channel by identity ends the call up front, with nothing sent and no grace
    /// waited. A root launchd holds has no exit status to collect: once the tree is down this returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) instead of waiting on a zombie that
    /// is not this process's to reap.
    pub async fn graceful_shutdown_tree(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        self.inner.require_contained()?;

        // One look at the root decides the cooperative signal (see `terminate_tree`), and what the
        // sweep may say was sent before it.
        #[cfg(unix)]
        let call = self.inner.tree_call(
            crate::containment::dispatch::TreeSignal::Term,
            "graceful_shutdown_tree",
            None,
        );
        #[cfg(unix)]
        let decision = self.inner.signal_tree_cooperatively(&call);
        #[cfg(not(unix))]
        let decision = self.inner.signal_tree_cooperatively();
        let (term_result, earlier) = match decision {
            SignalTreeCooperativelyOutcome::Sent { result, earlier } => (result, earlier),
            #[cfg(unix)]
            SignalTreeCooperativelyOutcome::End(e) => return Err(e),
            #[cfg(target_os = "linux")]
            SignalTreeCooperativelyOutcome::RootThroughPidfd(why) => {
                return Err(self.shut_down_root_through_pidfd(&call, grace, &why).await);
            }
            #[cfg(target_os = "macos")]
            SignalTreeCooperativelyOutcome::HoldersOnly(why) => {
                return Err(self.shut_down_holders_only(&call, grace, &why).await);
            }
        };

        // Hold-and-continue ONLY for the error shapes that are ORDINARY outcomes rather than a
        // dead mechanism — see the sync `src/child/graceful.rs` twin's identical match for the
        // per-member rationale it shares.
        let term = match term_result {
            Ok(()) => Ok(()),
            Err(e @ Error::Containment { .. }) | Err(e @ Error::Unassessable { source: None, .. }) => {
                log::debug!(
                    "graceful_shutdown_tree({id}): terminate_tree refused; the sweep's own outcome decides what surfaces: {e}",
                    id = self.pid()
                );
                Err(e)
            }
            Err(e) => return Err(e), // unchanged pre-existing behavior: no signal sent, no grace, no sweep
        };
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::AfterTerminate);

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
            match crate::tokio::wait::wait_tree_drained_dispatch(
                &self.inner.attached,
                crate::tokio::wait::deadline_from(grace),
            )
            .await
            {
                Ok(verdict) if verdict.permits_skipping_sweep() => (true, true, None),
                // Not sufficient proof alone to skip the sweep (see the doc above) — fall back
                // to the fresh, non-blocking, zero-duration root probe described there.
                Ok(_) => match self.exited_through_handle(Some(Duration::ZERO)).await {
                    Ok(exited) => (false, exited, None),
                    Err(e) => (false, false, Some(e)),
                },
                Err(e) => (false, false, Some(e)),
            }
        } else {
            // NON-reaping grace-wait on the root only.
            match self.exited_through_handle(Some(grace)).await {
                Ok(exited) => (false, exited, None),
                Err(e) => (false, false, Some(e)),
            }
        };
        if let Some(e) = &watch_err {
            log::debug!(
                "graceful_shutdown_tree({id}): watch error before escalation (subsumed if it also fails): {e}",
                id = self.pid()
            );
        }
        // A sweep Err subsumes any watch or terminate Err; it must propagate before the reap on
        // a LIVE root (waiting unswept would hang), but once the root is dead (its exit was observed,
        // or the sweep's backstop killed it), the reap runs first.
        if !drained {
            // The `#[cfg(test)]` arm lets a test PROVE the sweep is skipped when `drained`,
            // not merely that it would have no-op'd: forcing this call to fail and then
            // observing `Ok` from the whole function is only possible if this branch was
            // never entered at all.
            #[cfg(test)]
            let sweep_result = if fault::take_force_kill_tree_error() {
                Err(fault::forced_kill_tree_error().into())
            } else {
                self.kill_tree_after("graceful_shutdown_tree", earlier)
            };
            #[cfg(not(test))]
            let sweep_result = self.kill_tree_after("graceful_shutdown_tree", earlier);
            if let Err(sweep) = sweep_result {
                // A zombie launchd holds is not ours to reap: waiting on it only warns.
                if (root_exited || sweep.root_ended) && !self.inner.root_is_unpinned() {
                    // Best-effort reap so a dead root isn't left a zombie; `sweep`
                    // (below) is already the error this call reports, so a failure here is
                    // secondary — but every other discarded error in this module is still logged,
                    // and a silent one here would obscure a second, independent failure mode.
                    if let Err(e) = self.wait().await {
                        log::debug!(
                            "graceful_shutdown_tree({id}): best-effort reap after a swept, exited root also failed: {e}",
                            id = self.pid()
                        );
                    }
                }
                return Err(sweep.error);
            }
        }
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::BeforeReap);
        #[cfg(target_os = "macos")]
        if self.inner.root_is_unpinned() {
            return Err(crate::signal::unpinned_status(self.pid(), "graceful_shutdown_tree"));
        }
        #[cfg(unix)]
        let status = crate::child::tree_call::status_unless_reaped_elsewhere(self.wait().await, self.pid())?;
        #[cfg(not(unix))]
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
                id = self.pid()
            );
        }
        Ok(status)
    }

    /// [`Graceful::RootThroughPidfd`](crate::child::Graceful::RootThroughPidfd), `why` its reason.
    #[cfg(target_os = "linux")]
    async fn shut_down_root_through_pidfd(
        &self,
        call: &crate::child::TreeCall<'_>,
        grace: Duration,
        why: &str,
    ) -> Error {
        let shutdown = match crate::child::PidfdShutdown::start(self.inner.terminate_gate(), || {
            self.inner.proc.signal(crate::signal::Sig::Term)
        }) {
            Ok(shutdown) => shutdown,
            Err(unkillable) => return unkillable,
        };
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::AfterTerminate);
        let exited = if shutdown.needs_grace() {
            Some(self.exited_through_handle(Some(grace)).await)
        } else {
            None
        };
        shutdown.finish(
            call,
            why,
            exited,
            || self.inner.kill_gate(),
            || {
                self.inner
                    .kill_root()
                    .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.inner.may_run_as_another_user()))
            },
        )
    }

    /// [`Graceful::HoldersOnly`](crate::child::Graceful::HoldersOnly), `why` its reason.
    #[cfg(target_os = "macos")]
    async fn shut_down_holders_only(&self, call: &crate::child::TreeCall<'_>, grace: Duration, why: &str) -> Error {
        let term = call.holders_term();
        if let Err(e) = crate::tokio::wait::wait_tree_drained_dispatch(
            &self.inner.attached,
            crate::tokio::wait::deadline_from(grace),
        )
        .await
        {
            call.holders_grace_failed(&e);
        }
        call.holders_shutdown_error(why, term)
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;

#[cfg(all(test, windows))]
#[path = "ctrl_break_tests.rs"]
mod ctrl_break_tests;
