//! `Child` graceful shutdown — the soft-then-hard escalation trio. A submodule of `child`
//! so it can reach `Child`'s private `proc`/`id`.

use std::process::ExitStatus;
use std::time::Duration;

use super::Child;
use crate::containment::TerminateOutcome;
#[cfg(unix)]
use crate::containment::{Skip, SkipCall};
use crate::error::Error;

/// The `crate::wait::fault` grace-watch seam, consumed HERE rather than inside a specific
/// backend so it applies uniformly to whichever watch `graceful_shutdown_tree` actually
/// performs — root-only ([`OwnedChild::exited_by`](super::owned::OwnedChild::exited_by)) or whole-tree
/// ([`crate::containment::Attached::wait_drained`]). Outside test builds the seam module does
/// not exist at all, so this compiles to a constant `None`.
#[cfg(test)]
pub(crate) fn take_forced_watch_error() -> Option<Error> {
    crate::wait::fault::take_force_watch_error().then(crate::wait::fault::forced_watch_error)
}
#[cfg(not(test))]
pub(crate) fn take_forced_watch_error() -> Option<Error> {
    None
}

/// What [`Child::signal_tree_cooperatively`] decided: the cooperative signal of
/// `graceful_shutdown_tree`, which the caller then follows with the grace and the sweep.
pub(crate) enum SignalTreeCooperativelyOutcome {
    /// The cooperative signal went out, or failed, with `result`; the sweep says `earlier` was sent
    /// before it.
    Sent {
        result: Result<(), Error>,
        earlier: Option<&'static str>,
    },
    /// The call ends now, with this error.
    #[cfg(unix)]
    End(Error),
    /// [`TerminateOutcome::RootThroughPidfd`](crate::containment::TerminateOutcome::RootThroughPidfd);
    /// Linux.
    #[cfg(unix)]
    RootThroughPidfd(Skip),
    /// [`TerminateOutcome::HoldersOnly`](crate::containment::TerminateOutcome::HoldersOnly); macOS.
    #[cfg(unix)]
    HoldersOnly(Skip),
}

impl Child {
    /// Send the child its cooperative shutdown signal — a request to exit, not an order.
    /// Signal-only: does not wait or reap.
    ///
    /// Which signal, and how far it goes, is per child: read it from
    /// [`graceful_mechanism`](Child::graceful_mechanism). On Unix it is an identity-bound
    /// `SIGTERM` to this process alone, so it cannot race a concurrent reap onto a recycled pid.
    /// On Windows it is `CTRL_BREAK` to the child's own **console process group** — every child
    /// spawned with [`contain`](crate::Command::contain), including a nested
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
    /// **A macOS graphically-elevated child** ([`ElevatedVia::MacosOsascript`](crate::elevation::ElevatedVia::MacosOsascript))
    /// is refused while osascript runs, as its kill is (see [`kill`](Child::kill)): a `SIGTERM`
    /// would end osascript, not the program.
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
    /// **macOS, a root launchd holds** is refused with nothing sent, and an `Unknown` root is signalled
    /// through the handle, as for [`kill`](Child::kill).
    pub fn terminate(&self) -> Result<(), Error> {
        #[cfg(unix)]
        {
            // A front's refusal outranks a root launchd holds, as for `kill`.
            if let crate::elevation::front::Gate::Closed(unkillable) = self.terminate_gate() {
                return Err(unkillable);
            }
            self.refuse_unpinned("terminate", None)?;
        }
        crate::graceful::signal(self.graceful, self.pid(), |sig| self.proc.signal(sig).map(drop))
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
    /// A watch failure never skips the kill and reap; it surfaces only after they run, and a
    /// kill/reap error takes precedence (the child then stays owned — `Drop`'s teardown
    /// applies).
    ///
    /// An elevated child behind a front (see [`kill`](Child::kill)) that outlives the grace is killed
    /// only through a cgroup that holds it. Outside one it is left running, and this answers
    /// [`ElevationErrorKind::Unkillable`](crate::error::ElevationErrorKind::Unkillable).
    ///
    /// **macOS, a root launchd holds** is refused by the cooperative half, as for
    /// [`kill`](Child::kill). A root orphaned during the grace is not killed: the escalation returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) saying the kill sent nothing though
    /// the `SIGTERM` was sent, and the grace wait does not warn.
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<ExitStatus, Error> {
        self.terminate()?;
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::AfterTerminate);

        // Quiet about a zombie launchd holds: the refusal below is the one report of it.
        #[cfg(unix)]
        let watch = self.wait_timeout_quiet(grace);
        #[cfg(not(unix))]
        let watch = self.wait_timeout(grace);
        if let Ok(Some(status)) = &watch {
            return Ok(*status); // exited within grace (already reaped by wait_timeout)
        }
        if let Err(e) = &watch {
            log::debug!(
                "graceful_shutdown({id}): watch error before escalation (subsumed if it also fails): {report}",
                id = self.pid(),
                report = crate::error::Report(e)
            );
        }
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::BeforeEscalation);
        // A root orphaned during the grace is no longer ours to kill.
        #[cfg(unix)]
        self.refuse_unpinned("kill", Some("the SIGTERM"))?;
        // Escalate; an Err returns HERE, subsuming any watch Err (deliberate — mirrors kill_tree's
        // both-fail disposition). A live front outside a cgroup is not signalled; any other child's
        // refused kill stays the raw `Io`.
        #[cfg(unix)]
        match self.kill_gate() {
            crate::elevation::front::Gate::Closed(unkillable) => return Err(unkillable),
            // An exit is permanent, so a refused signal to an exited front changes nothing.
            crate::elevation::front::Gate::Exited => match self.kill_root() {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    log::debug!(
                        "the kill of exited front pid {} was refused ({report})",
                        self.pid(),
                        report = crate::error::Report(&e)
                    );
                }
                other => other.map(drop).map_err(Error::Io)?,
            },
            crate::elevation::front::Gate::Open => self.kill_root().map(drop).map_err(Error::Io)?,
            // A live front in its cgroup: killed through it, and nothing signalled after it.
            crate::elevation::front::Gate::CgroupOnly(front) => {
                // A cgroup kill names no group by the root's pid, so no root is given.
                debug_assert!(self.attached.is_cgroup(), "CgroupOnly is a front in a cgroup");
                self.attached
                    .hard_kill_settled("graceful_shutdown", &self.tree_killed, None)
                    .map_err(|e| crate::elevation::front::cgroup_kill_failed(front, self.pid(), e))?;
                self.cgroup_kill_reached(front)?;
            }
        }
        #[cfg(not(unix))]
        self.kill_root().map(drop).map_err(Error::Io)?;
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::BeforeReap);
        let status = self.wait()?;
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
    /// **A root reaped by something else** (see [`kill_tree`](Child::kill_tree)):
    ///
    /// - On Linux 6.9+ a process group that still has a member gets the `SIGTERM` through the
    ///   root's pidfd, then the sweep at once: the grace watches only the root, which is gone. One
    ///   with none left has nothing to shut down. Either way, once the tree is down the call
    ///   returns [`Error::Unassessable`](crate::error::Error::Unassessable) saying so, with no
    ///   `warn`: the root's exit status went to the other reaper.
    /// - Otherwise nothing goes out by the root's number, and the call ends with one `warn` and
    ///   [`Error::Unassessable`](crate::error::Error::Unassessable), with no sweep. A macOS fd
    ///   marker's holders, named by the pipe they hold, still get the `SIGTERM`, the grace, and a
    ///   kill of any left, whose error is returned if it fails; any other mechanism ends at once,
    ///   with no grace.
    ///
    /// On Linux, a root whose handle cannot say whether it was reaped still gets the `SIGTERM`
    /// through its pidfd, which names it exactly, then the grace, and a kill through the pidfd if
    /// it is still running; nothing goes out by its number, and the call ends the same way. On 6.9+
    /// its group is shut down as usual while it has a member. After this handle's own reap, with
    /// another process at the pid, the group is empty: only the holders get the `SIGTERM`, and the
    /// call goes on as usual; so it does for a macOS fd marker with no group, whose pid names no
    /// process, which has no group to skip. With any other pid that names no process, the group's
    /// number may be taken, so the call ends at once with
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) and the remedy: call `kill_tree`
    /// before `wait` to end the descendants, unless this handle already killed the tree, when it goes
    /// on and returns the status. A macOS marker's holders still get the `SIGTERM`, the grace and the
    /// kill. The `SIGTERM` and the sweep each decide on a look of their own at the root.
    ///
    /// **macOS, a root the handle cannot vouch for** is signalled as for
    /// [`terminate_tree`](Child::terminate_tree) and swept as for [`kill_tree`](Child::kill_tree). A
    /// mechanism with no channel by identity ends the call up front, with nothing sent and no grace
    /// waited. A root launchd holds has no exit status to collect: once the tree is down this returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) instead of waiting on a zombie that
    /// is not this process's to reap.
    pub fn graceful_shutdown_tree(&self, grace: Duration) -> Result<ExitStatus, Error> {
        // Fail fast before sending any signal. terminate_tree/kill_tree re-check this guard
        // internally; the redundancy is intentional so an uncontained child errors up front.
        self.require_contained()?;

        let (term_result, earlier) = match self.signal_tree_cooperatively() {
            SignalTreeCooperativelyOutcome::Sent { result, earlier } => (result, earlier),
            #[cfg(unix)]
            SignalTreeCooperativelyOutcome::End(e) => return Err(e),
            #[cfg(unix)]
            SignalTreeCooperativelyOutcome::RootThroughPidfd(skip) => {
                return Err(self.shut_down_root_through_pidfd(&skip, grace));
            }
            #[cfg(unix)]
            SignalTreeCooperativelyOutcome::HoldersOnly(skip) => {
                return Err(self.shut_down_holders_only(&skip, grace));
            }
        };

        // Hold-and-continue ONLY for the error shapes #61's fix can produce as ORDINARY
        // outcomes — a confirmed refusal (`Error::Containment`) or a per-member-unconfirmed
        // state (`Error::Unassessable { source: None, .. }`, `group::decide`'s shape). Both mean
        // a signal WAS attempted and reachable members WERE reached (`converge` delivers to
        // everyone it can, refusers or not), so the grace wait is still meaningful and the sweep
        // can still reach the rest. `Error::Unassessable { source: Some(_), .. }` — `group::
        // state`'s OWN listing failed, before any member was even examined — is deliberately
        // EXCLUDED from this arm and falls through to fail-fast below: `containment::fdmarker::
        // is_teardown_mechanism_failure` classifies that identical shape as a genuine
        // teardown-mechanism failure, not an ordinary #61 outcome, for the same reason (no
        // delivery was even attempted) — holding for a grace wait and sweep that reflect nothing
        // real would silently disagree with that classifier for the same error shape reaching a
        // different call site. Every OTHER error (`NoConsole`, `Unsupported`, `Io`, ...) keeps the
        // ORIGINAL fail-fast `?` — those mean no signal was sent at all (the documented contract
        // on this exact function, unchanged by this issue), so waiting a grace period and
        // hard-sweeping afterward would be new, undocumented behavior on a path #61 has nothing to
        // do with.
        let term = match term_result {
            Ok(()) => Ok(()),
            Err(e @ Error::Containment { .. }) | Err(e @ Error::Unassessable { source: None, .. }) => {
                log::debug!(
                    "graceful_shutdown_tree({id}): terminate_tree refused; the sweep's own outcome decides what surfaces: {report}",
                    id = self.pid(),
                    report = crate::error::Report(&e)
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
        // returned it. Used only below, to decide whether a best-effort reap is safe after a
        // sweep failure.
        let (drained, root_exited, watch_err) = if let Some(e) = take_forced_watch_error() {
            (false, false, Some(e))
        } else if self.containment().can_observe_drain() {
            match self.attached.wait_drained(crate::wait::deadline_from(grace)) {
                Ok(verdict) if verdict.permits_skipping_sweep() => (true, true, None),
                // Not sufficient proof alone to skip the sweep (see the doc above) — fall back
                // to the fresh, non-blocking, zero-duration root probe described there.
                Ok(_) => match self.proc.exited_by(crate::wait::deadline_from(Duration::ZERO)) {
                    Ok(exited) => (false, exited, None),
                    Err(e) => (false, false, Some(e)),
                },
                Err(e) => (false, false, Some(e)),
            }
        } else {
            match self.proc.exited_by(crate::wait::deadline_from(grace)) {
                // NON-reaping grace-wait on the root only.
                Ok(exited) => (false, exited, None),
                Err(e) => (false, false, Some(e)),
            }
        };
        if let Some(e) = &watch_err {
            log::debug!(
                "graceful_shutdown_tree({id}): watch error before escalation (subsumed if it also fails): {report}",
                id = self.pid(),
                report = crate::error::Report(e)
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
                if (root_exited || sweep.root_ended) && !self.root_is_unpinned() {
                    // Best-effort reap so a dead root isn't left a zombie; `sweep`
                    // (below) is already the error this call reports, so a failure here is
                    // secondary — but every other discarded error in this module is still logged,
                    // and a silent one here would obscure a second, independent failure mode.
                    if let Err(e) = self.wait() {
                        log::debug!(
                            "graceful_shutdown_tree({id}): best-effort reap after a swept, exited root also failed: {report}",
                            id = self.pid(),
                            report = crate::error::Report(&e)
                        );
                    }
                }
                return Err(sweep.error);
            }
        }
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::BeforeReap);
        #[cfg(target_os = "macos")]
        if self.root_is_unpinned() {
            return Err(crate::signal::unpinned_status(self.pid(), "graceful_shutdown_tree"));
        }
        #[cfg(unix)]
        let status = status_unless_reaped_elsewhere(self.wait(), self.pid())?;
        #[cfg(not(unix))]
        let status = self.wait()?;
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
                "graceful_shutdown_tree({id}): tree confirmed clear; discarding the superseded terminate_tree refusal: {report}",
                id = self.pid(),
                report = crate::error::Report(e)
            );
        }
        Ok(status)
    }

    /// `graceful_shutdown_tree`'s cooperative signal, for the sync and the async call alike: the
    /// mechanism's own, decided on its look at the root ([`Attached::terminate`]). This handle's reaps
    /// are held off from the look until the `SIGTERM` is sent. The hold is a std lock, and the root
    /// borrows it, so neither may live in an async caller's state: this is a plain `fn`, and the
    /// paths that send nothing by the root's number leave the hold here, before the caller waits the
    /// grace.
    pub(crate) fn signal_tree_cooperatively(&self) -> SignalTreeCooperativelyOutcome {
        #[cfg(unix)]
        let held = self.proc.hold(self.pid());
        #[cfg(unix)]
        let root: Option<&dyn crate::containment::Root> = Some(&held);
        #[cfg(not(unix))]
        let root: Option<&dyn crate::containment::Root> = None;
        match self.attached.terminate(self.pid(), root) {
            TerminateOutcome::Sent { result, earlier } => SignalTreeCooperativelyOutcome::Sent { result, earlier },
            #[cfg(unix)]
            TerminateOutcome::End(skip) => {
                let call = self.skip_call(
                    "graceful_shutdown_tree",
                    crate::containment::dispatch::TreeSignal::Term,
                    None,
                );
                match call.answer(&self.attached, &self.tree_killed, skip, None) {
                    Err(e) => SignalTreeCooperativelyOutcome::End(e),
                    // The tree is already killed, as this handle's own reap shows: nothing is left to
                    // signal, and the sweep and the reap go on.
                    Ok(()) => SignalTreeCooperativelyOutcome::Sent {
                        result: Ok(()),
                        earlier: None,
                    },
                }
            }
            #[cfg(unix)]
            TerminateOutcome::RootThroughPidfd(skip) => SignalTreeCooperativelyOutcome::RootThroughPidfd(skip),
            // A tree this handle already killed leaves nothing for the grace and the kill of the holders
            // to do: the sweep that follows answers as the tree calls do.
            #[cfg(unix)]
            TerminateOutcome::HoldersOnly(skip) if skip.is_moot(&self.tree_killed) => {
                log::debug!(
                    "graceful_shutdown_tree({}): this handle already killed the tree, so the holders' grace is skipped",
                    self.pid()
                );
                SignalTreeCooperativelyOutcome::Sent {
                    result: Ok(()),
                    earlier: None,
                }
            }
            #[cfg(unix)]
            TerminateOutcome::HoldersOnly(skip) => SignalTreeCooperativelyOutcome::HoldersOnly(skip),
            #[cfg(not(unix))]
            TerminateOutcome::End(_) | TerminateOutcome::RootThroughPidfd(_) | TerminateOutcome::HoldersOnly(_) => {
                unreachable!("only a Unix mechanism skips by the root's number")
            }
        }
    }

    /// [`TerminateOutcome::RootThroughPidfd`], `skip` what it skipped: the `SIGTERM` through the
    /// root's handle, the grace, then a kill through it if the root outlived it. Nothing goes out by
    /// the number. A front that may not be signalled is refused, as for the tree paths.
    #[cfg(unix)]
    fn shut_down_root_through_pidfd(&self, skip: &Skip, grace: Duration) -> Error {
        let call = self.skip_call(
            "graceful_shutdown_tree",
            crate::containment::dispatch::TreeSignal::Term,
            None,
        );
        let shutdown = match PidfdShutdown::start(self.terminate_gate(), || self.proc.signal(crate::signal::Sig::Term))
        {
            Ok(shutdown) => shutdown,
            Err(unkillable) => return unkillable,
        };
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::AfterTerminate);
        let exited = shutdown
            .needs_grace()
            .then(|| self.proc.exited_by(crate::wait::deadline_from(grace)));
        shutdown.finish(
            &call,
            skip,
            exited,
            || self.kill_gate(),
            || {
                self.kill_root()
                    .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.may_run_as_another_user()))
            },
        )
    }

    /// [`TerminateOutcome::HoldersOnly`], `skip` what it skipped: the holders were sent the `SIGTERM`;
    /// the grace, then the mechanism's own kill of any left.
    #[cfg(unix)]
    fn shut_down_holders_only(&self, skip: &Skip, grace: Duration) -> Error {
        let call = self.skip_call(
            "graceful_shutdown_tree",
            crate::containment::dispatch::TreeSignal::Term,
            None,
        );
        if let Err(e) = self.attached.wait_drained(crate::wait::deadline_from(grace)) {
            call.holders_grace_failed(&e);
        }
        self.holders_shutdown_error(&call, skip)
    }

    /// The end of [`shut_down_holders_only`](Self::shut_down_holders_only): the mechanism's kill with
    /// the same root, taken under a hold of its own, which is not held across the grace.
    #[cfg(unix)]
    pub(crate) fn holders_shutdown_error(&self, call: &SkipCall<'_>, skip: &Skip) -> Error {
        let kill = {
            let held = self.proc.hold(self.pid());
            self.attached.hard_kill(Some(&held))
        };
        call.holders_shutdown_error(&self.attached, &self.tree_killed, skip, kill)
    }
}

/// [`TerminateOutcome::RootThroughPidfd`] (Linux), sync and async: the `SIGTERM` through the root's
/// pidfd, the grace, then a kill through the pidfd if the root outlived it. Nothing goes out by the
/// number. A front that may not be signalled is refused, as for the tree paths.
///
/// The caller [`start`](Self::start)s it, waits the grace when [`needs_grace`](Self::needs_grace),
/// and [`finish`](Self::finish)es it with the wait's outcome.
#[cfg(unix)]
pub(crate) struct PidfdShutdown {
    term: Result<crate::signal::Sent, Error>,
}

#[cfg(unix)]
impl PidfdShutdown {
    /// The `SIGTERM`, sent by `term` unless `gate` refuses it; a refusal is the call's error.
    pub(crate) fn start(
        gate: crate::elevation::front::Gate,
        term: impl FnOnce() -> Result<crate::signal::Sent, Error>,
    ) -> Result<PidfdShutdown, Error> {
        if let crate::elevation::front::Gate::Closed(unkillable) = gate {
            return Err(unkillable);
        }
        Ok(PidfdShutdown { term: term() })
    }

    /// Whether the `SIGTERM` reached the root, so the grace is waited.
    pub(crate) fn needs_grace(&self) -> bool {
        matches!(self.term, Ok(crate::signal::Sent::Delivered))
    }

    /// The call's error, after `exited`, the grace wait's outcome (`None`: not waited): a root
    /// that did not exit within it, or whose wait failed, is killed by `kill` unless `kill_gate`
    /// refuses it. One `warn` names what was skipped and what was sent. The failed signal's error,
    /// or `Unassessable`.
    pub(crate) fn finish(
        self,
        call: &SkipCall<'_>,
        skip: &Skip,
        exited: Option<Result<bool, impl std::error::Error + 'static>>,
        kill_gate: impl FnOnce() -> crate::elevation::front::Gate,
        kill: impl FnOnce() -> Result<crate::signal::Sent, Error>,
    ) -> Error {
        use crate::elevation::front::Gate;
        use crate::signal::Sent;
        let kill = match exited {
            None | Some(Ok(true)) => None,
            Some(outcome) => {
                if let Err(e) = outcome {
                    log::debug!(
                        "{}({}): the root's grace wait failed, so it is killed now: {report}",
                        call.op,
                        call.pid,
                        report = crate::error::Report(&e)
                    );
                }
                Some(match kill_gate() {
                    Gate::Closed(unkillable) => Err(unkillable),
                    _ => kill(),
                })
            }
        };
        let termed = "sent the SIGTERM to the root through its pidfd, which names it exactly";
        let sent = match (&self.term, &kill) {
            (Err(e), _) => format!(
                "sent nothing: the SIGTERM to the root through its pidfd failed ({})",
                crate::error::Report(e)
            ),
            (Ok(Sent::Delivered), None) => format!("{termed}, and it exited within the grace; sent nothing else"),
            (Ok(Sent::Delivered), Some(Ok(Sent::Delivered))) => {
                format!("{termed}, then killed the root through its pidfd after the grace, and sent nothing else")
            }
            (Ok(Sent::Delivered), Some(Err(e))) => {
                format!(
                    "{termed}, then the kill of the root through its pidfd failed ({})",
                    crate::error::Report(e)
                )
            }
            (Ok(Sent::Delivered), Some(Ok(_))) => {
                format!("{termed}, and its pidfd showed it gone after the grace; sent nothing else")
            }
            (Ok(Sent::Gone), _) => "sent nothing: the root's pidfd shows it is gone".to_owned(),
            (Ok(_), _) => "sent nothing: the root's handle no longer reaches it".to_owned(),
        };
        let detail = call.skipped_detail(skip, &sent);
        log::warn!("{detail}");
        match (self.term, kill) {
            (Err(e), _) | (_, Some(Err(e))) => e,
            _ => Error::Unassessable { detail, source: None },
        }
    }
}

/// `graceful_shutdown_tree`'s answer (sync and async) from the root's reap, `waited`, once the tree is
/// down. A root reaped elsewhere (`ECHILD`) leaves no exit status for this handle: that is
/// `Unassessable`, saying the tree is down, as for a root launchd holds. Any other answer stands.
#[cfg(unix)]
pub(crate) fn status_unless_reaped_elsewhere(
    waited: Result<ExitStatus, Error>,
    pid: crate::identity::RawPid,
) -> Result<ExitStatus, Error> {
    match waited {
        Err(Error::Io(e)) if e.raw_os_error() == Some(libc::ECHILD) => {
            log::debug!("graceful_shutdown_tree({pid}): the tree is down, and the root was reaped elsewhere");
            Err(Error::Unassessable {
                detail: format!(
                    "pid {pid}: graceful_shutdown_tree brought the tree down, but its exit status cannot be \
                     collected: the root was reaped elsewhere"
                ),
                source: None,
            })
        }
        other => other,
    }
}

/// Test-only fault-injection seam for a forced `terminate_tree` failure inside
/// `graceful_shutdown_tree`, mirroring `crate::wait::fault`'s shape. The sync and the async call
/// share it: both read it through [`Child::signal_tree_cooperatively`] and the sweep.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    /// Which `terminate_tree` failure to fabricate on the next call, on this thread.
    /// `Containment` and `UnassessablePerMember` exercise the hold-and-continue path this
    /// task adds — both ORDINARY #61 outcomes, a signal was attempted. `Unsupported` and
    /// `UnassessableMechanism` exercise fail-fast paths: `Unsupported` models the
    /// PRE-EXISTING console-less-caller shape (`NoConsole`/`Unsupported`) this task must not
    /// touch; `UnassessableMechanism` models `Error::Unassessable { source: Some(_), .. }` —
    /// `group::state`'s own listing failure, `crate::containment::fdmarker::is_teardown_mechanism_failure`'s
    /// classification for the identical shape reaching `combine_group_errors` — which this task's
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

    /// The armed forced failure, in place of the mechanism's own cooperative signal, which is then
    /// not sent. The root's state is still read once on Unix, as the look the signal would have
    /// decided on, so a test that scripts the root's reads counts the same.
    pub(crate) fn forced_in_place_of_the_signal(
        root: Option<&dyn crate::containment::Root>,
    ) -> Option<crate::containment::TerminateOutcome> {
        let kind = take_force_terminate();
        if kind == Forced::None {
            return None;
        }
        #[cfg(unix)]
        let _ = root.map(crate::containment::Root::state);
        #[cfg(not(unix))]
        let _ = root;
        Some(crate::containment::TerminateOutcome::Sent {
            result: Err(forced_terminate_error(kind)),
            earlier: Some("the SIGTERM"),
        })
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

    #[cfg(unix)]
    pub(crate) use crate::graceful_hooks::at;
    #[cfg(windows)]
    pub(crate) use crate::graceful_hooks::at_checked;
    pub(crate) use crate::graceful_hooks::{release_at, run_hook, HookPoint};

    /// RAII disarm for `FORCE_KILL_TREE_ERROR`: a test that arms this seam expecting the sweep
    /// to skip (so the seam is never consumed by `take_force_kill_tree_error`) must still clear
    /// it before the thread is reused by a later test — a bare last-line
    /// `set_force_kill_tree_error(false)` would be skipped by an early return via a failed
    /// assertion (panic unwinds through this guard's `Drop` regardless). Consuming the seam
    /// normally (the sweep runs and calls `take_force_kill_tree_error`) already leaves it
    /// disarmed, so this guard's own `drop` is then a harmless no-op.
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
    // No `armed()` here, unlike `crate::wait::fault`'s seam: `take_force_terminate` runs
    // unconditionally at the very top of `graceful_shutdown_tree`, so by the time any test
    // assertion runs the seam is ALWAYS already consumed — an `armed()` check would be
    // tautologically true and, worse, an unused `pub(crate)` item once nothing calls it,
    // which `cargo clippy -D warnings` would hard-fail on.
    pub(crate) fn forced_terminate_error(kind: Forced) -> crate::error::Error {
        match kind {
            Forced::None => unreachable!("forced_terminate_error called with Forced::None"),
            Forced::Containment => crate::error::Error::Containment {
                detail: "forced term_group refusal (test seam)".into(),
                source: None,
            },
            Forced::UnassessablePerMember => crate::error::Error::Unassessable {
                detail: "forced per-member unconfirmed state (test seam) — group::decide's shape".into(),
                source: None,
            },
            Forced::UnassessableMechanism => crate::error::Error::Unassessable {
                detail: "forced listing-mechanism failure (test seam) — group::state's shape".into(),
                source: Some(crate::error::Error::io_cause(std::io::Error::other(
                    "forced (test seam)",
                ))),
            },
            Forced::Unsupported => crate::error::Error::Unsupported {
                op: "terminate_tree".into(),
                platform: "test",
                detail: "forced (test seam) — models NoConsole/Unsupported, NOT a #61 refusal".into(),
                source: None,
            },
        }
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "pidfd_shutdown_tests.rs"]
mod pidfd_shutdown_tests;

#[cfg(all(test, windows))]
#[path = "ctrl_break_tests.rs"]
mod ctrl_break_tests;
