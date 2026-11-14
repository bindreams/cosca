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
/// backend so it applies to the watches of `graceful_shutdown` and of `graceful_shutdown_tree`'s main path —
/// root-only ([`OwnedChild::exited_by`](super::owned::OwnedChild::exited_by)) or whole-tree
/// ([`DrainEdge::wait`](crate::containment::drain_edge::DrainEdge::wait)). The holders-only and root-through-pidfd
/// paths do not take it: their grace waits are their own. Outside test builds the seam module does
/// not exist at all, so this compiles to a constant `None`.
#[cfg(test)]
pub(crate) fn take_forced_watch_error() -> Option<Error> {
    crate::wait::fault::take_force_watch_error().then(crate::wait::fault::forced_watch_error)
}
#[cfg(not(test))]
pub(crate) fn take_forced_watch_error() -> Option<Error> {
    None
}

/// The failure a test forced on the sweep of `graceful_shutdown_tree` (see
/// [`fault::set_force_kill_tree_error`]), taken once; the sweep is not sent when it is `Some`. Outside test
/// builds it is a constant `None`.
#[cfg(test)]
fn take_forced_sweep() -> Option<crate::containment::dispatch::SweepFailure> {
    fault::take_force_kill_tree_error().then(|| fault::forced_kill_tree_error().into())
}
#[cfg(not(test))]
fn take_forced_sweep() -> Option<crate::containment::dispatch::SweepFailure> {
    None
}

/// What [`Child::signal_tree_cooperatively`] decided: the cooperative signal of
/// `graceful_shutdown_tree`, which the caller then follows with the grace and the sweep.
pub(crate) enum SignalTreeCooperativelyOutcome {
    /// The cooperative signal went out, and `result` is what the check after it found; the sweep says
    /// `earlier` was sent before it. `walk`: the token of this call's own complete `SIGTERM` walk, which
    /// its sweep may stand on; `None` when the walk was incomplete or did not run.
    Sent {
        result: Result<(), Error>,
        earlier: Option<&'static str>,
        walk: Option<crate::containment::treewalk::WalkToken>,
    },
    /// The call ends now, with this error: nothing was sent, or what the root's number names was
    /// skipped and nothing else is left to signal.
    End(Error),
    /// [`TerminateOutcome::RootThroughPidfd`](crate::containment::TerminateOutcome::RootThroughPidfd)
    #[cfg(target_os = "linux")]
    RootThroughPidfd(Skip),
    /// [`TerminateOutcome::HoldersOnly`](crate::containment::TerminateOutcome::HoldersOnly)
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
    /// A watch failure never skips the kill and reap; it surfaces only after they run. A kill or
    /// reap error is the call's error (the child then stays owned — `Drop`'s teardown applies), and
    /// the watch failure joins it as a peer (`Error::with_peers_or_warn`). The escalation is
    /// [`kill`](Child::kill), so its refusal answers as `kill`'s does: [`Unkillable`](crate::error::ElevationErrorKind::Unkillable)
    /// for a child that may run as another user (or a front); a refused kill of any other child is
    /// the OS's [`Error::Io`], with its code.
    ///
    /// An elevated child behind a front (see [`kill`](Child::kill)) that outlives the grace is killed
    /// only through a cgroup that holds it. Outside one it is left running, and this answers
    /// [`ElevationErrorKind::Unkillable`](crate::error::ElevationErrorKind::Unkillable).
    ///
    /// The grace watch reaps nothing: a root that exited within it, however it is held or reaped
    /// elsewhere, is not killed, and the reap that follows answers for it. A tracer-held zombie is
    /// waited on until the tracer hands it back. A root reaped elsewhere returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) with the `ECHILD` as its
    /// `source()` and no warn, as [`graceful_shutdown_tree`](Child::graceful_shutdown_tree) does.
    ///
    /// **macOS, a root launchd holds** is refused by the cooperative half, as for
    /// [`kill`](Child::kill). A root launchd comes to hold during the call is not killed or waited
    /// on, and nothing warns. If its exit was seen, the call returns `Unassessable` saying its exit
    /// status cannot be collected. If it was orphaned after the grace ran out, the escalation returns
    /// `Unassessable` saying the kill sent nothing though the `SIGTERM` was sent.
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<ExitStatus, Error> {
        shutdown::run_ready(shutdown::shutdown_lone(&mut shutdown::BlockingDriver(self), grace))
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
    /// A watch failure never skips the sweep and reap. A sweep error is the call's error over it
    /// — and over a graceful root exit (survivors may remain; the root is still reaped first when
    /// its exit was observed, otherwise the child stays owned for `Drop`) — and so is a reap
    /// error once the sweep succeeded. A refused graceful signal and then the watch failure join the
    /// error as peers, in that order (`Error::with_peers_or_warn`); for a [`Error::MembersLeft`]
    /// they are its `others`. The refusal is dropped only when the tree is proved clear and the root
    /// reaped.
    ///
    /// **A refused or unconfirmed graceful signal never skips the grace wait and hard sweep
    /// either.** If the signal went out and the check after it fails (a live member refuses it, or
    /// a member's state cannot be confirmed, whatever the error's variant: see
    /// [`terminate_tree`](Child::terminate_tree)), the grace is still waited and the sweep
    /// still runs, so a member that only needed the follow-up `SIGKILL` does not strand the
    /// rest of the tree. A subsequent successful sweep is fresher, positive proof the group
    /// cleared, which supersedes the earlier refusal: it is logged and discarded, and this
    /// call reports `Ok`. If the sweep fails too, the refusal is a peer of its error. A failed group
    /// send on an fd marker that still signalled the root, a holder or a walked descendant is a
    /// signal that went out: the grace is held and the sweep runs. A signal that was not sent at all
    /// (`NoConsole`, an invalid process group, a root whose number may name another process, an fd
    /// marker whose group send failed with nothing else signalled) returns at once: there is
    /// nothing for a grace wait or sweep to act on yet.
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
    /// it is still running; nothing goes out by its number, and the call ends the same way, with a
    /// failed signal's `Io` and a failed kill below the `Unassessable`. On 6.9+
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
    /// **A `TreeWalk` whose root exits within the grace.** The kernel reparents the root's children
    /// at its exit, so the sweep cannot walk to them from its pid. The `SIGTERM` walk, made while the
    /// root ran, is the call's listing of the tree: the sweep kills the members it listed that are
    /// still running by their identities and waits for them, and the call returns the root's real
    /// status when every one is gone or killed. A root with no descendants is an empty listing. The
    /// limit is [`kill_tree`](Child::kill_tree)'s: a process forked after the listing, here the
    /// `SIGTERM` walk, is not seen. An incomplete walk (a candidate it could not read) lists the tree
    /// whole for nobody: its members are still killed by identity, but the call is
    /// [`Error::Unassessable`](crate::error::Error::Unassessable). A root already exited before the
    /// call sends nothing and answers as `kill_tree` does. A root that outlives the grace is walked
    /// and killed as usual, and the members reparented meanwhile are killed by identity too. A sweep
    /// whose walk cannot be made (the process table cannot be read) kills nothing of its own, the root
    /// included: the call is that walk's error. The members the `SIGTERM` walk listed, and any other the
    /// handle holds, are killed by identity and waited for all the same, the members the root's exit
    /// reparented too, which no retry's walk would reach.
    ///
    /// **macOS, a root the handle cannot vouch for** is signalled as for
    /// [`terminate_tree`](Child::terminate_tree) and swept as for [`kill_tree`](Child::kill_tree). A
    /// mechanism with no channel by identity ends the call up front, with nothing sent and no grace
    /// waited. A root launchd holds has no exit status to collect: once the tree is down this returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) instead of waiting on a zombie that
    /// is not this process's to reap.
    pub fn graceful_shutdown_tree(&self, grace: Duration) -> Result<ExitStatus, Error> {
        shutdown::run_ready(shutdown::shutdown_tree(&mut shutdown::BlockingDriver(self), grace))
    }

    /// `graceful_shutdown_tree`'s cooperative signal, for the sync and the async call alike: the
    /// mechanism's own, decided on its look at the root ([`Tree::terminate`](crate::containment::Tree::terminate)). This handle's reaps
    /// are held off from the look until the `SIGTERM` is sent. A plain `fn`: the std-lock hold and the
    /// root borrowing it must not live in an async caller's state, so paths that send nothing release
    /// the hold here, before the grace.
    pub(crate) fn signal_tree_cooperatively(&self) -> SignalTreeCooperativelyOutcome {
        let held = self.proc.hold(self.pid());
        let root: Option<&dyn crate::containment::Root> = Some(&held);
        #[cfg(test)]
        if let Some(forced) = fault::forced_in_place_of_the_signal(root) {
            return forced;
        }
        let call = crate::containment::treewalk::WalkToken::new();
        let (outcome, walk) = self.tree.terminate(self.pid(), root, Some(&call));
        match outcome {
            TerminateOutcome::Sent { result, earlier, .. } => {
                SignalTreeCooperativelyOutcome::Sent { result, earlier, walk }
            }
            TerminateOutcome::NotSent(not_sent) => SignalTreeCooperativelyOutcome::End(not_sent),
            // No SIGTERM walk, so no token.
            TerminateOutcome::RootExited(exited) => {
                log::debug!(
                    "graceful_shutdown_tree({}): sent no SIGTERM: {report}",
                    self.pid(),
                    report = crate::error::Report(&exited)
                );
                SignalTreeCooperativelyOutcome::Sent {
                    result: Ok(()),
                    earlier: None,
                    walk: None,
                }
            }
            #[cfg(unix)]
            TerminateOutcome::End(skip) => {
                let call = self.skip_call(
                    "graceful_shutdown_tree",
                    crate::containment::dispatch::TreeSignal::Term,
                    None,
                );
                match call.answer(&self.tree, skip, None).answer {
                    Err(e) => SignalTreeCooperativelyOutcome::End(e),
                    // The tree is already killed, as this handle's own reap shows: nothing is left to
                    // signal, and the sweep and the reap go on.
                    Ok(()) => SignalTreeCooperativelyOutcome::Sent {
                        result: Ok(()),
                        earlier: None,
                        walk: None,
                    },
                }
            }
            #[cfg(target_os = "linux")]
            TerminateOutcome::RootThroughPidfd(skip) => SignalTreeCooperativelyOutcome::RootThroughPidfd(skip),
            #[cfg(all(unix, not(target_os = "linux")))]
            TerminateOutcome::RootThroughPidfd(_) => unreachable!("only a Linux pidfd names the root exactly"),
            // A tree this handle already killed leaves nothing for the grace and the kill of the holders
            // to do: the sweep that follows answers as the tree calls do.
            #[cfg(unix)]
            TerminateOutcome::HoldersOnly(mut skip) if skip.is_moot(&self.tree) => {
                log::debug!(
                    "graceful_shutdown_tree({}): this handle already killed the tree, so the holders' grace is skipped",
                    self.pid()
                );
                // The holders' SIGTERM was sent: a failure of it is the call's.
                SignalTreeCooperativelyOutcome::Sent {
                    result: skip.holders.take().unwrap_or(Ok(())),
                    earlier: None,
                    walk: None,
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

    /// The end of a holders-only shutdown ([`shutdown::holders_only`]): the mechanism's kill
    /// with the same root, taken under a hold of its own, which is not held across the grace. The pending
    /// shutdown is finished by its caller, sync or async, which waits for what that kill reached.
    #[cfg(unix)]
    pub(crate) fn holders_shutdown(&self, call: &SkipCall<'_>, skip: Skip) -> HoldersShutdown<'_> {
        let (kill, mut wait) = {
            let held = self.proc.hold(self.pid());
            self.tree.kill(Some(&held)).split()
        };
        let settled = call.holders_settled(&self.tree, skip, kill);
        wait.reaching(settled.killed_again);
        HoldersShutdown {
            error: settled.answer,
            wait,
        }
    }
}

/// The end of a call that signalled only an fd marker's holders: its error, and the wait for the
/// holders its kill reached. The wait runs only in [`finish`](Self::finish) or
/// [`finish_async`](Self::finish_async), which a caller must call.
#[cfg(unix)]
#[must_use = "the holders its kill reached are waited for only by finish or finish_async"]
pub(crate) struct HoldersShutdown<'a> {
    error: Error,
    wait: crate::containment::KillWait<'a>,
}

#[cfg(unix)]
impl HoldersShutdown<'_> {
    /// The call's error, after the wait. The call's answer is that the tree was not shut down whatever
    /// the wait finds, so a wait that failed is only logged, as a failed `kill_tree`'s is; the wait
    /// still ends the holders the kill reached.
    #[must_use]
    pub(crate) fn finish(self) -> Error {
        let HoldersShutdown { error, wait } = self;
        Self::answered(error, wait.wait())
    }

    /// [`finish`](Self::finish), awaited: no runtime thread is blocked.
    #[cfg(feature = "tokio")]
    #[must_use]
    pub(crate) async fn finish_async(self) -> Error {
        let HoldersShutdown { error, wait } = self;
        Self::answered(error, wait.wait_async().await)
    }

    fn answered(error: Error, waited: Result<(), Error>) -> Error {
        if let Err(waited) = waited {
            crate::containment::tree_kill::log_failed_wait("a holders-only shutdown", &waited);
        }
        error
    }
}

/// [`TerminateOutcome::RootThroughPidfd`] (Linux), sync and async: the `SIGTERM` through the root's
/// pidfd, the grace, then a kill through the pidfd if the root outlived it. Nothing goes out by the
/// number. A front that may not be signalled is refused, as for the tree paths.
///
/// The caller [`start`](Self::start)s it, waits the grace when [`needs_grace`](Self::needs_grace),
/// and [`finish`](Self::finish)es it with the wait's outcome.
#[cfg(target_os = "linux")]
pub(crate) struct PidfdShutdown {
    term: Result<crate::signal::Sent, Error>,
}

#[cfg(target_os = "linux")]
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
    /// refuses it. One `warn` names what was skipped and what was sent. The error is an `Unassessable`
    /// with the refusal's cause, and below it the failed signal's `Io` (a leaf: it takes no peers), the
    /// failed grace wait and the failed kill; a failed signal that is no `Io` keeps its variant, with the
    /// wait, the kill and the refusal's cause as peers. The call's own failure comes first, then the
    /// wait's.
    pub(crate) fn finish(
        self,
        call: &SkipCall<'_>,
        skip: &Skip,
        exited: Option<Result<bool, Error>>,
        kill_gate: impl FnOnce() -> crate::elevation::front::Gate,
        kill: impl FnOnce() -> Result<crate::signal::Sent, Error>,
    ) -> Error {
        use crate::elevation::front::Gate;
        use crate::signal::Sent;
        // A grace wait that failed means the root is killed now.
        let mut watch = None;
        let kill = match exited {
            None | Some(Ok(true)) => None,
            Some(outcome) => {
                watch = outcome.err().map(std::sync::Arc::new);
                Some(match kill_gate() {
                    Gate::Closed(unkillable) => Err(unkillable),
                    _ => kill(),
                })
            }
        };
        let termed = "sent the SIGTERM to the root through its pidfd, which names it exactly";
        // The warn says each failure in full; the returned `Unassessable` says only that it failed,
        // for the failure is a peer or a cause of the answer.
        let sent = |with_errors: bool| match (&self.term, &kill) {
            (Err(e), _) if with_errors => format!(
                "sent nothing: the SIGTERM to the root through its pidfd failed ({})",
                crate::error::Report(e)
            ),
            (Err(_), _) => "sent nothing: the SIGTERM to the root through its pidfd failed".to_owned(),
            (Ok(Sent::Delivered), None) => format!("{termed}, and it exited within the grace; sent nothing else"),
            (Ok(Sent::Delivered), Some(Ok(Sent::Delivered))) => {
                format!("{termed}, then killed the root through its pidfd after the grace, and sent nothing else")
            }
            (Ok(Sent::Delivered), Some(Err(e))) if with_errors => {
                format!(
                    "{termed}, then the kill of the root through its pidfd failed ({})",
                    crate::error::Report(e)
                )
            }
            (Ok(Sent::Delivered), Some(Err(_))) => {
                format!("{termed}, then the kill of the root through its pidfd failed")
            }
            (Ok(Sent::Delivered), Some(Ok(_))) => {
                format!("{termed}, and its pidfd showed it gone after the grace; sent nothing else")
            }
            (Ok(Sent::Gone), _) => "sent nothing: the root's pidfd shows it is gone".to_owned(),
            (Ok(_), _) => "sent nothing: the root's handle no longer reaches it".to_owned(),
        };
        let detail = call.skipped_detail(skip, &sent(false));
        skip.why.warn(&call.skipped_detail(skip, &sent(true)));
        // The refusal's reason, and a kill that failed after a SIGTERM that did, are peers of the error
        // the call returns; the warn above says each in a line.
        let cause = skip.why.cause();
        // An `Io` is a leaf with no slot for peers: it goes below the call's `Unassessable`.
        match (self.term, kill) {
            (Err(term), kill) => term.with_peers_or_unassessable(
                || detail,
                cause,
                watch
                    .into_iter()
                    .chain(kill.and_then(Result::err).map(std::sync::Arc::new)),
            ),
            (_, Some(Err(kill))) => kill.with_peers_or_unassessable(|| detail, cause, watch),
            _ => Error::Unassessable { detail, source: cause }.with_peers(watch),
        }
    }
}

/// Test-only fault-injection seam for a forced `terminate_tree` failure inside
/// `graceful_shutdown_tree`, mirroring `crate::wait::fault`'s shape. The sync and the async call
/// share it: both read it through [`Child::signal_tree_cooperatively`] and the sweep.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    /// Which `terminate_tree` failure to fabricate on the next call, on this thread.
    /// `Containment`, `UnassessablePerMember` and `UnassessableMechanism` are checks that failed
    /// after the signal went out (`TerminateOutcome::Sent`), which `graceful_shutdown_tree` holds for.
    /// `Unsupported` models a signal that was not sent (`TerminateOutcome::NotSent`: the
    /// console-less caller's `NoConsole`/`Unsupported`), which ends the call.
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
    /// decided on.
    pub(crate) fn forced_in_place_of_the_signal(
        root: Option<&dyn crate::containment::Root>,
    ) -> Option<super::SignalTreeCooperativelyOutcome> {
        let kind = take_force_terminate();
        if kind == Forced::None {
            return None;
        }
        #[cfg(unix)]
        let _ = root.map(crate::containment::Root::state);
        #[cfg(not(unix))]
        let _ = root;
        let error = forced_terminate_error(kind);
        Some(if kind == Forced::Unsupported {
            super::SignalTreeCooperativelyOutcome::End(error)
        } else {
            super::SignalTreeCooperativelyOutcome::Sent {
                result: Err(error),
                earlier: Some("the SIGTERM"),
                walk: None,
            }
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

#[path = "graceful/shutdown.rs"]
pub(crate) mod shutdown;

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "pidfd_shutdown_tests.rs"]
mod pidfd_shutdown_tests;

#[cfg(all(test, windows))]
#[path = "ctrl_break_tests.rs"]
mod ctrl_break_tests;
