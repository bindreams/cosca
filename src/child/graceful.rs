//! `Child` graceful shutdown — the soft-then-hard escalation trio. A submodule of `child`
//! so it can reach `Child`'s private `proc`/`id`.

use std::process::ExitStatus;
use std::time::Duration;

use super::Child;
#[cfg(unix)]
use crate::containment::{Skip, SkipCall};
use crate::error::Error;
use crate::stop::{RootRecord, StopError, StopTarget, TreeRecord};

/// What an action's own sends are called when it recorded none: a caller's own action, or one that
/// failed before it sent.
pub(crate) const STOP_ACTION: &str = "the stop action";

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

/// What [`shutdown::signal_tree_cooperatively`] decided: the cooperative signal of
/// `graceful_shutdown_tree`, which the caller then follows with the grace and the sweep.
#[derive(Debug)]
pub(crate) enum SignalTreeCooperativelyOutcome {
    /// The cooperative signal went out, and `result` is what the check after it found; the sweep says
    /// `earlier` was sent before it. `walk`: the token of this call's own complete `SIGTERM` walk, which
    /// its sweep may stand on; `None` when the walk was incomplete or did not run.
    Sent {
        result: Result<(), Error>,
        earlier: Option<String>,
        walk: Option<crate::containment::treewalk::WalkToken>,
    },
    /// The call ends now, with this error: nothing was sent, or what the root's number names was
    /// skipped and nothing else is left to signal.
    End(Error),
    /// [`TerminateOutcome::RootThroughPidfd`](crate::containment::TerminateOutcome::RootThroughPidfd):
    /// the stop's signal went to the root through its pidfd (`PidfdShutdown`), and the call waits the
    /// grace and kills through it. The signal is the one the route was given; the last is the error of
    /// the action that sent it, if it failed, which joins the call's.
    #[cfg(target_os = "linux")]
    RootThroughPidfd(Skip, PidfdShutdown, crate::signal::Sig, Option<Error>),
    /// [`TerminateOutcome::HoldersOnly`](crate::containment::TerminateOutcome::HoldersOnly), whose
    /// holders were sent the stop's signal; the last is the error of the action, as above.
    #[cfg(unix)]
    HoldersOnly(Skip, crate::signal::Sig, Option<Error>),
}

impl Child {
    /// Send the child its cooperative shutdown signal — a request to exit, not an order.
    /// Signal-only: does not wait or reap.
    ///
    /// Runs the child's stop action ([`Command::graceful_stop`](crate::Command::graceful_stop);
    /// [`stop::default`](crate::stop::default) when none was set) on a [`StopTarget`](crate::StopTarget)
    /// that stands for the root alone, and answers what the action answers. The call adds no rule of
    /// its own: the prepared functions of [`stop`](crate::stop) apply the rules below inside
    /// themselves, whoever calls them.
    ///
    /// **What a failure says of the send.** The error is a [`StopError`](crate::stop::StopError): the
    /// [`Error`](crate::error::Error) the action answered, and its
    /// [`outcome`](crate::stop::StopError::outcome), how the action's last prepared send went
    /// ([`SendOutcome`](crate::stop::SendOutcome)):
    /// - [`Sent`](crate::stop::SendOutcome::Sent): the signal went out to at least one process, whatever the error says of what a check after it found;
    /// - [`NotSent`](crate::stop::SendOutcome::NotSent): nothing was sent; the error says why;
    /// - [`NotYet`](crate::stop::SendOutcome::NotYet): nothing was sent because the child's console was not set up yet; asking again can succeed (Windows proxy only);
    /// - [`Unknown`](crate::stop::SendOutcome::Unknown): whether it went out cannot be told, as for an action that made no prepared send and failed.
    ///
    /// What the rest of this documentation says is what the default does. On Unix it is an
    /// identity-bound `SIGTERM` to this process alone, so it cannot race a concurrent reap onto a
    /// recycled pid. On Windows it is `CTRL_BREAK`, sent directly from this process to the child's
    /// console process group, or by the console-event proxy: a helper process, with no console of its
    /// own, that attaches to the child's console and sends the event to it
    /// (`stop::send_console_event_via_proxy`). [`stop::default`](crate::stop::default) says which child
    /// gets which, which are refused, and what a caller that changes its own console afterwards sets.
    ///
    /// **What it reaches on Windows.** The proxy reaches every process on the child's console: the
    /// child, its descendants that share the console (a nested *contained* one too, which by default
    /// leads a group of its own), and any other process attached to it. The direct send reaches every
    /// member of the child's console process group: a descendant that stayed in the group, and not a
    /// nested contained descendant. Neither reaches a descendant that has a console of its own or was
    /// started detached.
    ///
    /// **The proxy waits.** The default blocks the calling thread until the proxy answers, with no cap;
    /// see `stop::send_console_event_via_proxy`.
    ///
    /// **A child that has exited is `Ok`**, as on every platform, except a child created on this
    /// process's console that leads no group: the direct send refuses it with
    /// [`Error::Unsupported`](crate::error::Error::Unsupported), before and after its exit. A child the
    /// default sends through the proxy is looked at first (one look through its handle): an exited one is
    /// answered `Ok` with nothing started.
    ///
    /// **The direct send can report success for a child that left our console.** Windows reports
    /// success for an event aimed at a group in another console and delivers nothing, and this process
    /// cannot rule that case out: a GUI-subsystem child never attaches to this process's console
    /// whatever its flags say, and any child may free or change its console after it starts. The proxy
    /// has no such gap: it attaches to the child's own console and answers what it found. Each direct
    /// send also leaves a dead entry in the caller's console process list.
    ///
    /// **Every error of the default means nothing was killed, and, on Unix and on Windows for the direct
    /// send, that nothing was sent or that a check after the send failed**
    /// ([`outcome`](crate::stop::StopError::outcome) says which). Through the proxy on Windows an
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) (the proxy ended without a known answer, or
    /// sent the event and did not see its own copy) and an
    /// [`Error::MayHaveStarted`](crate::error::Error::MayHaveStarted) from the proxy's start leave
    /// whether it was sent [`Unknown`](crate::stop::SendOutcome::Unknown). The refusals on Windows, each an
    /// [`Error::Unsupported`](crate::error::Error::Unsupported), are listed by
    /// [`stop::default`](crate::stop::default).
    ///
    /// **A macOS graphically-elevated child** ([`ElevatedVia::MacosOsascript`](crate::elevation::ElevatedVia::MacosOsascript))
    /// is refused while osascript runs, as its kill is (see [`kill`](Child::kill)): a `SIGTERM`
    /// would end osascript, not the program. A child behind a `sudo` or `doas` front is refused a signal
    /// the front does not relay: see `stop::send_signal`.
    ///
    /// **Windows, before the child has run.** Between the spawn returning and the child
    /// executing its first instructions it has not yet registered with any console. A direct send in
    /// that window ends the child during loader init rather than through its own handler: an abrupt
    /// end, not a failed one, reported `Ok`. For a send through the proxy in that window see
    /// [`stop::default`](crate::stop::default).
    ///
    /// **macOS, a root launchd holds** is refused with nothing sent, and an `Unknown` root is signalled
    /// through the handle, as for [`kill`](Child::kill).
    ///
    /// # Panics
    ///
    /// On Windows: see [`stop::default`](crate::stop::default#panics).
    pub fn terminate(&self) -> Result<(), StopError> {
        shutdown::run_ready(shutdown::terminate(&shutdown::BlockingDriver(self)))
    }

    /// What a call that kills after the stop says the action sent ([`kill_after`](Child::kill_after)), from
    /// the record the action's last prepared send left on `target`: that send's stop when it went out or may
    /// have, [`STOP_ACTION`] when the action made no prepared send, and nothing when the last send was not
    /// sent. `stopped` is what the action answered, which is the call's answer.
    pub(crate) fn after_root_stop(
        &self,
        target: StopTarget<'_>,
        stopped: Result<(), Error>,
    ) -> (Result<(), Error>, Option<String>) {
        let earlier = match target.into_root_record() {
            Some(RootRecord::Sent(name) | RootRecord::Unknown(name)) => Some(crate::containment::earlier_of(name)),
            Some(RootRecord::NotSent(Some(report), _)) => {
                if stopped.is_ok() {
                    log::debug!(
                        "graceful_shutdown({}): the action went on after a refused send: {report}",
                        self.pid()
                    );
                }
                None
            }
            Some(RootRecord::NotSent(None, _)) => None,
            None => Some(STOP_ACTION.to_owned()),
        };
        (stopped, earlier)
    }

    /// Cooperative-then-forced lone shutdown: [`terminate`](Child::terminate), wait up to
    /// `grace` for the child to exit, then hard-kill it if it has not — reaping either way and
    /// returning its `ExitStatus`. The status distinguishes a graceful exit from a forced one —
    /// best-effort at the boundary: a child that exits of its own accord between the grace
    /// elapsing and the kill landing reports its own status. Escalation proceeds even if the
    /// child ignores the cooperative signal. `grace` is relative; `Duration::ZERO` signals,
    /// polls once, then escalates.
    ///
    /// The cooperative half is [`terminate`](Child::terminate): the child's stop action
    /// ([`Command::graceful_stop`](crate::Command::graceful_stop), else
    /// [`stop::default`](crate::stop::default)) run on a root target, and every caveat on it applies. An
    /// error of the action propagates immediately: no grace is waited, nothing is killed, and the child
    /// is left running for the caller to `kill`. The escalation after the grace names what was sent
    /// before it as what the action's last prepared send sent, or "the stop action" when it made none, and
    /// as nothing when the last send was not sent.
    ///
    /// The grace starts when the stop action returns: an action that does not return holds the call.
    ///
    /// **Windows: the two halves have different radii.** The cooperative half reaches the child's whole
    /// console group when it is sent directly, and every process on the child's console when it goes
    /// through the proxy (see [`terminate`](Child::terminate)); the forced half reaches only the
    /// child. So a descendant that stayed in the child's group, or on its console, can be left
    /// told-to-exit but not killed: if the child itself exits within `grace`, this returns `Ok` while
    /// that descendant — possibly hung mid-shutdown — keeps running, with no hard backstop and no
    /// error. For a leaf child, the common case, the two radii are identical. Two routes give matched
    /// radii: the tree variants on a contained root
    /// ([`graceful_shutdown_tree`](Child::graceful_shutdown_tree) plus [`kill_tree`](Child::kill_tree)),
    /// or each level shutting down its own children.
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
    ///
    /// # Panics
    ///
    /// On Windows: see [`stop::default`](crate::stop::default#panics).
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<ExitStatus, Error> {
        shutdown::run_ready(shutdown::shutdown_lone(&mut shutdown::BlockingDriver(self), grace))
    }

    /// Cooperative-then-forced shutdown of the contained tree: run the child's stop action
    /// ([`Command::graceful_stop`](crate::Command::graceful_stop), else
    /// [`stop::default`](crate::stop::default)) on a tree target, which by default sends the group its
    /// graceful signal (`SIGTERM` via `killpg`/cgroup, or `CTRL_BREAK` to the job/console group), wait
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
    /// **Windows: what the default action signals, and what the grace costs.** For a root that leads
    /// its group on this process's console, `CTRL_BREAK` goes to the root's **process group** only: a
    /// nested contained descendant that leads its own group never receives it — so it does not exit
    /// during the grace, idles through the whole window, and is then killed by the sweep (a job object
    /// *is* drain-observable, so this shows up as `grace` fully elapsing rather than draining early,
    /// not as a skipped wait). For a root created outside this process's console the default sends it
    /// through the proxy, which reaches every process on the root's console, a nested contained
    /// descendant included, and no descendant that has a console of its own or was started detached. Either way the call reports no error for
    /// a member the signal missed: on Windows the grace is spent regardless of how much of the tree the
    /// signal reached. Size it accordingly, and treat [`kill_tree`](Child::kill_tree) as the only op
    /// that reaches every member FROM THIS HANDLE. The layers the group signal skips are not beyond a
    /// polite shutdown, though: the holder of a nested descendant's own `Child` can drain it with
    /// [`graceful_shutdown`](Child::graceful_shutdown) before this root is torn down.
    ///
    /// **A root that cannot be sent the event is refused, and the call ends there:** the refusals are
    /// those of [`stop::default`](crate::stop::default), with nothing sent, no grace waited, nothing
    /// killed and the tree running. [`kill_tree`](Child::kill_tree) ends it. A direct send's success does
    /// not prove delivery: see [`terminate`](Child::terminate).
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
    /// call reports `Ok`. If the sweep fails too, the refusal is a peer of its error. A send that was made
    /// goes on to the grace and the sweep, whoever it reached. One that was not sent at all (`NoConsole`, an
    /// invalid process group, a root whose number may name another process, an fd marker whose group send
    /// failed with nothing else signalled) returns at once: there is nothing for a grace wait or sweep to act
    /// on yet.
    ///
    /// **The grace starts when the stop action returns.** An action that does not return holds the call.
    ///
    /// **An action's error ends the call before its grace unless its last prepared send was made.** When
    /// the last prepared send of the child's stop action was refused, or failed before it was made, or the
    /// action made none, the action's own `Err` is the call's answer, with nothing waited and nothing
    /// killed; this holds even when an earlier send of the same action went out and a later step failed.
    /// When its last prepared send was made, the call goes on to the grace and the sweep and keeps the
    /// action's error as the refusal above. An action of the caller's own that makes no prepared send and
    /// returns `Ok` goes on to the grace and the sweep, with nothing assumed about what it sent. An action that
    /// returns `Ok` after its last prepared send was refused goes on the same way, and the refusal is logged at
    /// `debug`.
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
    /// failed signal's `Io` and a failed kill below the `Unassessable`. An elevated child behind a
    /// front is refused there as for [`kill`](Child::kill): this path has no cgroup to kill through, so
    /// a live front is sent no kill, and a live osascript no `SIGTERM`. On 6.9+
    /// its group is shut down as usual while it has a member. A root this handle's `wait` saw exit
    /// is still a zombie that pins its number, so its group is shut down as for a running root; the
    /// handle consumes it only when it drops. A root another reaper took names no group by its
    /// number, whatever the pid names now: the call ends as the second case above does, and a tree
    /// this handle already killed does not change that. The `SIGTERM` and the sweep each decide on a
    /// look of their own at the root.
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
    /// included: the call is that walk's error. While the handle sees the root running, the members the
    /// `SIGTERM` walk listed, and any other it holds, are kept for the retry (a later `kill_tree`, or
    /// the drop), whose walk from the root reaches them and what they forked since, or whose kill by
    /// identity reaches the ones reparented meanwhile. Once the handle sees the root exited no walk
    /// reaches anything: the call kills them by identity and waits for them.
    ///
    /// **macOS, a root the handle cannot vouch for** is signalled as for
    /// [`terminate_tree`](Child::terminate_tree) and swept as for [`kill_tree`](Child::kill_tree). A
    /// mechanism with no channel by identity ends the call up front, with nothing sent and no grace
    /// waited. A root launchd holds has no exit status to collect: once the tree is down this returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) instead of waiting on a zombie that
    /// is not this process's to reap.
    ///
    /// # Panics
    ///
    /// On Windows: see [`stop::default`](crate::stop::default#panics).
    pub fn graceful_shutdown_tree(&self, grace: Duration) -> Result<ExitStatus, Error> {
        shutdown::run_ready(shutdown::shutdown_tree(&mut shutdown::BlockingDriver(self), grace))
    }

    /// The armed forced failure ([`fault`]) in place of `graceful_shutdown_tree`'s cooperative stop, which is
    /// then not run.
    #[cfg(test)]
    pub(crate) fn forced_in_place_of_the_stop(&self) -> Option<SignalTreeCooperativelyOutcome> {
        let root_handle = self.proc.hold(self.pid());
        let root: Option<&dyn crate::containment::Root> = Some(&root_handle);
        fault::forced_in_place_of_the_signal(root)
    }

    /// What `graceful_shutdown_tree` goes on from, once the child's stop action has run on `target` (a tree
    /// target) and answered `acted`: the record of its last prepared send and the action's own `Result`
    /// decide what follows. The action itself runs in [`shutdown::signal_tree_cooperatively`].
    ///
    /// | Tree record (the last prepared send) | Action returned `Ok` | Action returned `Err` |
    /// |---|---|---|
    /// | none (the caller's own action) | grace, sweep, reap; nothing assumed sent | the call ends with that error |
    /// | sent (to some process, to none, or unknown), or root exited, or tree already killed | grace, sweep, reap | grace, sweep, reap; the error is the call's cooperative error |
    /// | refused or failed before the send, or nothing names the tree | grace, sweep, reap; nothing assumed sent | the call ends with that error |
    /// | pidfd-only, holders-only | that outcome's own path | that path; the error joins its |
    pub(crate) fn after_tree_stop(
        &self,
        target: StopTarget<'_>,
        acted: Result<(), Error>,
    ) -> SignalTreeCooperativelyOutcome {
        match (target.into_tree_record(), acted) {
            (Some(TreeRecord::Sent { earlier, walk, .. }), result) => {
                SignalTreeCooperativelyOutcome::Sent { result, earlier, walk }
            }
            (None, Ok(())) => SignalTreeCooperativelyOutcome::Sent {
                result: Ok(()),
                earlier: Some(STOP_ACTION.to_owned()),
                walk: None,
            },
            (Some(TreeRecord::NotSent(report, _)), Ok(())) => {
                log::debug!(
                    "graceful_shutdown_tree({}): the action went on after a refused send: {report}",
                    self.pid()
                );
                SignalTreeCooperativelyOutcome::Sent {
                    result: Ok(()),
                    earlier: None,
                    walk: None,
                }
            }
            (None | Some(TreeRecord::NotSent(..)), Err(e)) => SignalTreeCooperativelyOutcome::End(e),
            #[cfg(target_os = "linux")]
            (Some(TreeRecord::RootThroughPidfd(skip, term, sig)), acted) => {
                SignalTreeCooperativelyOutcome::RootThroughPidfd(skip, PidfdShutdown::new(term), sig, acted.err())
            }
            #[cfg(not(target_os = "linux"))]
            (Some(TreeRecord::RootThroughPidfd(..)), _) => unreachable!("only a Linux pidfd names the root exactly"),
            #[cfg(unix)]
            (Some(TreeRecord::HoldersOnly(skip, sig)), acted) => {
                SignalTreeCooperativelyOutcome::HoldersOnly(skip, sig, acted.err())
            }
            #[cfg(not(unix))]
            (Some(TreeRecord::HoldersOnly(..)), _) => unreachable!("only a Unix mechanism skips by the root's number"),
        }
    }

    /// The end of a holders-only shutdown ([`shutdown::holders_only`]): the mechanism's kill
    /// with the same root, taken through a root handle of its own, which does not live across the grace. The pending
    /// shutdown is finished by its caller, sync or async, which waits for what that kill reached.
    #[cfg(unix)]
    pub(crate) fn holders_shutdown(&self, call: &SkipCall<'_>, skip: Skip) -> HoldersShutdown<'_> {
        let (kill, mut wait) = {
            let root_handle = self.proc.hold(self.pid());
            self.tree.kill(Some(&root_handle)).split()
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

/// [`TerminateOutcome::RootThroughPidfd`] (Linux), sync and async: the cooperative signal through the root's
/// pidfd, the grace, then a kill through the pidfd if the root outlived it. Nothing goes out by the
/// number. A front that may not be signalled is refused, as for the tree paths.
///
/// The caller [`start`](Self::start)s it, waits the grace when [`needs_grace`](Self::needs_grace),
/// and [`finish`](Self::finish)es it with the wait's outcome.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct PidfdShutdown {
    term: Result<crate::signal::Sent, Error>,
}

#[cfg(target_os = "linux")]
impl PidfdShutdown {
    /// The shutdown whose signal to the root went as `term` answered. The send is gated in front of the
    /// route, as every send of the stop action is
    /// ([`OwnedChild::terminate_by`](crate::child::owned::OwnedChild::terminate_by)).
    pub(crate) fn new(term: Result<crate::signal::Sent, Error>) -> PidfdShutdown {
        PidfdShutdown { term }
    }

    /// Whether the signal reached the root, so the grace is waited.
    pub(crate) fn needs_grace(&self) -> bool {
        matches!(self.term, Ok(crate::signal::Sent::Delivered))
    }

    /// The call's error, after `exited`, the grace wait's outcome (`None`: not waited): a root
    /// that did not exit within it, or whose wait failed, is killed by `kill`, which applies the
    /// rule for a front ([`OwnedChild::kill_root`](crate::child::owned::OwnedChild::kill_root)).
    /// One `warn` names what was skipped and what was sent. The error is an `Unassessable`
    /// with the refusal's cause, and below it the failed signal's `Io` (a leaf: it takes no peers), the
    /// failed grace wait and the failed kill; a failed signal that is no `Io` keeps its variant, with the
    /// wait, the kill and the refusal's cause as peers. The call's own failure comes first, then the
    /// wait's.
    pub(crate) fn finish(
        self,
        call: &SkipCall<'_>,
        skip: &Skip,
        exited: Option<Result<bool, Error>>,
        kill: impl FnOnce() -> Result<crate::signal::Sent, Error>,
    ) -> Error {
        use crate::signal::Sent;
        // A grace wait that failed means the root is killed now.
        let mut watch = None;
        let kill = match exited {
            None | Some(Ok(true)) => None,
            Some(outcome) => {
                watch = outcome.err().map(std::sync::Arc::new);
                Some(kill())
            }
        };
        let name = call.signal;
        let termed = format!("sent the {name} to the root through its pidfd, which names it exactly");
        // The warn says each failure in full; the returned `Unassessable` says only that it failed,
        // for the failure is a peer or a cause of the answer.
        let sent = |with_errors: bool| match (&self.term, &kill) {
            (Err(e), _) if with_errors => format!(
                "sent nothing: the {name} to the root through its pidfd failed ({})",
                crate::error::Report(e)
            ),
            (Err(_), _) => format!("sent nothing: the {name} to the root through its pidfd failed"),
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
/// share it: both read it through [`shutdown::signal_tree_cooperatively`] and the sweep.
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
                earlier: Some(default_stop().earlier()),
                walk: None,
            }
        })
    }

    /// The stop a child with no action set sends.
    fn default_stop() -> crate::containment::TreeStop {
        #[cfg(unix)]
        return crate::containment::TreeStop::default();
        #[cfg(windows)]
        crate::containment::TreeStop::named(
            crate::stop::proxy::protocol::CtrlEvent::CtrlBreak.name(),
            crate::containment::SendAnswer::Sent(Ok(())),
        )
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
pub(crate) mod ctrl_break_tests;

#[cfg(all(test, windows))]
#[path = "ctrl_break_proxy_tests.rs"]
mod ctrl_break_proxy_tests;
