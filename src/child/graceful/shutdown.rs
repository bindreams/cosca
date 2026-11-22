//! `terminate`, `graceful_shutdown`, `terminate_tree` and `graceful_shutdown_tree`, each written once for the
//! sync and the async `Child`; a [`Waits`] supplies the stop action's run and each wait ([`BlockingDriver`]
//! blocks, `tokio::Child` awaits). A call's `deadline` (`None`: no bound) is the instant every wait it makes
//! ends by, set once at the call.

use std::future::Future;
use std::pin::pin;
use std::process::ExitStatus;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[cfg(test)]
use super::fault;
use super::{take_forced_sweep, take_forced_watch_error, Child, SignalTreeCooperativelyOutcome};
use crate::child::owned::ChildWaitOutcome;
use crate::containment::dispatch::{SweepFailure, Swept};
use crate::containment::TreeDrain;
use crate::error::Error;
use crate::identity::ProcessId;
#[cfg(target_os = "macos")]
use crate::os_process::child::Foreign;
use crate::stop::{root_exited_within, ClockKind, Deadline, SendOutcome, StopError, StopTarget, StopWaits, TreeCall};

/// What the four stop calls need of a driver: the stop action's run, and the waits [`shutdown_lone`] and
/// [`shutdown_tree`] make, beside the root's exit look of [`StopWaits`]. A grace is a `Duration` from the
/// wait's start, cut to the call's deadline ([`Deadline::cut`]), which each driver turns into an instant on
/// its own clock.
pub(crate) trait Waits: StopWaits {
    /// The child the call acts on: its gates, signals, tree and pid.
    fn child(&self) -> &Child;

    /// Runs the child's stop action on `target`: the sync driver calls it, the async driver awaits it.
    async fn stop(&self, target: &StopTarget<'_>) -> Result<(), Error>;

    /// Until every member of the tree has exited (not reaped), or `grace`, cut to `deadline`, is over: the
    /// public `wait_tree_timeout`, through the tree's drain edge, or `Unsupported` where the mechanism has none.
    async fn tree_drained(&self, grace: Duration, deadline: Option<Deadline>) -> Result<TreeDrain, Error>;

    /// The sweep's answer once every member its kill reached has exited, or `deadline` has passed.
    async fn sweep(&self, swept: Swept<'_>, deadline: Option<Deadline>) -> Result<(), SweepFailure>;

    /// The root's reap, as the wait ended, until `deadline`: the exit record, the foreign verdict, or a
    /// deadline that passed with the root running, unfolded and with no warn ([`graceful_status_of_reap`]
    /// answers for it). The async driver closes an untaken stdin first, as its `wait` does.
    async fn reap(&mut self, deadline: Option<Deadline>) -> Result<ChildWaitOutcome, Error>;

    /// The error of a holders-only shutdown, once the holders its kill reached have exited, or `deadline`
    /// has passed.
    #[cfg(unix)]
    async fn holders_finish(&self, shutdown: super::HoldersShutdown<'_>, deadline: Option<Deadline>) -> Error;
}

/// The sync `Child`'s waits.
pub(crate) struct BlockingDriver<'a>(pub(crate) &'a Child);

impl StopWaits for BlockingDriver<'_> {
    async fn root_exited(&self, within: Duration) -> Result<bool, Error> {
        self.0.proc.exited_by(crate::wait::deadline_from(within))
    }

    async fn root_exited_by(&self, by: Deadline) -> Result<bool, Error> {
        self.0.proc.exited_by(by.at_on(ClockKind::Real))
    }

    #[cfg(windows)]
    type Proxy = Child;

    #[cfg(windows)]
    async fn start_proxy(
        &self,
        exe: &std::path::Path,
        args: &crate::stop::proxy::protocol::ProxyArgs,
    ) -> Result<(u32, Child), Error> {
        let mut command = crate::Command::new();
        crate::stop::proxy::configure_start(&mut command, exe, args)?;
        let proxy = command.spawn()?;
        Ok((proxy.pid(), proxy))
    }

    #[cfg(windows)]
    async fn wait_proxy(
        &self,
        proxy: &mut Child,
        after: Duration,
        late: impl FnOnce(Duration) + Send,
        deadline: Option<std::time::Instant>,
    ) -> Result<Option<std::process::ExitStatus>, Error> {
        proxy.wait_saying(after, late, deadline)
    }
}

impl Waits for BlockingDriver<'_> {
    fn child(&self) -> &Child {
        self.0
    }

    async fn stop(&self, target: &StopTarget<'_>) -> Result<(), Error> {
        self.0.stop.run(target)
    }

    async fn tree_drained(&self, grace: Duration, deadline: Option<Deadline>) -> Result<TreeDrain, Error> {
        self.0
            .tree
            .wait_drained(Deadline::grace_end(deadline, grace, ClockKind::Real))
    }

    async fn sweep(&self, swept: Swept<'_>, deadline: Option<Deadline>) -> Result<(), SweepFailure> {
        swept.wait(deadline)
    }

    async fn reap(&mut self, deadline: Option<Deadline>) -> Result<ChildWaitOutcome, Error> {
        self.0
            .reap_outcome(deadline.and_then(|deadline| deadline.at_on(ClockKind::Real)))
    }

    #[cfg(unix)]
    async fn holders_finish(&self, shutdown: super::HoldersShutdown<'_>, deadline: Option<Deadline>) -> Error {
        shutdown.finish(deadline)
    }
}

/// Polls `f` once with a no-op waker and returns its output. `f` must await only a [`BlockingDriver`],
/// whose waits are all ready.
///
/// # Panics
///
/// If `f` is pending: a hang here would hide the broken contract.
pub(crate) fn run_ready<F: Future>(f: F) -> F::Output {
    match pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("run_ready: the future is pending, but a blocking driver's waits are all ready"),
    }
}

/// What `op` answers for the root's reap, `outcome`, once its stop is done: the status, or the
/// reap's failure, or, for a root this process cannot collect, [`Error::Unassessable`] saying so. A
/// zombie launchd holds is the macOS refusal ([`unpinned_status`](crate::signal::unpinned_status));
/// a root reaped elsewhere (or whose pid names another process now) is the same, with the `ECHILD`
/// every wait answers for it as its `source()`. Neither warns: the caller's answer is the report. A reap
/// that ran into the call's deadline with the root, `id`, running is [`Error::TimedOut`] naming it: the root
/// stays with the handle, so a later `wait` or the drop collects it.
fn graceful_status_of_reap(
    pid: u32,
    id: Option<ProcessId>,
    op: &str,
    outcome: Result<ChildWaitOutcome, Error>,
) -> Result<ExitStatus, Error> {
    use crate::child::lifecycle::{echild, unbounded_status, Orphaned};

    match outcome? {
        ChildWaitOutcome::DeadlinePassed => Err(Error::TimedOut {
            detail: format!("pid {pid}: {op}: the call was waiting for the root to exit, and it had not"),
            members: id.into_iter().collect(),
            source: None,
        }),
        ChildWaitOutcome::Foreign(foreign) => {
            #[cfg(target_os = "macos")]
            if foreign == Foreign::Orphaned {
                return Err(crate::signal::unpinned_status(pid, op));
            }
            let _ = foreign;
            log::debug!("{op}({pid}): the root was reaped elsewhere");
            Err(Error::Unassessable {
                detail: format!(
                    "pid {pid}: {op}: the root's exit status cannot be collected: the root was reaped elsewhere"
                ),
                source: Some(std::sync::Arc::new(Error::Io(echild()))),
            })
        }
        reaped => unbounded_status(Some(pid), reaped, Orphaned::Quiet),
    }
}

/// [`Child::terminate`](crate::Child::terminate), for any [`Waits`]: the action's answer, with how its last
/// prepared send went when it failed. The waits the call makes end by `deadline` (`None`: no bound):
/// `terminate_timeout` is this call with one.
pub(crate) async fn terminate<W: Waits>(w: &W, deadline: Option<Deadline>) -> Result<(), StopError> {
    let target = StopTarget::root(w.child()).with_deadline(deadline);
    let acted = w.stop(&target).await;
    target.into_stop_result(acted)
}

/// [`Child::terminate_tree`](crate::Child::terminate_tree), for any [`Waits`], with [`terminate`]'s
/// `deadline`.
pub(crate) async fn terminate_tree<W: Waits>(w: &W, deadline: Option<Deadline>) -> Result<(), StopError> {
    // Before the action runs, so nothing was sent.
    w.child()
        .require_contained()
        .map_err(|refused| StopError::new(refused, SendOutcome::NotSent))?;
    // A separate `terminate_tree` is no call that sweeps: it holds its members for the next kill.
    let target = StopTarget::tree(w.child(), TreeCall::SignalOnly).with_deadline(deadline);
    let acted = w.stop(&target).await;
    target.into_stop_result(acted)
}

/// [`terminate`] with what the action said it sent, for the kill after the grace: the action's error ends the
/// call; see [`Child::after_root_stop`]. The action's waits end by `deadline`.
pub(crate) async fn stop_root<W: Waits>(
    w: &W,
    deadline: Option<Deadline>,
) -> Result<(Option<Error>, Option<String>), Error> {
    let target = StopTarget::root(w.child()).with_deadline(deadline);
    let stopped = w.stop(&target).await;
    w.child().after_root_stop(target, stopped)
}

/// `graceful_shutdown_tree`'s cooperative stop: the child's stop action, run on a target that stands for the
/// tree, and what the call goes on from. Only [`Child::after_tree_stop`] reads the record, once the action
/// has returned, awaited or not: the root a prepared send holds is dropped with the send, before the
/// grace, and never lives in an async caller's state. The action's waits end by `deadline`.
pub(crate) async fn signal_tree_cooperatively<W: Waits>(
    w: &W,
    deadline: Option<Deadline>,
) -> SignalTreeCooperativelyOutcome {
    #[cfg(test)]
    if let Some(forced) = w.child().forced_in_place_of_the_stop() {
        return forced;
    }
    let call = crate::containment::treewalk::WalkToken::new();
    let target = StopTarget::tree(w.child(), TreeCall::Shutdown(&call)).with_deadline(deadline);
    let acted = w.stop(&target).await;
    w.child().after_tree_stop(target, acted)
}

/// [`Child::graceful_shutdown`](crate::Child::graceful_shutdown), for any [`Waits`]: the signal, the
/// grace, the kill unless the root exited, and the reap. Every wait ends by `deadline` (`None`: no bound):
/// the grace is cut to it, and the kill is sent whatever it is.
pub(crate) async fn shutdown_lone<W: Waits>(
    w: &mut W,
    grace: Duration,
    deadline: Option<Deadline>,
) -> Result<ExitStatus, Error> {
    // What the stop sent is what a refused kill after it says was sent. `stop_root` decides what the action's error
    // does, as `signal_tree_cooperatively` does for the tree: this function has no rule of its own.
    let (mut stop_timeout, earlier) = stop_root(&*w, deadline).await?;
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::AfterTerminate);

    let pid = w.child().pid();
    let id = w.child().id();
    let call = || format!("graceful_shutdown({pid})");
    // A watch failure must not strand the child between the soft signal and the escalation: the
    // kill and the reap still run, then the failure surfaces.
    let watch = root_exited_within(&*w, deadline, grace).await.map(|(exited, _)| exited);
    let watch = crate::graceful::after_grace(call, watch, || {
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::BeforeEscalation);
        w.child().kill_after(earlier.as_deref())
    })
    .map_err(|killed| crate::graceful::joined(&call(), killed, stop_timeout.take()))?;
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::BeforeReap);
    let waited = graceful_status_of_reap(pid, id, "graceful_shutdown", w.reap(deadline).await);
    if let (Ok(_), Some(e)) = (&waited, &stop_timeout) {
        log::debug!(
            "graceful_shutdown({pid}): the root was reaped; discarding the superseded stop action timeout: {report}",
            report = crate::error::Report(e)
        );
    }
    crate::graceful::after_reap(call, waited, stop_timeout, watch)
}

/// [`Child::graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree), for any [`Waits`]: the signal,
/// the grace, the sweep unless the tree drained, and the reap. Every wait ends by `deadline` (`None`: no
/// bound), as for [`shutdown_lone`].
pub(crate) async fn shutdown_tree<W: Waits>(
    w: &mut W,
    grace: Duration,
    deadline: Option<Deadline>,
) -> Result<ExitStatus, Error> {
    // Fail fast before sending any signal. terminate_tree/kill_tree re-check this guard
    // internally; the redundancy is intentional so an uncontained child errors up front.
    w.child().require_contained()?;

    // The mechanism's look at the root decides the cooperative signal (see `terminate_tree`), and
    // what the sweep may say was sent before it.
    let (term, earlier, walk) = match signal_tree_cooperatively(&*w, deadline).await {
        SignalTreeCooperativelyOutcome::Sent { result, earlier, walk } => (result, earlier, walk),
        SignalTreeCooperativelyOutcome::End(e) => return Err(e),
        #[cfg(target_os = "linux")]
        SignalTreeCooperativelyOutcome::RootThroughPidfd(skip, started, sig, acted) => {
            let ended = root_through_pidfd(w, &skip, started, sig, grace, deadline).await;
            return Err(ended_with(w, ended, acted));
        }
        #[cfg(unix)]
        SignalTreeCooperativelyOutcome::HoldersOnly(skip, sig, acted) => {
            let ended = holders_only(w, skip, sig, grace, deadline).await;
            return Err(ended_with(w, ended, acted));
        }
    };

    // The signal went out, so every error of the check after it holds, whatever its variant: the
    // grace is waited and the sweep can still reach what the signal did not. A refusal is dropped
    // when the sweep proves the tree clear.
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::AfterTerminate);

    let pid = w.child().pid();
    let call = || format!("graceful_shutdown_tree({pid})");
    // Watch-Err ordering: sweep + reap first, then surface (see `Child::graceful_shutdown`).
    //
    // `drained`: the tree's drain edge proved every member exited (`permits_skipping_sweep`), so the
    // sweep is skipped. `AllMarkersClosed` is advisory (a live process can close its marker fd) and
    // does not count.
    let (drained, watch_err) = if let Some(e) = take_forced_watch_error() {
        (false, Some(e))
    } else if w.child().tree.drain_edge().is_some() {
        match w.tree_drained(grace, deadline).await {
            Ok(verdict) => (verdict.permits_skipping_sweep(), None),
            Err(e) => (false, Some(e)),
        }
    } else {
        (false, root_exited_within(&*w, deadline, grace).await.err())
    };
    if !drained {
        // A test forces this sweep to fail to prove it is skipped when `drained`.
        let sweep_result = match take_forced_sweep() {
            Some(failure) => Err(failure),
            None => {
                w.sweep(
                    w.child()
                        .kill_tree_after("graceful_shutdown_tree", earlier.as_deref(), walk.as_ref()),
                    deadline,
                )
                .await
            }
        };
        if let Err(sweep) = sweep_result {
            // A failed sweep is the answer. The call then looks at the root once, without waiting: an unswept root may
            // never exit. See `look_after_failed_sweep`. The look's own failure is below the answer, before the
            // cooperative signal's and the grace wait's.
            let (error, look) = look_after_failed_sweep(w.child(), sweep);
            return Err(crate::graceful::joined(
                &call(),
                error,
                look.into_iter().chain(term.err()).chain(watch_err),
            ));
        }
    }
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::BeforeReap);
    let waited = graceful_status_of_reap(pid, w.child().id(), "graceful_shutdown_tree", w.reap(deadline).await);
    // The tree is confirmed clear (drained, or the sweep returned Ok), which disproves a `term`
    // refusal: a successful reap discards it; a failed reap keeps it as a peer.
    if let (Ok(_), Err(e)) = (&waited, &term) {
        log::debug!(
            "graceful_shutdown_tree({pid}): tree confirmed clear; discarding the superseded terminate_tree refusal: {report}",
            report = crate::error::Report(e)
        );
    }
    crate::graceful::after_reap(call, waited, term.err(), watch_err)
}

/// The call's one look at the root, `child`'s, after `sweep` failed. It does not wait. An exit it sees is kept by the
/// handle, for its `wait` and its drop. A root it finds running joins a [`Error::TimedOut`]'s `members`, and `detail`
/// says so, when the sweep's answer does not cover the root ([`SweepFailure::root_ended`]). A root the sweep's wait
/// waited for is named by that wait, or was seen to exit. Any other error of the sweep stays as it is: the untimed
/// call does not name a root it did not wait for. Returns the answer, and the look's own failure (a root this process
/// cannot collect, or an `Io`), which goes below it.
fn look_after_failed_sweep(child: &Child, sweep: SweepFailure) -> (Error, Option<Error>) {
    let pid = child.pid();
    match child.proc.wait(Some(crate::wait::now())) {
        Ok(ChildWaitOutcome::Exited(_)) => (sweep.error, None),
        Ok(ChildWaitOutcome::DeadlinePassed) => match sweep.error {
            Error::TimedOut {
                detail,
                mut members,
                source,
            } if !sweep.root_ended => {
                let id = child.id();
                debug_assert!(
                    !id.is_some_and(|id| members.contains(&id)),
                    "a sweep whose answer does not cover the root names it"
                );
                members.extend(id);
                let detail =
                    format!("{detail}; the root, pid {pid}, was running when the call looked at it after the sweep");
                (
                    Error::TimedOut {
                        detail,
                        members,
                        source,
                    },
                    None,
                )
            }
            error => (error, None),
        },
        look => (
            sweep.error,
            graceful_status_of_reap(pid, child.id(), "graceful_shutdown_tree", look).err(),
        ),
    }
}

/// The error of a shutdown that ended on a skipped outcome, with the error of the action that sent
/// (`acted`) joined to it.
#[cfg(unix)]
fn ended_with<W: Waits>(w: &W, ended: Error, acted: Option<Error>) -> Error {
    crate::graceful::joined(&format!("graceful_shutdown_tree({})", w.child().pid()), ended, acted)
}

/// [`TerminateOutcome::RootThroughPidfd`](crate::containment::TerminateOutcome::RootThroughPidfd),
/// `skip` what it skipped: the signal `sig` went to the root through its handle (`shutdown`, the
/// send a prepared function made); the grace, then a kill through it if the root outlived it. Nothing
/// goes out by the number.
#[cfg(target_os = "linux")]
pub(crate) async fn root_through_pidfd<W: Waits>(
    w: &W,
    skip: &crate::containment::Skip,
    shutdown: super::PidfdShutdown,
    sig: crate::signal::Sig,
    grace: Duration,
    deadline: Option<Deadline>,
) -> Error {
    let child = w.child();
    let call = child.skip_call("graceful_shutdown_tree", sig, None);
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::AfterTerminate);
    let exited = if shutdown.needs_grace() {
        Some(root_exited_within(w, deadline, grace).await.map(|(exited, _)| exited))
    } else {
        None
    };
    shutdown.finish(&call, skip, exited, || child.proc.kill_root_only(Some(&child.tree)))
}

/// [`TerminateOutcome::HoldersOnly`](crate::containment::TerminateOutcome::HoldersOnly), `skip` what it
/// skipped: the holders were sent the signal `sig`; the grace, then the mechanism's own kill of any left.
#[cfg(unix)]
pub(crate) async fn holders_only<W: Waits>(
    w: &W,
    skip: crate::containment::Skip,
    sig: crate::signal::Sig,
    grace: Duration,
    deadline: Option<Deadline>,
) -> Error {
    let child = w.child();
    let call = child.skip_call("graceful_shutdown_tree", sig, None);
    // A failed grace wait means the holders are killed now.
    let watch = w.tree_drained(grace, deadline).await.err();
    let label = format!("graceful_shutdown_tree({})", child.pid());
    crate::graceful::joined(
        &label,
        w.holders_finish(child.holders_shutdown(&call, skip), deadline).await,
        watch,
    )
}

#[cfg(test)]
#[path = "shutdown_tests.rs"]
mod shutdown_tests;
