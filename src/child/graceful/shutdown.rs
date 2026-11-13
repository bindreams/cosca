//! `graceful_shutdown` and `graceful_shutdown_tree`, each written once for the sync and the async
//! `Child`; a [`Waits`] supplies each wait ([`BlockingDriver`] blocks, `tokio::Child` awaits).

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
#[cfg(target_os = "macos")]
use crate::os_process::child::Foreign;

/// The waits [`shutdown_lone`] and [`shutdown_tree`] make. A deadline is a `Duration` from the wait's start, which each
/// driver turns into an instant on its own clock.
pub(crate) trait Waits {
    /// The child the call acts on: its gates, signals, tree and pid.
    fn child(&self) -> &Child;

    /// Until every member of the tree has exited (not reaped), or `grace` is over: the public
    /// `wait_tree_timeout`, through the tree's drain edge, or `Unsupported` where the mechanism has none.
    async fn tree_drained(&self, grace: Duration) -> Result<TreeDrain, Error>;

    /// Whether the root has exited within `within`, looked at through its handle. Non-reaping, so its
    /// pid stays pinned.
    async fn root_exited(&self, within: Duration) -> Result<bool, Error>;

    /// The sweep's answer once every member its kill reached has exited.
    async fn sweep(&self, swept: Swept<'_>) -> Result<(), SweepFailure>;

    /// The root's reap, as the wait ended: the exit record or the foreign verdict, unfolded and with no
    /// warn ([`graceful_status_of_reap`] answers for it). The async driver closes an untaken stdin
    /// first, as its `wait` does.
    async fn reap(&mut self) -> Result<ChildWaitOutcome, Error>;

    /// The error of a holders-only shutdown, once the holders its kill reached have exited.
    #[cfg(unix)]
    async fn holders_finish(&self, shutdown: super::HoldersShutdown<'_>) -> Error;
}

/// The sync `Child`'s waits.
pub(crate) struct BlockingDriver<'a>(pub(super) &'a Child);

impl Waits for BlockingDriver<'_> {
    fn child(&self) -> &Child {
        self.0
    }

    async fn tree_drained(&self, grace: Duration) -> Result<TreeDrain, Error> {
        self.0.wait_tree_timeout(grace)
    }

    async fn root_exited(&self, within: Duration) -> Result<bool, Error> {
        self.0.proc.exited_by(crate::wait::deadline_from(within))
    }

    async fn sweep(&self, swept: Swept<'_>) -> Result<(), SweepFailure> {
        swept.wait()
    }

    async fn reap(&mut self) -> Result<ChildWaitOutcome, Error> {
        self.0.reap_outcome()
    }

    #[cfg(unix)]
    async fn holders_finish(&self, shutdown: super::HoldersShutdown<'_>) -> Error {
        shutdown.finish()
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

/// What `op` answers for the root's reap, `outcome`, once its signals went out: the status, or the
/// reap's failure, or, for a root this process cannot collect, [`Error::Unassessable`] saying so. A
/// zombie launchd holds is the macOS refusal ([`unpinned_status`](crate::signal::unpinned_status));
/// a root reaped elsewhere (or whose pid names another process now) is the same, with the `ECHILD`
/// every wait answers for it as its `source()`. Neither warns: the caller's answer is the report.
fn graceful_status_of_reap(pid: u32, op: &str, outcome: Result<ChildWaitOutcome, Error>) -> Result<ExitStatus, Error> {
    use crate::child::lifecycle::{echild, unbounded_status, Orphaned};

    match outcome? {
        ChildWaitOutcome::Foreign(foreign) => {
            #[cfg(target_os = "macos")]
            if foreign == Foreign::Orphaned {
                return Err(crate::signal::unpinned_status(pid, op));
            }
            let _ = foreign;
            log::debug!("{op}({pid}): the root was reaped elsewhere");
            Err(Error::Unassessable {
                detail: format!(
                    "pid {pid}: {op} sent its signals, but its exit status cannot be collected: the root was \
                     reaped elsewhere"
                ),
                source: Some(std::sync::Arc::new(Error::Io(echild()))),
            })
        }
        reaped => unbounded_status(Some(pid), reaped, Orphaned::Quiet),
    }
}

/// [`Child::graceful_shutdown`](crate::Child::graceful_shutdown), for any [`Waits`]: the signal, the
/// grace, the kill unless the root exited, and the reap.
pub(crate) async fn shutdown_lone<W: Waits>(w: &mut W, grace: Duration) -> Result<ExitStatus, Error> {
    w.child().terminate()?;
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::AfterTerminate);

    let pid = w.child().pid();
    let call = || format!("graceful_shutdown({pid})");
    // A watch failure must not strand the child between the soft signal and the escalation: the
    // kill and the reap still run, then the failure surfaces.
    let watch = w.root_exited(grace).await;
    // The escalation is `kill`, with the `SIGTERM` named as already sent.
    let watch = crate::graceful::after_grace(call, watch, || {
        #[cfg(test)]
        fault::run_hook(fault::HookPoint::BeforeEscalation);
        w.child().kill_after(Some("the SIGTERM"))
    })?;
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::BeforeReap);
    let waited = graceful_status_of_reap(pid, "graceful_shutdown", w.reap().await);
    crate::graceful::after_reap(call, waited, None, watch)
}

/// [`Child::graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree), for any [`Waits`]: the signal,
/// the grace, the sweep unless the tree drained, and the reap.
pub(crate) async fn shutdown_tree<W: Waits>(w: &mut W, grace: Duration) -> Result<ExitStatus, Error> {
    // Fail fast before sending any signal. terminate_tree/kill_tree re-check this guard
    // internally; the redundancy is intentional so an uncontained child errors up front.
    w.child().require_contained()?;

    // The mechanism's look at the root decides the cooperative signal (see `terminate_tree`), and
    // what the sweep may say was sent before it.
    let (term, earlier) = match w.child().signal_tree_cooperatively() {
        SignalTreeCooperativelyOutcome::Sent { result, earlier } => (result, earlier),
        SignalTreeCooperativelyOutcome::End(e) => return Err(e),
        #[cfg(target_os = "linux")]
        SignalTreeCooperativelyOutcome::RootThroughPidfd(skip) => {
            return Err(root_through_pidfd(w, &skip, grace).await);
        }
        #[cfg(unix)]
        SignalTreeCooperativelyOutcome::HoldersOnly(skip) => {
            return Err(holders_only(w, skip, grace).await);
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
    // `root_exited`: the root specifically exited; it comes from the drain edge or a zero-duration
    // root probe, since a tree verdict that does not clear the tree says nothing about the root. Only
    // used to decide whether a best-effort reap after a sweep failure is safe.
    let (drained, root_exited, watch_err) = if let Some(e) = take_forced_watch_error() {
        (false, false, Some(e))
    } else if w.child().tree.drain_edge().is_some() {
        match w.tree_drained(grace).await {
            Ok(verdict) if verdict.permits_skipping_sweep() => (true, true, None),
            // One look: a zero grace arms no wait, and so no kqueue.
            Ok(_) => match w.root_exited(Duration::ZERO).await {
                Ok(exited) => (false, exited, None),
                Err(e) => (false, false, Some(e)),
            },
            Err(e) => (false, false, Some(e)),
        }
    } else {
        match w.root_exited(grace).await {
            Ok(exited) => (false, exited, None),
            Err(e) => (false, false, Some(e)),
        }
    };
    // A sweep Err is the answer, with the terminate and watch failures below it; it must propagate
    // before the reap on a LIVE root (waiting unswept would hang), but once the root is dead (its
    // exit was observed, or the sweep's backstop killed it), the reap runs first.
    if !drained {
        // A test forces this sweep to fail to prove it is skipped when `drained`.
        let sweep_result = match take_forced_sweep() {
            Some(failure) => Err(failure),
            None => {
                w.sweep(w.child().kill_tree_after("graceful_shutdown_tree", earlier))
                    .await
            }
        };
        if let Err(sweep) = sweep_result {
            if root_exited || sweep.root_ended {
                // Best-effort: a dead root must not stay a zombie; `sweep` is the reported error. One
                // attempt that does not wait, through the handle: a zombie a tracer holds, or a root
                // that is not ours to reap, stays with the handle for its `wait` or `Drop`.
                if let Err(e) = w.child().proc.wait(Some(crate::wait::now())) {
                    log::warn!(
                        "graceful_shutdown_tree({pid}): the best-effort reap after a swept, exited root also failed: {report}",
                        report = crate::error::Report(&e)
                    );
                }
            }
            return Err(crate::graceful::joined(
                &call(),
                sweep.error,
                term.err().into_iter().chain(watch_err),
            ));
        }
    }
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::BeforeReap);
    let waited = graceful_status_of_reap(pid, "graceful_shutdown_tree", w.reap().await);
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

/// [`TerminateOutcome::RootThroughPidfd`](crate::containment::TerminateOutcome::RootThroughPidfd),
/// `skip` what it skipped: the `SIGTERM` through the root's handle, the grace, then a kill through it if
/// the root outlived it. Nothing goes out by the number. A front that may not be signalled is refused,
/// as for the tree paths.
#[cfg(target_os = "linux")]
pub(crate) async fn root_through_pidfd<W: Waits>(w: &W, skip: &crate::containment::Skip, grace: Duration) -> Error {
    let child = w.child();
    let call = child.skip_call(
        "graceful_shutdown_tree",
        crate::containment::dispatch::TreeSignal::Term,
        None,
    );
    let shutdown =
        match super::PidfdShutdown::start(child.terminate_gate(), || child.proc.signal(crate::signal::Sig::Term)) {
            Ok(shutdown) => shutdown,
            Err(unkillable) => return unkillable,
        };
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::AfterTerminate);
    let exited = if shutdown.needs_grace() {
        Some(w.root_exited(grace).await)
    } else {
        None
    };
    shutdown.finish(
        &call,
        skip,
        exited,
        || child.kill_gate(),
        || {
            child
                .kill_root()
                .map_err(|e| crate::elevation::map_elevated_kill_error(e, child.may_run_as_another_user()))
        },
    )
}

/// [`TerminateOutcome::HoldersOnly`](crate::containment::TerminateOutcome::HoldersOnly), `skip` what it
/// skipped: the holders were sent the `SIGTERM`; the grace, then the mechanism's own kill of any left.
#[cfg(unix)]
pub(crate) async fn holders_only<W: Waits>(w: &W, skip: crate::containment::Skip, grace: Duration) -> Error {
    let child = w.child();
    let call = child.skip_call(
        "graceful_shutdown_tree",
        crate::containment::dispatch::TreeSignal::Term,
        None,
    );
    // A failed grace wait means the holders are killed now.
    let watch = w.tree_drained(grace).await.err();
    let label = format!("graceful_shutdown_tree({})", child.pid());
    crate::graceful::joined(
        &label,
        w.holders_finish(child.holders_shutdown(&call, skip)).await,
        watch,
    )
}

#[cfg(test)]
#[path = "shutdown_tests.rs"]
mod shutdown_tests;
