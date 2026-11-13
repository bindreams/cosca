//! `graceful_shutdown_tree`, written once for the sync and the async `Child`. The sequence, its
//! decisions and its errors are [`shutdown_tree`]'s; what differs between the two is only how each wait
//! is made, which a [`Waits`] supplies: [`BlockingDriver`] blocks, `tokio::Child` awaits.

use std::future::Future;
use std::pin::pin;
use std::process::ExitStatus;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[cfg(test)]
use super::fault;
use super::{take_forced_sweep, take_forced_watch_error, Child, SignalTreeCooperativelyOutcome};
use crate::containment::dispatch::{SweepFailure, Swept};
use crate::containment::TreeDrain;
use crate::error::Error;

/// The waits [`shutdown_tree`] makes. Each takes what it waits on and nothing else: the decisions, the
/// sends and the errors are the core's. A deadline is a `Duration` from the wait's start, which each
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

    /// The root's reap. The async driver closes an untaken stdin first, as its `wait` does.
    async fn reap(&mut self) -> Result<ExitStatus, Error>;

    /// The error of a holders-only shutdown, once the holders its kill reached have exited.
    #[cfg(unix)]
    async fn holders_finish(&self, shutdown: super::HoldersShutdown<'_>) -> Error;
}

/// The sync `Child`'s waits: each blocks the calling thread and returns a ready future.
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

    async fn reap(&mut self) -> Result<ExitStatus, Error> {
        self.0.wait()
    }

    #[cfg(unix)]
    async fn holders_finish(&self, shutdown: super::HoldersShutdown<'_>) -> Error {
        shutdown.finish()
    }
}

/// Runs `f`, whose every await is ready at once (it awaits only a [`BlockingDriver`]), to its end on this
/// thread, with one poll.
///
/// # Panics
///
/// If `f` is pending: a driver that blocks never returns `Pending`, so that is a broken contract, and
/// parking here would turn it into a hang.
pub(crate) fn run_ready<F: Future>(f: F) -> F::Output {
    match pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("run_ready: the future is pending, but a blocking driver's waits are all ready"),
    }
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
    let call = format!("graceful_shutdown_tree({pid})");
    // Watch-Err ordering: sweep + reap first, then surface (see `Child::graceful_shutdown`).
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
    } else if w.child().tree.drain_edge().is_some() {
        match w.tree_drained(grace).await {
            Ok(verdict) if verdict.permits_skipping_sweep() => (true, true, None),
            // Not sufficient proof alone to skip the sweep (see the doc above) — fall back
            // to the fresh, non-blocking, zero-duration root probe described there.
            Ok(_) => match w.root_exited(Duration::ZERO).await {
                Ok(exited) => (false, exited, None),
                Err(e) => (false, false, Some(e)),
            },
            Err(e) => (false, false, Some(e)),
        }
    } else {
        // NON-reaping grace-wait on the root only.
        match w.root_exited(grace).await {
            Ok(exited) => (false, exited, None),
            Err(e) => (false, false, Some(e)),
        }
    };
    // A sweep Err is the answer, with the terminate and watch failures below it; it must propagate
    // before the reap on a LIVE root (waiting unswept would hang), but once the root is dead (its
    // exit was observed, or the sweep's backstop killed it), the reap runs first.
    if !drained {
        // The seam lets a test PROVE the sweep is skipped when `drained`, not merely that it
        // would have no-op'd: forcing this call to fail and then observing `Ok` from the whole
        // function is only possible if this branch was never entered at all.
        let sweep_result = match take_forced_sweep() {
            Some(failure) => Err(failure),
            None => {
                w.sweep(w.child().kill_tree_after("graceful_shutdown_tree", earlier))
                    .await
            }
        };
        if let Err(sweep) = sweep_result {
            // A zombie launchd holds is not ours to reap: waiting on it only warns.
            if (root_exited || sweep.root_ended) && !w.child().root_is_unpinned() {
                // Best-effort reap so a dead root isn't left a zombie; `sweep`
                // (below) is already the error this call reports, so a failure here is
                // secondary and is logged, not returned.
                if let Err(e) = w.reap().await {
                    log::warn!(
                        "graceful_shutdown_tree({pid}): the best-effort reap after a swept, exited root also failed: {report}",
                        report = crate::error::Report(&e)
                    );
                }
            }
            return Err(crate::graceful::joined(
                &call,
                sweep.error,
                term.err().into_iter().chain(watch_err),
            ));
        }
    }
    #[cfg(test)]
    fault::run_hook(fault::HookPoint::BeforeReap);
    #[cfg(target_os = "macos")]
    if w.child().root_is_unpinned() {
        return Err(crate::graceful::joined(
            &call,
            crate::signal::unpinned_status(pid, "graceful_shutdown_tree"),
            term.err().into_iter().chain(watch_err),
        ));
    }
    #[cfg(unix)]
    let waited = super::status_unless_reaped_elsewhere(w.reap().await, pid);
    #[cfg(not(unix))]
    let waited = w.reap().await;
    // The tree is confirmed clear here — either the drain watch observed the whole tree
    // directly (`drained`), or the sweep just returned `Ok`: either way, positive,
    // freshly-measured proof superseding whatever `term` held. A reap that succeeded discards
    // it, so an already-disproved refusal never outranks the evidence that disproved it; a reap
    // that failed is the call's own failure, and the refusal is one of its peers.
    if let (Ok(_), Err(e)) = (&waited, &term) {
        log::debug!(
            "graceful_shutdown_tree({pid}): tree confirmed clear; discarding the superseded terminate_tree refusal: {report}",
            report = crate::error::Report(e)
        );
    }
    crate::graceful::after_reap(&call, waited, term.err(), watch_err)
}

/// [`TerminateOutcome::RootThroughPidfd`](crate::containment::TerminateOutcome::RootThroughPidfd),
/// `skip` what it skipped: the `SIGTERM` through the root's handle, the grace, then a kill through it if
/// the root outlived it. Nothing goes out by the number. A front that may not be signalled is refused,
/// as for the tree paths.
#[cfg(target_os = "linux")]
async fn root_through_pidfd<W: Waits>(w: &W, skip: &crate::containment::Skip, grace: Duration) -> Error {
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
