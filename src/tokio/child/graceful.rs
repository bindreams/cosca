//! Async `Child` graceful shutdown: `graceful_shutdown` and `graceful_shutdown_tree` are the sync
//! `Child`'s cores (`child::graceful::shutdown`), run over this `Child`'s awaited [`Waits`].

use std::process::ExitStatus;
use std::time::Duration;

use super::Child;
use crate::child::graceful::shutdown::Waits;
#[cfg(unix)]
use crate::child::graceful::HoldersShutdown;
use crate::containment::dispatch::{SweepFailure, Swept};
use crate::containment::TreeDrain;
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
    /// A watch failure never skips the kill and reap; it surfaces only after they run. A kill or
    /// reap error is the call's error (the child then stays owned — `Drop`'s teardown applies), and
    /// the watch failure joins it as a peer, as for the sync
    /// [`graceful_shutdown`](crate::Child::graceful_shutdown).
    ///
    /// # Runtime
    ///
    /// Needs a runtime with the IO **and** time drivers enabled (the `#[tokio::main]` /
    /// `#[tokio::test]` defaults) — on a hand-built runtime missing either, tokio panics
    /// rather than returning a typed error.
    ///
    /// The grace watch reaps nothing: a root that exited within it, even one whose reap another
    /// process took, is not escalated against, and the reap that follows answers for it, as for the
    /// sync [`graceful_shutdown`](crate::Child::graceful_shutdown).
    ///
    /// **macOS, a root launchd holds** is answered as for the sync
    /// [`graceful_shutdown`](crate::Child::graceful_shutdown): refused by the cooperative half, and
    /// never killed or waited on, with no warn.
    pub async fn graceful_shutdown(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        crate::child::graceful::shutdown::shutdown_lone(self, grace).await
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
    /// Dropping this future mid-grace cancels the exit watch (on all platforms) and performs no
    /// further signalling — the
    /// child stays owned, and `Drop`'s teardown still applies.
    ///
    /// A watch failure never skips the sweep and reap. A sweep error is the call's error over it
    /// — and over a graceful root exit (survivors may remain; the root is still reaped first when
    /// its exit was observed, otherwise the child stays owned for `Drop`) — and so is a reap
    /// error once the sweep succeeded. A refused graceful signal and then the watch failure join the
    /// error as peers, as for the sync
    /// [`graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree).
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
    /// than returning a typed error. On Windows the grace-wait holds no thread and needs
    /// neither driver.
    ///
    /// **A root reaped by something else, a root its handle cannot vouch for, and one launchd
    /// holds** are answered as for the sync
    /// [`graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree), with the grace awaited.
    pub async fn graceful_shutdown_tree(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        crate::child::graceful::shutdown::shutdown_tree(self, grace).await
    }
}

/// The async `Child`'s waits for `graceful_shutdown` and `graceful_shutdown_tree`: each is awaited, on
/// tokio's clock.
impl Waits for Child {
    fn child(&self) -> &crate::Child {
        &self.inner
    }

    async fn tree_drained(&self, grace: Duration) -> Result<TreeDrain, Error> {
        self.wait_tree_timeout(grace).await
    }

    async fn root_exited(&self, within: Duration) -> Result<bool, Error> {
        self.exited_through_handle(Some(within)).await
    }

    async fn sweep(&self, swept: Swept<'_>) -> Result<(), SweepFailure> {
        swept.wait_async().await
    }

    async fn reap(&mut self) -> Result<crate::child::owned::ChildWaitOutcome, Error> {
        self.reap_outcome().await
    }

    #[cfg(unix)]
    async fn holders_finish(&self, shutdown: HoldersShutdown<'_>) -> Error {
        shutdown.finish_async().await
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;

#[cfg(all(test, windows))]
#[path = "ctrl_break_tests.rs"]
mod ctrl_break_tests;
