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
use crate::stop::{StopTarget, StopWaits};
use crate::tokio::stop::AsyncDriver;

impl Child {
    /// Send the child its cooperative shutdown signal — a request to exit, not an order.
    /// Signal-only: does not wait or reap.
    ///
    /// Awaits the child's stop action
    /// ([`Command::graceful_stop`](crate::tokio::Command::graceful_stop); [`stop::default`](crate::tokio::stop::default)
    /// when none was set) on a [`StopTarget`] that stands for the root alone, and answers
    /// what the action answers: the sync [`Child::terminate`](crate::Child::terminate) with the same
    /// default, awaited. The prepared functions of [`tokio::stop`](crate::tokio::stop) apply the rules of
    /// the sync ones, whoever calls them. After a future dropped while it holds the Windows console-event
    /// proxy, the proxy is ended and whether the event was sent is unknown (see
    /// `tokio::stop::send_console_event_via_proxy` for a drop during the proxy's start).
    ///
    /// On Unix the default is an identity-bound `SIGTERM` to this process alone, so it cannot race a
    /// concurrent reap onto a recycled pid.
    /// On Windows it is `CTRL_BREAK`, sent directly to the child's own **console process group** or by the
    /// console-event proxy, exactly as for the sync [`Child::terminate`](crate::Child::terminate), and
    /// [`stop::default`](crate::stop::default) says which child gets which and which are refused. `kill`
    /// is the always-available alternative.
    ///
    /// **What it reaches, what it refuses, and what success proves on Windows** are those of the sync
    /// [`Child::terminate`](crate::Child::terminate).
    ///
    /// **Every error means nothing was killed, and that nothing was sent, except on Windows through the
    /// proxy:** an [`Error::Unassessable`](crate::error::Error::Unassessable) and an
    /// [`Error::MayHaveStarted`](crate::error::Error::MayHaveStarted) from the proxy's start say whether
    /// it was sent is unknown. On Linux that includes a refused `pidfd_open`, which is `Unsupported` (see
    /// [`Error::Unsupported`](crate::error::Error::Unsupported)).
    ///
    /// **Windows, before the child has run.** As for the sync [`Child::terminate`](crate::Child::terminate) and
    /// [`stop::default`](crate::stop::default).
    ///
    /// **Windows, after the exit has been observed.** A console control event is addressed by pid
    /// alone. This handle pins the child's pid for its whole life, as the sync [`Child`](crate::Child)
    /// does, so a send never reaches a reissued pid. The call answers `Ok` before and after the exit
    /// has been observed (the direct send succeeds on the pinned pid, and the proxy path answers an
    /// exited child before it asks, see `stop::send_console_event_via_proxy`), except for a child
    /// created on this process's console that leads no group: the direct send refuses it with
    /// `Unsupported` before and after the exit alike.
    ///
    /// **A macOS graphically-elevated child** is refused, as for the sync
    /// [`Child::terminate`](crate::Child::terminate).
    ///
    /// **macOS, a root launchd holds** is refused with nothing sent, and an `Unknown` root is signalled
    /// through the handle, as for the sync [`Child::kill`](crate::Child::kill).
    ///
    /// # Runtime
    ///
    /// The default action on Unix waits for nothing and needs no driver; on Windows it may start the
    /// console-event proxy, on the blocking pool, and awaits its exit through a wait registered with the
    /// OS, which occupies no runtime thread and needs neither driver. An action that awaits
    /// [`tokio::stop::wait_exit`](crate::tokio::stop::wait_exit) with a non-zero grace needs, on Unix, a
    /// runtime with the IO **and** time drivers enabled, as that function documents.
    ///
    /// # Panics
    ///
    /// On Windows: see [`stop::default`](crate::stop::default#panics).
    pub async fn terminate(&self) -> Result<(), Error> {
        crate::child::graceful::shutdown::terminate(self).await
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
    /// ([`Command::graceful_stop`](crate::tokio::Command::graceful_stop), else
    /// [`stop::default`](crate::tokio::stop::default)) awaited on a root target, and every caveat on it applies. An
    /// error of the action propagates immediately: no grace is waited, nothing is killed, and the child
    /// is left running for the caller to `kill`. The escalation after the grace names what was sent
    /// before it as what the action's last prepared send sent, or "the stop action" when it sent none.
    ///
    /// The grace starts when the stop action returns: an action that does not return holds the call.
    ///
    /// An untaken stdin pipe stays open through the grace: unlike [`wait`](Child::wait), the grace
    /// does not close it, so the signal, not an EOF on stdin, is what ends the child. The reap
    /// after the exit or the kill closes it.
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
    /// Behaves as the sync [`graceful_shutdown`](crate::Child::graceful_shutdown), awaiting each wait.
    ///
    /// # Panics
    ///
    /// On Windows: see [`stop::default`](crate::stop::default#panics).
    pub async fn graceful_shutdown(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        crate::child::graceful::shutdown::shutdown_lone(self, grace).await
    }

    /// Cooperative-then-forced shutdown of the contained tree: run the child's stop action
    /// ([`Command::graceful_stop`](crate::tokio::Command::graceful_stop), else
    /// [`stop::default`](crate::tokio::stop::default)) awaited on a tree target, which by default sends the group its
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
    /// **Windows.** What the default signals, what it refuses, what the grace costs and what success
    /// proves are those of the sync [`Child::graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree).
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
    /// **The grace starts when the stop action returns.** An action that does not return holds the call.
    ///
    /// **An action's error ends the call before its grace unless its last prepared send went out.** When
    /// the last prepared send of the child's stop action was refused, or the action made none, the
    /// action's own `Err` is the call's answer, with nothing waited and nothing killed; this holds even
    /// when an earlier send of the same action went out and a later step failed. When its last prepared
    /// send went out, the call goes on to the grace and the sweep and keeps the action's error as the
    /// refusal above. An action of the caller's own that makes no prepared send and returns `Ok` goes on
    /// to the grace and the sweep, with nothing assumed about what it sent.
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
    ///
    /// # Panics
    ///
    /// On Windows: see [`stop::default`](crate::stop::default#panics).
    pub async fn graceful_shutdown_tree(&mut self, grace: Duration) -> Result<ExitStatus, Error> {
        crate::child::graceful::shutdown::shutdown_tree(self, grace).await
    }
}

impl StopWaits for Child {
    async fn root_exited(&self, within: Duration) -> Result<bool, Error> {
        AsyncDriver(&self.inner).root_exited(within).await
    }

    #[cfg(windows)]
    type Proxy = Child;

    #[cfg(windows)]
    async fn start_proxy(
        &self,
        exe: &std::path::Path,
        args: &crate::stop::proxy::protocol::ProxyArgs,
    ) -> Result<(u32, Child), Error> {
        AsyncDriver(&self.inner).start_proxy(exe, args).await
    }

    #[cfg(windows)]
    async fn wait_proxy(
        &self,
        proxy: &mut Child,
        after: Duration,
        late: impl FnOnce(Duration) + Send,
    ) -> Result<std::process::ExitStatus, Error> {
        AsyncDriver(&self.inner).wait_proxy(proxy, after, late).await
    }
}

/// The async `Child`'s waits for `graceful_shutdown` and `graceful_shutdown_tree`: each is awaited, on
/// tokio's clock.
impl Waits for Child {
    fn child(&self) -> &crate::Child {
        &self.inner
    }

    async fn stop(&self, target: &StopTarget<'_>) -> Result<(), Error> {
        self.inner.stop.run_async(target).await
    }

    async fn tree_drained(&self, grace: Duration) -> Result<TreeDrain, Error> {
        self.wait_tree_timeout(grace).await
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

#[cfg(all(test, windows))]
#[path = "ctrl_break_proxy_tests.rs"]
mod ctrl_break_proxy_tests;
