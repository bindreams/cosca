//! Async `Child` handle: the sync [`Child`](crate::Child) with awaited waits.

#[path = "child/graceful.rs"]
mod graceful;

#[path = "child/suspended.rs"]
mod suspended;
pub use suspended::SuspendedChild;

use std::collections::BTreeMap;
use std::process::ExitStatus;

use crate::containment::dispatch::SweepFailure;
use crate::containment::Containment;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::pipe::ParentEnd;
use crate::stdio::Fd;

/// Parent ends of the child's pipes (0/1/2 and fd >= 3), keyed by descriptor: the raw sync
/// `ParentEnd`, converted to a reactor pipe at take time.
pub(super) type FdPipes = BTreeMap<Fd, ParentEnd>;

/// Take the read end on `fd` out of `ends` (the first call moves it out, later calls find none) as a
/// reactor pipe. A write end is put back. If the reactor refuses the end it closes, and the error is
/// returned.
fn try_take_reader(ends: &mut FdPipes, fd: Fd) -> std::io::Result<Option<super::stdio::OwnedRead>> {
    match ends.remove(&fd) {
        None => Ok(None),
        Some(ParentEnd::Reader(r)) => super::stdio::register_reader(r).map(Some),
        Some(end) => {
            ends.insert(fd, end);
            Ok(None)
        }
    }
}

/// [`try_take_reader`] for a write end.
fn try_take_writer(ends: &mut FdPipes, fd: Fd) -> std::io::Result<Option<super::stdio::OwnedWrite>> {
    match ends.remove(&fd) {
        None => Ok(None),
        Some(ParentEnd::Writer(w)) => super::stdio::register_writer(w).map(Some),
        Some(end) => {
            ends.insert(fd, end);
            Ok(None)
        }
    }
}

/// The public taker over a fallible one: a refusal is logged at warn, naming `fd` and `what` end,
/// and `consequence` for the child, and the end, which was closed, is `None`.
fn logged<T>(taken: std::io::Result<Option<T>>, fd: Fd, what: &str, consequence: &str) -> Option<T> {
    taken.unwrap_or_else(|e| {
        log::warn!(
            "{fd} {what} dropped: tokio conversion failed ({report}); {consequence}",
            report = crate::error::Report(&e)
        );
        None
    })
}

const BROKEN_PIPE: &str = "the child will see a broken pipe on writes";
const EOF_ON_READS: &str = "the child will see EOF on reads";

/// A spawned child process the crate owns, with async waits: the sync [`Child`](crate::Child)'s
/// policy, written once, over the same process handle. Its waits register the process with the
/// runtime; its signals, its tree operations and its drop are the sync `Child`'s.
///
/// With `kill_on_drop` set (the default), dropping it kills the tree and the root and blocks the
/// dropping thread, whatever the runtime, until the root is reaped and the tree has drained, and
/// warns once past 1 s. To wait without blocking, call [`kill`](Child::kill) or
/// [`kill_tree`](Child::kill_tree), then await [`wait`](Child::wait) (and
/// [`wait_tree`](Child::wait_tree) for a tree), before dropping.
#[derive(Debug)]
pub struct Child {
    pub(crate) inner: crate::Child,
}

impl Child {
    /// The async handle over `inner`, which a spawn made with the async policy.
    pub(super) fn from_sync(inner: crate::Child) -> Child {
        Child { inner }
    }

    /// Commit the spawn: apply `kill_on_drop` to the containment resource (see
    /// [`crate::Child`]'s `commit_kill_on_drop`). A refused disarm (Windows) fails the commit: the
    /// child, still armed, is torn down as a failed run's is.
    pub(super) fn commit_kill_on_drop(self) -> Result<Child, crate::child::spawn::SpawnFailure> {
        self.inner.commit_kill_on_drop().map(Child::from_sync)
    }

    /// The failed run's teardown, awaited: what became of the child, and the child itself if its
    /// teardown could not end it (a refused kill, a running elevation front).
    pub(super) async fn tear_down_awaiting(self) -> (crate::error::ChildFate, Option<crate::Unreaped>) {
        self.inner
            .tear_down_or_hand_back_awaiting(crate::child::owned::teardown::Disposition::HandBack)
            .await
    }

    /// The child's stable identity; see [`Child::id`](crate::Child::id).
    pub fn id(&self) -> Option<ProcessId> {
        self.inner.id()
    }

    /// The pid the child had at spawn. A number only: it does not say the process still holds it
    /// (an identity is [`id`](Self::id)).
    pub fn pid(&self) -> u32 {
        self.inner.pid()
    }

    /// Whether the child is still running, read through the child's own handle, with or without an
    /// [`id`](Self::id); see [`Child::is_alive`](crate::Child::is_alive).
    pub fn is_alive(&self) -> crate::identity::Liveness {
        self.inner.is_alive()
    }

    /// The tree-teardown mechanism for this child; see [`Child::containment`](crate::Child::containment).
    pub fn containment(&self) -> Containment {
        self.inner.containment()
    }

    /// Async mirror of [`Child::graceful_mechanism`](crate::Child::graceful_mechanism) — see
    /// there for what the value claims, and what it deliberately does not.
    pub fn graceful_mechanism(&self) -> crate::graceful::GracefulMechanism {
        self.inner.graceful_mechanism()
    }

    /// The achieved elevation state, or `None` if elevation was not requested (mirrors the sync
    /// [`Child::elevation`](crate::Child::elevation)).
    pub fn elevation(&self) -> Option<crate::elevation::ElevationReport> {
        self.inner.elevation()
    }

    /// Take the child's stdin, once; `None` if it is not piped, already taken, or registering the
    /// end with the reactor failed (logged at warn).
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled: the end registers with the reactor
    /// when taken, in the runtime current then, not in the one that spawned the child.
    pub fn stdin(&mut self) -> Option<super::stdio::ChildStdin> {
        logged(self.stdin_or_error(), Fd::STDIN, "write end", EOF_ON_READS)
    }

    /// [`stdin`](Self::stdin) that returns the reactor's refusal as an error, not `None`. The end is
    /// closed then.
    pub(super) fn stdin_or_error(&mut self) -> std::io::Result<Option<super::stdio::ChildStdin>> {
        Ok(try_take_writer(&mut self.inner.pipes, Fd::STDIN)?.map(|inner| super::stdio::ChildStdin { inner }))
    }

    /// Take the child's stdout, once; `None` if it is not piped, already taken, or registering the
    /// end with the reactor failed (logged at warn).
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled: the end registers with the reactor
    /// when taken, in the runtime current then, not in the one that spawned the child.
    pub fn stdout(&mut self) -> Option<super::stdio::ChildStdout> {
        logged(self.stdout_or_error(), Fd::STDOUT, "read end", BROKEN_PIPE)
    }

    /// [`stdout`](Self::stdout) that returns the reactor's refusal as an error, not `None`. The end
    /// is closed then.
    pub(super) fn stdout_or_error(&mut self) -> std::io::Result<Option<super::stdio::ChildStdout>> {
        Ok(try_take_reader(&mut self.inner.pipes, Fd::STDOUT)?.map(|inner| super::stdio::ChildStdout { inner }))
    }

    /// Take the child's stderr, once; `None` if it is not piped, already taken, or registering the
    /// end with the reactor failed (logged at warn).
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled: the end registers with the reactor
    /// when taken, in the runtime current then, not in the one that spawned the child.
    pub fn stderr(&mut self) -> Option<super::stdio::ChildStderr> {
        logged(self.stderr_or_error(), Fd::STDERR, "read end", BROKEN_PIPE)
    }

    /// [`stderr`](Self::stderr) that returns the reactor's refusal as an error, not `None`. The end
    /// is closed then.
    pub(super) fn stderr_or_error(&mut self) -> std::io::Result<Option<super::stdio::ChildStderr>> {
        Ok(try_take_reader(&mut self.inner.pipes, Fd::STDERR)?.map(|inner| super::stdio::ChildStderr { inner }))
    }

    /// Take the parent's read end of the pipe on child descriptor `fd` (configured via
    /// `Command::fd(n, Stdio::pipe_out())`), as a reactor-registered pipe. Unix only.
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled (the pipe registers with the
    /// reactor).
    ///
    /// # Returns
    ///
    /// `Some(receiver)` on success. `None` if the fd was not configured as a piped read end,
    /// if it was already taken, or if converting the end to a reactor pipe failed (fstat/fcntl
    /// or reactor registration; logged at warn; the dropped end closes the fd, so the child
    /// observes EPIPE on its write end — a visible failure, never a hang).
    #[cfg(unix)]
    pub fn fd_read_end(&mut self, fd: impl Into<crate::stdio::Fd>) -> Option<::tokio::net::unix::pipe::Receiver> {
        let fd = fd.into();
        logged(try_take_reader(&mut self.inner.pipes, fd), fd, "read end", BROKEN_PIPE)
    }

    /// Take the parent's write end of the pipe on child descriptor `fd` (configured via
    /// `Command::fd(n, Stdio::pipe_in())`). Unix only.
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled (the pipe registers with the
    /// reactor).
    ///
    /// # Returns
    ///
    /// `Some(sender)` on success. `None` if the fd was not configured as a piped write end,
    /// if it was already taken, or if converting the end to a reactor pipe failed (fstat/fcntl
    /// or reactor registration; logged at warn; the dropped end closes the fd, so the child
    /// observes EOF on its read end — a visible failure, never a hang).
    #[cfg(unix)]
    pub fn fd_write_end(&mut self, fd: impl Into<crate::stdio::Fd>) -> Option<::tokio::net::unix::pipe::Sender> {
        let fd = fd.into();
        logged(
            try_take_writer(&mut self.inner.pipes, fd),
            fd,
            "write end",
            EOF_ON_READS,
        )
    }

    /// Take the parent's read end of the pipe on child descriptor `fd` (configured via
    /// `Command::fd(n, Stdio::pipe_out())`), as an async [`ChildStdout`](super::stdio::ChildStdout).
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled (the pipe registers with the
    /// reactor).
    ///
    /// # Returns
    ///
    /// `Some(reader)` on success. `None` if the fd was not configured as a piped read end, if it
    /// was already taken, or if registering the end with the reactor failed (logged at warn; the
    /// dropped end closes the pipe, so the child observes a broken pipe on its write end — a
    /// visible failure, never a hang). A wrong-direction take (a write end) leaves the end in place
    /// for [`fd_write_end`](Child::fd_write_end).
    #[cfg(windows)]
    pub fn fd_read_end(&mut self, fd: impl Into<Fd>) -> Option<super::stdio::ChildStdout> {
        let fd = fd.into();
        logged(try_take_reader(&mut self.inner.pipes, fd), fd, "read end", BROKEN_PIPE)
            .map(|inner| super::stdio::ChildStdout { inner })
    }

    /// Take the parent's write end of the pipe on child descriptor `fd` (configured via
    /// `Command::fd(n, Stdio::pipe_in())`), as an async [`ChildStdin`](super::stdio::ChildStdin).
    ///
    /// # Panics
    ///
    /// Panics outside a runtime with the IO driver enabled (the pipe registers with the
    /// reactor).
    ///
    /// # Returns
    ///
    /// `Some(writer)` on success. `None` if the fd was not configured as a piped write end, if it
    /// was already taken, or if registering the end with the reactor failed (logged at warn; the
    /// dropped end closes the pipe, so the child observes EOF on its read end). A wrong-direction
    /// take leaves the end in place for [`fd_read_end`](Child::fd_read_end).
    #[cfg(windows)]
    pub fn fd_write_end(&mut self, fd: impl Into<Fd>) -> Option<super::stdio::ChildStdin> {
        let fd = fd.into();
        logged(
            try_take_writer(&mut self.inner.pipes, fd),
            fd,
            "write end",
            EOF_ON_READS,
        )
        .map(|inner| super::stdio::ChildStdin { inner })
    }

    /// Test-only: whether this child is inside the crate's Job Object (`IsProcessInJob`
    /// against the held handle, not "any job"). `pub` so integration tests can call it.
    #[cfg(windows)]
    pub fn test_job_handle_contains_self(&self) -> bool {
        self.inner.test_job_handle_contains_self()
    }

    /// Test-only: [`test_job_handle_contains_self`](Self::test_job_handle_contains_self) for any
    /// `pid`, e.g. a descendant. `false` if the child is not job-contained or `pid` cannot be
    /// opened.
    #[cfg(windows)]
    pub fn test_job_handle_contains(&self, pid: u32) -> bool {
        self.inner.test_job_handle_contains(pid)
    }

    /// Block until the child exits, returning its status. For a bounded wait, fix a deadline
    /// instant once (`let deadline = tokio::time::Instant::now() + d;`) and use
    /// `tokio::time::timeout_at(deadline, child.wait())`, not a duration re-derived later.
    ///
    /// Closes the stdin pipe first if it was not taken, so a child that reads stdin to EOF can
    /// exit. That includes a stdin that is a merge target.
    pub async fn wait(&mut self) -> Result<ExitStatus, Error> {
        #[cfg(test)]
        if let Some(error) = crate::child::spawn::failure::seams::take_wait_failure() {
            return Err(error);
        }
        drop(self.inner.pipes.remove(&Fd::STDIN));
        self.inner.wait_async().await
    }

    /// Exit status if the child has already exited (non-blocking).
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        self.inner.try_wait()
    }

    /// Hard-kill the (lone) child. On Linux the signal goes through the pidfd the spawn holds, and
    /// on Windows through the process handle, so neither can race a recycled pid; a refused
    /// `pidfd_open` cannot fail it. On macOS it goes through the child's audit token, which the
    /// kernel checks against the process the pid names, so it cannot reach a recycled pid either.
    /// `Ok(())` if the child already exited, was reaped by a prior `wait`, or was reaped by someone
    /// else.
    /// Signal-only: does not reap — `wait().await` (or `Drop`) collects the exit status.
    ///
    /// **An elevated child behind a front** gets no signal of its own while it runs: in a Linux
    /// cgroup that holds it this kills, through `cgroup.kill`, what is still in the cgroup, and
    /// otherwise it sends nothing. An elevated program that moves its front out of the cgroup and
    /// back again around the kill can make an `Ok` false; `wait` stays truthful. See the sync
    /// [`Child::kill`](crate::Child::kill).
    ///
    /// **macOS, a root launchd holds** is refused with nothing sent, and an `Unknown` root is killed
    /// through the handle, as for the sync [`Child::kill`](crate::Child::kill), which says why.
    pub fn kill(&mut self) -> Result<(), Error> {
        self.inner.kill()
    }

    /// Hard-kill the contained tree. Requires an actionable containment mechanism
    /// (errors `Unsupported` otherwise — use [`kill`](Child::kill) for a lone process).
    /// If both the group teardown and the handle backstop fail, the group error is returned.
    ///
    /// Awaits nothing extra: the sync [`Child::kill_tree`](crate::Child::kill_tree), with every case it documents.
    pub fn kill_tree(&mut self) -> Result<(), Error> {
        self.inner.kill_tree()
    }

    /// [`kill_tree`](Self::kill_tree) for the operation `op`, as a step of it that already sent
    /// `earlier`, so an error never claims the whole operation sent nothing. `op` names the call in
    /// what it reports. A failure says whether the root is dead all the same ([`SweepFailure`]): a
    /// caller may wait for it before it returns the error.
    pub(crate) fn kill_tree_after(&mut self, op: &'static str, earlier: Option<&str>) -> Result<(), SweepFailure> {
        self.inner.kill_tree_after(op, earlier)
    }

    /// Send the graceful termination signal to the contained group — `SIGTERM` via
    /// `killpg`/cgroup, or `CTRL_BREAK` to the job/console group. **Signal-only:** does
    /// not wait or reap. Requires an actionable containment mechanism (errors
    /// `Unsupported` otherwise). Cooperative best-effort: on the `TreeWalk` mechanism a
    /// descendant whose identity transiently fails to resolve is intentionally left
    /// unsignaled; [`kill_tree`](Child::kill_tree) is the guaranteed hard teardown.
    ///
    /// The sync [`Child::terminate_tree`](crate::Child::terminate_tree), with every case it documents.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.inner.terminate_tree()
    }

    /// Block until every member of the contained tree has EXITED — not reaped; a status is
    /// never collected by this call, only the root's own `wait`/`try_wait` does that. Requires
    /// a mechanism with a real kernel drain edge (`Unsupported` otherwise — cgroup v2, a
    /// Windows job object, and the macOS fd marker have one; `ProcessGroup`/`Session`/
    /// `TreeWalk` and an uncontained or nested-`Delegated` child do not). No polling interval:
    /// macOS waits on the reactor; Linux awaits a broadcast from a thread the leaf owns, started
    /// by the first wait that blocks and joined when the child is dropped; Windows hands the wait to `spawn_blocking` (job
    /// objects have no pollable handle) with a cancel event so a dropped future releases the
    /// blocking watcher promptly instead of parking out the wait.
    pub async fn wait_tree(&self) -> Result<crate::containment::TreeDrain, Error> {
        self.inner.tree.wait_drained_async(None).await
    }

    /// Like [`wait_tree`](Child::wait_tree) but bounded by `timeout`.
    /// `TreeDrain::MembersRemain` at expiry is not an error. A `timeout` so large it would
    /// overflow `Instant` is treated as unbounded, matching [`wait_tree`](Child::wait_tree).
    pub async fn wait_tree_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<crate::containment::TreeDrain, Error> {
        self.inner
            .tree
            .wait_drained_async(super::wait::deadline_from(timeout))
            .await
    }

    /// Leave the child (and its contained tree) running after this handle drops (opt out of
    /// kill-on-drop). Also disarms the containment resource, so its own `Drop` never kills the
    /// tree itself, though if [`kill_tree`](Self::kill_tree) already returned `Ok` on this handle,
    /// its `Drop` still waits for that kill's drain before giving up the leaf: on Linux the
    /// dropping thread blocks until the leaf drains, and warns past 1 s. Await
    /// [`wait_tree`](Self::wait_tree) first and the drop finds nothing to wait for. A `kill_tree()`
    /// that returned `Err` leaves nothing to wait for; see
    /// [`Command::kill_on_drop`](crate::Command::kill_on_drop) for what that leaves behind.
    ///
    /// `Ok` promises that cosca no longer kills the tree: not this handle's drop, and not the
    /// containment resource's close. It makes no promise about a job the caller's own process runs
    /// in (see `breakaway_from_job()`).
    ///
    /// # Errors
    ///
    /// On Windows, the refusal of the OS to clear `KILL_ON_JOB_CLOSE` on the child's Job Object
    /// ([`Error::Io`], with the Win32 code). The handle is then unchanged and still armed: its
    /// drop kills the tree. Retry `detach`, keep the handle, or kill the tree on purpose. No other
    /// platform's disarm can fail. A child that `kill_on_drop(false)` already disarmed is `Ok`
    /// without asking the OS.
    pub fn detach(&mut self) -> Result<(), Error> {
        self.inner.disarm()
    }
}

/// The async policy of a spawn: what the sync spawn is told so that a teardown of the child it makes
/// warns past [`slow_teardown_after`], and an [`Unreaped`](crate::Unreaped) it hands back lets the
/// child go when dropped. Built per spawn: the threshold is read when the spawn starts.
pub(crate) fn async_policy() -> crate::child::spawn::policy::SpawnPolicy {
    crate::child::spawn::policy::SpawnPolicy {
        teardown_warn_after: slow_teardown_after(),
        unreaped_drop: crate::child::owned::unreaped::DropKind::LetGo,
    }
}

/// How long a failed spawn's teardown, or the armed drop, waits for what it killed before it warns
/// that it is still waiting. Messaging only: no wait ends on it.
#[cfg_attr(
    all(test, not(target_os = "linux")),
    allow(dead_code, reason = "a test opts in with its own threshold off Linux")
)]
const LATE: std::time::Duration = std::time::Duration::from_secs(1);

/// How long a failed spawn's teardown, or the armed drop, waits for what it killed before it warns
/// that it is still waiting: [`LATE`]. In a test, only one that opted in
/// (`fault::warn_slow_teardowns`): a loaded runner could pass the threshold, and a test's verdict
/// must not depend on elapsed time.
pub(crate) fn slow_teardown_after() -> Option<std::time::Duration> {
    #[cfg(test)]
    return fault::slow_teardown_after();
    #[cfg(not(test))]
    Some(LATE)
}

#[cfg(test)]
#[path = "child_tests.rs"]
mod child_tests;

#[cfg(all(test, windows))]
#[path = "child/disarm_refused_tests.rs"]
mod disarm_refused_tests;

#[cfg(test)]
#[path = "child_pipe_conversion_tests.rs"]
mod child_pipe_conversion_tests;

#[cfg(test)]
#[path = "child_wait_tree_tests.rs"]
mod child_wait_tree_tests;

#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    thread_local! {
        static SLOW_TEARDOWN_AFTER: Cell<Option<std::time::Duration>> = const { Cell::new(None) };
    }

    /// A failed spawn's teardown, or an armed drop, on THIS thread warns once its wait passes 1 s, as
    /// outside tests (see [`slow_teardown_after`](super::slow_teardown_after)).
    #[cfg(target_os = "linux")]
    pub(crate) fn warn_slow_teardowns() -> WarnSlowTeardowns {
        warn_slow_teardowns_after(super::LATE)
    }

    /// As [`warn_slow_teardowns`], past `after`: zero, for a test whose forced looks keep the child
    /// from showing its exit within it.
    pub(crate) fn warn_slow_teardowns_after(after: std::time::Duration) -> WarnSlowTeardowns {
        SLOW_TEARDOWN_AFTER.with(|w| w.set(Some(after)));
        WarnSlowTeardowns(())
    }

    #[must_use = "the warn is off again as soon as the guard is dropped"]
    pub(crate) struct WarnSlowTeardowns(());

    impl Drop for WarnSlowTeardowns {
        fn drop(&mut self) {
            SLOW_TEARDOWN_AFTER.with(|w| w.set(None));
        }
    }

    pub(super) fn slow_teardown_after() -> Option<std::time::Duration> {
        SLOW_TEARDOWN_AFTER.with(Cell::get)
    }
}
