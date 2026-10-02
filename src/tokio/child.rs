//! Async `Child` handle, wrapping `::tokio::process::Child` plus the stable `ProcessId` and the
//! contained-tree `Attached`.

#[path = "child/graceful.rs"]
mod graceful;

#[path = "child/proc_source.rs"]
mod proc_source;
pub(crate) use proc_source::ProcSource;
#[cfg(any(unix, test))]
pub(crate) use proc_source::Waited;

use std::collections::BTreeMap;
use std::process::ExitStatus;

#[cfg(unix)]
use crate::child::ParentEnd;
use crate::containment::{Attached, Containment};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::signal::{Sent, Sig};
use crate::stdio::Fd;

/// Parent ends of fd >= 3 pipes, keyed by descriptor. Unix stashes the raw sync `ParentEnd`
/// (converted to a reactor pipe at take time); Windows stashes the already-registered overlapped
/// async end (the raw backend's fd >= 3 pipes), taken directly (no `from_raw_handle`, which would
/// double-register the IOCP handle).
#[cfg(unix)]
pub(super) type FdPipes = BTreeMap<Fd, ParentEnd>;
#[cfg(windows)]
pub(super) type FdPipes = BTreeMap<Fd, super::stdio::OwnedStd>;

/// The `expect` behind the two backend accessors: only `Drop` takes `proc`, and nothing runs on
/// the handle after that, so both are infallible.
const PROC_TAKEN: &str = "the async child's process backend is taken only by Drop";

/// Every field of a [`Child`] that owns an OS resource, **declared in the order they must be
/// released**: the backend first, then the containment resource.
///
/// [`release_without_waiting`](OsResources::release_without_waiting) is the one place `Drop`
/// gives them up. Adding a resource-owning field here without releasing it there would silently
/// change when it is released.
#[derive(Debug, Default)]
pub(crate) struct OsResources {
    /// `Option` so the release can drop the backend before the containment resource; nothing else
    /// takes it. Read it through [`proc_mut`](OsResources::proc_mut), never directly.
    pub(crate) proc: Option<ProcSource>,
    pub(crate) attached: Attached,
    /// Parent ends of fd >= 3 pipes, read by [`fd_read_end`](Child::fd_read_end) /
    /// [`fd_write_end`](Child::fd_write_end). Unix: `fd_map`-wired reactor pipes; Windows: the
    /// raw backend's overlapped async ends (empty on the std path, which routes fd >= 3 to the raw
    /// backend).
    pub(crate) pipes: FdPipes,
    /// Our-owned parent ends of piped std-slot MERGE TARGETS (the spawn pre-pass owns those
    /// pipes; tokio's internal ones cannot be shared), keyed by the target slot.
    pub(crate) owned_std: BTreeMap<Fd, super::stdio::OwnedStd>,
}

impl OsResources {
    /// The process backend. The single `expect` site: only the release empties this, and it is
    /// the last reader.
    pub(crate) fn proc_mut(&mut self) -> &mut ProcSource {
        self.proc.as_mut().expect(PROC_TAKEN)
    }

    /// Whether the child's own handle shows its root reaped by someone else, which the start token
    /// cannot tell for a reuse in the same tick. `false` when this handle reaped it itself.
    #[cfg(unix)]
    pub(crate) fn root_reaped_elsewhere(&self, own_reap: bool) -> bool {
        !own_reap && self.proc.as_ref().is_some_and(ProcSource::reaped_elsewhere)
    }

    /// Give up every resource, in declaration order, without waiting for anything.
    ///
    /// The backend goes first. tokio's `Child` drops normally: it tries a reap once and queues a
    /// still-running child on tokio's orphan queue, tokio's state and not cosca's (principle 3). A
    /// child that something else reaped, or that cannot be verified, was forgotten before this by
    /// [`ProcSource::forget_foreign`], and the backend holds none. The Windows raw backend closes
    /// its handle. The containment resource follows through
    /// [`Attached::release_without_waiting`], bounded on every mechanism. The pipes and merge
    /// targets close last.
    pub(crate) fn release_without_waiting(mut self) {
        #[cfg(test)]
        fault::note_release();
        drop(self.proc.take());
        std::mem::take(&mut self.attached).release_without_waiting();
    }
}

#[derive(Debug)]
pub struct Child {
    os: OsResources,
    id: ProcessId,
    kill_on_drop: bool,
    containment: Containment,
    /// Whether this handle already hard-killed the tree; see [`crate::containment::TreeKilled`].
    tree_killed: crate::containment::TreeKilled,
    graceful: crate::graceful::GracefulMechanism,
    /// The achieved elevation state, or `None` if elevation was not requested (mirrors the sync
    /// `Child`). Drives the universal-teardown kill mapping.
    elevation: Option<crate::elevation::ElevationReport>,
}

impl Child {
    // The only caller is the sibling `spawn` (and `OwnedStd` is module-scoped).
    pub(super) fn from_parts(
        proc: ProcSource,
        id: ProcessId,
        kill_on_drop: bool,
        attachment: crate::containment::Attachment,
        pipes: FdPipes,
        owned_std: BTreeMap<Fd, super::stdio::OwnedStd>,
    ) -> Child {
        Child {
            os: OsResources {
                proc: Some(proc),
                attached: attachment.attached,
                pipes,
                owned_std,
            },
            id,
            kill_on_drop,
            containment: attachment.containment,
            tree_killed: Default::default(),
            graceful: attachment.graceful,
            elevation: None,
        }
    }

    /// The process backend. `pub(super)`: the sibling `pump` module borrows it for
    /// `communicate`'s `wait` future, and `child::graceful` for its pid-pinning guard.
    pub(super) fn proc_mut(&mut self) -> &mut ProcSource {
        self.os.proc_mut()
    }
    /// Shared read-only accessor for the two `pins_pid` guards, which hold `&self`.
    #[cfg(windows)]
    pub(super) fn proc(&self) -> &ProcSource {
        self.os.proc.as_ref().expect(PROC_TAKEN)
    }

    /// Commit the spawn: apply `kill_on_drop` to the containment resource (see
    /// [`Attached::honor_kill_on_drop`](crate::containment::Attached::honor_kill_on_drop)).
    pub(super) fn commit_kill_on_drop(&self) {
        self.os.attached.honor_kill_on_drop(self.kill_on_drop);
    }

    /// Kill the contained tree through its containment only, without the root's own kill that
    /// [`kill_tree`](Self::kill_tree) adds, for a failed spawn, which kills and reaps the root
    /// separately. The root may already be reaped: when it is (this handle's own reap, the number
    /// no longer reading as the root, or the child's own handle showing it reaped), nothing that
    /// names the tree by the root's number runs, and the skipped action is returned as
    /// `Ok(Some(action))`.
    #[cfg(unix)]
    pub(super) fn kill_tree_members_unless_reaped(&self) -> Result<Option<String>, Error> {
        let own_reap = self.os.proc.as_ref().is_none_or(ProcSource::is_reaped);
        let mut view = crate::containment::DropView::read(self.id, own_reap, &self.tree_killed);
        view.root_reaped |= self.os.root_reaped_elsewhere(own_reap);
        self.os
            .attached
            .hard_kill_marking_unless_reaped(view, &self.tree_killed)
    }

    /// Block until a cgroup-contained tree has drained, so the leaf's drop can remove it on its
    /// first `rmdir`. For a path that may block, such as a failed spawn: never `Drop`, never an
    /// `async fn`. Nothing else leaves work on the drain, so any other mechanism returns at once.
    #[cfg(unix)]
    pub(super) fn block_until_members_drained(&self) -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        if matches!(self.os.attached, crate::containment::Attached::Cgroup(_)) {
            return self.os.attached.wait_drained(None).map(drop);
        }
        Ok(())
    }

    /// Whether this child's tree is named by a number that outlives the root's reap (a process
    /// group), for a test that needs a number-named group kill.
    #[cfg(all(test, unix))]
    pub(super) fn carries_recyclable_pgid(&self) -> bool {
        self.os.attached.carries_recyclable_pgid()
    }

    /// What names this child's tree in a message about a failed teardown of it.
    #[cfg(unix)]
    pub(super) fn teardown_subject(&self) -> String {
        self.os.attached.teardown_subject()
    }

    /// Attach the elevation report — set by the spawn arms before the deferred password write, so
    /// a cleanup `kill` in the write-failure path already sees the elevated state.
    pub(crate) fn set_elevation(&mut self, report: Option<crate::elevation::ElevationReport>) {
        self.elevation = report;
    }
    /// The achieved elevation state, or `None` if elevation was not requested (mirrors the sync
    /// [`Child::elevation`](crate::Child::elevation)).
    pub fn elevation(&self) -> Option<crate::elevation::ElevationReport> {
        self.elevation.clone()
    }
    /// Is this a wrapper-elevated child a plain parent may be unable to signal?
    /// (`AlreadyElevated` is an ordinary child of an already-root parent — killable.)
    fn is_elevated_wrapper(&self) -> bool {
        matches!(
            self.elevation.as_ref().map(|r| &r.via),
            Some(crate::elevation::ElevatedVia::Wrapped(_) | crate::elevation::ElevatedVia::WindowsUac)
        )
    }
    /// Blocking reap used by the POSIX spawn-error cleanup path (a sync context — no reactor
    /// `await` available).
    ///
    /// **Wait-only, and the caller must already have killed successfully** — that kill is the
    /// precondition that bounds this wait. Killing again here would gate the wait on the second
    /// kill's result, and a second kill of an elevated child can be refused (it drops to root
    /// mid-teardown, and a zombie keeps the credentials it died with), so the reap would be
    /// skipped on the ordinary success path.
    ///
    /// Unix-only: the Windows elevation arm builds its child in-module with no deferred password.
    #[cfg(unix)]
    pub(super) fn wait_and_reap_blocking(&mut self) {
        let pid = self.id.pid();
        if self.proc_mut().wait_and_reap(pid) == Waited::Foreign {
            self.proc_mut().forget_foreign();
        }
    }

    /// The child's stable identity — valid after `wait`.
    pub fn id(&self) -> ProcessId {
        self.id
    }
    pub fn is_alive(&self) -> crate::identity::Liveness {
        self.id.is_alive()
    }
    pub fn containment(&self) -> Containment {
        self.containment
    }
    /// Async mirror of [`Child::graceful_mechanism`](crate::Child::graceful_mechanism) — see
    /// there for what the value claims, and what it deliberately does not.
    pub fn graceful_mechanism(&self) -> crate::graceful::GracefulMechanism {
        self.graceful
    }

    pub fn stdin(&mut self) -> Option<super::stdio::ChildStdin> {
        if let Some(owned) = self.take_owned_in(crate::stdio::Fd::STDIN) {
            return Some(super::stdio::ChildStdin { inner: owned });
        }
        self.proc_mut().take_stdin().map(|s| super::stdio::ChildStdin {
            inner: super::stdio::InInner::Tokio(s),
        })
    }
    pub fn stdout(&mut self) -> Option<super::stdio::ChildStdout> {
        if let Some(owned) = self.take_owned_out(crate::stdio::Fd::STDOUT) {
            return Some(super::stdio::ChildStdout { inner: owned });
        }
        self.proc_mut().take_stdout().map(|s| super::stdio::ChildStdout {
            inner: super::stdio::OutInner::Stdout(s),
        })
    }
    pub fn stderr(&mut self) -> Option<super::stdio::ChildStderr> {
        if let Some(owned) = self.take_owned_out(crate::stdio::Fd::STDERR) {
            return Some(super::stdio::ChildStderr { inner: owned });
        }
        self.proc_mut().take_stderr().map(|s| super::stdio::ChildStderr {
            inner: super::stdio::OutInner::Stderr(s),
        })
    }

    /// Take the stashed our-owned read end of an Out-direction merge target (plain
    /// `BTreeMap::remove` — TAKE semantics: the first call moves the end out, later calls
    /// return `None`, matching the tokio-owned branch's `Option::take`). Unix converts the
    /// raw end to a reactor pipe here; on a conversion failure the end drops (with a
    /// `log::warn!`), so the child observes EPIPE on writes — visible, never a hang.
    #[cfg(unix)]
    fn take_owned_out(&mut self, fd: Fd) -> Option<super::stdio::OutInner> {
        use std::os::fd::OwnedFd;
        match self.os.owned_std.remove(&fd)? {
            ParentEnd::Reader(r) => match ::tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(r)) {
                Ok(recv) => Some(super::stdio::OutInner::Owned(recv)),
                Err(e) => {
                    log::warn!(
                        "{fd} merge-target read end dropped: tokio conversion failed ({e}); the child will see EPIPE on writes"
                    );
                    None
                }
            },
            end => {
                self.os.owned_std.insert(fd, end); // wrong direction — put it back (fd_read_end mirror)
                None
            }
        }
    }

    /// The Windows twin yields the stashed `WinOwnedRead` DIRECTLY — the `NamedPipeServer`
    /// and its connect task were created at spawn, inside the runtime, so no conversion
    /// (and no `from_raw_handle`, which would double-register the IOCP handle) exists here.
    #[cfg(windows)]
    fn take_owned_out(&mut self, fd: Fd) -> Option<super::stdio::OutInner> {
        match self.os.owned_std.remove(&fd)? {
            super::stdio::OwnedStd::Read(r) => Some(super::stdio::OutInner::Owned(r)),
            end => {
                self.os.owned_std.insert(fd, end); // wrong direction — put it back (fd_read_end mirror)
                None
            }
        }
    }

    /// Take the stashed our-owned write end of an In-direction merge target (TAKE
    /// semantics, as [`take_owned_out`](Child::take_owned_out)). On a Unix conversion
    /// failure the dropped end closes the pipe, so the child observes EOF on reads.
    #[cfg(unix)]
    fn take_owned_in(&mut self, fd: Fd) -> Option<super::stdio::InInner> {
        use std::os::fd::OwnedFd;
        match self.os.owned_std.remove(&fd)? {
            ParentEnd::Writer(w) => match ::tokio::net::unix::pipe::Sender::from_owned_fd(OwnedFd::from(w)) {
                Ok(send) => Some(super::stdio::InInner::Owned(send)),
                Err(e) => {
                    log::warn!(
                        "{fd} merge-target write end dropped: tokio conversion failed ({e}); the child will see EOF on reads"
                    );
                    None
                }
            },
            end => {
                self.os.owned_std.insert(fd, end); // wrong direction — put it back (fd_write_end mirror)
                None
            }
        }
    }

    /// The Windows twin of [`take_owned_in`](Child::take_owned_in) — direct, no conversion
    /// (see [`take_owned_out`](Child::take_owned_out)).
    #[cfg(windows)]
    fn take_owned_in(&mut self, fd: Fd) -> Option<super::stdio::InInner> {
        match self.os.owned_std.remove(&fd)? {
            super::stdio::OwnedStd::Write(w) => Some(super::stdio::InInner::Owned(w)),
            end => {
                self.os.owned_std.insert(fd, end); // wrong direction — put it back (fd_write_end mirror)
                None
            }
        }
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
        use std::os::fd::OwnedFd;
        let fd = fd.into();
        match self.os.pipes.remove(&fd)? {
            crate::child::ParentEnd::Reader(r) => {
                match ::tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(r)) {
                    Ok(recv) => Some(recv),
                    Err(e) => {
                        log::warn!(
                            "{fd} read end dropped: tokio conversion failed ({e}); the child will see EPIPE on writes"
                        );
                        None
                    }
                }
            }
            end => {
                self.os.pipes.insert(fd, end); // wrong direction — put it back (sync mirror)
                None
            }
        }
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
        use std::os::fd::OwnedFd;
        let fd = fd.into();
        match self.os.pipes.remove(&fd)? {
            crate::child::ParentEnd::Writer(w) => {
                match ::tokio::net::unix::pipe::Sender::from_owned_fd(OwnedFd::from(w)) {
                    Ok(send) => Some(send),
                    Err(e) => {
                        log::warn!(
                            "{fd} write end dropped: tokio conversion failed ({e}); the child will see EOF on reads"
                        );
                        None
                    }
                }
            }
            end => {
                self.os.pipes.insert(fd, end);
                None
            }
        }
    }

    /// Take the parent's read end of the pipe on child descriptor `fd` (configured via
    /// `Command::fd(n, Stdio::pipe_out())`), as an async [`ChildStdout`](super::stdio::ChildStdout).
    /// The raw `CreateProcessW` backend serves fd >= 3 on Windows; the end is the overlapped
    /// named-pipe async end created at spawn (inside the runtime), yielded directly.
    ///
    /// # Returns
    ///
    /// `Some(reader)` on success. `None` if the fd was not configured as a piped read end, or was
    /// already taken. A wrong-direction take (a write end) leaves the end in place for
    /// [`fd_write_end`](Child::fd_write_end).
    #[cfg(windows)]
    pub fn fd_read_end(&mut self, fd: impl Into<Fd>) -> Option<super::stdio::ChildStdout> {
        let fd = fd.into();
        match self.os.pipes.remove(&fd)? {
            super::stdio::OwnedStd::Read(r) => Some(super::stdio::ChildStdout {
                inner: super::stdio::OutInner::Owned(r),
            }),
            end => {
                self.os.pipes.insert(fd, end); // wrong direction — put it back (Unix mirror)
                None
            }
        }
    }

    /// Take the parent's write end of the pipe on child descriptor `fd` (configured via
    /// `Command::fd(n, Stdio::pipe_in())`), as an async [`ChildStdin`](super::stdio::ChildStdin).
    /// See [`fd_read_end`](Child::fd_read_end) for the Windows raw-backend surface.
    ///
    /// # Returns
    ///
    /// `Some(writer)` on success. `None` if the fd was not configured as a piped write end, or was
    /// already taken. A wrong-direction take leaves the end in place for
    /// [`fd_read_end`](Child::fd_read_end).
    #[cfg(windows)]
    pub fn fd_write_end(&mut self, fd: impl Into<Fd>) -> Option<super::stdio::ChildStdin> {
        let fd = fd.into();
        match self.os.pipes.remove(&fd)? {
            super::stdio::OwnedStd::Write(w) => Some(super::stdio::ChildStdin {
                inner: super::stdio::InInner::Owned(w),
            }),
            end => {
                self.os.pipes.insert(fd, end); // wrong direction — put it back (Unix mirror)
                None
            }
        }
    }

    /// Test-only: whether this child is inside the crate's Job Object (`IsProcessInJob`
    /// against the held handle, not "any job"). `pub` so integration tests can call it.
    #[cfg(windows)]
    pub fn test_job_handle_contains_self(&self) -> bool {
        self.test_job_handle_contains(self.id.pid())
    }

    /// Test-only: [`test_job_handle_contains_self`](Self::test_job_handle_contains_self) for any
    /// `pid`, e.g. a descendant. `false` if the child is not job-contained or `pid` cannot be
    /// opened.
    #[cfg(windows)]
    pub fn test_job_handle_contains(&self, pid: u32) -> bool {
        crate::containment::windows::job_contains_pid(&self.os.attached, pid)
    }

    /// Block until the child exits, returning its status. For a bounded wait, fix a deadline
    /// instant once (`let deadline = tokio::time::Instant::now() + d;`) and use
    /// `tokio::time::timeout_at(deadline, child.wait())`, not a duration re-derived later.
    pub async fn wait(&mut self) -> Result<ExitStatus, Error> {
        self.proc_mut().wait().await
    }
    /// Exit status if the child has already exited (non-blocking).
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        self.proc_mut().try_wait()
    }

    /// Hard-kill the (lone) child. On Linux the signal goes through the pidfd the spawn holds, and
    /// on Windows through the process handle, so neither can race a recycled pid; a refused
    /// `pidfd_open` cannot fail it. macOS has no such handle: it sends by pid, only while the pid
    /// still has the unique id read at spawn, and a reap by someone else between that check and the
    /// send is an accepted gap.
    /// `Ok(())` if the child already exited, was reaped by a prior `wait`, or was reaped by someone
    /// else.
    /// Signal-only: does not reap — `wait().await` (or `Drop`) collects the exit status.
    pub fn kill(&mut self) -> Result<(), Error> {
        self.kill_sent().map(|_| ())
    }

    /// [`kill`](Child::kill), saying whether a signal was delivered ([`Sent::Delivered`]) or the
    /// child was already gone ([`Sent::Gone`]: nothing was sent, and the caller must not wait for
    /// a termination that did not happen).
    pub(crate) fn kill_sent(&mut self) -> Result<Sent, Error> {
        #[cfg(test)]
        if fault::take_force_kill_failure() {
            return Err(fault::forced_kill_failure());
        }
        // A plain child is unaffected (the mapping only fires on an elevated wrapper child whose
        // kill returns EPERM/ACCESS_DENIED). A child that is already gone is `Ok`, sent or not.
        match self.proc_mut().signal(Sig::Kill) {
            Err(Error::Io(e)) => Err(crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper())),
            Err(other) => Err(other),
            Ok(Sent::Gone) => {
                // Gone on evidence of a foreign reap: tokio's wait and drop reap by pid, so forget.
                #[cfg(unix)]
                self.proc_mut().forget_if_foreign();
                Ok(Sent::Gone)
            }
            Ok(delivered) => Ok(delivered),
        }
    }

    /// Hard-kill the contained tree. Requires an actionable containment mechanism
    /// (errors `Unsupported` otherwise — use [`kill`](Child::kill) for a lone process).
    /// If both the group teardown and the handle backstop fail, the group error is returned.
    ///
    /// On the `TreeWalk` mechanism, an [`Error::Unassessable`] (or `Unsupported`) means the
    /// process table could not be read or trusted, so the descendants could not be found: NOTHING
    /// was killed, the root included, and a retry can work. (`Drop` cannot retry, so it still
    /// kills the root and logs that descendants may be orphaned.)
    ///
    /// On the Unix process-group and session mechanisms this returns
    /// [`Error::Containment`](crate::error::Error::Containment) when a live member of the
    /// group refused the signal — a setuid binary in the tree is the ordinary cause. The
    /// tree is still running and this process cannot bring it down.
    ///
    /// **This guarantee, and its converse — that `Ok` is positive proof the group cleared —
    /// hold only for the `ProcessGroup`/`Session` mechanisms**, not `TreeWalk`: a separate,
    /// unfixed gap means `TreeWalk` does not yet propagate a live refuser's outcome into this
    /// call's result.
    ///
    /// **A `hidepid`-restricted Linux host can still return `Ok` with a live refuser left
    /// running.** `/proc` is this mechanism's only way to confirm the group cleared, and
    /// `hidepid=invisible`/`hidepid=2` hides a foreign-uid process from it entirely — the
    /// ordinary setuid-in-a-container case. That member is then never listed, never
    /// classified, never signaled, and the group can report cleared regardless. No fix
    /// exists within this mechanism: the pid is never learned, and `killpg`'s own return
    /// value is not trustworthy evidence either.
    ///
    /// **Kernel requirement.** As for the sync [`Child::kill_tree`](crate::Child::kill_tree): the
    /// `cgroup.kill` fork-race fix, see [`Command::kill_on_drop`](crate::Command::kill_on_drop).
    pub fn kill_tree(&mut self) -> Result<(), Error> {
        self.require_contained()?;
        // Precondition (a separate, unfixed gap — asserted, not fixed, here): see the sync
        // twin, `Child::kill_tree` in `src/child.rs`, for the full rationale (including which
        // mechanisms `carries_recyclable_pgid` covers, and why this is `#[cfg(unix)]`).
        #[cfg(unix)]
        debug_assert!(
            !self.os.attached.carries_recyclable_pgid() || {
                let now = ProcessId::of(self.id.pid());
                let now_liveness = match now {
                    crate::identity::Resolved::Found(id) => id.is_alive(),
                    crate::identity::Resolved::Gone | crate::identity::Resolved::Unknown => {
                        crate::identity::Liveness::Unknown
                    }
                };
                !crate::child::root_pid_was_recycled(self.id, now, now_liveness)
            },
            "kill_tree/terminate_tree called after the contained root's pid ({}) was reaped and \
             recycled onto a different, live process; a pgid-based mechanism would now signal an \
             unrelated process group",
            self.id.pid()
        );
        let group_result = self.os.attached.hard_kill_marking(&self.tree_killed);
        // A TreeWalk that could not walk killed nothing, and the root's death would strand the
        // descendants beyond a retry: return the error with the tree intact.
        if self.os.attached.hard_kill_refused_to_walk(&group_result) {
            return group_result;
        }
        // Backstop for the TreeWalk mechanism: its hard_kill kills the root by identity, which
        // no-ops if `ProcessId::of` transiently fails to resolve — this handle-based kill
        // covers that, so its failure is contract-relevant.
        let backstop = self.kill();
        // Both-fail: the group error is surfaced; subsuming the backstop's is deliberate.
        if let (Err(group), Err(bs)) = (&group_result, &backstop) {
            log::debug!("kill_tree handle backstop also failed ({bs}); surfacing the group error: {group}");
        }
        group_result.and(backstop)
    }

    /// Send the graceful termination signal to the contained group — `SIGTERM` via
    /// `killpg`/cgroup, or `CTRL_BREAK` to the job/console group. **Signal-only:** does
    /// not wait or reap. Requires an actionable containment mechanism (errors
    /// `Unsupported` otherwise). Cooperative best-effort: on the `TreeWalk` mechanism a
    /// descendant whose identity transiently fails to resolve is intentionally left
    /// unsignaled; [`kill_tree`](Child::kill_tree) is the guaranteed hard teardown.
    ///
    /// **Windows: what this actually signals.** `CTRL_BREAK` is delivered to the root's
    /// **process group**, not to the tree. A nested contained descendant leads its own
    /// group and never receives it, so from THIS handle only
    /// [`kill_tree`](Child::kill_tree) reaches every member. The layers this skips are not
    /// beyond a polite shutdown, though: the holder of a nested descendant's own `Child` can
    /// drain it with [`terminate`](Child::terminate) or
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
    /// **And it needs the caller to have a console.** The event is deliverable only within
    /// the *calling* process's console, so a GUI-subsystem binary, a service, or anything
    /// spawned detached cannot deliver it. The failure is classified best-effort: usually
    /// [`Error::NoConsole`](crate::error::Error::NoConsole), but a raw `Error::Io` when the
    /// crate cannot confirm the cause. Treat **any** error here as "no signal was sent, the
    /// tree is still running" rather than keying a fallback on the variant alone. Attach a
    /// console before spawning the tree, or use `kill_tree`, which needs none.
    ///
    /// On the Unix process-group and session mechanisms this returns
    /// [`Error::Containment`](crate::error::Error::Containment) when a live member of the
    /// group refused the signal — a setuid binary in the tree is the ordinary cause. The
    /// tree is still running and this process cannot bring it down.
    ///
    /// See [`kill_tree`](Child::kill_tree)'s doc for two things that also apply here: the
    /// `ProcessGroup`/`Session`-only scope of this guarantee (a separate, unfixed gap for
    /// `TreeWalk`), and the residual `hidepid` gap on Linux.
    ///
    /// **Windows, after the root's exit has been observed.** The event is addressed by the
    /// ROOT's pid — on the job-object mechanism and the tree walk alike — and this handle stops
    /// pinning that pid the moment `wait`/`try_wait` reports the exit, so the OS may reissue it
    /// to an unrelated group leader. A root exiting while its descendants are still alive is an
    /// ordinary flow, so this is refused from that point
    /// ([`Error::Unassessable`](crate::error::Error::Unassessable)) rather than fired at a bare
    /// pid; [`kill_tree`](Child::kill_tree) addresses no pid and still reaches the survivors.
    /// The sync [`Child`](crate::Child) pins for its whole life and is unaffected.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
        // After the mechanism guard, which is permanent and pid-independent: an uncontained
        // child must keep hearing why it has no tree to signal, not why a pid is unpinned.
        #[cfg(windows)]
        if !self.proc().pins_pid() {
            return Err(self.unpinned_pid_refusal("terminate_tree"));
        }
        // See kill_tree's identical precondition assert for the full rationale, including the
        // `#[cfg(unix)]` gate (`carries_recyclable_pgid` does not exist on Windows).
        #[cfg(unix)]
        debug_assert!(
            !self.os.attached.carries_recyclable_pgid() || {
                let now = ProcessId::of(self.id.pid());
                let now_liveness = match now {
                    crate::identity::Resolved::Found(id) => id.is_alive(),
                    crate::identity::Resolved::Gone | crate::identity::Resolved::Unknown => {
                        crate::identity::Liveness::Unknown
                    }
                };
                !crate::child::root_pid_was_recycled(self.id, now, now_liveness)
            },
            "kill_tree/terminate_tree called after the contained root's pid ({}) was reaped and \
             recycled onto a different, live process; a pgid-based mechanism would now signal an \
             unrelated process group",
            self.id.pid()
        );
        self.os.attached.terminate(self.id.pid())
    }

    /// The refusal both cooperative ops answer with once this handle has stopped pinning the
    /// child's pid — the async backend releases the Windows process handle when `wait`/`try_wait`
    /// observes the exit. Shared so the lone and the tree op cannot drift on what is, for both,
    /// the same hazard: a console control event carries a bare pid and nothing else.
    #[cfg(windows)]
    fn unpinned_pid_refusal(&self, op: &str) -> Error {
        Error::Unassessable {
            detail: format!(
                "this handle no longer pins pid {pid}: the async backend released the child's \
                 process handle when its exit was observed, so the pid may since name an \
                 unrelated process. A console control event is addressed by pid alone, so {op}() \
                 sent nothing. The child itself is already gone; kill_tree() addresses no pid and \
                 still tears down any survivors.",
                pid = self.id.pid()
            ),
            source: None,
        }
    }

    /// Guard for the `_tree` operations (single-sourced with the sync `Child`).
    fn require_contained(&self) -> Result<(), Error> {
        crate::containment::require_contained(self.containment, &self.os.attached)
    }

    /// Guard for `wait_tree`/`wait_tree_timeout` (single-sourced with the sync `Child`).
    fn require_drainable(&self) -> Result<(), Error> {
        crate::containment::require_drainable(self.containment, &self.os.attached)
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
        self.require_drainable()?;
        super::wait::wait_tree_drained_dispatch(&self.os.attached, None).await
    }

    /// Like [`wait_tree`](Child::wait_tree) but bounded by `timeout`.
    /// `TreeDrain::MembersRemain` at expiry is not an error. A `timeout` so large it would
    /// overflow `Instant` is treated as unbounded, matching [`wait_tree`](Child::wait_tree).
    pub async fn wait_tree_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<crate::containment::TreeDrain, Error> {
        self.require_drainable()?;
        let deadline = super::wait::deadline_from(timeout);
        super::wait::wait_tree_drained_dispatch(&self.os.attached, deadline).await
    }
}

impl Child {
    /// Leave the child (and its contained tree) running after this handle drops. The drop then
    /// never signals the tree or the root, except that a leaf this handle already killed through
    /// [`kill_tree`](Self::kill_tree) has its `cgroup.kill` written once more by the release.
    ///
    /// Dropping never waits: a leaf this handle killed and that has not drained is left behind
    /// with a warning, and one nothing killed is left at `debug`, since the caller asked for that.
    /// Call [`wait_tree`](Self::wait_tree) before dropping to observe the drain.
    pub fn detach(&mut self) {
        self.kill_on_drop = false;
        self.os.attached.disarm();
    }
}

#[cfg(test)]
#[path = "child_drop_tests.rs"]
mod child_drop_tests;

/// Test seam counting what a drop does to the root by its number. Thread-local, with an RAII reset.
#[cfg(all(test, unix))]
pub(crate) mod drop_fault {
    use std::cell::Cell;

    thread_local! {
        static COUNTS: Cell<Option<(u32, u32)>> = const { Cell::new(None) };
    }

    /// From now on `Drop` on THIS thread counts the root kills it starts and the tokio `Child`s it
    /// forgets. It still does both.
    pub(crate) fn record() -> Recorder {
        COUNTS.with(|c| c.set(Some((0, 0))));
        Recorder(())
    }

    #[must_use = "recording stops as soon as the recorder is dropped"]
    pub(crate) struct Recorder(());

    impl Recorder {
        /// Root kills started.
        pub(crate) fn kills(&self) -> u32 {
            COUNTS.with(|c| c.get().expect("the recorder is live").0)
        }

        /// tokio `Child`s forgotten instead of dropped.
        pub(crate) fn forgets(&self) -> u32 {
            COUNTS.with(|c| c.get().expect("the recorder is live").1)
        }
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            COUNTS.with(|c| c.set(None));
        }
    }

    pub(super) fn note_root_kill() {
        COUNTS.with(|c| {
            if let Some((k, f)) = c.get() {
                c.set(Some((k + 1, f)));
            }
        });
    }

    pub(super) fn note_forget() {
        COUNTS.with(|c| {
            if let Some((k, f)) = c.get() {
                c.set(Some((k, f + 1)));
            }
        });
    }
}

#[cfg(all(test, unix))]
#[path = "child_drop_reaped_tests.rs"]
mod child_drop_reaped_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/pid_reuse_tests.rs"]
mod pid_reuse_tests;

#[cfg(all(test, windows))]
#[path = "child/windows_signal_tests.rs"]
mod windows_signal_tests;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "child/bypass_drop_tests.rs"]
mod bypass_drop_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "child/macos_kill_tests.rs"]
mod macos_kill_tests;

#[cfg(all(test, unix))]
#[path = "child_pipe_conversion_tests.rs"]
mod child_pipe_conversion_tests;

#[cfg(test)]
#[path = "child_reap_tests.rs"]
mod child_reap_tests;

#[cfg(test)]
#[path = "child_wait_tree_tests.rs"]
mod child_wait_tree_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child_kill_tree_view_tests.rs"]
mod child_kill_tree_view_tests;

#[cfg(all(test, windows))]
impl Child {
    /// Test-only: install the per-instance raw-wait observer on this child (see the raw backend's
    /// `WaitObserver`), forwarded to the backend.
    pub(crate) fn install_wait_observer(
        &mut self,
        started: ::tokio::sync::oneshot::Sender<()>,
        outcome: ::tokio::sync::oneshot::Sender<crate::child::spawn::windows_raw::WaitOutcome>,
    ) {
        self.proc_mut().install_wait_observer(started, outcome);
    }
}

/// Signals the tree and the root (unless opted out) and does NOT wait: the child is not
/// necessarily gone when `drop` returns, and neither is it necessarily reaped. A caller that must
/// observe the teardown calls [`kill`](Child::kill)/[`kill_tree`](Child::kill_tree) and then
/// awaits [`wait`](Child::wait)/[`wait_tree`](Child::wait_tree). This handle's `Drop` does
/// bounded work only: at most two `cgroup.kill` writes and two `rmdir`s of the leaf (the release
/// re-fires the kill and retries once, when the first `rmdir` finds the leaf populated), and one
/// sweep of the leaf's empty child cgroups. It starts no thread and keeps no state.
///
/// With `kill_on_drop` set (the default), it hard-kills the contained tree, then kills the root.
/// With it clear ([`detach`](Child::detach), or `kill_on_drop(false)`), it signals nothing of its
/// own. One exception: a leaf this handle already killed through
/// [`kill_tree`](Child::kill_tree) is released like an armed one.
///
/// Then it releases what the handle owns:
///
/// - **The root.** tokio's own `Child` is dropped normally. It tries one reap, and a root that has
///   not exited yet goes to tokio's orphan queue, which reaps it once a runtime next sees
///   `SIGCHLD`. That queue is tokio's, not cosca's, and it is best-effort: it drains only while
///   some runtime runs. On Windows the process handle is closed.
/// - **The containment resource.** A `Cgroup` leaf is removed if it has drained. A leaf that has
///   not drained is **left behind**, and a warning names it, if this handle killed it or was
///   armed to. Nothing waits for the drain: `cgroup.kill` is asynchronous, and a member stuck in
///   uninterruptible I/O outlives it. Call [`wait_tree`](Child::wait_tree) first to have the leaf
///   removed. A Job Object is terminated by the drop's tree kill and its handle closed there
///   (`TerminateJobObject`, then `CloseHandle`); one opted out of teardown is closed with
///   `KILL_ON_JOB_CLOSE` cleared, and nothing kills it. Other mechanisms drop in place.
///
/// Once the root is reaped the drop skips kills named by its number and warns; see
/// [`Command::kill_on_drop`](crate::tokio::Command::kill_on_drop). A root reaped outside this
/// handle also makes the drop forget tokio's `Child`, armed or not, so tokio cannot reap by that
/// number. The evidence is the number no longer reading as this root, or the child's own handle (on
/// Linux its pidfd, on macOS the pid's unique id) showing it reaped. The handle is asked before the
/// signals, so a number-named tree kill is skipped, and again after them, for a reap that lands in
/// between. On macOS a child with no unique id, or whose peek fails, cannot be shown to be ours and
/// is forgotten too.
///
/// # Known limitation: `fork()` without `exec`
///
/// **A process that forks and then keeps running Rust code in the child inherits tokio's orphan
/// queue without the runtime that would drain it.** A dropped, still-running root that lands on
/// the queue in such a child is never reaped there ([tokio#4301]). cosca keeps no pool of its
/// own for a fork to break, so nothing else is lost. It does **not** affect ordinary subprocess
/// spawning: `fork`+`exec` and `posix_spawn` replace the child image at once. Nor Windows, which
/// has no `fork`.
///
/// A forking consumer should `kill` and `await` [`wait`](Child::wait) explicitly in the forked
/// child rather than rely on `Drop`. The sync [`Child`](crate::Child) is unaffected: it reaps on
/// the dropping thread.
///
/// [tokio#4301]: https://github.com/tokio-rs/tokio/issues/4301
impl Drop for Child {
    fn drop(&mut self) {
        // Enforced in debug builds: nothing below may wait for an exit or a drain. Declared before
        // `os`, so a panic in the signals unwinds through the resources while still inside it.
        let _bounded = crate::bounded::Section::enter();
        let mut os = std::mem::take(&mut self.os);
        // Read before the `kill_on_drop` branch: a disarmed drop signals nothing, but releasing
        // tokio's `Child` still `try_wait`s the root's number, so it needs the same evidence.
        #[cfg(unix)]
        let own_reap = os.proc.as_ref().is_none_or(|proc| proc.is_reaped());
        #[cfg(unix)]
        let view = {
            let mut view = crate::containment::DropView::read(self.id, own_reap, &self.tree_killed);
            view.root_reaped |= os.root_reaped_elsewhere(own_reap);
            view
        };
        if self.kill_on_drop {
            #[cfg(unix)]
            signal_on_drop(self.id, view, &mut os);
            #[cfg(not(unix))]
            signal_on_drop(self.id, &self.tree_killed, &mut os);
        }
        // A reap outside this handle (tokio's state cannot see it) leaves the number possibly
        // naming another child, so tokio's `Child` must not run its own drop, which reaps by pid.
        #[cfg(unix)]
        // Asked again: a reap can land after the read above (and before or during the root kill).
        if !own_reap && (view.root_reaped || os.root_reaped_elsewhere(own_reap)) {
            if let Some(proc) = os.proc.as_mut() {
                // Forgotten before anything logs: a panicking logger would unwind with tokio's
                // `Child` held, and its drop would reap by pid.
                proc.forget_foreign();
                log::debug!(
                    "async child {} was reaped outside its handle; dropping it would reap by that number, so it was forgotten",
                    self.id.pid()
                );
            }
        }
        os.release_without_waiting();
    }
}

/// The signals of a kill-on-drop drop: the tree, then the root.
fn signal_on_drop(
    id: ProcessId,
    #[cfg(unix)] view: crate::containment::DropView,
    #[cfg(not(unix))] tree_killed: &crate::containment::TreeKilled,
    os: &mut OsResources,
) {
    let pid = id.pid();
    // Tree teardown — the SOLE coverage for descendants (the root's own kill below reaches only
    // the root); a no-op for an uncontained child.
    //
    // MUST come before the handle is dismembered: on Windows a job object's kill is the only
    // signal reaching a nested descendant that leads its own console group (console control
    // events stop at that boundary). On Unix this and `terminate_tree` have the same radius. The
    // contract either way: the tree is signalled before `drop` returns.
    //
    // On Unix, nothing that names the tree by the root's number runs once the root is reaped:
    // this handle's own state, or the number no longer reading as this root (tokio's state cannot
    // see a foreign reap until it is polled). Accepted gaps: a foreign reap landing after `view`
    // was read, and tokio's orphan queue reaping by number afterwards.
    #[cfg(unix)]
    let tree = os.attached.hard_kill_for_drop(view);
    #[cfg(not(unix))]
    let tree = {
        _ = tree_killed;
        os.attached.hard_kill()
    };
    if let Err(e) = &tree {
        // A real OS outcome (e.g. `EACCES`/`EIO` on `cgroup.kill`): logged, never asserted on.
        log::warn!("Child::drop: contained-tree teardown did not fully succeed: {e}");
        if os.attached.hard_kill_refused_to_walk(&tree) {
            // Unlike `kill_tree`, a drop cannot be retried: the root dies below either way.
            log::warn!("Child::drop: the root is killed regardless, so its descendants may be orphaned");
        }
    }
    // Already reaped: no signal to issue.
    #[cfg(unix)]
    if view.root_reaped {
        return;
    }
    #[cfg(not(unix))]
    if os.proc.as_ref().is_none_or(|proc| proc.is_reaped()) {
        return;
    }
    let Some(proc) = os.proc.as_mut() else {
        return;
    };
    #[cfg(all(test, unix))]
    drop_fault::note_root_kill();
    // No `debug_assert` here: a failed kill is a designed outcome the branch below serves (a
    // higher-integrity elevated child), and asserting would panic inside a destructor.
    //
    // The test seam REPLACES the kill rather than masking its result — a masked kill would still
    // have signalled the child, and the branch below is about one that was not.
    #[cfg(test)]
    let killed = if fault::take_force_kill_failure() {
        Err(fault::forced_kill_failure())
    } else {
        proc.signal(Sig::Kill)
    };
    #[cfg(not(test))]
    let killed = proc.signal(Sig::Kill);
    // Nothing was delivered because the child is gone (reaped by someone else, and its pid
    // possibly reused): the pid names nothing of ours to wait for.
    // Nothing is logged here: the drop forgets the child next, and logs that.
    if matches!(killed, Ok(Sent::Gone)) {
        return;
    }
    if killed.is_err() {
        // The `try_wait` below reaps by pid: forget a foreign reap first.
        #[cfg(unix)]
        proc.forget_if_foreign();
        if !proc.is_reaped() && !matches!(proc.try_wait(), Ok(Some(_))) {
            log::warn!("async child {pid} could not be terminated on drop; leaving it running");
        }
    }
}

/// Re-encodes a `waitid` result as a raw `wait` status.
#[cfg(all(test, unix))]
fn exit_status_of(info: &libc::siginfo_t) -> std::process::ExitStatus {
    // SAFETY: `info` was filled in by a successful `waitid`, which sets `si_status`.
    exit_status_from_parts(info.si_code, unsafe { info.si_status() })
}

/// [`exit_status_of`] on the `si_code` and `si_status` of a `SIGCHLD` `siginfo_t`.
#[cfg(all(test, unix))]
fn exit_status_from_parts(si_code: libc::c_int, si_status: libc::c_int) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;
    let raw = match si_code {
        libc::CLD_EXITED => si_status << 8,
        libc::CLD_DUMPED => si_status | 0x80,
        _ => si_status, // CLD_KILLED: the signal number
    };
    std::process::ExitStatus::from_raw(raw)
}

/// Test seams for the drop path. Thread-local and take-once: each read consumes the flag, and the
/// guard clears whatever is left.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    use crate::error::Error;

    /// What a backend holds so that its drop is counted ([`count_backend_drops`]).
    #[derive(Debug)]
    pub(crate) struct BackendDrop(());

    impl BackendDrop {
        pub(crate) fn new() -> BackendDrop {
            BackendDrop(())
        }
    }

    impl Drop for BackendDrop {
        fn drop(&mut self) {
            note_backend_drop();
        }
    }

    thread_local! {
        static FORCE_KILL_FAILURE: Cell<bool> = const { Cell::new(false) };
        static RELEASES: Cell<usize> = const { Cell::new(0) };
        static BACKEND_DROPS: Cell<usize> = const { Cell::new(0) };
    }

    /// Counts the process backends ([`ProcSource`](super::ProcSource), so tokio's own `Child`
    /// with it) dropped on THIS thread from now on. Starts at zero; zeroed again when dropped.
    /// A backend that was forgotten, or moved to another thread, is not counted.
    pub(crate) fn count_backend_drops() -> BackendDropCount {
        BACKEND_DROPS.with(|d| d.set(0));
        BackendDropCount(())
    }

    #[must_use = "the count is zeroed as soon as the guard is dropped"]
    pub(crate) struct BackendDropCount(());

    impl BackendDropCount {
        pub(crate) fn get(&self) -> usize {
            BACKEND_DROPS.with(Cell::get)
        }
    }

    impl Drop for BackendDropCount {
        fn drop(&mut self) {
            BACKEND_DROPS.with(|d| d.set(0));
        }
    }

    fn note_backend_drop() {
        BACKEND_DROPS.with(|d| d.set(d.get() + 1));
    }

    /// Counts the releases ([`OsResources::release_without_waiting`](super::OsResources)) that
    /// run on THIS thread from now on. Starts at zero; zeroed again when dropped, so a count
    /// cannot reach the next test on this thread.
    pub(crate) fn count_releases() -> ReleaseCount {
        RELEASES.with(|r| r.set(0));
        ReleaseCount(())
    }

    #[must_use = "the count is zeroed as soon as the guard is dropped"]
    pub(crate) struct ReleaseCount(());

    impl ReleaseCount {
        pub(crate) fn get(&self) -> usize {
            RELEASES.with(Cell::get)
        }
    }

    impl Drop for ReleaseCount {
        fn drop(&mut self) {
            RELEASES.with(|r| r.set(0));
        }
    }

    pub(super) fn note_release() {
        RELEASES.with(|r| r.set(r.get() + 1));
    }

    /// Makes the NEXT root kill on THIS thread report failure, from [`Child::kill`] (and so
    /// `kill_tree`'s backstop) or from `Drop`. It REPLACES the kill rather than masking its
    /// result, so the child really is left unsignalled. Take-once: a test that forces two kills
    /// arms it twice.
    ///
    /// [`Child::kill`]: super::Child::kill
    pub(crate) fn force_kill_failure() -> KillFailureGuard {
        FORCE_KILL_FAILURE.with(|f| f.set(true));
        KillFailureGuard(())
    }

    /// Clears the seam when dropped, so an unread arming cannot reach the next test on this thread.
    #[must_use = "the seam is cleared as soon as the guard is dropped"]
    pub(crate) struct KillFailureGuard(());

    impl Drop for KillFailureGuard {
        fn drop(&mut self) {
            FORCE_KILL_FAILURE.with(|f| f.set(false));
        }
    }

    pub(super) fn take_force_kill_failure() -> bool {
        FORCE_KILL_FAILURE.with(|f| f.replace(false))
    }

    pub(super) fn forced_kill_failure() -> Error {
        Error::Io(std::io::Error::other("forced kill failure (test seam)"))
    }
}
