//! Async `Child` handle, wrapping `::tokio::process::Child` plus the stable `ProcessId` and the
//! contained-tree `Attached`.

#[path = "child/graceful.rs"]
mod graceful;

#[path = "child/proc_source.rs"]
mod proc_source;
pub(crate) use proc_source::ProcSource;

use std::collections::BTreeMap;
use std::process::ExitStatus;

#[cfg(unix)]
use crate::child::ParentEnd;
use crate::containment::{Attached, Containment};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::stdio::Fd;

/// Parent ends of fd >= 3 pipes, keyed by descriptor. Unix stashes the raw sync `ParentEnd`
/// (converted to a reactor pipe at take time); Windows stashes the already-registered overlapped
/// async end (the raw backend's fd >= 3 pipes), taken directly (no `from_raw_handle`, which would
/// double-register the IOCP handle).
#[cfg(unix)]
pub(super) type FdPipes = BTreeMap<Fd, ParentEnd>;
#[cfg(windows)]
pub(super) type FdPipes = BTreeMap<Fd, super::stdio::OwnedStd>;

#[derive(Debug)]
pub struct Child {
    // `pub(super)`: the sibling `pump` module borrows the backend for `communicate`'s `wait` future.
    pub(super) proc: ProcSource,
    id: ProcessId,
    attached: Attached,
    kill_on_drop: bool,
    containment: Containment,
    graceful: crate::graceful::GracefulMechanism,
    /// Parent ends of fd >= 3 pipes, read by [`fd_read_end`](Child::fd_read_end) /
    /// [`fd_write_end`](Child::fd_write_end). Unix: `command-fds`-wired reactor pipes; Windows: the
    /// raw backend's overlapped async ends (empty on the std path, which routes fd >= 3 to the raw
    /// backend).
    pipes: FdPipes,
    /// Our-owned parent ends of piped std-slot MERGE TARGETS (the spawn pre-pass owns those
    /// pipes; tokio's internal ones cannot be shared), keyed by the target slot.
    owned_std: BTreeMap<Fd, super::stdio::OwnedStd>,
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
            proc,
            id,
            attached: attachment.attached,
            kill_on_drop,
            containment: attachment.containment,
            graceful: attachment.graceful,
            pipes,
            owned_std,
            elevation: None,
        }
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
    /// Blocking kill-then-reap used by the POSIX spawn-error cleanup path (a sync context — no
    /// reactor `await` available), delegating to the same per-backend primitive `Drop` uses.
    /// Unix-only: the Windows elevation arm builds its child in-module with no deferred password.
    #[cfg(unix)]
    pub(super) fn reap_blocking(&mut self) {
        self.proc.reap_now_on_drop(self.id.pid());
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
        self.proc.take_stdin().map(|s| super::stdio::ChildStdin {
            inner: super::stdio::InInner::Tokio(s),
        })
    }
    pub fn stdout(&mut self) -> Option<super::stdio::ChildStdout> {
        if let Some(owned) = self.take_owned_out(crate::stdio::Fd::STDOUT) {
            return Some(super::stdio::ChildStdout { inner: owned });
        }
        self.proc.take_stdout().map(|s| super::stdio::ChildStdout {
            inner: super::stdio::OutInner::Stdout(s),
        })
    }
    pub fn stderr(&mut self) -> Option<super::stdio::ChildStderr> {
        if let Some(owned) = self.take_owned_out(crate::stdio::Fd::STDERR) {
            return Some(super::stdio::ChildStderr { inner: owned });
        }
        self.proc.take_stderr().map(|s| super::stdio::ChildStderr {
            inner: super::stdio::OutInner::Stderr(s),
        })
    }

    /// Take the stashed our-owned read end of an Out-direction merge target (plain
    /// `BTreeMap::remove` — TAKE semantics: the first call moves the end out, later calls
    /// return `None`, matching the tokio-owned branch's `Option::take`). Unix converts the
    /// raw end to a reactor pipe here; on a conversion failure (a contract violation:
    /// debug_assert + `log::warn!`) the end drops, so the child observes EPIPE on writes —
    /// visible, never a hang.
    #[cfg(unix)]
    fn take_owned_out(&mut self, fd: Fd) -> Option<super::stdio::OutInner> {
        use std::os::fd::OwnedFd;
        match self.owned_std.remove(&fd)? {
            ParentEnd::Reader(r) => match ::tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(r)) {
                Ok(recv) => Some(super::stdio::OutInner::Owned(recv)),
                Err(e) => {
                    debug_assert!(false, "own pipe end failed tokio conversion: {e}");
                    log::warn!(
                        "{fd} merge-target read end dropped: tokio conversion failed ({e}); the child will see EPIPE on writes"
                    );
                    None
                }
            },
            end => {
                self.owned_std.insert(fd, end); // wrong direction — put it back (fd_read_end mirror)
                None
            }
        }
    }

    /// The Windows twin yields the stashed `WinOwnedRead` DIRECTLY — the `NamedPipeServer`
    /// and its connect task were created at spawn, inside the runtime, so no conversion
    /// (and no `from_raw_handle`, which would double-register the IOCP handle) exists here.
    #[cfg(windows)]
    fn take_owned_out(&mut self, fd: Fd) -> Option<super::stdio::OutInner> {
        match self.owned_std.remove(&fd)? {
            super::stdio::OwnedStd::Read(r) => Some(super::stdio::OutInner::Owned(r)),
            end => {
                self.owned_std.insert(fd, end); // wrong direction — put it back (fd_read_end mirror)
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
        match self.owned_std.remove(&fd)? {
            ParentEnd::Writer(w) => match ::tokio::net::unix::pipe::Sender::from_owned_fd(OwnedFd::from(w)) {
                Ok(send) => Some(super::stdio::InInner::Owned(send)),
                Err(e) => {
                    debug_assert!(false, "own pipe end failed tokio conversion: {e}");
                    log::warn!(
                        "{fd} merge-target write end dropped: tokio conversion failed ({e}); the child will see EOF on reads"
                    );
                    None
                }
            },
            end => {
                self.owned_std.insert(fd, end); // wrong direction — put it back (fd_write_end mirror)
                None
            }
        }
    }

    /// The Windows twin of [`take_owned_in`](Child::take_owned_in) — direct, no conversion
    /// (see [`take_owned_out`](Child::take_owned_out)).
    #[cfg(windows)]
    fn take_owned_in(&mut self, fd: Fd) -> Option<super::stdio::InInner> {
        match self.owned_std.remove(&fd)? {
            super::stdio::OwnedStd::Write(w) => Some(super::stdio::InInner::Owned(w)),
            end => {
                self.owned_std.insert(fd, end); // wrong direction — put it back (fd_write_end mirror)
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
    /// if it was already taken, or if reactor registration failed (a contract violation:
    /// debug_assert + `log::warn!`; the dropped end closes the fd, so the child observes
    /// EPIPE on its write end — a visible failure, never a hang).
    #[cfg(unix)]
    pub fn fd_read_end(&mut self, fd: impl Into<crate::stdio::Fd>) -> Option<::tokio::net::unix::pipe::Receiver> {
        use std::os::fd::OwnedFd;
        let fd = fd.into();
        match self.pipes.remove(&fd)? {
            crate::child::ParentEnd::Reader(r) => {
                match ::tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(r)) {
                    Ok(recv) => Some(recv),
                    // Reactor registration failure — a contract violation for an
                    // our-own-pipe end (see docstring).
                    Err(e) => {
                        debug_assert!(false, "own pipe end failed tokio conversion: {e}");
                        log::warn!("fd {fd} read end dropped: tokio conversion failed ({e}); the child will see EPIPE on writes");
                        None
                    }
                }
            }
            end => {
                self.pipes.insert(fd, end); // wrong direction — put it back (sync mirror)
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
    /// if it was already taken, or if reactor registration failed (a contract violation:
    /// debug_assert + `log::warn!`; the dropped end closes the fd, so the child observes
    /// EOF on its read end — a visible failure, never a hang).
    #[cfg(unix)]
    pub fn fd_write_end(&mut self, fd: impl Into<crate::stdio::Fd>) -> Option<::tokio::net::unix::pipe::Sender> {
        use std::os::fd::OwnedFd;
        let fd = fd.into();
        match self.pipes.remove(&fd)? {
            crate::child::ParentEnd::Writer(w) => {
                match ::tokio::net::unix::pipe::Sender::from_owned_fd(OwnedFd::from(w)) {
                    Ok(send) => Some(send),
                    Err(e) => {
                        debug_assert!(false, "own pipe end failed tokio conversion: {e}");
                        log::warn!(
                            "fd {fd} write end dropped: tokio conversion failed ({e}); the child will see EOF on reads"
                        );
                        None
                    }
                }
            }
            end => {
                self.pipes.insert(fd, end);
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
        match self.pipes.remove(&fd)? {
            super::stdio::OwnedStd::Read(r) => Some(super::stdio::ChildStdout {
                inner: super::stdio::OutInner::Owned(r),
            }),
            end => {
                self.pipes.insert(fd, end); // wrong direction — put it back (Unix mirror)
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
        match self.pipes.remove(&fd)? {
            super::stdio::OwnedStd::Write(w) => Some(super::stdio::ChildStdin {
                inner: super::stdio::InInner::Owned(w),
            }),
            end => {
                self.pipes.insert(fd, end); // wrong direction — put it back (Unix mirror)
                None
            }
        }
    }

    /// Test-only: whether this child is inside the crate's Job Object (`IsProcessInJob`
    /// against the held handle, not "any job"). `pub` so integration tests can call it.
    #[cfg(windows)]
    pub fn test_job_handle_contains_self(&self) -> bool {
        crate::containment::windows::job_contains_pid(&self.attached, self.id.pid())
    }

    /// Block until the child exits, returning its status. For a bounded wait use
    /// `tokio::time::timeout(d, child.wait())`.
    pub async fn wait(&mut self) -> Result<ExitStatus, Error> {
        self.proc.wait().await
    }
    /// Exit status if the child has already exited (non-blocking).
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        self.proc.try_wait()
    }

    /// Hard-kill the (lone) child. Handle-bound, so it cannot race a recycled pid.
    /// `Ok(())` if the child already exited or was reaped by a prior `wait` (tokio's
    /// `start_kill` maps the reaped state to `Ok`). Signal-only: does not reap —
    /// `wait().await` (or `Drop`) collects the exit status.
    pub fn kill(&mut self) -> Result<(), Error> {
        // A plain child is unaffected (the mapping only fires on an elevated wrapper child whose
        // kill returns EPERM/ACCESS_DENIED); everything else stays `Io`/`Ok` exactly as before.
        match self.proc.start_kill() {
            Err(Error::Io(e)) => Err(crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper())),
            other => other,
        }
    }

    /// Hard-kill the contained tree. Requires an actionable containment mechanism
    /// (errors `Unsupported` otherwise — use [`kill`](Child::kill) for a lone process).
    /// If both the group teardown and the handle backstop fail, the group error is returned.
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
    pub fn kill_tree(&mut self) -> Result<(), Error> {
        self.require_contained()?;
        // Precondition (a separate, unfixed gap — asserted, not fixed, here): see the sync
        // twin, `Child::kill_tree` in `src/child.rs`, for the full rationale (including which
        // mechanisms `carries_recyclable_pgid` covers, and why this is `#[cfg(unix)]`).
        #[cfg(unix)]
        debug_assert!(
            !self.attached.carries_recyclable_pgid() || {
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
        let group_result = self.attached.hard_kill();
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
    /// console with the caller is reported as success and reaches nobody.
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
        if !self.proc.pins_pid() {
            return Err(self.unpinned_pid_refusal("terminate_tree"));
        }
        // See kill_tree's identical precondition assert for the full rationale, including the
        // `#[cfg(unix)]` gate (`carries_recyclable_pgid` does not exist on Windows).
        #[cfg(unix)]
        debug_assert!(
            !self.attached.carries_recyclable_pgid() || {
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
        self.attached.terminate(self.id.pid())
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
        crate::containment::require_contained(self.containment, &self.attached)
    }

    /// Guard for `wait_tree`/`wait_tree_timeout` (single-sourced with the sync `Child`).
    fn require_drainable(&self) -> Result<(), Error> {
        crate::containment::require_drainable(self.containment, &self.attached)
    }

    /// Block until every member of the contained tree has EXITED — not reaped; a status is
    /// never collected by this call, only the root's own `wait`/`try_wait` does that. Requires
    /// a mechanism with a real kernel drain edge (`Unsupported` otherwise — cgroup v2, a
    /// Windows job object, and the macOS fd marker have one; `ProcessGroup`/`Session`/
    /// `TreeWalk` and an uncontained or nested-`Delegated` child do not). Reactor-native on
    /// Linux and macOS (no polling interval); Windows hands the wait to `spawn_blocking` (job
    /// objects have no pollable handle) with a cancel event so a dropped future releases the
    /// blocking watcher promptly instead of parking out the wait.
    pub async fn wait_tree(&self) -> Result<crate::containment::TreeDrain, Error> {
        self.require_drainable()?;
        super::wait::wait_tree_drained_dispatch(&self.attached, None).await
    }

    /// Like [`wait_tree`](Child::wait_tree) but bounded by `timeout`.
    /// `TreeDrain::MembersRemain` at expiry is not an error. A `timeout` so large it would
    /// overflow `Instant` is treated as unbounded, matching [`wait_tree`](Child::wait_tree).
    pub async fn wait_tree_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<crate::containment::TreeDrain, Error> {
        self.require_drainable()?;
        let deadline = crate::wait::deadline_from(timeout);
        super::wait::wait_tree_drained_dispatch(&self.attached, deadline).await
    }
}

impl Child {
    /// Leave the child (and its contained tree) running after this handle drops.
    pub fn detach(&mut self) {
        self.kill_on_drop = false;
        self.attached.disarm();
    }
}

#[cfg(test)]
#[path = "child_drop_tests.rs"]
mod child_drop_tests;

#[cfg(test)]
#[path = "child_wait_tree_tests.rs"]
mod child_wait_tree_tests;

#[cfg(all(test, windows))]
impl Child {
    /// Test-only: install the per-instance raw-wait observer on this child (see the raw backend's
    /// `WaitObserver`), forwarded to the backend.
    pub(crate) fn install_wait_observer(
        &mut self,
        started: ::tokio::sync::oneshot::Sender<()>,
        outcome: ::tokio::sync::oneshot::Sender<crate::child::spawn::windows_raw::WaitOutcome>,
    ) {
        self.proc.install_wait_observer(started, outcome);
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return;
        }
        // Tree teardown — the SOLE coverage for descendants (reap_now only guarantees the root),
        // so surface a real mechanism failure in debug. A no-op for an uncontained child.
        let tree = self.attached.hard_kill();
        if let Err(e) = &tree {
            debug_assert!(
                !crate::child::is_teardown_mechanism_failure(e),
                "contained-tree teardown failed on async Drop: {e:?}"
            );
            log::warn!("Child::drop: contained-tree teardown did not fully succeed: {e}");
        }
        let _ = tree;
        // Guaranteed reap of the root on the real exit event (no park dependence). Briefly blocks
        // the dropping thread; the child is SIGKILL'd so it exits at once. Dispatches per backend
        // (tokio field-drop reap vs the raw handle's kill-then-wait).
        let pid = self.id.pid();
        self.proc.reap_now_on_drop(pid);
    }
}

/// Guaranteed synchronous teardown, shared by `Drop` and the spawn error path: kill the child,
/// then block until it has exited. On Unix we wait with `WNOWAIT` (NOT reaping), so tokio's own
/// `Child` field-drop reaps the zombie synchronously in its drop (its `try_wait` returns
/// `Ok(Some)`, not a park-dependent orphan enqueue) — a guaranteed reap before `Drop` returns.
/// We only wait while tokio still owns the child (`id().is_some()`), which pins the pid; once
/// tokio is `Done` (a prior `wait()` reaped it), the pid may be recycled and we must not wait on
/// it. `done_ok` says whether an already-`Done` child is legal here: `true` for `Drop` (the user
/// may have `wait()`ed), `false` for the spawn-error path (the child was never awaited).
/// **Invariant:** no `wait()` future for this child is in flight when this runs.
pub(crate) fn reap_now(child: &mut ::tokio::process::Child, pid: u32, done_ok: bool) {
    // `start_kill` bounds the wait below — it MUST run in release (NOT inside `debug_assert!`,
    // whose argument is stripped in release). A no-op on an already-exited child.
    let killed = child.start_kill();
    debug_assert!(killed.is_ok(), "start_kill of an owned child should not fail");
    // A failed start_kill means this is not a live process to wait on (ESRCH = already exited;
    // EPERM is impossible for our own child) — skip, so a kill failure can never turn the bounded
    // exit-wait into an unbounded block. tokio's field-drop reaps any leftover zombie.
    if killed.is_err() {
        return;
    }
    // tokio `Done` ⇒ already reaped, pid possibly recycled ⇒ nothing to do (the recycled-pid wait
    // hazard the sync side avoids by holding a handle).
    if child.id().is_none() {
        debug_assert!(
            done_ok,
            "reap_now found an already-reaped child where one was impossible"
        );
        return;
    }
    #[cfg(unix)]
    {
        // `nix` doesn't expose `waitid` on macOS (0.31 configures it out), so call `libc::waitid`
        // directly (WEXITED | WNOWAIT: block until exit without reaping) — portable across every Unix
        // target and the identical syscall.
        debug_assert!(pid <= i32::MAX as u32, "pid {pid} exceeds i32::MAX");
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: a well-formed `waitid` call; `info` is a valid, owned, zeroed `siginfo_t` the
            // kernel fills in. WNOWAIT leaves the child reapable for tokio's in-drop reap.
            let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // id() was Some above (tokio un-reaped ⇒ pid pinned), so no ECHILD / other errno should
            // occur — a debug tripwire, with a safe release `break`.
            debug_assert!(false, "waitid in reap_now failed unexpectedly: {err}");
            break;
        }
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
        let _ = pid;
        let h = child.raw_handle().expect("tokio owns the handle while id() is Some");
        // SAFETY: tokio owns and (on its field-drop) closes the handle; we only wait on it.
        // INFINITE is bounded by `start_kill` above.
        let waited = unsafe { WaitForSingleObject(HANDLE(h), INFINITE) };
        debug_assert!(
            waited == WAIT_OBJECT_0,
            "reap_now did not observe the child's exit: {waited:?}"
        );
    }
}
