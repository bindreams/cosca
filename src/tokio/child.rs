//! Async `Child` handle, wrapping `::tokio::process::Child` plus the stable `ProcessId` and the
//! contained-tree `Attached`.

#[path = "child/graceful.rs"]
mod graceful;

#[path = "child/suspended.rs"]
mod suspended;
pub use suspended::SuspendedChild;

#[path = "child/proc_source.rs"]
mod proc_source;
#[cfg(target_os = "macos")]
pub(crate) use proc_source::Forgotten;
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
/// [`release_without_waiting`](OsResources::release_without_waiting) and, on Unix,
/// `release_backend_and_rekill` (the start of both drain releases) are the only places a teardown
/// gives them up. Adding a resource-owning field here without releasing it in both would silently
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

    /// Give up every resource, in declaration order, without waiting for anything.
    ///
    /// The backend goes first, through [`ProcSource::release`]. tokio's `Child` drops: it tries a
    /// reap once and queues a still-running child on tokio's orphan queue, tokio's state and not
    /// cosca's. A child that something else reaped, or that cannot be verified, was
    /// forgotten before this by [`ProcSource::forget_foreign`], and the backend holds none. The
    /// Windows raw backend closes its handle. The containment resource follows through
    /// [`Attached::release_without_waiting`], bounded on every mechanism.
    pub(crate) fn release_without_waiting(mut self) {
        #[cfg(test)]
        fault::note_release();
        if let Some(proc) = self.proc.take() {
            proc.release();
        }
        std::mem::take(&mut self.attached).release_without_waiting();
    }

    /// Give up every resource, in declaration order, waiting for the tree's drain: what an armed
    /// drop does once it has reaped the root or found it gone. The backend goes first, through
    /// [`ProcSource::release`]; it holds no unreaped child by now, so tokio's drop queues nothing.
    /// The containment resource then drops in place, as the sync `Drop` drops it: a cgroup leaf
    /// is killed again if it is still populated, drained, swept and removed. The drain shares the
    /// drop's one `late` warn. `tree_failed`: the drop's own tree kill failed.
    #[cfg(unix)]
    fn release_after_drain(self, late: &mut LateWarn, tree_failed: bool) {
        let Some(attached) = self.release_backend_and_rekill(tree_failed) else {
            return;
        };
        #[cfg(target_os = "linux")]
        if let (Attached::Cgroup(leaf), Some(until)) = (&attached, late.due()) {
            // Only the warn depends on this bounded look; the leaf's own drop waits for the drain.
            if matches!(
                leaf.wait_drained(Some(Some(until))),
                Ok(crate::containment::TreeDrain::MembersRemain)
            ) {
                late.warn(&format!(
                    "has a cgroup leaf {} that has not drained",
                    leaf.path().display()
                ));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = late;
        drop(attached);
    }

    /// [`release_after_drain`](Self::release_after_drain) for an `async fn`: the drain is awaited
    /// before the leaf's drop, which then finds the leaf drained.
    #[cfg(unix)]
    async fn release_after_drain_awaiting(self, tree_failed: bool) {
        let Some(attached) = self.release_backend_and_rekill(tree_failed) else {
            return;
        };
        // A drain that cannot be watched is the leaf's own drop's to report.
        #[cfg(target_os = "linux")]
        if let Attached::Cgroup(leaf) = &attached {
            _ = crate::tokio::wait::cgroup_wait_tree_drained(leaf, None).await;
        }
        drop(attached);
    }

    /// The first half of both drain releases: the backend goes, and a failed tree kill is fired
    /// again. Answers the containment resource whose drain the kills bound, or `None` once it has
    /// been given up without waiting, because neither kill landed and nothing bounds its drain.
    #[cfg(unix)]
    fn release_backend_and_rekill(mut self, tree_failed: bool) -> Option<Attached> {
        #[cfg(test)]
        fault::note_release();
        if let Some(proc) = self.proc.take() {
            proc.release();
        }
        let attached = std::mem::take(&mut self.attached);
        #[cfg(target_os = "linux")]
        if let Attached::Cgroup(leaf) = &attached {
            if tree_failed && leaf.hard_kill().is_err() {
                attached.release_without_waiting();
                return None;
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = tree_failed;
        Some(attached)
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
    /// The elevation front this child is, if any, as its spawn found it (see the sync `Child`).
    front: Option<crate::elevation::front::Front>,
    /// What a failed-spawn cleanup already warned of, so the drop reports a repeat of it at `debug`
    /// and anything new at `warn`.
    #[cfg(unix)]
    reported: Vec<crate::child::drop_report::PartKey>,
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
            front: None,
            #[cfg(unix)]
            reported: Vec::new(),
        }
    }

    /// The process handle, borrowed from `self`, while the backend still holds one.
    #[cfg(windows)]
    pub(super) fn process_handle(&self) -> Option<std::os::windows::io::RawHandle> {
        self.os.proc.as_ref()?.raw_handle()
    }

    /// See [`ProcSource::forget_for`].
    #[cfg(unix)]
    pub(super) fn forget_for(
        &mut self,
        view: &crate::containment::DropView,
    ) -> Option<crate::child::drop_report::Forgot> {
        self.os.proc.as_mut()?.forget_for(view)
    }

    /// Whether this handle already killed its tree completely.
    #[cfg(unix)]
    pub(super) fn tree_killed(&self) -> bool {
        self.tree_killed.is_set()
    }

    /// End a failed spawn's cleanup: `settled` (the tree and the root were each killed, are gone, or
    /// were deliberately left alone) disarms the drop, whose error reports what the cleanup did and
    /// left. Otherwise the handle stays armed so its drop tries again. `warned` is what the cleanup
    /// already warned of, so the drop, armed or not, does not warn of the same twice.
    #[cfg(unix)]
    pub(super) fn end_cleanup(&mut self, settled: bool, warned: Vec<crate::child::drop_report::PartKey>) {
        if settled {
            self.kill_on_drop = false;
        }
        self.reported = warned;
    }

    /// Set by the spawn, from its command.
    pub(super) fn set_front(&mut self, front: Option<crate::elevation::front::Front>) {
        self.front = front;
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
    /// names the tree by the root's number runs, and why and what was skipped is returned as
    /// `Ok(Some(note))`. The same when the handle could not say (`RootState::Unknown`).
    #[cfg(unix)]
    pub(super) fn kill_tree_members_unless_reaped(
        &self,
        view: &crate::containment::DropView,
    ) -> Result<Option<String>, Error> {
        self.os
            .attached
            .hard_kill_marking_unless_reaped(view, &self.tree_killed)
    }

    /// What this child's own handle and the root's number say about the root, for a cleanup that
    /// decides on both. Logs nothing about an unsettled root: the caller does, once.
    #[cfg(unix)]
    pub(super) fn read_root_view(&self, label: &str) -> crate::containment::DropView {
        crate::containment::DropView::read(
            label,
            self.id,
            || {
                self.os
                    .proc
                    .as_ref()
                    .map_or(crate::signal::RootState::Reaped, ProcSource::state)
            },
            &self.tree_killed,
        )
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

    /// Whether this child's tree is a process group named by the root's pid, for a test that needs
    /// one.
    #[cfg(all(test, unix))]
    pub(super) fn signals_a_group(&self) -> bool {
        self.os.attached.signals_a_group()
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
    /// What a forced kill of this child may do (see [`crate::elevation::front`]).
    #[cfg(unix)]
    pub(super) fn kill_gate(&self) -> crate::elevation::front::Gate {
        kill_gate(self.front, &self.os, self.id.pid())
    }
    /// Whether a kill through this child's cgroup landed.
    #[cfg(unix)]
    pub(super) fn cgroup_was_killed(&self) -> bool {
        self.tree_killed.is_set()
    }
    /// The refusal of a kill of this front whose cgroup no kill reached (see
    /// [`crate::elevation::front::cgroup_not_killed`]).
    #[cfg(unix)]
    pub(super) fn cgroup_not_killed(&self, failure: Option<&str>) -> Error {
        crate::elevation::front::cgroup_not_killed_of(self.front, self.id.pid(), failure)
    }
    /// Whether a cgroup kill just written reached this child's tracked process, a front (see
    /// [`crate::elevation::front::cgroup_kill_reached`]).
    #[cfg(unix)]
    pub(super) fn cgroup_kill_reached(&self) -> Result<(), Error> {
        cgroup_kill_reached(self.front, &self.os, self.id.pid())
    }
    /// What a `SIGTERM` to this child may do (see [`crate::elevation::front`]).
    #[cfg(unix)]
    pub(super) fn terminate_gate(&self) -> crate::elevation::front::Gate {
        crate::elevation::front::terminate_gate(self.front, self.id.pid(), || {
            self.os.proc.as_ref().map_or(Ok(false), ProcSource::is_running)
        })
    }
    /// Is this child an elevation backend, whose elevated program may outlive it?
    pub(crate) fn behind_wrapper(&self) -> bool {
        #[cfg(test)]
        if crate::child::spawn::failure::seams::wrapper() {
            return true;
        }
        self.elevation
            .as_ref()
            .is_some_and(|report| report.via.program_outlives_child())
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
    /// A child something else reaped, or that cannot be shown to be ours, is forgotten instead,
    /// quietly (nothing above `debug`): what the forget leaked, and why the wait found the child
    /// foreign, are returned for the caller's one warn. `None`: the child was waited for.
    ///
    /// Unix-only: the Windows elevation arm builds its child in-module with no deferred password.
    #[cfg(unix)]
    ///
    /// Answers what the wait found, for a caller whose kill was delivered: the collected exit
    /// (`Reaped`), or, for a child it could not show to be ours, which is forgotten, `Killed`.
    pub(super) fn wait_and_reap_blocking(
        &mut self,
    ) -> (crate::error::ChildFate, Option<crate::child::drop_report::Forgot>) {
        let pid = self.id.pid();
        let (waited, cause) = self.proc_mut().wait_and_reap_caused(pid, log::Level::Debug);
        match waited {
            Waited::Exited => {
                let id = Some(self.id);
                (self.proc_mut().collect_exit(id), None)
            }
            _ => (
                crate::error::ChildFate::Killed,
                self.proc_mut().forget_for_wait(waited, cause),
            ),
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

    /// The root a `TreeWalk` attachment walks from.
    #[cfg(all(test, unix))]
    pub(crate) fn test_treewalk_root(&self) -> Option<ProcessId> {
        match &self.os.attached {
            crate::containment::Attached::TreeWalk(root) => Some(*root),
            _ => None,
        }
    }

    /// The root an fd marker's ppid-walk channel starts from.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn test_marker_root(&self) -> Option<ProcessId> {
        match &self.os.attached {
            crate::containment::Attached::FdMarker(m) => Some(m.root()),
            _ => None,
        }
    }

    /// Block until the child exits, returning its status. For a bounded wait, fix a deadline
    /// instant once (`let deadline = tokio::time::Instant::now() + d;`) and use
    /// `tokio::time::timeout_at(deadline, child.wait())`, not a duration re-derived later.
    pub async fn wait(&mut self) -> Result<ExitStatus, Error> {
        #[cfg(test)]
        if let Some(error) = crate::child::spawn::failure::seams::take_wait_failure() {
            return Err(error);
        }
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
        self.kill_sent().map(|_| ())
    }

    /// [`kill`](Child::kill), saying whether a signal was delivered ([`Sent::Delivered`]) or the
    /// child was already gone ([`Sent::Gone`]: nothing was sent, and the caller must not wait for
    /// a termination that did not happen).
    pub(crate) fn kill_sent(&mut self) -> Result<Sent, Error> {
        #[cfg(unix)]
        let gate = self.kill_gate();
        // A front's refusal is permanent and says nothing of the pid, so it outranks a root launchd
        // holds, which the caller can do nothing about either way.
        #[cfg(unix)]
        if !matches!(gate, crate::elevation::front::Gate::Closed(_)) {
            self.refuse_unpinned("kill", None)?;
        }
        self.kill_sent_gated(
            #[cfg(unix)]
            gate,
        )
    }

    /// [`kill_sent`](Child::kill_sent) under `gate`, this child's kill gate read by the caller.
    pub(crate) fn kill_sent_gated(&mut self, #[cfg(unix)] gate: crate::elevation::front::Gate) -> Result<Sent, Error> {
        let sent = self.signal_gated(
            #[cfg(unix)]
            gate,
        );
        if matches!(sent, Ok(Sent::Gone | Sent::Unverified)) {
            // Nothing was sent. A child not shown ours is forgotten: tokio's wait and drop reap by pid.
            #[cfg(unix)]
            self.proc_mut().forget_if_foreign();
        }
        sent
    }

    /// [`kill_sent_gated`](Child::kill_sent_gated) without forgetting a child that is gone: for a
    /// caller that decides what to do with it, and what to log.
    pub(crate) fn signal_gated(&mut self, #[cfg(unix)] gate: crate::elevation::front::Gate) -> Result<Sent, Error> {
        #[cfg(test)]
        if fault::take_force_kill_failure() {
            return Err(fault::forced_kill_failure());
        }
        #[cfg(unix)]
        let exited_front = matches!(gate, crate::elevation::front::Gate::Exited);
        #[cfg(not(unix))]
        let exited_front = false;
        #[cfg(unix)]
        match gate {
            crate::elevation::front::Gate::Open | crate::elevation::front::Gate::Exited => {}
            // Nothing is signalled after the cgroup kill: it could only be refused.
            crate::elevation::front::Gate::CgroupOnly => {
                self.os
                    .attached
                    .hard_kill_marking(&self.tree_killed)
                    .map_err(|e| crate::elevation::front::cgroup_kill_failed(self.front, self.id.pid(), e))?;
                cgroup_kill_reached(self.front, &self.os, self.id.pid())?;
                return Ok(Sent::Delivered);
            }
            crate::elevation::front::Gate::Closed(unkillable) => return Err(unkillable),
        }
        // A plain child is unaffected (the mapping only fires on an elevated wrapper child whose
        // kill returns EPERM/ACCESS_DENIED). A child that is already gone is `Ok`, sent or not.
        match self.proc_mut().signal(Sig::Kill) {
            // An exit is permanent, so a refused signal to an exited front changes nothing.
            Err(Error::Io(e)) if exited_front && e.kind() == std::io::ErrorKind::PermissionDenied => {
                log::debug!("the kill of exited front pid {} was refused ({e})", self.id.pid());
                Ok(Sent::Delivered)
            }
            Err(Error::Io(e)) => Err(crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper())),
            Err(other) => Err(other),
            Ok(sent) => Ok(sent),
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
    ///
    /// **An elevated child behind a front** is reached only through a cgroup, as for the sync
    /// [`Child::kill_tree`](crate::Child::kill_tree).
    ///
    /// **macOS, a root the handle cannot vouch for.** If the root is `Unpinned` (launchd holds its
    /// zombie, see the sync [`Child::kill`](crate::Child::kill)) or `Unknown`, nothing that names the
    /// tree by the root's number runs: no `killpg`, no walk from its pid, no kill of the root by pid,
    /// and no handle backstop. An fd marker still kills its marker holders, which are named by identity
    /// (an `Unpinned` root is an exited zombie and is left alone), and the call is `Ok` only if every
    /// holder was reached. Any other mechanism has nothing left to send, and the call returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) saying that nothing was sent and what
    /// was skipped. The handle backstop reads the root's state again: a root orphaned during the sweep
    /// is an exited zombie, so the backstop is skipped and the sweep's answer stands.
    ///
    /// **A root reaped by something else, after this handle's own reap, and a reap after the
    /// look.** As for the sync [`Child::kill_tree`](crate::Child::kill_tree).
    pub fn kill_tree(&mut self) -> Result<(), Error> {
        self.kill_tree_after(None)
    }

    /// [`kill_tree`](Self::kill_tree), as a step of an operation that already sent `earlier`, so an
    /// error never claims the whole operation sent nothing.
    pub(crate) fn kill_tree_after(&mut self, earlier: Option<&str>) -> Result<(), Error> {
        #[cfg(not(unix))]
        let _ = earlier;
        self.require_contained()?;
        // Decided once: the gate is not asked again after the kill, when a killed front may read as
        // neither exited nor in its cgroup. `None` for a child the backstop may signal; for a front
        // it must not, `Some(true)` when the front is in the cgroup, `Some(false)` when it exited.
        // It comes before the root's state: a front that may not be signalled is refused whatever
        // the root's number names.
        #[cfg(unix)]
        let front = match self.kill_gate() {
            crate::elevation::front::Gate::Closed(unkillable) => return Err(unkillable),
            crate::elevation::front::Gate::Open => None,
            crate::elevation::front::Gate::Exited => Some(false),
            crate::elevation::front::Gate::CgroupOnly => Some(true),
        };
        // One look at the root decides: one launchd holds, or one the handle cannot vouch for, is
        // signalled by identity alone, and so is a group named by the root's pid once that pid may
        // name another process.
        #[cfg(unix)]
        if let Some(result) = self
            .tree_call(crate::containment::dispatch::TreeSignal::Kill, "kill_tree", earlier)
            .root_checked(|| self.root_state_and_own_reap(), || self.kill_root_through_handle())
        {
            return result;
        }
        let group_result = self.os.attached.hard_kill_marking(&self.tree_killed);
        // A TreeWalk that could not walk killed nothing, and the root's death would strand the
        // descendants beyond a retry: return the error with the tree intact.
        if self.os.attached.hard_kill_refused_to_walk(&group_result) {
            return group_result;
        }
        // A front in the cgroup: a signal after its kill could only be refused, and whether the kill
        // reached it is read after it. One whose kill failed may still have its program running:
        // left alone. An exited front needs no backstop.
        #[cfg(unix)]
        if let Some(in_cgroup) = front {
            return match group_result {
                Ok(()) if in_cgroup => cgroup_kill_reached(self.front, &self.os, self.id.pid()),
                Err(e) if in_cgroup => Err(crate::elevation::front::cgroup_kill_failed(
                    self.front,
                    self.id.pid(),
                    e,
                )),
                other => other,
            };
        }
        // Backstop for the TreeWalk mechanism: its hard_kill kills the root by identity, which
        // no-ops if `ProcessId::of` transiently fails to resolve — this handle-based kill
        // covers that, so its failure is contract-relevant.
        // Read again: the sweep above can be long, and a root orphaned meanwhile is an exited zombie
        // launchd holds, so there is nothing left for the backstop to kill. Read once: the send
        // below is the gated one, which does not read the state again.
        #[cfg(unix)]
        let backstop = if self.root_is_unpinned() {
            log::debug!(
                "kill_tree({}): launchd holds the root's zombie, so the handle backstop is skipped",
                self.id.pid()
            );
            Ok(())
        } else {
            // `front` was `None`, so the gate was open.
            self.kill_sent_gated(crate::elevation::front::Gate::Open).map(|_| ())
        };
        #[cfg(not(unix))]
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
    /// See [`kill_tree`](Child::kill_tree)'s doc for four things that also apply here: the
    /// `ProcessGroup`/`Session`-only scope of this guarantee (a separate, unfixed gap for
    /// `TreeWalk`), the residual `hidepid` gap on Linux, a root reaped by something else, and a reap
    /// after the look, which may send the `SIGTERM` to a number another process holds.
    ///
    /// **Windows, after the root's exit has been observed.** The event is addressed by the
    /// ROOT's pid — on the job-object mechanism and the tree walk alike — and this handle stops
    /// pinning that pid the moment `wait`/`try_wait` reports the exit, so the OS may reissue it
    /// to an unrelated group leader. A root exiting while its descendants are still alive is an
    /// ordinary flow, so this is refused from that point
    /// ([`Error::Unassessable`](crate::error::Error::Unassessable)) rather than fired at a bare
    /// pid; [`kill_tree`](Child::kill_tree) addresses no pid and still reaches the survivors.
    /// The sync [`Child`](crate::Child) pins for its whole life and is unaffected.
    ///
    /// **macOS, a root the handle cannot vouch for.** If the root is `Unpinned` (launchd holds its
    /// zombie, see the sync [`Child::kill`](crate::Child::kill)) or `Unknown`, nothing that names the
    /// tree by the root's number runs: no `killpg`, no walk from its pid. An fd marker still signals
    /// its marker holders, which are named by identity (an `Unpinned` root is left alone), and the call
    /// is `Ok` only if every holder was reached. Any other mechanism has nothing left to send, and the
    /// call returns [`Error::Unassessable`](crate::error::Error::Unassessable) saying that nothing was
    /// sent and what was skipped.
    ///
    /// **Linux, a root whose handle cannot say whether it was reaped** is sent the `SIGTERM` through
    /// its pidfd, which names it exactly. Nothing goes out by its number, and the call returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable), with one `warn` saying so.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
        // One look at the root decides, as for `kill_tree`.
        #[cfg(unix)]
        if let Some(result) = self
            .tree_call(crate::containment::dispatch::TreeSignal::Term, "terminate_tree", None)
            .root_checked(|| self.root_state_and_own_reap(), || self.term_root_through_handle())
        {
            return result;
        }
        self.terminate_tree_unchecked()
    }

    /// A kill of the root through its own handle (Linux: its pidfd), with no look at its state.
    #[cfg(unix)]
    fn kill_root_through_handle(&self) -> Result<Sent, Error> {
        let Some(proc) = self.os.proc.as_ref() else {
            return Ok(Sent::Gone);
        };
        match proc.signal(Sig::Kill) {
            Err(Error::Io(e)) => Err(crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper())),
            other => other,
        }
    }

    /// A `SIGTERM` to the root through its own handle (Linux: its pidfd), with no look at its state.
    #[cfg(unix)]
    fn term_root_through_handle(&self) -> Result<Sent, Error> {
        self.os
            .proc
            .as_ref()
            .map_or(Ok(Sent::Gone), |proc| proc.signal(Sig::Term))
    }

    /// A tree call on this child's tree ([`TreeCall`](crate::child::TreeCall)).
    #[cfg(unix)]
    fn tree_call<'a>(
        &'a self,
        signal: crate::containment::dispatch::TreeSignal,
        op: &'static str,
        earlier: Option<&'a str>,
    ) -> crate::child::TreeCall<'a> {
        crate::child::TreeCall {
            attached: &self.os.attached,
            pid: self.id.pid(),
            signal,
            op,
            earlier,
            killed: &self.tree_killed,
        }
    }

    /// The group's termination signal, with no look at the root's state.
    fn terminate_tree_unchecked(&self) -> Result<(), Error> {
        // After the mechanism guard, which is permanent and pid-independent: an uncontained
        // child must keep hearing why it has no tree to signal, not why a pid is unpinned.
        #[cfg(windows)]
        if !self.proc().pins_pid() {
            return Err(self.unpinned_pid_refusal("terminate_tree"));
        }
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

    /// The root's state through its own handle; see [`ProcSource::state`].
    #[cfg(unix)]
    fn root_state(&self) -> crate::signal::RootState {
        self.os
            .proc
            .as_ref()
            .map_or(crate::signal::RootState::Reaped, ProcSource::state)
    }

    /// [`root_state`](Self::root_state), and whether a `Reaped` is this handle's own reap (a
    /// forgotten child's is not).
    #[cfg(unix)]
    fn root_state_and_own_reap(&self) -> (crate::signal::RootState, bool) {
        self.os.proc.as_ref().map_or(
            (crate::signal::RootState::Reaped, false),
            ProcSource::state_and_own_reap,
        )
    }

    /// Refuse `op` while the root is not pinned by this process (macOS: launchd holds its zombie).
    /// `earlier` names what the same operation sent before. See [`crate::signal::refuse_unpinned`].
    #[cfg(unix)]
    pub(super) fn refuse_unpinned(&self, op: &str, earlier: Option<&str>) -> Result<(), Error> {
        crate::signal::refuse_unpinned(self.id.pid(), op, earlier, || self.root_state())
    }

    /// Whether launchd holds the root's zombie now (macOS; `false` elsewhere, where the state is
    /// not read).
    pub(super) fn root_is_unpinned(&self) -> bool {
        #[cfg(unix)]
        return crate::signal::is_unpinned(|| self.root_state());
        #[cfg(not(unix))]
        false
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

#[cfg(all(test, unix))]
#[path = "child/armed_drop_tests.rs"]
mod armed_drop_tests;

#[cfg(all(test, unix))]
#[path = "child/foreign_reap_tree_tests.rs"]
mod foreign_reap_tree_tests;

#[cfg(all(test, unix))]
#[path = "child/root_state_tests.rs"]
mod root_state_tests;

#[cfg(all(test, unix))]
#[path = "child/drop_report_tests.rs"]
mod drop_report_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "child/unpinned_public_tests.rs"]
mod unpinned_public_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "child/unpinned_graceful_tests.rs"]
mod unpinned_graceful_tests;

#[cfg(all(test, windows))]
#[path = "child/windows_signal_tests.rs"]
mod windows_signal_tests;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "child/bypass_drop_tests.rs"]
mod bypass_drop_tests;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "child/drop_fate_tests.rs"]
mod drop_fate_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "child/macos_kill_tests.rs"]
mod macos_kill_tests;

#[cfg(all(test, unix))]
#[path = "child/front_kill_tests.rs"]
mod front_kill_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/front_cgroup_tests.rs"]
mod front_cgroup_tests;

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

/// With `kill_on_drop` set (the default), hard-kills the contained tree, kills the root, and on Unix
/// **blocks until the root is reaped and the tree has drained**: the root's exit seen through its own
/// handle (on Linux its pidfd, on macOS its pid checked against its unique id), then collected
/// through tokio's `try_wait`, by pid; and a `Cgroup` leaf as the sync [`Child`](crate::Child)'s
/// drop does it (killed again if still populated, drained, its empty
/// child cgroups removed, then removed). The wait runs on the dropping thread, which may be a tokio
/// worker, on any runtime: a destructor cannot be awaited. The kills bound it, except for a process
/// stuck in uninterruptible I/O (D state) or a root whose zombie a foreign tracer holds until it lets
/// go. Past 1 s the drop logs one `warn` naming the root's pid, and keeps waiting.
///
/// To wait without blocking, call [`kill`](Child::kill) or [`kill_tree`](Child::kill_tree), then
/// await [`wait`](Child::wait) (and [`wait_tree`](Child::wait_tree) for a tree), before dropping:
/// the drop then finds nothing to wait for.
///
/// The drop waits for nothing, and does bounded work only, when it kills nothing: with
/// `kill_on_drop` clear ([`detach`](Child::detach), or `kill_on_drop(false)`), or when the root's
/// kill fails or cannot be sent, so the root may still run. Then:
///
/// - **The root.** tokio's own `Child` is dropped normally. It tries one reap, and a root that has
///   not exited yet goes to tokio's orphan queue, which reaps it once a runtime next sees
///   `SIGCHLD`. That queue is tokio's, not cosca's, and it is best-effort: it drains only while
///   some runtime runs.
/// - **The containment resource.** A `Cgroup` leaf is removed if it has drained. A leaf that has
///   not drained is **left behind**, and a warning names it, if this handle killed it (a disarmed
///   handle's [`kill_tree`](Child::kill_tree) is released like an armed one, with its `cgroup.kill`
///   written once more) or was armed to. Call [`wait_tree`](Child::wait_tree) first to have the
///   leaf removed. Other mechanisms drop in place.
///
/// A leaf whose `cgroup.kill` fails twice, in the tree kill and again before the drain, has nothing
/// to bound its drain: it is given up the same way, though the drop still reaps a root its kill
/// reached.
///
/// On Windows the drop terminates the tree and the root and waits for neither: a Job Object is
/// terminated by the tree kill and its handle closed there (`TerminateJobObject`, then
/// `CloseHandle`); one opted out of teardown is closed with `KILL_ON_JOB_CLOSE` cleared, and nothing
/// kills it. The process handle is closed.
///
/// An elevated child behind a front (see [`kill`](Child::kill)) gets no signal of its own while it
/// runs. In a cgroup that holds it, the tree's kill ends it, and the drop reaps it as any killed
/// root. Otherwise, or when that kill fails, the drop signals nothing, warns and waits for nothing:
/// the leaf's release still writes `cgroup.kill`, which ends the front if it is in the leaf, and
/// tokio reaps it once it exits.
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
/// queue without the runtime that would drain it.** A dropped root that lands on the queue in such
/// a child (one the drop could not kill) is never reaped there ([tokio#4301]). cosca keeps no pool
/// of its own for a fork to break, so nothing else is lost. It does **not** affect ordinary subprocess
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
        _ = self.tear_down();
    }
}

impl Child {
    /// What [`Drop`] does, now, and what it did with the child; the drop then does nothing more. For
    /// a sync caller that must say what became of the child: a failed resume.
    pub(crate) fn tear_down_now(&mut self) -> crate::error::ChildFate {
        let fate = self.tear_down();
        self.kill_on_drop = false;
        fate
    }

    /// [`tear_down_now`](Self::tear_down_now) for an `async fn`: the run-to-completion helpers,
    /// which fail after the spawn. The armed drop's waits (see [`Settle`]) are awaited instead of
    /// blocked on, without the drop's 1 s warn, which is about a blocked thread. Dropped before the
    /// reap is over, the future finishes the teardown as the drop does, blocking; dropped during the
    /// drain, it leaves the leaf to its own drop, which blocks on the drain too.
    pub(crate) async fn tear_down_awaiting(&mut self) -> crate::error::ChildFate {
        let teardown = self.signal_for_teardown();
        // Before the waits, so the handle's own drop does nothing more if this future is dropped.
        self.kill_on_drop = false;
        match teardown {
            Teardown::Done(fate) => fate,
            #[cfg(unix)]
            Teardown::Waits(signalled) => {
                let mut reaping = Reaping {
                    child: self,
                    signalled: Some(signalled),
                };
                let signalled = reaping.signalled.as_mut().expect("taken only once the reap is over");
                if signalled.signals.settle == Settle::ReapAndDrain {
                    reap_killed_root_awaiting(self.id, &mut signalled.os, &mut signalled.signals).await;
                }
                let signalled = reaping.signalled.take().expect("taken only here before the drop");
                let (os, fate, tree_failed) = self.report(*signalled);
                os.release_after_drain_awaiting(tree_failed).await;
                fate
            }
        }
    }

    /// The drop's teardown: signal (when armed), then, on Unix, wait for what the signals reached
    /// (see [`Settle`]), and release. Answers what became of the child. A second call finds the
    /// resources already taken, and does nothing.
    fn tear_down(&mut self) -> crate::error::ChildFate {
        match self.signal_for_teardown() {
            Teardown::Done(fate) => fate,
            #[cfg(unix)]
            Teardown::Waits(signalled) => self.settle(signalled),
        }
    }

    /// An armed drop's waits, report and release, on this thread whatever the runtime: what the
    /// signals reached is reaped and drained before this returns. Never `block_in_place`: tokio
    /// panics in it inside a `LocalSet` and offers no way to ask first.
    #[cfg(unix)]
    fn settle(&self, mut signalled: Box<Signalled>) -> crate::error::ChildFate {
        let mut late = LateWarn::new(self.id.pid());
        if signalled.signals.settle == Settle::ReapAndDrain {
            reap_killed_root(self.id, &mut signalled.os, &mut signalled.signals, &mut late);
        }
        let (os, fate, tree_failed) = self.report(*signalled);
        os.release_after_drain(&mut late, tree_failed);
        fate
    }

    /// The teardown's signals (when armed), inside the bounded section. A teardown that waits for
    /// nothing is finished there. An armed one whose kill landed leaves the section, and hands its
    /// waits, report and release to the caller.
    fn signal_for_teardown(&mut self) -> Teardown {
        use crate::error::ChildFate;
        // Enforced in debug builds: nothing in it may wait for an exit or a drain. Declared before
        // `os`, so a panic in the signals unwinds through the resources while still inside it.
        let bounded = crate::bounded::Section::enter();
        let mut os = std::mem::take(&mut self.os);
        // Read before the `kill_on_drop` branch: a disarmed drop signals nothing, but releasing
        // tokio's `Child` still `try_wait`s the root's number, so it needs the same evidence.
        let own_reap = os.proc.as_ref().is_none_or(|proc| proc.is_reaped());
        // What an earlier forgetting recorded of a backend that no longer holds the child.
        #[cfg(unix)]
        let forgotten = os.proc.as_ref().and_then(|proc| proc.forgotten_fate(Some(self.id)));
        // A live elevation front gets no signal of its own: outside a cgroup it is left running,
        // and named in the drop's one warn. The gate comes first, so the look at the root is right
        // before the signals it decides.
        #[cfg(unix)]
        let gate = self.kill_on_drop.then(|| kill_gate(self.front, &os, self.id.pid()));
        #[cfg(unix)]
        let view = crate::containment::DropView::read(
            "Child::drop",
            self.id,
            || {
                os.proc
                    .as_ref()
                    .map_or(crate::signal::RootState::Reaped, ProcSource::state)
            },
            &self.tree_killed,
        );
        let mut signals = DropSignals::new(ChildFate::Running { id: Some(self.id) });
        #[cfg(unix)]
        let mut front_left = None;
        if self.kill_on_drop {
            #[cfg(unix)]
            match gate.expect("an armed drop reads the gate") {
                crate::elevation::front::Gate::Closed(unkillable) => front_left = Some(unkillable),
                gate => {
                    let cgroup_front = matches!(gate, crate::elevation::front::Gate::CgroupOnly)
                        .then_some(self.front)
                        .flatten();
                    signals = signal_on_drop(self.id, &view, cgroup_front, &mut os);
                }
            }
            #[cfg(not(unix))]
            {
                signals = signal_on_drop(self.id, &self.tree_killed, &mut os);
            }
        }
        // A root that was reaped outside this handle (tokio's state cannot see it), or that the
        // handle cannot show is ours (unknown, unpinned), leaves the number possibly naming another
        // child, so tokio's `Child` must not run its own drop, which reaps by pid. Asked again: a
        // reap can land after the read above (and before or during the root kill).
        #[cfg(unix)]
        if !own_reap && signals.forgot.is_none() {
            if let Some(proc) = os.proc.as_mut() {
                signals.forgot = proc.forget_for(&view);
                if let Some(forgot) = &signals.forgot {
                    log::debug!(
                        "async child {} cannot be shown to be ours (reaped outside its handle, unknown, or unpinned); \
                         dropping it would reap by that number, so it was forgotten",
                        self.id.pid()
                    );
                    // Reaped elsewhere before the kill could reach it; one it reached stays killed. A
                    // child not shown ours is not claimed reaped.
                    if forgot.reaped_elsewhere() && signals.fate != ChildFate::Killed {
                        signals.fate = ChildFate::Gone;
                    }
                }
            }
        }
        let signalled = Signalled {
            os,
            signals,
            own_reap,
            #[cfg(unix)]
            forgotten,
            #[cfg(unix)]
            view,
            #[cfg(unix)]
            front_left,
        };
        #[cfg(unix)]
        if self.kill_on_drop && signalled.signals.settle != Settle::Nothing {
            drop(bounded);
            return Teardown::Waits(Box::new(signalled));
        }
        // The section stays open over a release that does not wait.
        let (os, fate, _) = self.report(signalled);
        os.release_without_waiting();
        drop(bounded);
        Teardown::Done(fate)
    }

    /// The teardown's one report, once its waits are over. Answers the resources left to release,
    /// what became of the child, and whether the drop's own tree kill failed.
    fn report(&self, signalled: Signalled) -> (OsResources, crate::error::ChildFate, bool) {
        use crate::error::ChildFate;
        let Signalled {
            os,
            mut signals,
            own_reap,
            #[cfg(unix)]
            forgotten,
            #[cfg(unix)]
            view,
            #[cfg(unix)]
            front_left,
        } = signalled;
        // A backend forgotten earlier says why: a status collected by this handle is `Reaped`, and
        // nothing else is. This holds whether or not the drop is armed.
        if own_reap {
            #[cfg(unix)]
            {
                signals.fate = forgotten.unwrap_or(ChildFate::Reaped);
            }
            #[cfg(not(unix))]
            {
                signals.fate = ChildFate::Reaped;
            }
        }
        #[cfg(unix)]
        let tree_failed = signals.tree.is_some();
        #[cfg(unix)]
        {
            let mut report = crate::child::drop_report::DropReport::new("Child::drop", &view);
            report.front = front_left.as_ref();
            report.skipped = signals.skipped;
            report.forgot = signals.forgot;
            report.tree = signals.tree;
            report.left = signals.left;
            report.emit(&self.reported);
        }
        // Off Unix there is no root state to report: what the signals could not do is the event.
        #[cfg(not(unix))]
        let tree_failed = false;
        #[cfg(not(unix))]
        if !signals.left.is_empty() {
            log::warn!("Child::drop: {}", signals.left.join("; "));
        }
        (os, signals.fate, tree_failed)
    }
}

/// Where a teardown stands after its signals.
enum Teardown {
    /// Finished within the bounded section: nothing to wait for.
    Done(crate::error::ChildFate),
    /// An armed drop whose kill landed: its waits, report and release remain.
    #[cfg(unix)]
    Waits(Box<Signalled>),
}

/// An awaited teardown's reap in progress. Dropped with the reap unfinished (its future was), it
/// settles the rest as the drop would, unless the thread is unwinding: then the resources go to
/// their own drops, which log nothing.
#[cfg(unix)]
struct Reaping<'a> {
    child: &'a Child,
    signalled: Option<Box<Signalled>>,
}

#[cfg(unix)]
impl Drop for Reaping<'_> {
    fn drop(&mut self) {
        if let Some(signalled) = self.signalled.take() {
            if !std::thread::panicking() {
                _ = self.child.settle(signalled);
            }
        }
    }
}

/// What a teardown's signals leave for its report and release.
struct Signalled {
    os: OsResources,
    signals: DropSignals,
    /// This handle had collected the root's status before the teardown.
    own_reap: bool,
    /// What an earlier forgetting recorded of the child.
    #[cfg(unix)]
    forgotten: Option<crate::error::ChildFate>,
    #[cfg(unix)]
    view: crate::containment::DropView,
    /// The refusal of a live front left running.
    #[cfg(unix)]
    front_left: Option<Error>,
}

/// How long the armed drop waits before it says so. Messaging only: no wait ends on it.
#[cfg(unix)]
const LATE: std::time::Duration = std::time::Duration::from_secs(1);

/// The armed drop's one warn, once its waits pass [`LATE`]: the reap and the drain share it.
#[cfg(unix)]
struct LateWarn {
    pid: u32,
    until: std::time::Instant,
    warned: bool,
}

#[cfg(unix)]
impl LateWarn {
    fn new(pid: u32) -> LateWarn {
        LateWarn {
            pid,
            until: crate::wait::now() + LATE,
            warned: false,
        }
    }

    /// When the warn is due, or `None` once it has gone out: the next wait is unbounded.
    fn due(&self) -> Option<std::time::Instant> {
        (!self.warned).then_some(self.until)
    }

    /// Warn, once, that `what` (completing "async child N ...") still holds the drop.
    fn warn(&mut self, what: &str) {
        if std::mem::replace(&mut self.warned, true) {
            return;
        }
        log::warn!(
            "Child::drop: async child {} {what} {} s after its kill; still waiting: the drop blocks \
             until the child is reaped and its tree has drained (call kill() and wait().await, and \
             wait_tree().await for a tree, before dropping, to wait without blocking)",
            self.pid,
            LATE.as_secs()
        );
    }
}

/// Reap a root the drop's kill reached, through its handle: wait until its exit is visible, warning
/// once past [`LATE`], then collect it. A root the wait finds reaped elsewhere, or cannot show to be
/// ours, is forgotten instead, for the drop's one report.
#[cfg(unix)]
fn reap_killed_root(id: ProcessId, os: &mut OsResources, signals: &mut DropSignals, late: &mut LateWarn) {
    let Some(proc) = os.proc.as_mut() else {
        return;
    };
    // Forgotten by the second look, or already reaped: nothing is left to wait for.
    if proc.is_reaped() {
        return;
    }
    let pid = id.pid();
    if let Some(until) = late.due() {
        if !proc.exit_visible_by(pid, until) {
            late.warn("has not been reaped");
        }
    }
    let (waited, cause) = proc.wait_and_reap_caused(pid, log::Level::Debug);
    match waited {
        Waited::Exited => signals.fate = proc.collect_exit(Some(id)),
        // The kill was delivered: dead or dying, and its exit not collected here.
        _ => signals.forgot = proc.forget_for_wait(waited, cause),
    }
}

/// [`reap_killed_root`] for an `async fn`: the exit is awaited, and nothing warns.
#[cfg(unix)]
async fn reap_killed_root_awaiting(id: ProcessId, os: &mut OsResources, signals: &mut DropSignals) {
    let Some(proc) = os.proc.as_mut() else {
        return;
    };
    if proc.is_reaped() {
        return;
    }
    let (waited, cause) = proc.wait_and_reap_awaiting().await;
    match waited {
        Waited::Exited => signals.fate = proc.collect_exit(Some(id)),
        _ => signals.forgot = proc.forget_for_wait(waited, cause),
    }
}

/// What a forced kill of the child may do (see [`crate::elevation::front`]).
#[cfg(unix)]
fn kill_gate(
    front: Option<crate::elevation::front::Front>,
    os: &OsResources,
    pid: u32,
) -> crate::elevation::front::Gate {
    crate::elevation::front::kill_gate(
        front,
        pid,
        || os.proc.as_ref().map_or(Ok(false), ProcSource::is_running),
        || {
            os.attached
                .kill_reaches_across_credentials(pid, os.proc.as_ref().and_then(ProcSource::pidfd))
        },
    )
}

/// Whether a cgroup kill just written reached the tracked process, a front (see
/// [`crate::elevation::front::cgroup_kill_reached`]).
#[cfg(unix)]
fn cgroup_kill_reached(front: Option<crate::elevation::front::Front>, os: &OsResources, pid: u32) -> Result<(), Error> {
    crate::elevation::front::cgroup_kill_reached(
        front,
        pid,
        || {
            os.proc
                .as_ref()
                .map_or(Ok(false), ProcSource::is_running)
                .map(|running| !running)
        },
        || {
            os.attached
                .cgroup_names(pid, os.proc.as_ref().and_then(ProcSource::pidfd))
        },
    )
}

/// What the signals of a kill-on-drop drop found, for the drop's one report, and what became of the
/// child.
struct DropSignals {
    /// What became of the child.
    fate: crate::error::ChildFate,
    /// What the tree kill skipped ([`DropKill::skipped`](crate::containment::dispatch::DropKill)).
    #[cfg(unix)]
    skipped: Option<String>,
    /// What forgetting tokio's `Child` leaked, if the failed root kill forgot it.
    #[cfg(unix)]
    forgot: Option<crate::child::drop_report::Forgot>,
    /// The contained tree's teardown failure, if it failed.
    #[cfg(unix)]
    tree: Option<String>,
    /// What the root kill could not do.
    left: Vec<String>,
    /// What the armed drop waits for once it has signalled.
    #[cfg(unix)]
    settle: Settle,
}

/// What an armed drop waits for after its signals: the root's reap, when its kill reached it, and
/// the tree's drain, unless the kill failed or the root may still run.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settle {
    /// Nothing: the kill failed or sent nothing, so the root may still run, and the drop stays
    /// bounded.
    Nothing,
    /// The tree's drain only: the root is already reaped, or not this handle's to reap.
    Drain,
    /// The root's reap, then the tree's drain.
    ReapAndDrain,
}

impl DropSignals {
    fn new(fate: crate::error::ChildFate) -> DropSignals {
        DropSignals {
            fate,
            #[cfg(unix)]
            settle: Settle::Nothing,
            #[cfg(unix)]
            skipped: None,
            #[cfg(unix)]
            forgot: None,
            #[cfg(unix)]
            tree: None,
            left: Vec::new(),
        }
    }
}

/// The signals of a kill-on-drop drop: the tree, then the root. A failed tree kill is returned for
/// the drop's one warn, with what became of the child.
fn signal_on_drop(
    id: ProcessId,
    #[cfg(unix)] view: &crate::containment::DropView,
    #[cfg(unix)] cgroup_front: Option<crate::elevation::front::Front>,
    #[cfg(not(unix))] tree_killed: &crate::containment::TreeKilled,
    os: &mut OsResources,
) -> DropSignals {
    use crate::error::ChildFate;
    #[allow(unused_mut, reason = "only the Unix signals collect anything")]
    let mut signals = DropSignals::new(ChildFate::Unknown);
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
    let tree = {
        let kill = os.attached.hard_kill_for_drop(view);
        signals.skipped = kill.skipped;
        kill.result
    };
    #[cfg(not(unix))]
    let tree = {
        _ = tree_killed;
        os.attached.hard_kill()
    };
    if let Err(e) = &tree {
        // A real OS outcome (e.g. `EACCES`/`EIO` on `cgroup.kill`): reported, never asserted on.
        let mut failed = format!("contained-tree teardown did not fully succeed: {e}");
        if os.attached.hard_kill_refused_to_walk(&tree) {
            // Unlike `kill_tree`, a drop cannot be retried: the root dies below either way.
            failed.push_str("; the root is killed regardless, so its descendants may be orphaned");
        }
        #[cfg(unix)]
        {
            signals.tree = Some(failed);
        }
        #[cfg(not(unix))]
        signals.left.push(failed);
    }
    // Already reaped, or not pinned by this process: no signal to issue. The caller tells its own
    // reap from a foreign one; a root someone else reaped, or launchd holds, is `Gone`.
    #[cfg(unix)]
    if view.leaves_root_alone() {
        signals.fate = ChildFate::Gone;
        signals.settle = Settle::Drain;
        return signals;
    }
    #[cfg(not(unix))]
    if os.proc.as_ref().is_none_or(|proc| proc.is_reaped()) {
        signals.fate = ChildFate::Reaped;
        return signals;
    }
    // The cgroup kill ended the front, and the drop reaps it. One the kill did not end may still
    // have its program running, and a kill of the front would orphan it.
    #[cfg(unix)]
    if let Some(front) = cgroup_front {
        match tree.and_then(|()| cgroup_kill_reached(Some(front), os, pid)) {
            // Ended by the cgroup kill: reaped through its handle like any killed root.
            Ok(()) => {
                signals.fate = ChildFate::Killed;
                signals.settle = Settle::ReapAndDrain;
            }
            Err(e) => {
                // The leaf's release still writes `cgroup.kill`, which ends the front if it is in the
                // leaf; nothing waits to see.
                signals.left.push(format!(
                    "elevation front pid {pid}: its cgroup kill is not shown to have reached it ({e}); the front is \
                     killed through its cgroup if it is still in it; cosca does not wait for it, and tokio reaps it \
                     once it exits"
                ));
                // Not shown to be dead: it may still be running.
                signals.fate = ChildFate::Running { id: Some(id) };
            }
        }
        return signals;
    }
    let Some(proc) = os.proc.as_mut() else {
        return signals;
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
    // `Unverified`: nothing was sent because the pid cannot be verified (a backend forgotten without
    // proof of a foreign reap), so the child may be running.
    // Nothing is logged here: the drop forgets the child next, and logs that.
    match killed {
        Ok(Sent::Gone) => {
            signals.fate = ChildFate::Gone;
            #[cfg(unix)]
            {
                signals.settle = Settle::Drain;
            }
            return signals;
        }
        Ok(Sent::Unverified) => {
            signals.fate = ChildFate::Running { id: Some(id) };
            return signals;
        }
        _ => {}
    }
    if killed.is_err() {
        // The `try_wait` below reaps by pid: forget a foreign reap first.
        #[cfg(unix)]
        {
            signals.forgot = proc.forget_for(view);
            if let Some(forgot) = &signals.forgot {
                signals.fate = if forgot.reaped_elsewhere() {
                    ChildFate::Gone
                } else {
                    ChildFate::Running { id: Some(id) }
                };
                return signals;
            }
        }
        if proc.is_reaped() {
            signals.fate = ChildFate::Reaped;
            return signals;
        }
        let looked = proc.try_wait();
        if !matches!(looked, Ok(Some(_))) {
            signals.left.push(format!(
                "async child {pid} could not be terminated on drop; leaving it running"
            ));
        }
        signals.fate = crate::child::spawn::fate_of_a_look(looked.map_err(|e| e.raw_os_error()), Some(id));
        return signals;
    }
    // Signalled: on Unix the drop reaps it next; Windows closes the handle.
    signals.fate = ChildFate::Killed;
    #[cfg(unix)]
    {
        signals.settle = Settle::ReapAndDrain;
    }
    signals
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

    thread_local! {
        static FORCE_KILL_FAILURE: Cell<bool> = const { Cell::new(false) };
        static PEND_AWAITED_REAP: Cell<bool> = const { Cell::new(false) };
        static RELEASES: Cell<usize> = const { Cell::new(0) };
        static BACKEND_DROPS: Cell<usize> = const { Cell::new(0) };
    }

    /// Counts the process backends ([`ProcSource`](super::ProcSource), so tokio's own `Child`
    /// with it) released to tokio's drop on THIS thread from now on. A backend that was forgotten, or moved to another thread, is not counted.
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

    /// tokio's `Child`, counted when it drops.
    pub(crate) struct CountedDrop {
        pub(crate) _child: ::tokio::process::Child,
    }

    impl Drop for CountedDrop {
        fn drop(&mut self) {
            note_backend_drop();
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

    /// The next awaited reap on this thread ([`ProcSource::wait_and_reap_awaiting`]) never
    /// completes, as for a root a tracer holds, so a test can drop the future awaiting it.
    ///
    /// [`ProcSource::wait_and_reap_awaiting`]: super::ProcSource::wait_and_reap_awaiting
    pub(crate) fn pend_awaited_reap() -> PendAwaitedReap {
        PEND_AWAITED_REAP.with(|f| f.set(true));
        PendAwaitedReap(())
    }

    #[must_use = "the seam is cleared as soon as the guard is dropped"]
    pub(crate) struct PendAwaitedReap(());

    impl Drop for PendAwaitedReap {
        fn drop(&mut self) {
            PEND_AWAITED_REAP.with(|f| f.set(false));
        }
    }

    pub(super) fn take_pend_awaited_reap() -> bool {
        PEND_AWAITED_REAP.with(|f| f.replace(false))
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "child/identity_macos_tests.rs"]
mod identity_macos_tests;
