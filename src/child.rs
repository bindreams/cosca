//! The owned child handle.

use std::collections::BTreeMap;
use std::io::{PipeReader, PipeWriter};

use crate::child::owned::teardown::{Disposition, TeardownKind, TeardownOutcome};
use crate::command::Command;
use crate::containment::dispatch::TeardownCaller;
use crate::containment::Containment;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::stdio::Fd;

#[path = "child/pump.rs"]
pub(crate) mod pump;

#[path = "child/spawn.rs"]
pub(crate) mod spawn;

#[cfg(unix)]
#[path = "child/drop_report.rs"]
pub(crate) mod drop_report;
#[path = "child/owned.rs"]
pub(crate) mod owned;
use owned::slot::ChildSlot;
use owned::OwnedChild;

#[path = "child/lifecycle.rs"]
mod lifecycle;

#[path = "child/suspended.rs"]
pub(crate) mod suspended;
pub use owned::unreaped::Unreaped;
pub use suspended::SuspendedChild;

#[path = "child/graceful.rs"]
mod graceful;

#[cfg(unix)]
#[path = "child/tree_call.rs"]
pub(crate) mod tree_call;
#[cfg(target_os = "linux")]
pub(crate) use tree_call::PidfdShutdown;
#[cfg(unix)]
pub(crate) use tree_call::{Graceful, TreeCall};

#[cfg(test)]
#[path = "child_tests.rs"]
mod child_tests;

#[cfg(test)]
#[path = "child/hand_back_tests.rs"]
mod hand_back_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/pid_reuse_tests.rs"]
mod pid_reuse_tests;

#[cfg(all(test, unix))]
#[path = "child/foreign_reap_tree_tests.rs"]
mod foreign_reap_tree_tests;

#[cfg(all(test, unix))]
#[path = "child/root_number_matrix_tests.rs"]
mod root_number_matrix_tests;

#[cfg(all(test, unix))]
#[path = "child/own_reap_tests.rs"]
mod own_reap_tests;

#[cfg(all(test, unix))]
#[path = "child/foreign_reap_after_look_tests.rs"]
pub(crate) mod foreign_reap_after_look_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/group_route_tests.rs"]
mod group_route_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/group_exact_tests.rs"]
pub(crate) mod group_exact_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/drop_group_exact_tests.rs"]
mod drop_group_exact_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/openat2_refused_drop_tests.rs"]
mod openat2_refused_drop_tests;

#[cfg(all(test, unix))]
#[path = "child/drop_reaped_tests.rs"]
mod drop_reaped_tests;

#[cfg(all(test, unix))]
#[path = "child/root_state_tests.rs"]
mod root_state_tests;

#[cfg(all(test, unix))]
#[path = "child/drop_report_tests.rs"]
mod drop_report_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "child/unpinned_public_tests.rs"]
pub(crate) mod unpinned_public_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "child/unpinned_graceful_tests.rs"]
mod unpinned_graceful_tests;

#[cfg(all(test, unix))]
#[path = "child/front_kill_tests.rs"]
pub(crate) mod front_kill_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/front_cgroup_tests.rs"]
pub(crate) mod front_cgroup_tests;

/// A parent-side pipe end retained for a configured descriptor.
#[derive(Debug)]
pub(crate) enum ParentEnd {
    Reader(PipeReader),
    Writer(PipeWriter),
}

/// A spawned child process the crate owns.
#[derive(Debug)]
pub struct Child {
    /// Empty only inside [`tear_down_or_hand_back`](Child::tear_down_or_hand_back), which consumes
    /// the child.
    proc: ChildSlot,
    /// Stable identity resolved immediately after spawn.
    id: ProcessId,
    pipes: BTreeMap<Fd, ParentEnd>,
    kill_on_drop: bool,
    containment: Containment,
    attached: crate::containment::Attached,
    /// Whether this handle already hard-killed the tree; see [`crate::containment::TreeKilled`].
    tree_killed: crate::containment::TreeKilled,
    graceful: crate::graceful::GracefulMechanism,
    elevation: Option<crate::elevation::ElevationReport>,
    /// The elevation front this child is, if any, as its spawn found it (see
    /// [`crate::elevation::front`]). The one source the kill and `SIGTERM` gates read.
    front: Option<crate::elevation::front::Front>,
    /// What a failed-spawn cleanup already warned of, so the drop reports a repeat of it at `debug`
    /// and anything new at `warn`
    /// ([`DropReport::emit`](crate::child::drop_report::DropReport::emit)).
    #[cfg(unix)]
    reported: Vec<crate::child::drop_report::PartKey>,
}

impl Child {
    pub(crate) fn from_parts(
        proc: OwnedChild,
        id: ProcessId,
        pipes: BTreeMap<Fd, ParentEnd>,
        kill_on_drop: bool,
        attachment: crate::containment::Attachment,
    ) -> Child {
        Child {
            proc: ChildSlot::new(proc),
            id,
            pipes,
            kill_on_drop,
            containment: attachment.containment,
            attached: attachment.attached,
            tree_killed: Default::default(),
            graceful: attachment.graceful,
            elevation: None,
            front: None,
            #[cfg(unix)]
            reported: Vec::new(),
        }
    }

    /// Set by the spawn, from its command (see [`Child::front`](Self#structfield.front)).
    pub(crate) fn set_front(&mut self, front: Option<crate::elevation::front::Front>) {
        self.front = front;
    }

    /// The process handle, borrowed from `self`.
    #[cfg(windows)]
    pub(crate) fn process_handle(&self) -> std::os::windows::io::RawHandle {
        use std::os::windows::io::AsRawHandle;
        self.proc.os_handle().as_raw_handle()
    }

    /// Commit the spawn: apply `kill_on_drop` to the containment resource (see
    /// [`Attached::honor_kill_on_drop`](crate::containment::Attached::honor_kill_on_drop)).
    pub(crate) fn commit_kill_on_drop(&self) {
        self.attached.honor_kill_on_drop(self.kill_on_drop);
    }

    // Set by the elevation spawn arms.
    pub(crate) fn set_elevation(&mut self, report: Option<crate::elevation::ElevationReport>) {
        self.elevation = report;
    }

    /// The achieved elevation state, or `None` if elevation was not requested
    /// (mirrors [`Child::containment`]).
    pub fn elevation(&self) -> Option<crate::elevation::ElevationReport> {
        self.elevation.clone()
    }

    /// The tree-teardown mechanism for this child: a nested member reports
    /// [`Containment::Delegated`], an uncontained child [`Containment::None`]. Use
    /// [`Containment::can_teardown`] to predict whether `kill_tree`/`terminate_tree`
    /// act or return `Unsupported`.
    pub fn containment(&self) -> Containment {
        self.containment
    }

    /// Which cooperative signal [`terminate`](Child::terminate) sends this child, how far it
    /// reaches, and whether this process has a route to deliver it. A spawn-time fact, so it is
    /// stable for the child's whole life and costs no syscall.
    ///
    /// Independent of [`containment`](Child::containment): that answers who tears this child's
    /// *tree* down, this answers what a polite signal to the child itself is.
    ///
    /// **Not a delivery guarantee.** [`ConsoleGroup`](crate::GracefulMechanism::ConsoleGroup)
    /// means only that the
    /// creation flags do not exclude delivery from this process — Windows reports success for a
    /// console control event aimed at a group in another console and delivers nothing, and no
    /// spawn-time fact can predict a child that leaves or joins a console after it starts.
    /// Each such call also leaves a dead entry in the caller's console process list.
    pub fn graceful_mechanism(&self) -> crate::graceful::GracefulMechanism {
        self.graceful
    }

    /// Guard for the `_tree` operations (single-sourced with the async `Child`).
    fn require_contained(&self) -> Result<(), Error> {
        crate::containment::require_contained(self.containment, &self.attached)
    }

    /// Guard for `wait_tree`/`wait_tree_timeout` (single-sourced with the async `Child`).
    fn require_drainable(&self) -> Result<(), Error> {
        crate::containment::require_drainable(self.containment, &self.attached)
    }

    /// This child's stable identity (see [`crate::identity::ProcessId`]).
    pub fn id(&self) -> ProcessId {
        self.id
    }

    /// Whether the child is still running — re-checked via its stable identity, so a
    /// recycled pid never reads as alive. [`crate::identity::Liveness::Unknown`] when the OS
    /// refuses the query: an unelevated parent cannot open a UAC-elevated child by pid, and
    /// the honest answer there is not "dead".
    pub fn is_alive(&self) -> crate::identity::Liveness {
        self.id.is_alive()
    }

    /// Block until the child exits, returning its status.
    ///
    /// Reaps the root; a later drop then skips number-named kills, so call
    /// [`kill_tree`](Child::kill_tree) first to end descendants (see `Drop`).
    pub fn wait(&self) -> Result<std::process::ExitStatus, Error> {
        #[cfg(test)]
        if let Some(error) = crate::child::spawn::failure::seams::take_wait_failure() {
            return Err(error);
        }
        lifecycle::wait_for_status(&self.proc, lifecycle::Orphaned::Warn)
    }

    /// Return the exit status if the child has already exited.
    pub fn try_wait(&self) -> Result<Option<std::process::ExitStatus>, Error> {
        // One look at the present moment. A zombie launchd holds is the caller's to report.
        self.wait_root(Some(crate::wait::now()), lifecycle::Orphaned::Quiet)
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

    /// Hard-kill the process. Returns `Ok(())` if already dead. Unlike
    /// [`Process::kill`](crate::Process::kill), which acts through a handle opened earlier, this
    /// signals through the child's own handle, so a refused Linux `pidfd_open` cannot fail it.
    ///
    /// **An elevated child behind a front** ([`Backend::Sudo`](crate::elevation::Backend::Sudo),
    /// [`Backend::Doas`](crate::elevation::Backend::Doas),
    /// [`ElevatedVia::MacosOsascript`](crate::elevation::ElevatedVia::MacosOsascript)): the tracked
    /// process is usually the wrapper, which outlives the root program, so a kill would orphan the
    /// program. While it runs, it is sent no signal. In a Linux cgroup ([`Containment::CgroupV2`])
    /// this kills through `cgroup.kill`, which reaches the front whatever its credentials, and every
    /// process still in the cgroup. A process root moved out of the cgroup (as
    /// `sudo systemd-run --scope` does) is not killed, and cosca cannot see it, so `Ok` says only
    /// that the front and what was still in the cgroup were killed. Otherwise, including when the
    /// front has left the cgroup, this sends nothing and returns
    /// [`ElevationErrorKind::Unkillable`](crate::error::ElevationErrorKind::Unkillable), and
    /// [`wait`](Child::wait) still returns only once the program has exited.
    ///
    /// Whether the cgroup kill reached the front is read after it; a front someone else moves out of
    /// the cgroup before it exits reads as moved, and this returns `Unkillable` though it is dying.
    /// The other `Unkillable` cases are listed on [`Command::contain`](crate::Command::contain).
    ///
    /// An elevated program that moves its front out of the cgroup and back again around the kill
    /// can make an `Ok` false, as [`Command::contain`](crate::Command::contain) says; `wait` stays
    /// truthful.
    ///
    /// **macOS, a root launchd holds.** If a tracer reparented the root and died, launchd holds its
    /// zombie and reaps it on its own schedule, so this process no longer pins its pid. Nothing is sent
    /// to it, by pid or to its group, and nothing is waited on: the call returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) naming launchd, and the root is left
    /// as it was. The state is read before anything is sent, so a tracer that dies after the read
    /// passes still leaves a window in which the signal lands on a pid launchd has since reused.
    ///
    /// A root the handle cannot vouch for (`Unknown`: a failed peek or an unreadable unique id) is
    /// still killed through the handle on Linux: its pidfd names it whoever reaped it. On macOS
    /// this root, like any other, is signalled through its audit token: the kernel refuses the
    /// send if the pid now names another process. If the unique id read at spawn cannot be read
    /// again, nothing is sent and `kill` returns the error.
    pub fn kill(&self) -> Result<(), Error> {
        #[cfg(unix)]
        {
            self.kill_sent().map(drop)
        }
        // Returns Ok(()) for an already-exited child (std delegates to std::process::Child::kill;
        // the raw path maps an already-dead TerminateProcess to Ok). ACCESS_DENIED on a UAC child
        // becomes the typed `Unkillable`.
        #[cfg(not(unix))]
        {
            self.kill_root()
                .map(drop)
                .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper()))
        }
    }

    /// Hard-kill the root through its handle ([`Sent::Gone`](crate::signal::Sent) once it has exited
    /// or been reaped), with the OS's error as it gave it.
    pub(crate) fn kill_root(&self) -> std::io::Result<crate::signal::Sent> {
        self.proc.signal(crate::signal::Sig::Kill).map_err(Error::into_io)
    }

    /// Whether the root is running, read without reaping it, for the elevation front's gates.
    #[cfg(unix)]
    fn root_running(&self) -> std::io::Result<bool> {
        let peeked = self.proc.hold(self.id.pid()).peek().map_err(Error::into_io)?;
        Ok(matches!(peeked, crate::os_process::child::PeekOutcome::Running))
    }

    /// [`kill`](Child::kill), reporting whether a signal was sent (see [`Sent`](crate::signal::Sent)).
    #[cfg(unix)]
    pub(crate) fn kill_sent(&self) -> Result<crate::signal::Sent, Error> {
        let gate = self.kill_gate();
        // A front's refusal is permanent and says nothing of the pid, so it outranks a root launchd
        // holds, which the caller can do nothing about either way.
        if !matches!(gate, crate::elevation::front::Gate::Closed(_)) {
            self.refuse_unpinned("kill", None)?;
        }
        self.kill_sent_gated(gate)
    }

    /// Refuse `op` while the root is not pinned by this process (macOS: launchd holds its zombie).
    /// `earlier` names what the same operation sent before. See [`crate::signal::refuse_unpinned`].
    #[cfg(unix)]
    pub(crate) fn refuse_unpinned(&self, op: &str, earlier: Option<&str>) -> Result<(), Error> {
        crate::signal::refuse_unpinned(self.id.pid(), op, earlier, || self.proc.state())
    }

    /// Whether launchd holds the root's zombie now (macOS; `false` elsewhere, where the state is
    /// not read).
    pub(crate) fn root_is_unpinned(&self) -> bool {
        #[cfg(unix)]
        return crate::signal::is_unpinned(|| self.proc.state());
        #[cfg(not(unix))]
        false
    }

    /// [`kill_sent`](Child::kill_sent) under `gate`, this child's [`kill_gate`](Child::kill_gate)
    /// read by the caller.
    #[cfg(unix)]
    pub(crate) fn kill_sent_gated(&self, gate: crate::elevation::front::Gate) -> Result<crate::signal::Sent, Error> {
        use crate::elevation::front::Gate;
        match gate {
            Gate::Open => {}
            // An exit is permanent, so a refused signal to an exited front changes nothing.
            Gate::Exited => {
                return match self.kill_root() {
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        log::debug!("the kill of exited front pid {} was refused ({e})", self.id.pid());
                        Ok(crate::signal::Sent::Delivered)
                    }
                    other => other.map_err(Error::Io),
                }
            }
            // Nothing is signalled after the cgroup kill: it could only be refused.
            Gate::CgroupOnly => {
                // A cgroup kill names no group by the root's pid, so no root is given.
                debug_assert!(self.attached.is_cgroup(), "CgroupOnly is a front in a cgroup");
                self.attached
                    .hard_kill_marking(&self.tree_killed, &crate::containment::GroupRoot::none())
                    .map_err(|e| crate::elevation::front::cgroup_kill_failed(self.front, self.id.pid(), e))?;
                self.cgroup_kill_reached()?;
                return Ok(crate::signal::Sent::Delivered);
            }
            Gate::Closed(unkillable) => return Err(unkillable),
        }
        // A plain child returns Ok(()) once exited. EPERM on an elevated wrapper child becomes
        // the typed `Unkillable`.
        self.kill_root()
            .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper()))
    }

    /// A drop's end for an elevation front it cannot be sure its cgroup kill reached: its leaf is
    /// torn down (killed through, with a failed kill retried, drained, removed), and then the front
    /// is looked at through [`tear_down`](OwnedChild::tear_down), which waits for it only if its
    /// place says the kill reached it. The leaf's subtree is captured while the leaf exists, since
    /// it places the front once the leaf is gone. How the look went is worded by [`word_front`],
    /// with `why`, under `caller`'s name and `disposition`.
    #[cfg(unix)]
    fn tear_down_leaf_and_look_at_front(
        &mut self,
        caller: TeardownCaller,
        why: &dyn std::fmt::Display,
        disposition: Disposition,
    ) -> TeardownOutcome {
        use crate::child::owned::teardown::Reach;

        #[cfg(target_os = "linux")]
        let subtree = match &self.attached {
            crate::containment::Attached::Cgroup(leaf) => leaf.subtree().map(Some),
            _ => Ok(None),
        };
        drop(std::mem::take(&mut self.attached));
        #[cfg(target_os = "linux")]
        let (subtree, unreadable) = match subtree {
            Ok(subtree) => (subtree, None),
            Err(e) => (None, Some(e)),
        };
        #[cfg(target_os = "linux")]
        let reach = match unreadable {
            Some(e) => Err(e),
            None => Ok(subtree.as_ref().map(|subtree| subtree as &dyn Reach)),
        };
        #[cfg(not(target_os = "linux"))]
        let reach: Result<Option<&dyn Reach>, std::io::Error> = Ok(None);
        let torn = self.proc.tear_down(Some(self.id), TeardownKind::Look(reach), None);
        word_front(caller, self.id.pid(), why, disposition, torn)
    }

    /// What a forced kill of this child may do (see [`crate::elevation::front`]).
    #[cfg(unix)]
    fn kill_gate(&self) -> crate::elevation::front::Gate {
        let pid = self.id.pid();
        crate::elevation::front::kill_gate(
            self.front,
            pid,
            || self.root_running(),
            || self.attached.kill_reaches_across_credentials(pid, self.proc.pidfd()),
        )
    }

    /// Whether a cgroup kill just written reached this child's tracked process, a front (see
    /// [`crate::elevation::front::cgroup_kill_reached`]).
    #[cfg(unix)]
    fn cgroup_kill_reached(&self) -> Result<(), Error> {
        let pid = self.id.pid();
        crate::elevation::front::cgroup_kill_reached(
            self.front,
            pid,
            || self.root_running().map(|running| !running),
            || self.attached.cgroup_names(pid, self.proc.pidfd()),
        )
    }

    /// What a `SIGTERM` to this child may do (see [`crate::elevation::front`]).
    #[cfg(unix)]
    fn terminate_gate(&self) -> crate::elevation::front::Gate {
        crate::elevation::front::terminate_gate(self.front, self.id.pid(), || self.root_running())
    }

    /// Hard-kill the contained tree. Requires an actionable containment mechanism
    /// (errors `Unsupported` otherwise — use `kill()` for a lone process).
    ///
    /// **macOS `Containment::FdMarker` is stricter than the paragraph above:** `Err` there
    /// means at least one known or suspected tree member could not be assessed or signalled
    /// this call — not merely "some descendant's identity transiently failed to resolve and
    /// was left running," which the rest of this doc comment calls acceptable. The tree may
    /// still be partially alive after such an `Err`. This is a real, expected outcome on a
    /// real host (e.g. a member that `exec`s a setuid binary becomes unqueryable), not a bug
    /// to route around by ignoring the `Result`.
    ///
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
    /// **Kernel requirement.** Under [`CgroupV2`](crate::Containment::CgroupV2) the kill needs
    /// the `cgroup.kill` fork-race fix: see [`Command::kill_on_drop`](crate::Command::kill_on_drop).
    /// Without it, `wait_tree` also waits for a child that escaped the kill.
    ///
    /// **An elevated child behind a front** (see [`kill`](Child::kill)) is reached only through a
    /// cgroup that holds it, and nothing is signalled after its kill. Under any other mechanism, or
    /// once it has left the cgroup, this sends nothing and returns
    /// [`ElevationErrorKind::Unkillable`](crate::error::ElevationErrorKind::Unkillable).
    ///
    /// **macOS, a root the handle cannot vouch for.** If the root is `Unpinned` (launchd holds its
    /// zombie, see [`kill`](Child::kill)) or `Unknown`, nothing that names the tree by the root's
    /// number runs: no `killpg`, no walk from its pid, no kill of the root by pid, and no handle
    /// backstop. An fd marker still kills its marker holders, which are named by identity (an
    /// `Unpinned` root is an exited zombie and is left alone), and the call is `Ok` only if every
    /// holder was reached. Any other mechanism has nothing left to send, and the call returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) saying that nothing was sent and what
    /// was skipped. The handle backstop reads the root's state again: a root orphaned during the sweep
    /// is an exited zombie, so the backstop is skipped and the sweep's answer stands.
    ///
    /// **On Linux 6.9+, a process group whose root is reaped, or whose root's handle cannot say,** is
    /// still named exactly by the root's pidfd, whoever reaped it: while the group has a member it is
    /// killed through the pidfd as usual, and each member's resend checks the group the same way
    /// first (below). A process listed by the group's number once the group has no member left is
    /// in another group that took the number, and is sent nothing. A root reaped elsewhere, or after
    /// this handle's own reap with its pid unreadable, whose group has no member left has no tree
    /// left: nothing is sent, and the call is `Ok`.
    ///
    /// **A root reaped by something else.** A process group, and a macOS fd marker's group and
    /// walk, are named by the root's pid. If the root's own handle shows it was reaped by another
    /// reaper in the process, that pid may name another process: nothing is sent by it, and the call
    /// returns [`Error::Unassessable`](crate::error::Error::Unassessable), with a `warn` naming what
    /// it skipped, or the error of a failed marker holders' sweep (below), such as
    /// [`Error::Containment`](crate::error::Error::Containment). A root whose handle cannot say is
    /// answered the same way, except that on Linux the root itself is still signalled through its
    /// pidfd, which names it exactly, and the `warn` says so: `kill_tree` kills it,
    /// [`terminate_tree`](Child::terminate_tree) sends it the `SIGTERM`, and
    /// [`graceful_shutdown_tree`](Child::graceful_shutdown_tree) sends the `SIGTERM`, then the kill if
    /// it is still running after the grace; on macOS it is answered as in the paragraph above. An fd
    /// marker still kills its marker holders, which are named by the pipe they hold, so no pid reuse
    /// redirects the kill.
    ///
    /// **After this handle's own reap.** The root's children were reparented at its exit, so no walk
    /// runs from its pid. Another process at that pid means the group is empty: nothing is sent by
    /// the pid, and the call is `Ok` once every marker holder was reached. A pid that cannot be read
    /// is `Unassessable` as above. A pid that names no process is still signalled as the group's id:
    /// the root's group while a member survives, but once none does, another process may take the
    /// number, and lead a group by it, first. On Linux 6.9+ the root's pidfd shows exactly whether
    /// the group still has a member, so no send by number reaches a group that took the number.
    ///
    /// **A reap after the look.** All of this is decided on one look at the root. A
    /// [`wait`](Child::wait) on another thread is held off from the look until the sweep has sent
    /// what it sends by the root's number. On Linux 6.9+ a process group's signal goes through the
    /// root's pidfd, which names the group exactly, whoever reaps the root. Each send by the group's
    /// number (the `killpg` below 6.9 and on macOS, and the leader's signal) checks the root again
    /// right before it. Each member's resend checks the root, which shows the listing named the
    /// root's group, then the member's own identity right before the send by the member's pid.
    /// Nothing goes out once a check fails: on 6.9+ the root's check asks the pidfd whether the
    /// group still has a member, and elsewhere it asks the root's handle whether the root was reaped
    /// elsewhere. A reap by another reaper between such a check and its send is not seen, and the
    /// send then goes to a number another process may hold; a program with such a reaper should use
    /// [`CgroupV2`](crate::Containment::CgroupV2), whose kill names no pid. An fd marker's walk from
    /// the root's pid checks each process it signals by its identity.
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.kill_tree_after(None)
    }

    /// [`kill_tree`](Self::kill_tree), as a step of an operation that already sent `earlier`, so an
    /// error never claims the whole operation sent nothing.
    pub(crate) fn kill_tree_after(&self, earlier: Option<&str>) -> Result<(), Error> {
        #[cfg(not(unix))]
        let _ = earlier;
        self.require_contained()?;
        // Decided once: the gate is not asked again after the kill, when a killed front may read as
        // neither exited nor in its cgroup. It comes before the root's state: a front
        // that may not be signalled is refused whatever the root's number names.
        #[cfg(unix)]
        let front = match self.kill_gate() {
            crate::elevation::front::Gate::Closed(unkillable) => return Err(unkillable),
            crate::elevation::front::Gate::Open => None,
            crate::elevation::front::Gate::Exited => Some(false),
            crate::elevation::front::Gate::CgroupOnly => Some(true),
        };
        // One look at the root decides: one launchd holds, or one the handle cannot vouch for, is
        // signalled by identity alone, and so is a group named by the root's pid once that pid may
        // name another process. This handle's reaps are held off from the look to the sweep's end.
        #[cfg(unix)]
        let held = self.proc.hold(self.id.pid());
        #[cfg(unix)]
        let group = held.group();
        #[cfg(not(unix))]
        let group = crate::containment::GroupRoot::none();
        #[cfg(unix)]
        if let Some(result) = self
            .tree_call(crate::containment::dispatch::TreeSignal::Kill, "kill_tree", earlier)
            .root_checked(
                || held.state(),
                || {
                    held.signal(crate::signal::Sig::Kill)
                        .map_err(Error::into_io)
                        .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper()))
                },
                &group,
            )
        {
            return result;
        }
        let group_result = self.attached.hard_kill_marking(&self.tree_killed, &group);
        #[cfg(unix)]
        drop(held);
        // A TreeWalk that could not walk killed nothing, and the root's death would strand the
        // descendants beyond a retry: return the error with the tree intact.
        if self.attached.hard_kill_refused_to_walk(&group_result) {
            return group_result;
        }
        // A front in the cgroup: a signal after its kill could only be refused, and whether the kill
        // reached it is read after it. One whose kill failed may still have its program running:
        // left alone. An exited front needs no backstop.
        #[cfg(unix)]
        if let Some(in_cgroup) = front {
            return match group_result {
                Ok(()) if in_cgroup => self.cgroup_kill_reached(),
                Err(e) if in_cgroup => Err(crate::elevation::front::cgroup_kill_failed(
                    self.front,
                    self.id.pid(),
                    e,
                )),
                other => other,
            };
        }
        // Backstop for the TreeWalk mechanism: its hard_kill kills the root by identity,
        // which no-ops if `ProcessId::of` transiently fails to resolve the root — this
        // handle-based kill covers that, so its failure is contract-relevant.
        // Read again: the sweep above can be long, and a root orphaned meanwhile is an exited zombie
        // launchd holds, so there is nothing left for the backstop to kill.
        let backstop = if self.root_is_unpinned() {
            log::debug!(
                "kill_tree({}): launchd holds the root's zombie, so the handle backstop is skipped",
                self.id.pid()
            );
            Ok(())
        } else {
            self.kill_root()
                .map(drop)
                .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper()))
        };
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
    /// unsignaled; `kill_tree` is the guaranteed hard teardown.
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
    /// tree is still running" rather than keying a fallback on the variant alone.
    ///
    /// **macOS `Containment::FdMarker` is stricter than the paragraph above:** `Err` there
    /// means at least one known or suspected tree member could not be assessed or signalled
    /// this call — not merely "some descendant's identity transiently failed to resolve and
    /// was left running," which the rest of this doc comment calls acceptable. The tree may
    /// still be partially alive after such an `Err`. This is a real, expected outcome on a
    /// real host (e.g. a member that `exec`s a setuid binary becomes unqueryable), not a bug
    /// to route around by ignoring the `Result`.
    ///
    /// Attach a console before spawning the tree, or use `kill_tree`, which needs none.
    ///
    /// On the Unix process-group and session mechanisms this returns
    /// [`Error::Containment`](crate::error::Error::Containment) when a live member of the
    /// group refused the signal — a setuid binary in the tree is the ordinary cause. The
    /// tree is still running and this process cannot bring it down.
    ///
    /// In a cgroup v2 leaf, a listed member that got no `SIGTERM` makes this
    /// [`Error::Containment`](crate::error::Error::Containment) if its send failed, else
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) (it could not be pinned or shown to
    /// be in the leaf: a `hidepid`-hidden member of another user before Linux 6.13 or without a
    /// readable leaf id, or a member listed as pid `0` in an unseen pid namespace); one `warn` names
    /// the leaf and pids. [`kill_tree`](Child::kill_tree) still reaches them.
    ///
    /// See [`kill_tree`](Child::kill_tree)'s doc for four things that also apply here: the
    /// `ProcessGroup`/`Session`-only scope of this guarantee (a separate, unfixed gap for
    /// `TreeWalk`), the residual `hidepid` gap on Linux, a root reaped by something else, and a reap
    /// between a check and its send, which may send the `SIGTERM` to a number another process holds.
    ///
    /// **macOS, a root the handle cannot vouch for.** If the root is `Unpinned` (launchd holds its
    /// zombie, see [`kill`](Child::kill)) or `Unknown`, nothing that names the tree by the root's
    /// number runs: no `killpg`, no walk from its pid. An fd marker still signals its marker holders,
    /// which are named by identity (an `Unpinned` root is left alone), and the call is `Ok` only if
    /// every holder was reached. Any other mechanism has nothing left to send, and the call returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) saying that nothing was sent and what
    /// was skipped.
    ///
    /// **Linux, a root whose handle cannot say whether it was reaped.** On 6.9+ a process group
    /// that still has a member is signalled as usual through the root's pidfd, and the call is
    /// `Ok`. Otherwise the root is sent the `SIGTERM` through its pidfd, which names it exactly,
    /// nothing goes out by its number, and the call returns
    /// [`Error::Unassessable`](crate::error::Error::Unassessable), with one `warn` saying so.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
        // One look at the root decides, as for `kill_tree`, and this handle's reaps are held off
        // until the signal is sent.
        #[cfg(unix)]
        let held = self.proc.hold(self.id.pid());
        #[cfg(unix)]
        let group = held.group();
        #[cfg(not(unix))]
        let group = crate::containment::GroupRoot::none();
        #[cfg(unix)]
        if let Some(result) = self
            .tree_call(crate::containment::dispatch::TreeSignal::Term, "terminate_tree", None)
            .root_checked(|| held.state(), || held.signal(crate::signal::Sig::Term), &group)
        {
            return result;
        }
        self.terminate_tree_unchecked(&group)
    }

    /// The group's termination signal, with no look at the root's state but `group`'s own check
    /// before each send by the root's number.
    fn terminate_tree_unchecked(&self, group: &crate::containment::GroupRoot<'_>) -> Result<(), Error> {
        self.attached.terminate(self.id.pid(), group)
    }

    /// A tree call on this child's tree ([`TreeCall`]).
    #[cfg(unix)]
    fn tree_call<'a>(
        &'a self,
        signal: crate::containment::dispatch::TreeSignal,
        op: &'static str,
        earlier: Option<&'a str>,
    ) -> TreeCall<'a> {
        TreeCall {
            attached: &self.attached,
            pid: self.id.pid(),
            signal,
            op,
            earlier,
            killed: &self.tree_killed,
        }
    }

    /// Take the parent's write end of the child's stdin pipe, if configured.
    pub fn stdin(&mut self) -> Option<PipeWriter> {
        self.fd_write_end(Fd::STDIN)
    }

    /// Take the parent's read end of the child's stdout pipe, if configured.
    pub fn stdout(&mut self) -> Option<PipeReader> {
        take_reader(&mut self.pipes, Fd::STDOUT)
    }

    /// Take the parent's read end of the child's stderr pipe, if configured.
    pub fn stderr(&mut self) -> Option<PipeReader> {
        take_reader(&mut self.pipes, Fd::STDERR)
    }

    /// Take the parent's write end of a pipe configured for `fd` (child reads).
    /// Returns `None` if `fd` was not configured as a pipe, or the write end has
    /// already been taken.
    pub fn fd_write_end(&mut self, fd: Fd) -> Option<PipeWriter> {
        match self.pipes.remove(&fd) {
            Some(ParentEnd::Writer(w)) => Some(w),
            other => {
                if let Some(e) = other {
                    self.pipes.insert(fd, e);
                }
                None
            }
        }
    }

    /// Take the parent's read end of a pipe configured for `fd` (child writes).
    /// Returns `None` if `fd` was not configured as a pipe, or the read end has
    /// already been taken.
    pub fn fd_read_end(&mut self, fd: Fd) -> Option<PipeReader> {
        take_reader(&mut self.pipes, fd)
    }

    /// Consume the handle without killing or waiting for the child (opt out of
    /// kill-on-drop). Also disarms the containment resource, so its own `Drop` never kills the
    /// tree itself — though if [`kill_tree`](Self::kill_tree) already returned `Ok` on this
    /// handle, its `Drop` still waits for that kill's drain before giving up the leaf. A
    /// `kill_tree()` that returned `Err` leaves nothing to wait for; see
    /// [`Command::kill_on_drop`](crate::Command::kill_on_drop) for what that leaves behind.
    pub fn detach(mut self) {
        self.attached.disarm();
        self.kill_on_drop = false;
    }

    /// Feed `input` to stdin (if piped) and capture stdout/stderr (if piped),
    /// pumping all streams concurrently to avoid deadlock. Returns the full
    /// `Output` and exit status.
    ///
    /// A child that stops reading stdin ends the input; it is not an error. Errors from the pipes
    /// are returned after the child has been waited for.
    ///
    /// On Unix the streams are served by one `poll` loop on the calling thread, so no thread is
    /// started after the child is. On Windows each stream has a thread of its own, and a thread
    /// that cannot be created panics, until the Windows half of #869 (overlapped pipes, #143)
    /// removes them. As with [`std::process::Command::output`], a grandchild that inherits a pipe
    /// and holds it open keeps `communicate` waiting, whether or not the child has exited.
    pub fn communicate(&mut self, input: Option<&[u8]>) -> Result<crate::Output, Error> {
        #[cfg(test)]
        if let Some(error) = crate::child::spawn::failure::seams::take_pump_failure() {
            return Err(error);
        }
        pump::communicate(self, input)
    }

    pub(crate) fn take_stdin_writer(&mut self) -> Option<PipeWriter> {
        self.stdin()
    }

    pub(crate) fn take_reader(&mut self, fd: Fd) -> Option<PipeReader> {
        take_reader(&mut self.pipes, fd)
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
        crate::containment::windows::job_contains_pid(&self.attached, pid)
    }

    /// Test-only: the marker pipe's kernel identity, for tests that must sweep this tree.
    #[cfg(all(test, target_os = "macos"))]
    #[allow(
        dead_code,
        reason = "awaits a unit-test consumer; not visible to integration tests (pub(crate))"
    )]
    pub(crate) fn test_marker_handle(&self) -> Option<u64> {
        match &self.attached {
            crate::containment::Attached::FdMarker(m) => Some(m.handle()),
            _ => None,
        }
    }

    /// Test-only: the fd-marker descriptor's number in the child, so this crate's OWN
    /// integration tests (`tests/*.rs`, which cannot name a `pub(crate)` item) can be TOLD the
    /// exact number rather than inferring it from ambient process state. A prior version of
    /// `tests/macos_fdmarker.rs` had a testbin mode scan its own open fds for "the one nobody
    /// explains" — passing locally but flaky on CI, where the runner hands the process extra
    /// inherited descriptors the scan could not tell apart from the marker (#59). This is the
    /// crate's own bookkeeping, not a guess: `None` if `self` is not `Attached::FdMarker`.
    /// `#[doc(hidden)]`: not public API, present only for this crate's own `tests/` binaries.
    #[doc(hidden)]
    #[cfg(target_os = "macos")]
    pub fn test_fdmarker_fd(&self) -> Option<i32> {
        match &self.attached {
            crate::containment::Attached::FdMarker(m) => Some(m.own_fd()),
            _ => None,
        }
    }

    /// Test-only: force the FdMarker mechanism's process-group id, so a test can drive
    /// `containment::unix::signal_group`'s real `pgid <= 0` guard — a real,
    /// privilege-free `Error::Unassessable { source: None, .. }` outcome, not a synthetic
    /// `Error` value — through this crate's own public `kill_tree`/`terminate_tree`/`Drop`
    /// path and `is_teardown_mechanism_failure` below. Exists because a live cross-uid
    /// refuser (the `Error::Containment` scenario) needs real root to construct at all — see
    /// `tests/group_teardown_setuid.rs`'s own module docs for why that is not reliably
    /// provisionable on macOS (SIP) — and because calling `Marker::hard_kill`/`terminate`
    /// directly, the way `fdmarker_tests.rs` otherwise does, bypasses `dispatch.rs`'s
    /// `Attached::FdMarker` arm entirely: exactly where an earlier version of this fix
    /// laundered `Error::Containment` into `Error::Io` without any test noticing.
    ///
    /// Panics if `self` is not `Attached::FdMarker` — a misuse of this seam by the caller,
    /// not a case to silently no-op past.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn test_force_fdmarker_pgid(&mut self, pgid: i32) {
        match &mut self.attached {
            crate::containment::Attached::FdMarker(m) => m.force_pgid_for_test(pgid),
            other => panic!("test_force_fdmarker_pgid called on a non-FdMarker child: {other:?}"),
        }
    }

    /// The root a `TreeWalk` attachment walks from.
    #[cfg(all(test, unix))]
    pub(crate) fn test_treewalk_root(&self) -> Option<ProcessId> {
        match &self.attached {
            crate::containment::Attached::TreeWalk(root) => Some(*root),
            _ => None,
        }
    }

    /// The root an fd marker's ppid-walk channel starts from.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn test_marker_root(&self) -> Option<ProcessId> {
        match &self.attached {
            crate::containment::Attached::FdMarker(m) => m.root(),
            _ => None,
        }
    }
}

/// Whether the root has been reaped, from its inputs: this handle's own reap, or the root's number
/// reading `Gone` or as another process.
#[cfg(unix)]
pub(crate) fn root_reaped(own_reap: bool, id: ProcessId, now: crate::identity::Resolved<ProcessId>) -> bool {
    own_reap
        || match now {
            crate::identity::Resolved::Found(now) => now != id,
            crate::identity::Resolved::Gone => true,
            crate::identity::Resolved::Unknown => false,
        }
}

#[cfg(unix)]
pub(crate) fn root_identity_now(pid: crate::identity::RawPid) -> crate::identity::Resolved<ProcessId> {
    #[cfg(test)]
    if let Some(forced) = fault::take_forced_root_read() {
        return forced;
    }
    ProcessId::of(pid)
}

/// Test seam for [`root_identity_now`]. Thread-local, with an RAII reset.
#[cfg(all(test, unix))]
pub(crate) mod fault {
    use std::cell::Cell;

    use crate::identity::{ProcessId, Resolved};

    thread_local! {
        static FORCED: Cell<Option<Resolved<ProcessId>>> = const { Cell::new(None) };
    }

    /// The next drop-time read of a root's number on THIS thread answers `read`. Standing in for
    /// an OS refusal (`Unknown`), which cannot be provoked without a live process on the number.
    pub(crate) fn force_next_root_read(read: Resolved<ProcessId>) -> ForcedRootRead {
        FORCED.with(|f| f.set(Some(read)));
        ForcedRootRead(())
    }

    #[must_use = "the seam is cleared as soon as the guard is dropped"]
    pub(crate) struct ForcedRootRead(());

    impl Drop for ForcedRootRead {
        fn drop(&mut self) {
            FORCED.with(|f| f.set(None));
        }
    }

    /// Every read of a root's number on THIS thread answers `read` until the guard drops, after any
    /// [`force_next_root_read`].
    pub(crate) fn force_root_reads(read: Resolved<ProcessId>) -> ForcedRootReads {
        FORCED_ALWAYS.with(|f| f.set(Some(read)));
        ForcedRootReads(())
    }

    #[must_use = "the seam is cleared as soon as the guard is dropped"]
    pub(crate) struct ForcedRootReads(());

    impl Drop for ForcedRootReads {
        fn drop(&mut self) {
            FORCED_ALWAYS.with(|f| f.set(None));
        }
    }

    thread_local! {
        static FORCED_ALWAYS: Cell<Option<Resolved<ProcessId>>> = const { Cell::new(None) };
    }

    pub(super) fn take_forced_root_read() -> Option<Resolved<ProcessId>> {
        FORCED.with(|f| f.take()).or_else(|| FORCED_ALWAYS.with(|f| f.get()))
    }
}

/// With `kill_on_drop` set (the default), hard-kills the contained tree, then kills and reaps the
/// root. See [`Command::kill_on_drop`](crate::Command::kill_on_drop) for the rest.
///
/// Once the root is reaped the drop skips kills named by its number and warns; see
/// [`Command::kill_on_drop`](crate::Command::kill_on_drop). On Linux 6.9+ a process
/// group is decided by the root's pidfd instead: killed while it has a member left.
///
/// An elevated child behind a front (see [`Child::kill`]) gets no signal of its own while it runs.
/// In a cgroup that holds it, the tree's kill ends it and the drop reaps it. Otherwise, or when
/// that kill fails, the drop tears its leaf down all the same, which kills what the leaf holds and
/// waits for it, and then looks at the front: one that has exited is reaped, and so is one the leaf
/// held, whose place shows it dying, which is waited for. One the leaf did not hold, which is
/// running, is left running and unreaped, with a warning.
impl Drop for Child {
    fn drop(&mut self) {
        if self.kill_on_drop {
            _ = self.tear_down(TeardownCaller::Drop, Disposition::Leave);
        }
    }
}

impl Child {
    /// What [`Drop`] does, now, for a caller that owns the child and fails after its spawn: it says
    /// what became of the child. With [`Disposition::HandBack`], a child whose teardown could not
    /// end it, a refused kill or an elevation front (which is sent none), is given back too if it
    /// still runs.
    ///
    /// Only a `kill_on_drop(false)` child is left whatever `disposition` says. The containment is
    /// torn down as `self` drops, before this returns. On Windows a refused root kill gets the
    /// single look.
    pub(crate) fn tear_down_or_hand_back(
        mut self,
        disposition: Disposition,
    ) -> (crate::error::ChildFate, Option<Unreaped>) {
        use crate::error::ChildFate;

        if !self.kill_on_drop {
            let fate = if self.proc.is_reaped() {
                ChildFate::Reaped
            } else {
                ChildFate::Running { id: Some(self.id) }
            };
            return (fate, None);
        }
        self.kill_on_drop = false;
        let torn = self.tear_down(TeardownCaller::FailedRun, disposition);
        (torn.fate, disposition.hands_back(&torn).then(|| self.into_unreaped()))
    }

    /// The root, as an [`Unreaped`]. `self` has already torn its containment down by dropping.
    fn into_unreaped(mut self) -> Unreaped {
        debug_assert!(!self.kill_on_drop, "a handed-back child is no longer killed on drop");
        let root = self.proc.take().expect("a child handed back still holds its root");
        Unreaped::new(root, Some(self.id))
    }

    /// The kill-on-drop teardown, answering what became of the child. `caller` prefixes the event's
    /// warn, and `disposition` words it for a child that still runs after a refused kill, and for an
    /// elevation front left running. The outcome's `left` is empty: the warn has said it.
    fn tear_down(&mut self, caller: TeardownCaller, disposition: Disposition) -> TeardownOutcome {
        // Hard-kill the contained tree (if any) — on Linux cgroup.kill reaches an elevated
        // subtree — then tear the direct child down. The dispatcher preserves the Unix
        // kill-before-wait order and NEVER blocks on an unkillable elevated child.
        #[cfg(unix)]
        {
            self.drop_unix(caller, disposition)
        }
        #[cfg(not(unix))]
        {
            let mut left = Vec::new();
            let tree = self.attached.hard_kill(&crate::containment::GroupRoot::none());
            if let Err(e) = &tree {
                let orphaned = if self.attached.hard_kill_refused_to_walk(&tree) {
                    "; the root is killed regardless, so its descendants may be orphaned"
                } else {
                    ""
                };
                left.push(format!("contained-tree teardown did not fully succeed: {e}{orphaned}"));
            }
            let mut torn = self.proc.tear_down(
                Some(self.id),
                TeardownKind::Kill {
                    disposition,
                    tree: None,
                },
                None,
            );
            left.extend(torn.left.take());
            if !left.is_empty() {
                log::warn!("{}: {}", caller.label(), left.join("; "));
            }
            torn
        }
    }
}

#[cfg(unix)]
impl Child {
    /// The kill-on-drop teardown, with one report of the event.
    ///
    /// Nothing that names the tree by the root's number runs once the root is reaped, or when its
    /// handle cannot say: the handle's own answer (`RootState`), or the number no longer reading as
    /// this root. Each send by the group's number checks the root again, as for
    /// [`kill_tree`](Child::kill_tree). On Linux 6.9+ a process group is decided by the root's pidfd
    /// ([`Attached::hard_kill_for_drop`](crate::containment::Attached::hard_kill_for_drop)). An
    /// unreaped root stays a zombie, pinning its number, until `tear_down`.
    fn drop_unix(&mut self, caller: TeardownCaller, disposition: Disposition) -> TeardownOutcome {
        use crate::child::drop_report::DropReport;
        use crate::child::owned::teardown::Reach;
        use crate::error::ChildFate;

        // A live elevation front gets no signal of its own: outside a cgroup it is sent nothing and
        // stays running and unreaped, named by the warn; a `HandBack` caller then takes it. The
        // gate comes first, so the look at the root is right before the kill it decides.
        let gate = self.kill_gate();
        let view = crate::containment::DropView::read(caller, self.id, || self.proc.state(), &self.tree_killed);
        let mut report = DropReport::new(&view);
        let cgroup_only = match gate {
            crate::elevation::front::Gate::Closed(unkillable) => {
                // The leaf stays armed: its teardown kills what it holds, a front among it if it is
                // in it. Run now, not at field drop, so the look at the front comes after it.
                let mut torn = self.tear_down_leaf_and_look_at_front(caller, &unkillable, disposition);
                report.left.extend(torn.left.take());
                report.emit(&self.reported);
                return torn;
            }
            gate => matches!(gate, crate::elevation::front::Gate::CgroupOnly),
        };
        // The hold names the root's group. The handle owns the child outright here, so no reap
        // can land; it is dropped before anything below locks the child.
        let held = self.proc.hold(self.id.pid());
        let kill = self.attached.hard_kill_for_drop(&view, &held.group());
        drop(held);
        report.skipped = kill.skipped;
        if let Err(e) = &kill.result {
            // A live member refused, or couldn't be confirmed — visible, not silently
            // discarded, on the RAII teardown path most callers actually hit. A mechanism
            // failure (e.g. `EACCES`/`EIO` on `cgroup.kill`) is a real OS outcome, so it is
            // reported, never asserted on.
            let mut tree = format!("contained-tree teardown did not fully succeed: {e}");
            if self.attached.hard_kill_refused_to_walk(&kill.result) {
                // Unlike `kill_tree`, a drop cannot be retried: the root dies below either way.
                tree.push_str("; the root is killed regardless, so its descendants may be orphaned");
            }
            report.tree = Some(tree);
        }
        // Kill, block until the child has exited, and collect its status here — this handle owns
        // the child outright, and a sync caller owns the thread it is blocking. The async twin
        // (`cosca::tokio::Child`'s `Drop`) does the same on Unix.
        // A reaped root is neither killed nor waited for: its number may name another child by now.
        // Neither is a root this process does not pin (macOS: launchd holds its zombie). Its fate is
        // `Reaped` by this handle's own reap, else `Gone`: nothing was signalled, so a root someone
        // else reaped or launchd holds is `Gone`, as the classifier has it.
        let mut torn = if view.leaves_root_alone() {
            TeardownOutcome::new(if self.proc.is_reaped() {
                ChildFate::Reaped
            } else {
                ChildFate::Gone
            })
        } else {
            if cgroup_only {
                match kill.result.and_then(|()| self.cgroup_kill_reached()) {
                    // The cgroup kill ended it: reap it, sending nothing.
                    Ok(()) => self.proc.reap_after_tree_kill(disposition),
                    // Never waited for. The armed leaf still kills what it holds, retrying a kill
                    // that failed, and the front is looked at once that is done.
                    Err(e) => self.tear_down_leaf_and_look_at_front(caller, &e, disposition),
                }
            } else {
                // The tree kill above may have reached the root: if the root's own kill is refused,
                // that kill is what ends it.
                let tree = kill.result.is_ok().then_some(&self.attached as &dyn Reach);
                self.proc
                    .tear_down(Some(self.id), TeardownKind::Kill { disposition, tree }, None)
            }
        };
        report.left.extend(torn.left.take());
        report.emit(&self.reported);
        torn
    }
}

/// What `caller` says of how its look at the elevation front `pid` (`None`: not known) went (`torn.look`): what the
/// front's [`Settlement`](lifecycle::Settlement) words, a debug line or a leftover for its one warn
/// (a front reaped with its status needs no word), and a leftover for any other. `why` is why the
/// caller did not kill the front. An outcome with no look is returned as it
/// is. A front seen running (left running, or with its place or its leaf's subtree unreadable) is
/// worded as handed back if `disposition` says the caller hands it back, and as left otherwise; no
/// other outcome depends on it.
#[cfg(unix)]
fn word_front(
    caller: TeardownCaller,
    pid: impl Into<Option<u32>>,
    why: &dyn std::fmt::Display,
    disposition: Disposition,
    mut torn: TeardownOutcome,
) -> TeardownOutcome {
    use crate::child::owned::teardown::LookOutcome;

    let label = caller.label();
    let front = pid.into().map_or_else(
        || "the elevation front (pid unknown)".to_owned(),
        |pid| format!("elevation front pid {pid}"),
    );
    let Some(look) = torn.look.take() else {
        return torn;
    };
    // A front seen running whose reach cannot be read: it is not known whether the cgroup kill ended it.
    let unreadable = |cause: String| match disposition {
        Disposition::Leave => {
            format!("{front} is left unreaped: {cause}, so it is not known whether the cgroup kill ended it")
        }
        Disposition::HandBack => format!(
            "{front} is running and unreaped: {cause}, so it is not known whether the cgroup kill \
             ended it; handed back to the caller in the error"
        ),
    };
    torn.left = match look {
        LookOutcome::Ended(settlement) => settlement.leftover(&front, None, disposition, &format!("{label}: ")),
        LookOutcome::LeftRunning => Some(match disposition {
            Disposition::Leave => format!(
                "{front} is left running and unreaped: {why}, and a kill of the front would orphan \
                 the elevated program"
            ),
            Disposition::HandBack => format!(
                "{front} is running and unreaped: {why}, and a kill of the front would orphan \
                 the elevated program; handed back to the caller in the error"
            ),
        }),
        LookOutcome::PlaceUnreadable(e) => Some(unreadable(format!("where it is cannot be read ({e})"))),
        LookOutcome::SubtreeUnreadable(e) => Some(unreadable(format!("its leaf's subtree cannot be read ({e})"))),
    };
    torn
}

fn take_reader(pipes: &mut BTreeMap<Fd, ParentEnd>, fd: Fd) -> Option<PipeReader> {
    match pipes.remove(&fd) {
        Some(ParentEnd::Reader(r)) => Some(r),
        other => {
            if let Some(e) = other {
                pipes.insert(fd, e);
            }
            None
        }
    }
}

impl Command {
    /// Spawn the configured command.
    ///
    /// # Errors
    ///
    /// Every error says whether the program could have started; see [`Error::MayHaveStarted`].
    pub fn spawn(&mut self) -> Result<Child, Error> {
        Ok(spawn::spawn(self)?)
    }
}
