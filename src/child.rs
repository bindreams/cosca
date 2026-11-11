//! The owned child handle.

use crate::pipe::{ParentEnd, PipeReader, PipeWriter};
use std::collections::BTreeMap;

use crate::child::owned::teardown::Disposition;
use crate::child::spawn::policy::SpawnPolicy;
use crate::command::Command;
use crate::containment::dispatch::{SweepFailure, TeardownCaller};
#[cfg(unix)]
use crate::containment::dispatch::{TreeKillOutcome, TreeSignal};
use crate::containment::{Containment, TerminateOutcome};
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
#[path = "child/drop_teardown.rs"]
mod drop_teardown;
#[cfg(all(unix, any(test, target_os = "linux")))]
use drop_teardown::word_front;
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
pub(crate) mod graceful;

#[cfg(test)]
#[path = "child_tests.rs"]
mod child_tests;

#[cfg(test)]
#[path = "child/hand_back_tests.rs"]
mod hand_back_tests;

#[cfg(all(test, windows))]
#[path = "child/disarm_refused_tests.rs"]
mod disarm_refused_tests;

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
#[path = "child/killed_tree_tests.rs"]
mod killed_tree_tests;

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

/// A spawned child process the crate owns.
#[derive(Debug)]
pub struct Child {
    /// Empty only inside [`tear_down_or_hand_back`](Child::tear_down_or_hand_back), which consumes
    /// the child.
    pub(crate) proc: ChildSlot,
    /// See [`Child::id`].
    pub(crate) id: Option<ProcessId>,
    pub(crate) pipes: BTreeMap<Fd, ParentEnd>,
    pub(crate) kill_on_drop: bool,
    containment: Containment,
    pub(crate) attached: crate::containment::Attached,
    /// Where this handle's tree stands after its kills; see [`crate::containment::TreeKilled`].
    pub(crate) tree_killed: crate::containment::TreeKilled,
    graceful: crate::graceful::GracefulMechanism,
    /// What the spawn achieved; [`Child::front`] reads the front from it.
    elevation: Option<crate::elevation::ElevationReport>,
    /// What a failed-spawn cleanup already warned of, so the drop reports a repeat of it at `debug`
    /// and anything new at `warn`
    /// ([`DropReport::emit`](crate::child::drop_report::DropReport::emit)).
    #[cfg(unix)]
    pub(crate) reported: Vec<crate::child::drop_report::PartKey>,
    /// What the spawn that made this child was told about its teardowns.
    pub(crate) policy: SpawnPolicy,
}

impl Child {
    pub(crate) fn from_parts(
        proc: OwnedChild,
        id: Option<ProcessId>,
        pipes: BTreeMap<Fd, ParentEnd>,
        kill_on_drop: bool,
        attachment: crate::containment::Attachment,
        elevation: Option<crate::elevation::ElevationReport>,
        policy: SpawnPolicy,
    ) -> Child {
        debug_assert!(proc.pid().is_some(), "a child's process has the pid its spawn learned");
        debug_assert!(
            id.is_none_or(|id| proc.pid() == Some(id.pid())),
            "a child's process and identity name one pid"
        );
        Child {
            proc: ChildSlot::new(proc),
            id,
            pipes,
            kill_on_drop,
            containment: attachment.containment,
            attached: attachment.attached,
            tree_killed: Default::default(),
            graceful: attachment.graceful,
            elevation,
            #[cfg(unix)]
            reported: Vec::new(),
            policy,
        }
    }

    /// The process handle, borrowed from `self`.
    #[cfg(windows)]
    pub(crate) fn process_handle(&self) -> std::os::windows::io::RawHandle {
        use std::os::windows::io::AsRawHandle;
        self.proc.os_handle().as_raw_handle()
    }

    /// Commit the spawn: apply `kill_on_drop` to the containment resource (see
    /// [`Attached::honor_kill_on_drop`](crate::containment::Attached::honor_kill_on_drop)).
    ///
    /// A refused disarm (Windows) fails the commit: the still-armed child is torn down as a failed
    /// run's is (handed back in the error if its kill is refused), with the refusal as the cause.
    pub(crate) fn commit_kill_on_drop(mut self) -> Result<Child, crate::child::spawn::SpawnFailure> {
        let Err(refusal) = self.attached.honor_kill_on_drop(self.kill_on_drop) else {
            return Ok(self);
        };
        // Armed, whatever the caller asked for: the teardown leaves a `kill_on_drop(false)` child.
        self.kill_on_drop = true;
        let behind_front = self.front().is_some();
        let (fate, unreaped) = self.tear_down_or_hand_back(crate::child::owned::teardown::Disposition::HandBack);
        Err(crate::child::spawn::failed_after_the_spawn(
            Error::Io(refusal),
            fate,
            unreaped,
            behind_front,
        ))
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
    pub(crate) fn require_contained(&self) -> Result<(), Error> {
        crate::containment::require_contained(self.containment, &self.attached)
    }

    /// Guard for `wait_tree`/`wait_tree_timeout` (single-sourced with the async `Child`).
    pub(crate) fn require_drainable(&self) -> Result<(), Error> {
        crate::containment::require_drainable(self.containment, &self.attached)
    }

    /// This child's stable identity (see [`crate::identity::ProcessId`]), or `None` when the OS
    /// refused to report it at spawn (below Linux 6.9 with no usable `/proc`, or a refused query on
    /// another OS). Such a child is otherwise a child like any other: [`pid`](Self::pid), `wait`,
    /// `kill` and the drop go through its handle. A containment that names its tree by the root's
    /// identity (a tree walk, the macOS fd marker) cannot be had without one, and the spawn fails.
    pub fn id(&self) -> Option<ProcessId> {
        self.id
    }

    /// The pid the child had at spawn. A number only: it does not say the process still holds it
    /// (an identity is [`id`](Self::id)).
    ///
    /// The handle's pid is an `Option` because a handle exists pid-less before the spawn handshake;
    /// a `Child` always has one, asserted in `from_parts`.
    pub fn pid(&self) -> u32 {
        self.proc
            .pid()
            .expect("a Child's process has the pid its spawn learned")
    }

    /// Whether the child is still running, read through the child's own handle, with or without an
    /// [`id`](Self::id): a recycled pid never reads as alive. An exited child that has not been
    /// reaped is dead. [`crate::identity::Liveness::Unknown`] when the OS refuses the query: the
    /// handle of a UAC-elevated child may not be readable by an unelevated parent, and the honest
    /// answer there is not "dead".
    pub fn is_alive(&self) -> crate::identity::Liveness {
        self.proc.liveness().unwrap_or_else(|e| {
            log::debug!(
                "child {}: its liveness could not be read ({report})",
                self.pid(),
                report = crate::error::Report(&e)
            );
            crate::identity::Liveness::Unknown
        })
    }

    /// Block until the child exits, returning its status.
    ///
    /// Reaps the root; a later drop then skips kills named by its number (a tree walk proves its own
    /// root, and is not one of them), so call [`kill_tree`](Child::kill_tree) first to end
    /// descendants (see `Drop`).
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

    /// The elevation front this child is, if any (see [`crate::elevation::front`]). The kill and
    /// `SIGTERM` gates read it.
    pub(crate) fn front(&self) -> Option<crate::elevation::front::Front> {
        self.elevation
            .as_ref()
            .and_then(crate::elevation::ElevationReport::front)
    }

    /// Whether this child's tracked process may run as another user, so a refused signal to it is
    /// `Unkillable` (see [`ElevationReport::may_run_as_another_user`](crate::elevation::ElevationReport::may_run_as_another_user)).
    pub(crate) fn may_run_as_another_user(&self) -> bool {
        self.elevation
            .as_ref()
            .is_some_and(crate::elevation::ElevationReport::may_run_as_another_user)
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
                .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.may_run_as_another_user()))
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
        let peeked = self.proc.hold(self.pid()).peek().map_err(Error::into_io)?;
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
        self.kill_sent_gated("kill", gate)
    }

    /// Refuse `op` while the root is not pinned by this process (macOS: launchd holds its zombie).
    /// `earlier` names what the same operation sent before. See [`crate::signal::refuse_unpinned`].
    #[cfg(unix)]
    pub(crate) fn refuse_unpinned(&self, op: &str, earlier: Option<&str>) -> Result<(), Error> {
        crate::signal::refuse_unpinned(self.pid(), op, earlier, || self.proc.state())
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
    /// read by the caller. `op` names the call in the warns of a cgroup kill that left members.
    #[cfg(unix)]
    pub(crate) fn kill_sent_gated(
        &self,
        op: &str,
        gate: crate::elevation::front::Gate,
    ) -> Result<crate::signal::Sent, Error> {
        use crate::elevation::front::Gate;
        match gate {
            Gate::Open => {}
            // An exit is permanent, so a refused signal to an exited front changes nothing.
            Gate::Exited => {
                return match self.kill_root() {
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        log::debug!(
                            "the kill of exited front pid {} was refused ({report})",
                            self.pid(),
                            report = crate::error::Report(&e)
                        );
                        Ok(crate::signal::Sent::Delivered)
                    }
                    other => other.map_err(Error::Io),
                }
            }
            // Nothing is signalled after the cgroup kill: it could only be refused.
            Gate::CgroupOnly(front) => {
                // A cgroup kill names no group by the root's pid, so no root is given.
                debug_assert!(self.attached.is_cgroup(), "CgroupOnly is a front in a cgroup");
                self.attached
                    .hard_kill_settled(op, &self.tree_killed, None)
                    .map_err(|e| crate::elevation::front::cgroup_kill_failed(front, self.pid(), e))?;
                self.cgroup_kill_reached(front)?;
                return Ok(crate::signal::Sent::Delivered);
            }
            Gate::Closed(unkillable) => return Err(unkillable),
        }
        // A plain child returns Ok(()) once exited. EPERM on an elevated wrapper child becomes
        // the typed `Unkillable`.
        self.kill_root()
            .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.may_run_as_another_user()))
    }

    /// What a forced kill of this child may do (see [`crate::elevation::front`]).
    #[cfg(unix)]
    pub(crate) fn kill_gate(&self) -> crate::elevation::front::Gate {
        let pid = self.pid();
        crate::elevation::front::kill_gate(
            self.front(),
            pid,
            || self.root_running(),
            || self.attached.kill_reaches_across_credentials(pid, self.proc.pidfd()),
        )
    }

    /// Whether a cgroup kill just written reached this child's tracked process, the `front` (see
    /// [`crate::elevation::front::cgroup_kill_reached`]).
    #[cfg(unix)]
    fn cgroup_kill_reached(&self, front: crate::elevation::front::Front) -> Result<(), Error> {
        let pid = self.pid();
        crate::elevation::front::cgroup_kill_reached(
            front,
            pid,
            || self.root_running().map(|running| !running),
            || self.attached.cgroup_names(pid, self.proc.pidfd()),
        )
    }

    /// What a `SIGTERM` to this child may do (see [`crate::elevation::front`]).
    #[cfg(unix)]
    pub(crate) fn terminate_gate(&self) -> crate::elevation::front::Gate {
        crate::elevation::front::terminate_gate(self.front(), self.pid(), || self.root_running())
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
    /// kills the root and logs that descendants may be orphaned.) A root that is gone (this handle
    /// reaped it) or no longer holds its pid is `Unassessable` too: no walk ran and nothing was
    /// killed, and a retry cannot work, since the root will not come back.
    ///
    /// On the `TreeWalk` mechanism (on macOS, only where the ppid walk runs instead of the fd
    /// marker), a walk that killed what it could and left a member running is an
    /// [`Error::MemberNotKilled`] naming the first and why: its identity could not be read, or its
    /// kill was refused. The handle keeps the members the walk left: a later `kill_tree`, or the
    /// drop, kills those whose identity was read again, and reports the others again. That holds
    /// whatever the later walk finds, a root that is gone included. Once those members are gone, a
    /// gone root is `Unassessable` on every later call, saying the members an earlier kill left are
    /// gone and the tree could not be walked: the tree cannot be vouched for again. A walk that left
    /// only the root is `Ok` once the handle backstop killed it, but the walk saw the root running
    /// and what it forked meanwhile was never looked for, so the tree is unvouched in the same way:
    /// a later `kill_tree` over the gone root is `Unassessable`, and the drop warns.
    ///
    /// On the Unix process-group and session mechanisms this returns
    /// [`Error::Containment`](crate::error::Error::Containment) when a live member of the
    /// group refused the signal — a setuid binary in the tree is the ordinary cause. The
    /// tree is still running and this process cannot bring it down.
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
    /// `Unpinned` root is an exited zombie and is left alone), and the call is
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) saying what was skipped even when
    /// every holder was reached; a holder that could not be reached is that holder's error. Any other
    /// mechanism has nothing left to send, and the call returns `Unassessable` saying that nothing
    /// was sent and what was skipped. The handle backstop reads the root's state again: a root
    /// orphaned during the sweep is an exited zombie, so the backstop is skipped and the sweep's
    /// answer stands.
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
    /// the pid, and the call is `Ok` once every marker holder was reached. A macOS fd marker with no
    /// group, whose pid names no process, is answered the same way: it has no group to skip. A pid
    /// that cannot be read is `Unassessable` as above, and so is any other pid that names no
    /// process: once the group has no member, another process may take the number, and lead a group
    /// by it, first. Descendants that outlived the reaped root are then not ended: call `kill_tree`
    /// before [`wait`](Child::wait) to end them. A tree this handle already killed is `Ok`.
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
        self.kill_tree_after("kill_tree", None).map_err(|failure| failure.error)
    }

    /// [`kill_tree`](Self::kill_tree) for the operation `op`, as a step of it that already sent
    /// `earlier`, so an error never claims the whole operation sent nothing. `op` names the call in
    /// what it reports. A failure says whether the root is dead all the same ([`SweepFailure`]): a
    /// caller may wait for it before it returns the error.
    pub(crate) fn kill_tree_after(&self, op: &'static str, earlier: Option<&str>) -> Result<(), SweepFailure> {
        #[cfg(not(unix))]
        let _ = earlier;
        self.require_contained()?;
        // Decided once: the gate is not asked again after the kill, when a killed front may read as
        // neither exited nor in its cgroup. It comes before the root's state: a front
        // that may not be signalled is refused whatever the root's number names.
        #[cfg(unix)]
        let front = match self.kill_gate() {
            crate::elevation::front::Gate::Closed(unkillable) => return Err(unkillable.into()),
            crate::elevation::front::Gate::Open => None,
            crate::elevation::front::Gate::Exited => Some(None),
            crate::elevation::front::Gate::CgroupOnly(front) => Some(Some(front)),
        };
        // The mechanism looks at the root right before it sends by the root's number. This handle's
        // reaps are held off from the look to the end of the sweep's sends.
        #[cfg(unix)]
        let held = self.proc.hold(self.pid());
        #[cfg(unix)]
        let root: Option<&dyn crate::containment::Root> = Some(&held);
        #[cfg(not(unix))]
        let root: Option<&dyn crate::containment::Root> = None;
        let group_result = self.attached.hard_kill(root);
        #[cfg(unix)]
        let group_result = match group_result {
            // An answer that needs no kill ends the call: no backstop.
            answered @ TreeKillOutcome::Answered(_) => {
                drop(held);
                return self
                    .attached
                    .settle_for_kill_tree(op, &self.tree_killed, answered, false)
                    .map_err(SweepFailure::from);
            }
            TreeKillOutcome::Skipped(skip) => {
                // The root's handle names the root even when its number is reused; its kill ends the
                // root.
                let sent = skip.root_alone.then(|| {
                    held.signal(crate::signal::Sig::Kill)
                        .map_err(Error::into_io)
                        .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.may_run_as_another_user()))
                });
                let root_ended = sent.as_ref().is_some_and(SweepFailure::killed_root);
                let answered =
                    self.skip_call(op, TreeSignal::Kill, earlier)
                        .answer(&self.attached, &self.tree_killed, skip, sent);
                drop(held);
                return answered.map_err(|error| SweepFailure { error, root_ended });
            }
            other => {
                drop(held);
                other
            }
        };
        let group_result = self.attached.unless_unwalked(op, &self.tree_killed, group_result)?;
        // A front in the cgroup: a signal after its kill could only be refused, and whether the kill
        // reached it is read after it. One whose kill failed may still have its program running:
        // left alone. An exited front needs no backstop.
        #[cfg(unix)]
        if let Some(in_cgroup) = front {
            return match (
                self.attached
                    .settle_for_kill_tree(op, &self.tree_killed, group_result, false),
                in_cgroup,
            ) {
                (Ok(()), Some(front)) => self.cgroup_kill_reached(front),
                (Err(left), Some(front)) => Err(crate::elevation::front::cgroup_kill_failed(front, self.pid(), left)),
                (other, None) => other,
            }
            .map_err(SweepFailure::from);
        }
        // Backstop for the TreeWalk mechanism: its hard_kill kills the root by identity,
        // which no-ops if `ProcessId::of` transiently fails to resolve the root — this
        // handle-based kill covers that, so its failure is contract-relevant.
        // Read again: the sweep above can be long, and a root orphaned meanwhile is an exited zombie
        // launchd holds, so there is nothing left for the backstop to kill.
        let (backstop, root_ended) = if self.root_is_unpinned() {
            log::debug!(
                "{op}({}): launchd holds the root's zombie, so the handle backstop is skipped",
                self.pid()
            );
            (Ok(()), true)
        } else {
            SweepFailure::backstop_of(
                self.kill_root()
                    .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.may_run_as_another_user())),
            )
        };
        SweepFailure::of(
            op,
            &self.attached,
            &self.tree_killed,
            group_result,
            backstop,
            root_ended,
        )
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
    /// See [`kill_tree`](Child::kill_tree)'s doc for three things that also apply here: the
    /// residual `hidepid` gap on Linux, a root reaped by something else, and a reap between a check
    /// and its send, which may send the `SIGTERM` to a number another process holds.
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
        // The mechanism looks at the root as for `kill_tree`, and this handle's reaps are held off
        // until the signal is sent.
        #[cfg(unix)]
        let held = self.proc.hold(self.pid());
        #[cfg(unix)]
        let root: Option<&dyn crate::containment::Root> = Some(&held);
        #[cfg(not(unix))]
        let root: Option<&dyn crate::containment::Root> = None;
        let outcome = self.attached.terminate(self.pid(), root);
        #[cfg(unix)]
        {
            let call = self.skip_call("terminate_tree", TreeSignal::Term, None);
            match outcome {
                TerminateOutcome::Sent { result, .. } => result,
                TerminateOutcome::End(skip) | TerminateOutcome::HoldersOnly(skip) => {
                    call.answer(&self.attached, &self.tree_killed, skip, None)
                }
                TerminateOutcome::RootThroughPidfd(skip) => {
                    let sent = held.signal(crate::signal::Sig::Term);
                    call.answer(&self.attached, &self.tree_killed, skip, Some(sent))
                }
            }
        }
        #[cfg(not(unix))]
        match outcome {
            TerminateOutcome::Sent { result, .. } => result,
            _ => unreachable!("only a Unix mechanism skips by the root's number"),
        }
    }

    /// A tree call on this child's tree that skipped what the root's number names ([`SkipCall`]).
    #[cfg(unix)]
    pub(crate) fn skip_call<'a>(
        &self,
        op: &'a str,
        signal: TreeSignal,
        earlier: Option<&'a str>,
    ) -> crate::containment::SkipCall<'a> {
        crate::containment::SkipCall {
            op,
            pid: self.pid(),
            signal,
            earlier,
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
    ///
    /// `Ok` promises that cosca no longer kills the tree: not this handle's drop, and not the
    /// containment resource's close. It makes no promise about a job the caller's own process runs
    /// in (see `breakaway_from_job()`).
    ///
    /// # Errors
    ///
    /// On Windows, the refusal of the OS to clear `KILL_ON_JOB_CLOSE` on the child's Job Object
    /// ([`Error::Io`], with the Win32 code). The disarm comes first, so nothing was consumed: the
    /// child comes back with the error, still armed, and dropping it kills the tree. Retry
    /// `detach`, keep the handle, or kill the tree on purpose. No other platform's disarm can fail.
    /// A child that `kill_on_drop(false)` already disarmed is `Ok` without asking the OS.
    #[allow(
        clippy::result_large_err,
        reason = "the child is handed back untouched for the caller to deal with"
    )]
    pub fn detach(mut self) -> Result<(), (Child, Error)> {
        match self.disarm() {
            Ok(()) => Ok(()),
            Err(refusal) => Err((self, refusal)),
        }
    }

    /// [`detach`](Self::detach) in place: the disarm, which leaves the handle armed if it is refused.
    pub(crate) fn disarm(&mut self) -> Result<(), Error> {
        if !self.kill_on_drop {
            return Ok(());
        }
        self.attached.disarm().map_err(Error::Io)?;
        self.kill_on_drop = false;
        Ok(())
    }

    /// Feed `input` to stdin (if piped) and capture stdout/stderr (if piped),
    /// serving all streams together to avoid deadlock. Returns the full
    /// `Output` and exit status.
    ///
    /// A child that stops reading stdin ends the input; it is not an error. Errors from the pipes
    /// are returned after the child has been waited for.
    ///
    /// `input` of `Some` for a child whose stdin is not piped, or was already taken, is an
    /// [`Error::Io`] of kind `InvalidInput`; no pipe is taken then.
    ///
    /// The streams are served by one loop on the calling thread (`poll` on Unix, overlapped I/O on
    /// Windows), so no thread is started after the child is. As with
    /// [`std::process::Command::output`], a grandchild that inherits a pipe
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
        self.test_job_handle_contains(self.pid())
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
pub(crate) fn root_reaped(own_reap: bool, id: Option<ProcessId>, now: crate::identity::Resolved<ProcessId>) -> bool {
    own_reap
        || match now {
            // With no identity to compare, a number that names a process says nothing: the handle decides.
            crate::identity::Resolved::Found(now) => id.is_some_and(|id| now != id),
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
/// group is decided by the root's pidfd instead: killed while it has a member left. A tree walk
/// proves its root before it walks, so a reaped root, or one its handle cannot vouch for, walks as
/// usual (on Linux).
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
