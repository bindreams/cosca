//! The owned child handle.

use crate::pipe::{ParentEnd, PipeReader, PipeWriter};
use std::collections::BTreeMap;

use crate::child::owned::teardown::{Disposition, Reach};
use crate::child::spawn::policy::SpawnPolicy;
use crate::command::Command;
use crate::containment::dispatch::{Keeping, SweepFailure, Swept, TeardownCaller, TreeKillOutcome};
use crate::containment::treewalk::WalkToken;
use crate::containment::Containment;
use crate::elevation::front::{AloneStep, KillNeed, KillRootOutcome, RootStep};
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
pub(crate) mod drop_teardown;
#[cfg(unix)]
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
#[path = "child/reap_at_drop_tests.rs"]
mod reap_at_drop_tests;

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

#[cfg(all(test, target_os = "linux"))]
#[path = "child/treewalk_exited_root_tests.rs"]
mod treewalk_exited_root_tests;

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

/// Whether a tree kill reads the members its kill will reach, for the wait that follows it.
#[derive(Clone, Copy)]
enum KillTree {
    Waiting,
    SendOnly,
}

/// What a sweep's kill of the tree leaves for the rest of the sweep when the root's own kill follows
/// it ([`Child::sweep_tree`]).
enum Followed<'a> {
    /// The mechanism skipped the kill: the root's own kill is part of the skip's answer.
    #[cfg(unix)]
    Skipped(crate::containment::Skip, crate::containment::KillWait<'a>),
    /// The root's own kill is the backstop of a walk that was made.
    Backstop {
        walked: TreeKillOutcome,
        wait: crate::containment::KillWait<'a>,
    },
}

/// What a sweep's kill of the tree leaves for the rest of the sweep when no kill of the root follows
/// it ([`Child::sweep_tree`]).
enum Unsent<'a> {
    /// No backstop: `outcome` is settled with what `keeping` says.
    NoBackstop {
        outcome: TreeKillOutcome,
        keeping: Keeping,
        wait: crate::containment::KillWait<'a>,
    },
    /// The mechanism skipped the kill, and the skip leaves the root's handle no kill to send.
    #[cfg(unix)]
    Skipped(crate::containment::Skip, crate::containment::KillWait<'a>),
    /// A walk was made, and launchd holds the root's zombie, so no backstop was sent.
    Unpinned {
        walked: TreeKillOutcome,
        wait: crate::containment::KillWait<'a>,
    },
}

/// A spawned child process the crate owns.
///
/// To act on a process this program did not spawn, hold it with a [`Process`](crate::Process); to
/// name a process exactly, or keep its identity for later, use a [`ProcessId`].
#[derive(Debug)]
pub struct Child {
    /// Empty only inside [`tear_down_or_hand_back`](Child::tear_down_or_hand_back), which consumes
    /// the child.
    pub(crate) proc: ChildSlot,
    /// See [`Child::id`].
    pub(crate) id: Option<ProcessId>,
    pub(crate) pipes: BTreeMap<Fd, ParentEnd>,
    pub(crate) kill_on_drop: bool,
    /// The tree this handle owns, and where it stands after its kills; see [`crate::containment::Tree`].
    pub(crate) tree: crate::containment::Tree,
    /// What the child's cooperative stop does: the caller's own, or [`stop::default`](crate::stop::default).
    pub(crate) stop: crate::stop::StopAction,
    /// What the spawn recorded about the child's console, which the Windows stop functions read.
    #[cfg(windows)]
    pub(crate) console: crate::containment::windows::ConsoleFacts,
    /// What the spawn achieved; the box holds who the tracked process is
    /// ([`OwnedChild::tracked_kind`]).
    elevation: Option<crate::elevation::ElevationReport>,
    /// What a failed-spawn cleanup already warned of, so the drop reports a repeat of it at `debug`
    /// and anything new at `warn`
    /// ([`DropReport::emit`](crate::child::drop_report::DropReport::emit)).
    #[cfg(unix)]
    pub(crate) reported: Vec<crate::child::drop_report::PartKey>,
    /// What the spawn that made this child was told about its teardowns.
    pub(crate) policy: SpawnPolicy,
}

/// What a commit fails with when the disarm of `kill_on_drop` was refused, sync and async alike: the
/// refusal is the cause, and `torn_down` is the teardown that followed it (see
/// [`failed_after_teardown`](crate::child::spawn::failed_after_teardown)).
pub(crate) fn refused_commit(
    refusal: std::io::Error,
    behind_front: bool,
    torn_down: Result<drop_teardown::Torn, Error>,
) -> crate::child::spawn::SpawnFailure {
    crate::child::spawn::failed_after_teardown(Error::Io(refusal), behind_front, torn_down)
}

impl Child {
    #[allow(
        clippy::too_many_arguments,
        reason = "the one construction of a child: each fact a spawn leaves is a parameter, as at every spawn route"
    )]
    pub(crate) fn from_parts(
        proc: OwnedChild,
        id: Option<ProcessId>,
        pipes: BTreeMap<Fd, ParentEnd>,
        kill_on_drop: bool,
        attachment: crate::containment::Attachment,
        elevation: Option<crate::elevation::ElevationReport>,
        policy: SpawnPolicy,
        stop: crate::stop::StopAction,
    ) -> Child {
        debug_assert!(proc.pid().is_some(), "a child's process has the pid its spawn learned");
        debug_assert!(
            id.is_none_or(|id| proc.pid() == Some(id.pid())),
            "a child's process and identity name one pid"
        );
        debug_assert_eq!(
            proc.tracked_kind(),
            elevation.as_ref().map_or(
                crate::elevation::front::TrackedKind::Own,
                crate::elevation::ElevationReport::tracked
            ),
            "the box tracks who the report says the spawn left tracked"
        );
        Child {
            proc: ChildSlot::new(proc),
            id,
            pipes,
            kill_on_drop,
            tree: attachment.tree,
            stop,
            #[cfg(windows)]
            console: attachment.console,
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
    /// [`Tree::honor_kill_on_drop`](crate::containment::Tree::honor_kill_on_drop)).
    ///
    /// A refused disarm (Windows) fails the commit: the still-armed child is torn down as a failed
    /// run's is (handed back in the error if its kill is refused), with the refusal as the cause.
    pub(crate) fn commit_kill_on_drop(mut self) -> Result<Child, crate::child::spawn::SpawnFailure> {
        match self.try_commit_kill_on_drop() {
            Ok(()) => Ok(self),
            Err(refusal) => {
                let behind_front = self.proc.tracked_kind().front().is_some();
                Err(refused_commit(
                    refusal,
                    behind_front,
                    Ok(self.tear_down_refused_commit()),
                ))
            }
        }
    }

    /// The disarm half of [`commit_kill_on_drop`](Self::commit_kill_on_drop): what it asks of the
    /// containment resource, which is bounded work that waits for nothing. A refusal leaves the child
    /// armed, for [`tear_down_refused_commit`](Self::tear_down_refused_commit).
    pub(crate) fn try_commit_kill_on_drop(&mut self) -> std::io::Result<()> {
        self.tree.honor_kill_on_drop(self.kill_on_drop)
    }

    /// The teardown half of [`commit_kill_on_drop`](Self::commit_kill_on_drop): the still-armed child
    /// whose disarm was refused is torn down as a failed run's is (handed back if its kill is
    /// refused). This waits for the child to be reaped.
    pub(crate) fn tear_down_refused_commit(mut self) -> drop_teardown::Torn {
        // Armed, whatever the caller asked for: the teardown leaves a `kill_on_drop(false)` child.
        self.kill_on_drop = true;
        self.tear_down_or_hand_back(crate::child::owned::teardown::Disposition::HandBack)
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
        self.tree.containment()
    }

    /// Guard for the `_tree` operations (single-sourced with the async `Child`).
    pub(crate) fn require_contained(&self) -> Result<(), Error> {
        self.tree.require_contained()
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
    /// The handle's pid is an `Option` because a handle may exist pid-less (a box built over a
    /// pidfd alone); a `Child` always has one, asserted in `from_parts`.
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
    /// Observes the exit and consumes nothing: the root stays a zombie, which pins its number, until
    /// this handle drops (see `Drop`). So a [`kill_tree`](Child::kill_tree) or the drop after `wait`
    /// still names a process group, a session or a macOS marker's group by the root's number, and is
    /// exact, on every platform. A tree walk names no tree by the root's number, and walks nothing
    /// from an exited root, zombie or not. The cost is one process-table slot (and, on Linux, one
    /// `RLIMIT_NPROC` and pids-cgroup charge) per exited handle that has not dropped; a handle that is
    /// leaked (`mem::forget`) leaks its zombie.
    pub fn wait(&self) -> Result<std::process::ExitStatus, Error> {
        self.status_of_reap(self.reap_outcome()?)
    }

    /// The root's unbounded reap, as the wait ended: the exit record, or the foreign verdict
    /// (reaped elsewhere, or a zombie launchd holds), not folded into an error and not warned of.
    pub(crate) fn reap_outcome(&self) -> Result<owned::ChildWaitOutcome, Error> {
        #[cfg(test)]
        if let Some(error) = crate::child::spawn::failure::seams::take_wait_failure() {
            return Err(error);
        }
        lifecycle::wait_to_exit(&self.proc, None)
    }

    /// Return the exit status if the child has already exited.
    pub fn try_wait(&self) -> Result<Option<std::process::ExitStatus>, Error> {
        // One look at the present moment. A zombie launchd holds is the caller's to report.
        self.wait_root(Some(crate::wait::now()), lifecycle::Orphaned::Quiet)
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
        self.kill_after(None)
    }

    /// [`kill`](Child::kill) as a step of an operation that already sent `earlier`, so an error never
    /// claims the whole operation sent nothing: the escalation of a graceful shutdown.
    pub(crate) fn kill_after(&self, earlier: Option<&str>) -> Result<(), Error> {
        #[cfg(unix)]
        {
            self.kill_sent(earlier).map(drop)
        }
        // Returns Ok(()) for an already-exited child (std delegates to std::process::Child::kill;
        // the raw path maps an already-dead TerminateProcess to Ok). ACCESS_DENIED on a UAC child
        // becomes the typed `Unkillable`.
        #[cfg(not(unix))]
        {
            let _ = earlier;
            self.proc.kill_root_only(None).map(drop)
        }
    }

    /// [`kill_after`](Child::kill_after), reporting whether a signal was sent (see [`Sent`](crate::signal::Sent)).
    #[cfg(unix)]
    pub(crate) fn kill_sent(&self, earlier: Option<&str>) -> Result<crate::signal::Sent, Error> {
        // A front's refusal is permanent and says nothing of the pid, so it outranks a root launchd
        // holds, which the caller can do nothing about either way: the rule asks the step only
        // after it refused.
        let killed = self.proc.kill_root(
            Some(&self.tree),
            |_| match self.refuse_unpinned("kill", earlier) {
                Err(refused) => AloneStep::Answered(refused),
                Ok(()) => {
                    debug_assert_eq!(
                        self.containment(),
                        Containment::CgroupV2,
                        "a front the rule leaves to its containment is in a cgroup"
                    );
                    // A cgroup kill names no group by the root's pid, so no root is given.
                    AloneStep::Killed {
                        result: self.tree.kill_settled(None),
                        carry: (),
                    }
                }
            },
            |_| match self.refuse_unpinned("kill", earlier) {
                Err(refused) => RootStep::Answered(refused),
                Ok(()) => RootStep::ThenRoot(()),
            },
        );
        match killed {
            KillRootOutcome::Refused(refused) | KillRootOutcome::Answered(refused) => Err(refused),
            KillRootOutcome::Contained { reached, .. } => reached.map(|()| crate::signal::Sent::Delivered),
            KillRootOutcome::Root { sent, .. } => sent,
        }
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

    /// Hard-kill the contained tree. Requires an actionable containment mechanism
    /// (errors `Unsupported` otherwise — use `kill()` for a lone process).
    ///
    /// **macOS `Containment::FdMarker` is stricter than the paragraph above:** `Err` there
    /// means at least one known or suspected tree member could not be assessed or signalled
    /// this call — not merely "some descendant's identity transiently failed to resolve and
    /// was left running," which the rest of this doc comment calls acceptable. The tree may
    /// still be partially alive after such an `Err`. This is a real, expected outcome on a
    /// real host (e.g. a member that `exec`s a setuid binary becomes unqueryable), not a bug
    /// to route around by ignoring the `Result`. `Err` can also mean the tree was still forking
    /// when the sweep stopped: a process forked during the last pass may be left running.
    ///
    /// The handle backstop, the kill of the root through its own handle, is part of the kill: its
    /// failure is a member left, and the error says so by mechanism.
    ///
    /// - `TreeWalk`: an [`Error::MembersLeft`]. A root the walk left and the backstop could not kill
    ///   either is one [`Error::MemberNotKilled`] whose `source` is an [`Error::Several`] of the
    ///   backstop's failure and the walk's, the backstop first. A backstop that fails after a walk that
    ///   left nothing is a `MembersLeft` of the root alone. A walk that could not be made runs no
    ///   backstop, so the root has no `MemberNotKilled` peer: it is its [`Error::Unassessable`] (or
    ///   `Unsupported`) alone, or a `MembersLeft` of the held members an earlier kill refused that may
    ///   still run (over a running root nothing is killed to find out), and, over a root the handle
    ///   sees exited, of those that survived their kill by identity, with the walk's error beside them.
    /// - Any other mechanism keeps its own error and its variant, with the root's `MemberNotKilled` as
    ///   its peer, below it after its own cause. A kill that left nothing is an [`Error::Containment`]
    ///   over the root's `MemberNotKilled`.
    ///
    /// On the `TreeWalk` mechanism, an [`Error::Unassessable`] (or `Unsupported`) means the
    /// process table could not be read or trusted, so the descendants could not be found: NOTHING
    /// was killed, the root included, and a retry can work. The members the handle holds are the
    /// exception once the handle sees the root exited: no walk reaches anything then, so they are
    /// killed by identity in that call. While it sees the root running, or cannot say, they are kept
    /// for the retry: its walk from the root reaches the ones still under it, and what they forked
    /// since, and its settlement kills by identity the ones reparented meanwhile. (`Drop`
    /// cannot retry, so it kills the held members and the root, and warns that its other
    /// descendants may be orphaned.)
    /// A root whose exit has begun (a zombie, a reaped root or one that no longer holds its pid
    /// included), or whose exit flag cannot be read, is `Unassessable` too: its children are reparented
    /// at its exit, so the walk says nothing of the tree. Members found are killed all the same; with
    /// none found nothing is killed, and a retry can read an unreadable flag. A tree vouched for before
    /// (a graceful shutdown's own complete `SIGTERM` listing, or an earlier kill) stays so.
    ///
    /// On the `TreeWalk` mechanism (on macOS, only where the ppid walk runs instead of the fd
    /// marker), a walk that killed what it could and left members running is an
    /// [`Error::MembersLeft`] of every member, each an [`Error::MemberNotKilled`] naming it and why:
    /// its identity could not be read, or its kill was refused. The handle keeps the members the walk
    /// left, and those a [`terminate_tree`](Child::terminate_tree) or
    /// [`graceful_shutdown_tree`](Child::graceful_shutdown_tree) `SIGTERM` walk reached: a later
    /// `kill_tree`, or the
    /// drop, kills those whose identity was read again, and reports the others again. That holds
    /// whatever the later walk finds, a root that is gone included. A walk that cannot be made kills
    /// nothing of its own (the root stays for a retry's walk of what is still under it), and over a
    /// root the handle sees running it keeps the members held and still answers the ones an earlier
    /// kill refused (above). Once those
    /// members are gone, a gone root is `Unassessable` on every later call, saying the members an earlier kill left are
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
    /// in another group that took the number, and is sent nothing. A root reaped elsewhere, or whose
    /// pid is unreadable, whose group has no member left has no tree left: nothing is sent, and the
    /// call is `Ok`.
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
    /// **After this handle's [`wait`](Child::wait).** The root is still a zombie of this handle, which
    /// pins its number: a process group, a session and a macOS fd marker's group are killed by that
    /// number as for a running root, on every platform. The root's children were reparented at its
    /// exit, so no walk runs from its pid: a tree walk's kill walks nothing from an exited root (it
    /// kills the members it finds, and is `Unassessable` when it finds none). A tree this handle
    /// already killed is `Ok`. The zombie is consumed when the handle drops.
    ///
    /// **A reap after the look.** All of this is decided on one look at the root. A
    /// [`wait`](Child::wait) on another thread consumes nothing, so it cannot free the root's number.
    /// Only a reaper outside the handle can. On Linux 6.9+ a process group's signal goes through the
    /// root's pidfd, which names the group exactly, whoever reaps the root. Each send by the group's
    /// number (the `killpg` below 6.9 and on macOS, and the leader's signal) checks the root again
    /// right before it. Each member's resend opens the member by its identity, then checks the
    /// root, which shows the listing named the root's group, then sends through the member's handle.
    /// Nothing goes out once a check fails: on 6.9+ the root's check asks the pidfd whether the
    /// group still has a member, and elsewhere it asks the root's handle whether the root was reaped
    /// elsewhere. A reap by another reaper between such a check and its send is not seen, and the
    /// send then goes to a number another process may hold; a program with such a reaper should use
    /// [`CgroupV2`](crate::Containment::CgroupV2), whose kill names no pid. An fd marker's walk from
    /// the root's pid checks each process it signals by its identity.
    ///
    /// **`Ok` means every member the kill reached has exited**, and so has the root once its kill
    /// landed: the call waits for them, with no deadline. On macOS "exited" is a zombie or gone, not
    /// merely a fired exit edge, so [`ProcessId::is_alive`](crate::identity::ProcessId::is_alive) never reads
    /// `Alive` for a member afterwards. What it waits on is what its mechanism's
    /// kill reached, and a member forked after the kill's listing is not seen. On a cgroup leaf, a
    /// member another process moves across the leaf's boundary while the call runs is a stated
    /// limit, in both directions. A member found outside the leaf after the kill is taken to have
    /// left before it, so one moved out after the kill reached it is not waited for, though it was
    /// sent `SIGKILL`. A process moved into the leaf after the kill is waited for until it exits,
    /// though it was not killed, as the drop's wait is (see
    /// [`kill_on_drop`](crate::Command::kill_on_drop)). On Linux below 6.9 a
    /// member that was killed and reaped, and whose pid was taken again within its own start tick, is
    /// waited for in its successor's place (a documented limit of the by-identity open there). A
    /// member whose exit cannot be observed (its identity cannot be read, or it cannot be opened or
    /// looked at) is an [`Error::Unassessable`](crate::error::Error::Unassessable) naming it, returned
    /// once the others have been waited for. [`send_kill_tree`](Child::send_kill_tree) is the call
    /// that only sends.
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.kill_tree_after("kill_tree", None, None)
            .wait()
            .map_err(|failure| failure.error)
    }

    /// [`kill_tree`](Self::kill_tree) that sends and does not wait: the tree is killed, and the call
    /// returns once the kill is sent, with the same errors for a kill that could not be sent. `Ok`
    /// says every member was reached, not that any has exited. A caller that needs the members gone
    /// uses [`kill_tree`](Self::kill_tree), or [`wait_tree`](Child::wait_tree) after a send-only
    /// kill, which waits for the tree's drain (on Windows, for each job member a system process
    /// snapshot still names, within the limit stated at [`wait_tree`](Child::wait_tree)).
    pub fn send_kill_tree(&self) -> Result<(), Error> {
        self.send_kill_tree_after("send_kill_tree", None)
            .map_err(|failure| failure.error)
    }

    /// [`kill_tree`](Self::kill_tree) for the operation `op`, as a step of it that already sent
    /// `earlier`, so an error never claims the whole operation sent nothing. `op` names the call in
    /// what it reports. The [`Swept`] has the answer, which says whether the root is dead all the same
    /// on a failure ([`SweepFailure`]), and the wait for what the kill reached: a caller that waits
    /// [`wait`](Swept::wait)s, and one that sends alone takes the [`answer`](Swept::answer).
    ///
    /// `call`: the `graceful_shutdown_tree` call whose complete `SIGTERM` walk the sweep may stand on
    /// ([`TreeKilled::settle`](crate::containment::dispatch::TreeKilled::settle)); `None` for every
    /// other caller.
    pub(crate) fn kill_tree_after(
        &self,
        op: &'static str,
        earlier: Option<&str>,
        call: Option<&WalkToken>,
    ) -> Swept<'_> {
        self.sweep(op, earlier, call, KillTree::Waiting)
    }

    /// [`kill_tree_after`](Self::kill_tree_after) for a caller that sends and does not wait: the tree
    /// is killed without reading its members first, and the answer is what the kill left.
    pub(crate) fn send_kill_tree_after(&self, op: &'static str, earlier: Option<&str>) -> Result<(), SweepFailure> {
        self.sweep(op, earlier, None, KillTree::SendOnly).answer()
    }

    /// The sweep behind both: the kill, its settlement and the root's backstop. Only the
    /// [`Waiting`](KillTree::Waiting) one reads the members its kill will reach.
    fn sweep(&self, op: &'static str, earlier: Option<&str>, call: Option<&WalkToken>, kind: KillTree) -> Swept<'_> {
        #[cfg(not(unix))]
        let _ = earlier;
        if let Err(e) = self.require_contained() {
            return Swept::unwaited(op, Err(e.into()));
        }
        // The mechanism looks at the root right before it sends by the root's number, and sends the
        // root its own signal through this handle.
        let root_handle = self.proc.hold(self.pid());
        #[cfg(unix)]
        let reach: Option<&dyn Reach> = Some(&self.tree);
        #[cfg(not(unix))]
        let reach: Option<&dyn Reach> = None;
        // The rule decides once, before the tree is killed: a front that may not be signalled is
        // refused whatever the root's number names, and its tree is not killed.
        let root: Option<&dyn crate::containment::Root> = Some(&root_handle);
        // What the settlement kills again is waited for with what the send reached.
        let kill_tree = || match kind {
            KillTree::Waiting => self.tree.kill(root).split(),
            KillTree::SendOnly => (self.tree.send_kill(root), crate::containment::KillWait::none()),
        };
        let killed = self.proc.kill_root(
            reach,
            // A front in the cgroup: its kill is the only one, and it is settled before the rule reads
            // whether it reached the front.
            |_| {
                let (group_result, mut wait) = kill_tree();
                let settled = self.tree.settle_for_kill_tree(group_result, false, Keeping::Nothing);
                wait.reaching(settled.killed_again);
                AloneStep::Killed {
                    result: settled.answer,
                    carry: wait,
                }
            },
            |need| {
                let (group_result, wait) = kill_tree();
                self.sweep_tree(need, group_result, wait)
            },
        );
        match killed {
            KillRootOutcome::Refused(refusal) => Swept::unwaited(op, Err(refusal.into())),
            // A signal after the front's cgroup kill could only be refused, and whether the kill reached
            // it was read after it. One whose kill failed may still have its program running: left alone.
            KillRootOutcome::Contained { reached, carry: wait } => {
                Swept::new(op, reached.map_err(SweepFailure::from), wait)
            }
            #[cfg(unix)]
            KillRootOutcome::Root {
                sent,
                carry: Followed::Skipped(skip, wait),
            } => self.skipped_sweep(op, earlier, skip, wait, Some(sent)),
            KillRootOutcome::Root {
                sent,
                carry: Followed::Backstop { walked, wait },
            } => {
                // Backstop for the TreeWalk mechanism: its hard_kill sends the root's kill through this
                // handle, but kills nothing if the walk finds no root or cannot read the process table —
                // this handle-based kill covers that, so its failure is contract-relevant.
                self.backstopped_sweep(op, call, walked, wait, SweepFailure::backstop_of(sent), false)
            }
            // A walk not made runs no backstop: it would end the root a retry walks from. The settlement
            // keeps the members while the root runs and kills them once it has exited.
            KillRootOutcome::Answered(Unsent::NoBackstop { outcome, keeping, wait }) => {
                self.settled_sweep(op, outcome, keeping, wait, std::convert::identity)
            }
            #[cfg(unix)]
            KillRootOutcome::Answered(Unsent::Skipped(skip, wait)) => self.skipped_sweep(op, earlier, skip, wait, None),
            KillRootOutcome::Answered(Unsent::Unpinned { walked, wait }) => {
                log::debug!(
                    "{op}({}): launchd holds the root's zombie, so the handle backstop is skipped",
                    self.pid()
                );
                self.backstopped_sweep(op, call, walked, wait, (Ok(()), true), true)
            }
        }
    }

    /// The end of a sweep whose tree kill the mechanism skipped: `skip`, answered with `sent`, the
    /// root's own kill through its handle (`None`: none was sent).
    #[cfg(unix)]
    fn skipped_sweep<'a>(
        &'a self,
        op: &'static str,
        earlier: Option<&str>,
        skip: crate::containment::Skip,
        mut wait: crate::containment::KillWait<'a>,
        sent: Option<Result<crate::signal::Sent, Error>>,
    ) -> Swept<'a> {
        // The root's handle names the root even when its number is reused; its kill ends the root.
        let root_ended = sent.as_ref().is_some_and(SweepFailure::killed_root);
        let answered = self
            .skip_call(op, crate::signal::Sig::Kill, earlier)
            .answer(&self.tree, skip, sent);
        wait.reaching(answered.killed_again);
        Swept::new(
            op,
            answered.answer.map_err(|error| SweepFailure { error, root_ended }),
            wait.with_root(self.proc.os_process(), self.pid(), root_ended),
        )
    }

    /// The end of a sweep whose walk was made: `walked` settled with the root's backstop, `backstop`
    /// and `root_ended` as [`SweepFailure::backstop_of`] gives them (`Ok(())` and `true` where launchd
    /// holds the root's zombie and none was sent: `unpinned`).
    fn backstopped_sweep<'a>(
        &'a self,
        op: &'static str,
        call: Option<&WalkToken>,
        walked: TreeKillOutcome,
        mut wait: crate::containment::KillWait<'a>,
        (backstop, root_ended): (Result<(), Error>, bool),
        unpinned: bool,
    ) -> Swept<'a> {
        let settled = SweepFailure::of(&self.tree, walked.in_call(call), backstop, self.pid(), root_ended);
        wait.reaching(settled.killed_again);
        // A root launchd holds is not ours to wait on: nothing of ours killed it.
        Swept::new(
            op,
            settled.answer,
            wait.with_root(self.proc.os_process(), self.pid(), root_ended && !unpinned),
        )
    }

    /// What the sweep's kill of the tree (`group_result`, `wait`) leaves for the rest of the sweep, as
    /// the step of [`kill_root`](OwnedChild::kill_root) for a root its own kill may follow: what `need`
    /// says of the root decides it.
    fn sweep_tree<'a>(
        &'a self,
        need: KillNeed,
        group_result: TreeKillOutcome,
        wait: crate::containment::KillWait<'a>,
    ) -> RootStep<Followed<'a>, Unsent<'a>> {
        let without_backstop =
            |outcome, keeping, wait| RootStep::Answered(Unsent::NoBackstop { outcome, keeping, wait });
        #[cfg(unix)]
        let group_result = match group_result {
            answered @ TreeKillOutcome::Answered(_) => return without_backstop(answered, Keeping::Nothing, wait),
            TreeKillOutcome::Skipped(skip) if skip.root_alone => {
                return RootStep::ThenRoot(Followed::Skipped(skip, wait))
            }
            TreeKillOutcome::Skipped(skip) => return RootStep::Answered(Unsent::Skipped(skip, wait)),
            other => other,
        };
        let group_result = match group_result {
            unwalked @ TreeKillOutcome::Unwalked(_) => {
                return without_backstop(unwalked, self.keeping_over_unwalked(), wait);
            }
            walked => walked,
        };
        // An exited front needs no backstop.
        if need == KillNeed::Exited {
            return without_backstop(group_result, Keeping::Nothing, wait);
        }
        // Read again: the sweep above can be long, and a root orphaned meanwhile is an exited zombie
        // launchd holds, so there is nothing left for the backstop to kill.
        if self.root_is_unpinned() {
            RootStep::Answered(Unsent::Unpinned {
                walked: group_result,
                wait,
            })
        } else {
            RootStep::ThenRoot(Followed::Backstop {
                walked: group_result,
                wait,
            })
        }
    }

    /// The end of a sweep that runs no backstop: `outcome` settled (see
    /// [`TreeKilled::settle_for_kill_tree`](crate::containment::dispatch::TreeKilled::settle_for_kill_tree)),
    /// the members that killed again joined to `wait`, and the answer as `answer_of` makes it of the
    /// settlement's.
    fn settled_sweep<'a>(
        &'a self,
        op: &'static str,
        outcome: TreeKillOutcome,
        keeping: Keeping,
        mut wait: crate::containment::KillWait<'a>,
        answer_of: impl FnOnce(Result<(), Error>) -> Result<(), Error>,
    ) -> Swept<'a> {
        let settled = self.tree.settle_for_kill_tree(outcome, false, keeping);
        wait.reaching(settled.killed_again);
        Swept::new(op, answer_of(settled.answer).map_err(SweepFailure::from), wait)
    }

    /// What a walk that was not made leaves, by this handle's own look at the root (one look, no wait,
    /// no reap): the held members are kept while the root runs, and while the look cannot say, for a
    /// walk from it; once it has exited no walk reaches anything, so they are killed in the call. A tree
    /// that holds none is settled the same either way, so the root is not looked at.
    fn keeping_over_unwalked(&self) -> Keeping {
        if !self.tree.holds_members() {
            return Keeping::ForWalkFromRunningRoot;
        }
        match self
            .proc
            .exited_by(crate::wait::deadline_from(std::time::Duration::ZERO))
        {
            Ok(true) => Keeping::Nothing,
            Ok(false) | Err(_) => Keeping::ForWalkFromRunningRoot,
        }
    }

    /// Runs the child's stop action ([`Command::graceful_stop`](crate::Command::graceful_stop);
    /// [`stop::default`](crate::stop::default) when none was set) on the contained tree, to ask the
    /// group to stop. The action is given a [`StopTarget`](crate::StopTarget) that
    /// [covers the tree](crate::StopTarget::covers_tree), and what the call answers is what the action
    /// answers. By default that is `SIGTERM` via `killpg`/cgroup, or `CTRL_BREAK` to the job/console
    /// group. **Signal-only:** does not wait or reap. Requires an actionable containment mechanism
    /// (errors `Unsupported` otherwise). Cooperative best-effort: on the `TreeWalk` mechanism a
    /// descendant whose identity transiently fails to resolve is intentionally left
    /// unsignaled; `kill_tree` is the guaranteed hard teardown.
    ///
    /// What the rest of this documentation says of "the signal" is what the default action does, and
    /// what `stop::send_signal` does on a tree target with its signal. An
    /// action of the caller's own answers as it chooses: the call does nothing else.
    ///
    /// **Windows: what the default actually signals.** `CTRL_BREAK` is delivered to the root's
    /// **process group**, not to the tree. A nested contained descendant that leads its own
    /// group never receives it, so from THIS handle only
    /// [`kill_tree`](Child::kill_tree) reaches every member. The layers this skips are not
    /// beyond a polite shutdown, though: the holder of a nested descendant's own `Child` can
    /// drain it with [`terminate`](Child::terminate) or
    /// [`graceful_shutdown`](Child::graceful_shutdown) before this root is torn down, and a
    /// chain in which each level shuts down its own children drains completely, because a
    /// child that owns a console can politely signal its own group-leading children.
    ///
    /// **A root created with `new_process_group(false)` is refused.** The default action returns
    /// [`Error::Unsupported`](crate::error::Error::Unsupported): nothing is sent, nothing is waited for,
    /// nothing is killed, and the tree keeps running. [`kill_tree`](Child::kill_tree) ends it.
    ///
    /// **And success here does not prove the event was delivered.** A root that shares no
    /// console with the caller is reported as success and reaches nobody — including a root
    /// spawned with [`no_window`](crate::Command::no_window) or
    /// `detached()`, which gets a console of its own. Whether the spawn recorded the child as leading
    /// its group on this process's console is
    /// `StopTarget::leads_group_on_our_console`: what
    /// cosca recorded about the *route* from this process, never an authority on whether a signal will
    /// arrive. It is also not "this child cannot be shut down politely" — a process attached to the
    /// child's own console can deliver the event. The cooperative op returns `Ok` and delivers nothing; the
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
    ///
    /// **`TreeWalk`: a root whose exit has begun** (reaped, a zombie, or still exiting), or whose exit
    /// flag cannot be read, and whose walk finds no member, is
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) with nothing sent: its children were
    /// reparented at its exit, so the walk says nothing of the tree. A walk that finds members signals
    /// them and is `Ok`, but the handle does not take them for the whole tree. The handle holds the
    /// members the walk reached, and a later [`kill_tree`](Child::kill_tree) or the drop kills them by
    /// identity.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
        // A separate `terminate_tree` is no call that sweeps: it holds its members for the next kill.
        self.stop
            .run(&crate::stop::StopTarget::tree(self, crate::stop::TreeCall::SignalOnly))
    }

    /// A tree call on this child's tree that skipped what the root's number names ([`SkipCall`]).
    #[cfg(unix)]
    pub(crate) fn skip_call<'a>(
        &self,
        op: &'a str,
        signal: crate::signal::Sig,
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
    /// kill-on-drop). The handle's end reaps an exited child (on macOS only one this handle's `wait`
    /// saw); one that still runs is left, and becomes a zombie once it exits, since cosca starts no
    /// reaper. Also disarms the containment resource, so its own `Drop` never kills the
    /// tree itself — though after a kill on this handle its `Drop` can still wait for that kill's
    /// drain before giving up the leaf. When it waits, and what it leaves behind, is stated on
    /// [`Command::kill_on_drop`](crate::Command::kill_on_drop).
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
        self.tree.disarm().map_err(Error::Io)?;
        self.kill_on_drop = false;
        Ok(())
    }

    /// Feed `input` to stdin (if piped) and capture stdout/stderr (if piped),
    /// serving all streams together to avoid deadlock. Returns the full
    /// `Output` and exit status.
    ///
    /// A child that stops reading stdin ends the input; it is not an error. Errors from the pipes
    /// are returned after the child has been waited for. When more than one of the wait, the pump
    /// loop and the streams fails, the first (in that order, then stdout, stderr, stdin) is the error,
    /// as it is. Each later one names its stream (`pump`, `stdout`, `stderr` or `stdin`) and joins the
    /// error as a peer (`Error::with_peers_or_warn`).
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
        self.tree.job_contains_for_test(pid)
    }

    /// Test-only: the marker pipe's kernel identity, for tests that must sweep this tree.
    #[cfg(all(test, target_os = "macos"))]
    #[allow(
        dead_code,
        reason = "awaits a unit-test consumer; not visible to integration tests (pub(crate))"
    )]
    pub(crate) fn test_marker_handle(&self) -> Option<u64> {
        self.tree.marker_handle_for_test()
    }

    /// Test-only: the fd-marker descriptor's number in the child, so this crate's OWN
    /// integration tests (`tests/*.rs`, which cannot name a `pub(crate)` item) can be TOLD the
    /// exact number rather than inferring it from ambient process state. A prior version of
    /// `tests/macos_fdmarker.rs` had a testbin mode scan its own open fds for "the one nobody
    /// explains" — passing locally but flaky on CI, where the runner hands the process extra
    /// inherited descriptors the scan could not tell apart from the marker (#59). This is the
    /// crate's own bookkeeping, not a guess: `None` if the child is not contained by an fd marker.
    /// `#[doc(hidden)]`: not public API, present only for this crate's own `tests/` binaries.
    #[doc(hidden)]
    #[cfg(target_os = "macos")]
    pub fn test_fdmarker_fd(&self) -> Option<i32> {
        self.tree.marker_fd_for_test()
    }

    /// Test-only: force the FdMarker mechanism's process-group id, so a test can drive
    /// `containment::unix::signal_group`'s real `pgid <= 0` guard — a real,
    /// privilege-free `Error::Unassessable { source: None, .. }` outcome, not a synthetic
    /// `Error` value — through this crate's own public `kill_tree`/`terminate_tree`/`Drop`
    /// path below. Exists because a live cross-uid
    /// refuser (the `Error::Containment` scenario) needs real root to construct at all — see
    /// `tests/group_teardown_setuid.rs`'s own module docs for why that is not reliably
    /// provisionable on macOS (SIP) — and because calling `Marker::hard_kill`/`terminate`
    /// directly, the way `fdmarker_tests.rs` otherwise does, bypasses the tree's dispatch to
    /// its marker mechanism entirely: exactly where an earlier version of this fix
    /// laundered `Error::Containment` into `Error::Io` without any test noticing.
    ///
    /// Panics if the child is not contained by an fd marker — a misuse of this seam by the caller,
    /// not a case to silently no-op past.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn test_force_fdmarker_pgid(&mut self, pgid: i32) {
        self.tree.force_marker_pgid_for_test(pgid);
    }

    /// The root a `TreeWalk` attachment walks from.
    #[cfg(all(test, unix))]
    pub(crate) fn test_treewalk_root(&self) -> Option<ProcessId> {
        self.tree.walk_root_for_test()
    }

    /// The root an fd marker's ppid-walk channel starts from.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn test_marker_root(&self) -> Option<ProcessId> {
        self.tree.marker_root_for_test()
    }
}

/// Whether the root has been reaped, from its inputs: the handle's own peek showed a reap by another
/// (`handle_reaped`), or the root's number reads `Gone` or as another process.
#[cfg(unix)]
pub(crate) fn root_reaped(
    handle_reaped: bool,
    id: Option<ProcessId>,
    now: crate::identity::Resolved<ProcessId>,
) -> bool {
    handle_reaped
        || match now {
            // With no identity to compare, a number that names a process says nothing: the handle decides.
            crate::identity::Resolved::Found(now) => id.is_some_and(|id| now != id),
            crate::identity::Resolved::Gone => true,
            crate::identity::Resolved::Unknown => false,
        }
}

/// With `kill_on_drop` set (the default), hard-kills the contained tree, then kills and reaps the
/// root. See [`Command::kill_on_drop`](crate::Command::kill_on_drop) for the rest.
///
/// The drop is where the root is reaped, armed or not, and a root that still runs is left. On
/// Linux a root that has exited without a [`wait`](Child::wait) is reaped too. On macOS the
/// consume is by the root's number, so the handle consumes only an exit its own wait saw: an armed
/// drop's teardown waits, so it consumes such a root too, and a disarmed drop leaves it (see
/// [`Command::kill_on_drop`](crate::Command::kill_on_drop)). A root a foreign reaper took leaves
/// the drop's kills named by its number skipped, with a warn; see
/// [`Command::kill_on_drop`](crate::Command::kill_on_drop). On Linux 6.9+ a process group is decided
/// by the root's pidfd instead: killed while it has a member left. A tree walk proves its root
/// before it walks, so a reaped root, or one its handle cannot vouch for, walks as usual (on Linux).
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
    /// # Linux
    ///
    /// The child starts with `SIGPIPE` at its default, as std's does. A binary built with nightly
    /// `-Zon-broken-pipe=error` or `=inherit` still gets that here, where std would pass the parent's
    /// disposition.
    ///
    /// # Errors
    ///
    /// Every error says whether the program could have started; see [`Error::MayHaveStarted`].
    pub fn spawn(&mut self) -> Result<Child, Error> {
        Ok(spawn::spawn(self)?)
    }
}
