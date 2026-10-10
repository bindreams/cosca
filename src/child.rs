//! The owned child handle.

use std::collections::BTreeMap;
use std::io::{PipeReader, PipeWriter};

use crate::command::Command;
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
#[path = "child/proc_handle.rs"]
pub(crate) mod proc_handle;
#[path = "child/shared.rs"]
pub(crate) mod shared;
use proc_handle::ProcHandle;

#[path = "child/lifecycle.rs"]
mod lifecycle;

#[path = "child/graceful.rs"]
mod graceful;

#[cfg(all(target_os = "macos", test))]
impl Child {
    /// The unique id the handle checks its by-pid actions against.
    pub(crate) fn adopted_unique(&self) -> Option<u64> {
        self.proc.adopted_unique()
    }
}

#[cfg(test)]
#[path = "child_tests.rs"]
mod child_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/pid_reuse_tests.rs"]
mod pid_reuse_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "child/kill_tree_view_tests.rs"]
mod kill_tree_view_tests;

#[cfg(all(test, unix))]
#[path = "child/drop_reaped_tests.rs"]
mod drop_reaped_tests;

#[cfg(all(test, unix))]
#[path = "child/root_state_tests.rs"]
mod root_state_tests;

#[cfg(all(test, unix))]
#[path = "child/drop_report_tests.rs"]
mod drop_report_tests;

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

/// True only when there is POSITIVE evidence that a contained root's pid was reaped **and**
/// recycled: it now resolves to a DIFFERENT identity than `original`, and that different
/// identity is confirmed [`Liveness::Alive`](crate::identity::Liveness::Alive) — not merely
/// resolvable, since a not-yet-reaped zombie also resolves. Reaping alone, without a
/// subsequent recycle, is harmless to a pgid-based mechanism: `killpg` on an absent pgid
/// returns `ESRCH`, which `signal_group`/`verify` in `containment::unix` already treat as
/// `Cleared`. [`Existence`](crate::identity::Existence) cannot distinguish these two cases — it
/// collapses "reaped, nothing there yet" and "reaped, a different live process now holds the
/// pid" into the same `Gone` — which is why `kill_tree`/`terminate_tree`'s precondition assert
/// needs this finer, two-value read (a fresh [`Resolved`](crate::identity::Resolved) plus a
/// [`Liveness`](crate::identity::Liveness) reading of whatever it found) instead.
///
/// A pure function of already-resolved values, deliberately: it is unit-tested (`child_tests.rs`)
/// with synthetic `ProcessId`s rather than by racing the kernel's own pid allocator to construct
/// a genuine recycle — that would be synchronizing on luck, not a real test.
#[cfg_attr(
    not(unix),
    allow(
        dead_code,
        reason = "only called from the `#[cfg(unix)]` debug_assert!s below and in `tokio/child.rs`; still unit-tested everywhere"
    )
)]
pub(crate) fn root_pid_was_recycled(
    original: ProcessId,
    current: crate::identity::Resolved<ProcessId>,
    current_liveness: crate::identity::Liveness,
) -> bool {
    match current {
        crate::identity::Resolved::Found(now) => {
            now != original && current_liveness == crate::identity::Liveness::Alive
        }
        crate::identity::Resolved::Gone | crate::identity::Resolved::Unknown => false,
    }
}

/// A spawned child process the crate owns.
#[derive(Debug)]
pub struct Child {
    proc: ProcHandle,
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
    /// A failed-spawn cleanup that left this handle armed already warned about its event, so the
    /// drop that retries reports at `debug` ([`DropReport::emit`](crate::child::drop_report::DropReport::emit)).
    #[cfg(unix)]
    reported: bool,
}

impl Child {
    pub(crate) fn from_parts(
        proc: ProcHandle,
        id: ProcessId,
        pipes: BTreeMap<Fd, ParentEnd>,
        kill_on_drop: bool,
        attachment: crate::containment::Attachment,
    ) -> Child {
        Child {
            proc,
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
            reported: false,
        }
    }

    /// Set by the spawn, from its command (see [`Child::front`](Self#structfield.front)).
    pub(crate) fn set_front(&mut self, front: Option<crate::elevation::front::Front>) {
        self.front = front;
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
        self.proc.wait().map_err(Error::Io)
    }

    /// Return the exit status if the child has already exited.
    pub fn try_wait(&self) -> Result<Option<std::process::ExitStatus>, Error> {
        self.proc.try_wait().map_err(Error::Io)
    }

    /// Is this a wrapper-elevated child a plain parent may be unable to signal?
    /// (`AlreadyElevated` is an ordinary child of an already-root parent — killable.)
    fn is_elevated_wrapper(&self) -> bool {
        matches!(
            self.elevation.as_ref().map(|r| &r.via),
            Some(crate::elevation::ElevatedVia::Wrapped(_) | crate::elevation::ElevatedVia::WindowsUac)
        )
    }

    /// Hard-kill the process. Returns `Ok(())` if already dead. Unlike [`Process::kill`](crate::Process::kill), this
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
            self.proc
                .kill()
                .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper()))
        }
    }

    /// [`kill`](Child::kill), reporting whether a signal was sent (see [`Sent`](crate::signal::Sent)).
    #[cfg(unix)]
    pub(crate) fn kill_sent(&self) -> Result<crate::signal::Sent, Error> {
        self.kill_sent_gated(self.kill_gate())
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
                return match self.proc.kill_sent() {
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        log::debug!("the kill of exited front pid {} was refused ({e})", self.id.pid());
                        Ok(crate::signal::Sent::Delivered)
                    }
                    other => other.map_err(Error::Io),
                }
            }
            // Nothing is signalled after the cgroup kill: it could only be refused.
            Gate::CgroupOnly => {
                self.attached
                    .hard_kill_marking(&self.tree_killed)
                    .map_err(|e| crate::elevation::front::cgroup_kill_failed(self.front, self.id.pid(), e))?;
                self.cgroup_kill_reached()?;
                return Ok(crate::signal::Sent::Delivered);
            }
            Gate::Closed(unkillable) => return Err(unkillable),
        }
        // A plain child returns Ok(()) once exited. EPERM on an elevated wrapper child becomes
        // the typed `Unkillable`.
        self.proc
            .kill_sent()
            .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper()))
    }

    /// A drop's end for an elevation front it cannot be sure its cgroup kill reached: its leaf is
    /// torn down (killed through, with a failed kill retried, drained, removed), and then the front
    /// is looked at, without waiting unless its place says it is dying.
    ///
    /// - Exited: reaped.
    /// - Reading as running: before Linux 6.19 a killed task leaves its cgroup, which ends the
    ///   drain, before it can be collected, so that does not say it was not killed. A killed task
    ///   keeps its cgroup until it is freed, so the front's place does: in the leaf's subtree, with
    ///   a kill through the leaf landed, it is dying (its `SIGKILL` is pending), and is waited for
    ///   and reaped; outside it, or in it with no kill landed, it is running, and is left, as `why`
    ///   says. A place that cannot be read is said so, and is not called running.
    #[cfg(unix)]
    fn tear_down_leaf_and_look_at_front(&mut self, why: &dyn std::fmt::Display) -> Option<String> {
        let pid = self.id.pid();
        // Captured while the leaf exists: it places the front once the leaf is gone.
        #[cfg(target_os = "linux")]
        let subtree = match &self.attached {
            crate::containment::Attached::Cgroup(leaf) => Some(leaf.subtree()),
            _ => None,
        };
        drop(std::mem::take(&mut self.attached));
        #[cfg(all(test, target_os = "linux"))]
        fault::run_before_front_look();
        #[cfg(all(test, target_os = "linux"))]
        let looked = if fault::front_read_as_running() {
            Ok(None)
        } else {
            self.proc.try_wait()
        };
        #[cfg(not(all(test, target_os = "linux")))]
        let looked = self.proc.try_wait();
        let reaped = |status: std::process::ExitStatus| {
            log::debug!("Child::drop: elevation front pid {pid} was killed through its cgroup and reaped ({status})");
            None
        };
        match looked {
            Ok(Some(status)) => reaped(status),
            Ok(None) => {
                #[cfg(target_os = "linux")]
                let note = match subtree {
                    Some(Ok(subtree)) => match subtree.reached(pid, self.proc.pidfd()) {
                        // Dying: its kill is pending, so this wait ends.
                        Ok(true) => match self.wait_for_dying_front() {
                            Ok(status) => reaped(status),
                            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                                log::debug!("Child::drop: elevation front pid {pid} was reaped by someone else");
                                None
                            }
                            Err(e) => Some(format!(
                                "elevation front pid {pid} was killed through its cgroup, and could not be reaped ({e})"
                            )),
                        },
                        Ok(false) => Some(self.front_left_running(why)),
                        Err(e) => Some(format!(
                            "elevation front pid {pid} is left unreaped: where it is cannot be read ({e}), so it is \
                             not known whether the cgroup kill ended it"
                        )),
                    },
                    Some(Err(e)) => Some(format!(
                        "elevation front pid {pid} is left unreaped: its leaf's subtree cannot be read ({e}), so it \
                         is not known whether the cgroup kill ended it"
                    )),
                    None => Some(self.front_left_running(why)),
                };
                #[cfg(not(target_os = "linux"))]
                let note = Some(self.front_left_running(why));
                note
            }
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                log::debug!("Child::drop: elevation front pid {pid} was reaped by someone else");
                None
            }
            Err(e) => Some(format!(
                "elevation front pid {pid} could not be looked at after its cgroup's teardown ({e})"
            )),
        }
    }

    /// The blocking wait for a front placed in its leaf with a kill landed: dying, so it ends.
    #[cfg(target_os = "linux")]
    fn wait_for_dying_front(&self) -> std::io::Result<std::process::ExitStatus> {
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        self.proc.wait()
    }

    #[cfg(unix)]
    fn front_left_running(&self, why: &dyn std::fmt::Display) -> String {
        format!(
            "elevation front pid {} is left running and unreaped: {why}, and a kill of the front would orphan the \
             elevated program",
            self.id.pid()
        )
    }

    /// What a forced kill of this child may do (see [`crate::elevation::front`]).
    #[cfg(unix)]
    fn kill_gate(&self) -> crate::elevation::front::Gate {
        let pid = self.id.pid();
        crate::elevation::front::kill_gate(
            self.front,
            pid,
            || self.proc.is_running(),
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
            || self.proc.is_running().map(|running| !running),
            || self.attached.cgroup_names(pid, self.proc.pidfd()),
        )
    }

    /// What a `SIGTERM` to this child may do (see [`crate::elevation::front`]).
    #[cfg(unix)]
    fn terminate_gate(&self) -> crate::elevation::front::Gate {
        crate::elevation::front::terminate_gate(self.front, self.id.pid(), || self.proc.is_running())
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
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
        // Precondition (a separate, unfixed gap — asserted, not fixed, here): if a pgid-based
        // mechanism's leader pid has been reaped AND RECYCLED onto a DIFFERENT, LIVE process
        // group, `killpg` would signal that unrelated group instead. `carries_recyclable_pgid`
        // (`containment/dispatch.rs`) names exactly the mechanisms this applies to:
        // `Attached::ProcessGroup` (covers both `Containment::ProcessGroup` and
        // `Containment::Session`) and macOS `Attached::FdMarker` when its mode created a pgid
        // (it fires `killpg` on pass 1 of every sweep unconditionally, so the hazard is
        // identical there, not merely similar). Reaping alone is harmless — `killpg` on an
        // absent pgid returns `ESRCH`, which `containment::unix::signal_group`/`verify` already
        // treat as `Cleared` — so this only asserts on POSITIVE evidence of an actual recycle
        // (see `root_pid_was_recycled`), never on a mere reap. That positive-evidence case is
        // reachable without an explicit `wait()` before `kill_tree()`/`terminate_tree()`:
        // `SharedChild::adopt` (inside `Command::spawn`) reaps nothing, but something else in
        // the process can (`SIGCHLD` set to `SIG_IGN`, a `waitpid(-1)` reaper) — and then the
        // kernel may recycle the leader's pid before the caller ever gets a `Child` handle back,
        // so this assert can fire on the very first call the caller makes, whatever ordering
        // they use. Gated to mechanisms that carry a recyclable pgid: a
        // recycled pgid is meaningless for Cgroup (keyed by an fd), JobObject (no pgid),
        // Delegated (no mechanism), TreeWalk (checks after its snapshot that the root still
        // holds its pid, and re-resolves identity per member, so a recycled root pid walks
        // nothing), or a macOS FdMarker whose mode created no pgid — asserting it there
        // would be a false alarm unrelated to what this precondition is about. An OS refusal to
        // answer either resolve (`Resolved::Unknown` / `Liveness::Unknown`) is permitted
        // through: this asserts against POSITIVE evidence of a violation, not against every
        // case we merely couldn't rule out.
        //
        // `#[cfg(unix)]`: `Attached::carries_recyclable_pgid` is itself Unix-only (see
        // `containment/dispatch.rs`) — referencing it unconditionally does not compile on
        // Windows (`cargo check --target x86_64-pc-windows-msvc` confirmed E0599 without this
        // gate). Windows has no pgid to recycle, so there is nothing for this precondition to
        // assert there.
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
                !root_pid_was_recycled(self.id, now, now_liveness)
            },
            "kill_tree/terminate_tree called after the contained root's pid ({}) was reaped and \
             recycled onto a different, live process; a pgid-based mechanism would now signal an \
             unrelated process group",
            self.id.pid()
        );
        // Decided once: the gate is not asked again after the kill, when a killed front may read as
        // neither exited nor in its cgroup.
        #[cfg(unix)]
        let front = match self.kill_gate() {
            crate::elevation::front::Gate::Closed(unkillable) => return Err(unkillable),
            crate::elevation::front::Gate::Open => None,
            crate::elevation::front::Gate::Exited => Some(false),
            crate::elevation::front::Gate::CgroupOnly => Some(true),
        };
        let group_result = self.attached.hard_kill_marking(&self.tree_killed);
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
        let backstop = self
            .proc
            .kill()
            .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper()));
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
    /// See [`kill_tree`](Child::kill_tree)'s doc for two things that also apply here: the
    /// `ProcessGroup`/`Session`-only scope of this guarantee (a separate, unfixed gap for
    /// `TreeWalk`), and the residual `hidepid` gap on Linux.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
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
                !root_pid_was_recycled(self.id, now, now_liveness)
            },
            "kill_tree/terminate_tree called after the contained root's pid ({}) was reaped and \
             recycled onto a different, live process; a pgid-based mechanism would now signal an \
             unrelated process group",
            self.id.pid()
        );
        self.attached.terminate(self.proc.id())
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
    pub fn communicate(&mut self, input: Option<&[u8]>) -> Result<crate::Output, Error> {
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
        self.test_job_handle_contains(self.proc.id())
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
            crate::containment::Attached::FdMarker(m) => Some(m.root()),
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
        static ROOT_TEARDOWNS: Cell<Option<u32>> = const { Cell::new(None) };
    }

    /// From now on every root teardown a drop starts on THIS thread (`ProcHandle::teardown_on_drop`:
    /// a kill by pid and a wait by pid) is counted. It still runs.
    pub(crate) fn record_root_teardowns() -> RootTeardownRecorder {
        ROOT_TEARDOWNS.with(|c| c.set(Some(0)));
        RootTeardownRecorder(())
    }

    #[must_use = "recording stops as soon as the recorder is dropped"]
    pub(crate) struct RootTeardownRecorder(());

    impl RootTeardownRecorder {
        pub(crate) fn count(&self) -> u32 {
            ROOT_TEARDOWNS.with(|c| c.get().expect("the recorder is live"))
        }
    }

    impl Drop for RootTeardownRecorder {
        fn drop(&mut self) {
            ROOT_TEARDOWNS.with(|c| c.set(None));
        }
    }

    pub(crate) fn note_root_teardown() {
        ROOT_TEARDOWNS.with(|c| {
            if let Some(n) = c.get() {
                c.set(Some(n + 1));
            }
        });
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

    pub(super) fn take_forced_root_read() -> Option<Resolved<ProcessId>> {
        FORCED.with(|f| f.take())
    }

    #[cfg(target_os = "linux")]
    thread_local! {
        static BEFORE_FRONT_LOOK: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    }

    /// Run `hook` once on this thread when a drop is about to look at its elevation front, after its
    /// leaf's teardown. On a kernel before 6.19 a task leaves its cgroup before it can be collected,
    /// so a front the leaf's kill ended may still read as running at that point: a test that expects
    /// it ended waits for that here, and releases a front nothing killed, so a mutant fails an
    /// assertion on how the front died instead of hanging.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_before_front_look(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
        crate::oneshot_hook::arm(&BEFORE_FRONT_LOOK, hook)
    }

    #[cfg(target_os = "linux")]
    thread_local! {
        static FRONT_READ_AS_RUNNING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// While the guard lives, a drop's look at its front on this thread reads it as running by its
    /// exit, whatever it did: as on a kernel before 6.19, where a killed front can still be
    /// uncollected when its leaf has drained.
    #[cfg(target_os = "linux")]
    pub(crate) fn read_front_as_running_at_the_look() -> FrontReadAsRunning {
        FRONT_READ_AS_RUNNING.with(|f| f.set(true));
        FrontReadAsRunning(())
    }

    #[cfg(target_os = "linux")]
    #[must_use = "fronts are read as they are again as soon as the guard is dropped"]
    pub(crate) struct FrontReadAsRunning(());

    #[cfg(target_os = "linux")]
    impl Drop for FrontReadAsRunning {
        fn drop(&mut self) {
            FRONT_READ_AS_RUNNING.with(|f| f.set(false));
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn front_read_as_running() -> bool {
        FRONT_READ_AS_RUNNING.with(std::cell::Cell::get)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn run_before_front_look() {
        crate::oneshot_hook::fire(&BEFORE_FRONT_LOOK);
    }
}

/// With `kill_on_drop` set (the default), hard-kills the contained tree, then kills and reaps the
/// root. See [`Command::kill_on_drop`](crate::Command::kill_on_drop) for the rest.
///
/// Once the root is reaped the drop skips kills named by its number and warns; see
/// [`Command::kill_on_drop`](crate::Command::kill_on_drop).
///
/// An elevated child behind a front (see [`Child::kill`]) gets no signal of its own while it runs.
/// In a cgroup that holds it, the tree's kill ends it and the drop reaps it. Otherwise, or when
/// that kill fails, the drop tears its leaf down all the same, which kills what the leaf holds and
/// waits for it, and then looks at the front: one that has exited is reaped, and so is one the leaf
/// held, whose place shows it dying, which is waited for. One the leaf did not hold, which is
/// running, is left running and unreaped, with a warning.
impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return; // detached / opted out
        }
        // Hard-kill the contained tree (if any) — on Linux cgroup.kill reaches an elevated
        // subtree — then tear the direct child down. The dispatcher preserves the Unix
        // kill-before-wait order and NEVER blocks on an unkillable elevated child.
        #[cfg(unix)]
        self.drop_unix();
        #[cfg(not(unix))]
        {
            let tree = self.attached.hard_kill();
            if let Err(e) = &tree {
                let orphaned = if self.attached.hard_kill_refused_to_walk(&tree) {
                    "; the root is killed regardless, so its descendants may be orphaned"
                } else {
                    ""
                };
                log::warn!("Child::drop: contained-tree teardown did not fully succeed: {e}{orphaned}");
            }
            self.proc.teardown_on_drop();
        }
    }
}

#[cfg(unix)]
impl Child {
    /// The kill-on-drop teardown, with one report of the event.
    ///
    /// Nothing that names the tree by the root's number runs once the root is reaped, or when its
    /// handle cannot say: the handle's own answer (`RootState`), or the number no longer reading
    /// as this root. A foreign reap landing after the read is the accepted gap. An unreaped root
    /// stays a zombie, pinning its number, until `teardown_on_drop`.
    fn drop_unix(&mut self) {
        use crate::child::drop_report::DropReport;

        let view = crate::containment::DropView::read("Child::drop", self.id, || self.proc.state(), &self.tree_killed);
        let mut report = DropReport::new("Child::drop", &view);
        // A live elevation front gets no signal of its own: outside a cgroup it is left running,
        // unreaped, and named.
        let cgroup_only = match self.kill_gate() {
            crate::elevation::front::Gate::Closed(unkillable) => {
                // The leaf stays armed: its teardown kills what it holds, a front among it if it is
                // in it. Run now, not at field drop, so the look at the front comes after it.
                report.left.extend(self.tear_down_leaf_and_look_at_front(&unkillable));
                report.emit(self.reported);
                return;
            }
            gate => matches!(gate, crate::elevation::front::Gate::CgroupOnly),
        };
        let kill = self.attached.hard_kill_for_drop(&view);
        report.skipped = kill.skipped;
        if let Err(e) = &kill.result {
            // A live member refused, or couldn't be confirmed — visible, not silently
            // discarded, on the RAII teardown path most callers actually hit. A mechanism
            // failure (e.g. `EACCES`/`EIO` on `cgroup.kill`) is a real OS outcome, so it is
            // reported, never asserted on.
            report
                .left
                .push(format!("contained-tree teardown did not fully succeed: {e}"));
            if self.attached.hard_kill_refused_to_walk(&kill.result) {
                // Unlike `kill_tree`, a drop cannot be retried: the root dies below either way.
                report
                    .left
                    .push("the root is killed regardless, so its descendants may be orphaned".to_owned());
            }
        }
        // Kill, block until the child has exited, and collect its status here — this handle owns
        // the child outright, and a sync caller owns the thread it is blocking. The async twin
        // (`cosca::tokio::Child`'s `Drop`) diverges twice, deliberately: it only signals and
        // never waits, rather than parking a runtime worker, and it must not collect, since tokio
        // owns that child and its own reaping.
        // A reaped root is neither killed nor waited for: its number may name another child by now.
        // Neither is a root this process does not pin (macOS: launchd holds its zombie).
        if !view.leaves_root_alone() {
            if cgroup_only {
                match kill.result.and_then(|()| self.cgroup_kill_reached()) {
                    // The cgroup kill ended it: reap it, sending nothing.
                    Ok(()) => report.left.extend(self.proc.reap_after_tree_kill()),
                    // Never waited for. The armed leaf still kills what it holds, retrying a kill
                    // that failed, and the front is looked at once that is done.
                    Err(e) => report.left.extend(self.tear_down_leaf_and_look_at_front(&e)),
                }
            } else {
                report.left.extend(self.proc.teardown_on_drop());
            }
        }
        report.emit(self.reported);
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
    pub fn spawn(&mut self) -> Result<Child, Error> {
        spawn::spawn(self)
    }
}
