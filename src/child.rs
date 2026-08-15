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

#[path = "child/proc_handle.rs"]
pub(crate) mod proc_handle;
use proc_handle::ProcHandle;

#[path = "child/lifecycle.rs"]
mod lifecycle;

#[path = "child/graceful.rs"]
mod graceful;

#[cfg(test)]
#[path = "child_tests.rs"]
mod child_tests;

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
#[cfg_attr(not(unix), allow(dead_code))] // only called from the `#[cfg(unix)]` debug_assert!s below
                                         // and in `tokio/child.rs`; still unit-tested everywhere.
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
    elevation: Option<crate::elevation::ElevationReport>,
}

impl Child {
    pub(crate) fn from_parts(
        proc: ProcHandle,
        id: ProcessId,
        pipes: BTreeMap<Fd, ParentEnd>,
        kill_on_drop: bool,
        containment: Containment,
        attached: crate::containment::Attached,
    ) -> Child {
        Child {
            proc,
            id,
            pipes,
            kill_on_drop,
            containment,
            attached,
            elevation: None,
        }
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

    /// Guard for the `_tree` operations (single-sourced with the async `Child`).
    fn require_contained(&self) -> Result<(), Error> {
        crate::containment::require_contained(self.containment, &self.attached)
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

    /// Hard-kill the process. Returns `Ok(())` if already dead.
    pub fn kill(&self) -> Result<(), Error> {
        // Both backends return Ok(()) for an already-exited child (std delegates to
        // std::process::Child::kill; the raw path maps an already-dead TerminateProcess to Ok).
        // EPERM/ACCESS_DENIED on an elevated wrapper child becomes the typed `Unkillable`.
        self.proc
            .kill()
            .map_err(|e| crate::elevation::map_elevated_kill_error(e, self.is_elevated_wrapper()))
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
        // reachable on the ORDINARY spawn-then-teardown path for any fast-exiting child, not
        // only via an explicit `wait()` before `kill_tree()`/`terminate_tree()`: `std`'s
        // `SharedChild::new` (inside `Command::spawn`, see `child/spawn.rs`'s own comment on
        // this) can reap a fast-exiting leader itself, before the caller ever gets a `Child`
        // handle back — this assert can therefore fire on the very first call the caller makes,
        // whatever ordering they use. Gated to mechanisms that carry a recyclable pgid: a
        // recycled pgid is meaningless for Cgroup (keyed by an fd), JobObject (no pgid),
        // Delegated (no mechanism), TreeWalk (re-resolves identity per member, immune to this
        // by construction), or a macOS FdMarker whose mode created no pgid — asserting it there
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
        let group_result = self.attached.hard_kill();
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
    /// group and never receives it; only [`kill_tree`](Child::kill_tree) reaches every
    /// member.
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
    /// kill-on-drop). For Job Object containment, `disarm()` clears the
    /// `KILL_ON_JOB_CLOSE` flag before the job handle is released, ensuring the
    /// tree keeps running after `detach`.
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
        crate::containment::windows::job_contains_pid(&self.attached, self.proc.id())
    }

    /// Test-only: the marker pipe's kernel identity, for tests that must sweep this tree.
    #[cfg(all(test, target_os = "macos"))]
    #[allow(dead_code)] // awaits a unit-test consumer; not visible to integration tests (pub(crate))
    pub(crate) fn test_marker_handle(&self) -> Option<u64> {
        match &self.attached {
            crate::containment::Attached::FdMarker(m) => Some(m.handle()),
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
}

/// Whether a `hard_kill`/`terminate` result is still a genuine teardown MECHANISM failure —
/// as opposed to `Error::Containment` (a live member refused the signal), both ORDINARY,
/// expected outcomes after #61's fix and specifically the scenario it exists to report
/// honestly, not bugs. Shared by both `Child::drop` impls (sync here, async in
/// `src/tokio/child.rs`) so the classification has exactly one implementation instead of two
/// hand-copied ones drifting apart.
///
/// **`Error::Unassessable` is NOT uniformly one or the other — it splits on `source`.**
/// `group::decide` produces `source: None` when the group WAS listed successfully but one or
/// more of its individual members could not be confirmed cleared (`check_or_signal` /
/// `check_or_signal_linux_sigkill` returning `Reached::Unknown` for a live-or-unknown member)
/// — an ordinary, expected outcome of the feature this issue adds, not a bug. `signal_group`'s
/// `pgid <= 0` guard ALSO produces `source: None`, for a different but equally ORDINARY
/// reason: a directly and deliberately TESTED input-validation refusal
/// (`kill_group_and_term_group_reject_non_positive_pgid`, Task 5), not a "should never
/// happen" internal contract violation — this function never got as far as attempting
/// anything, the same way `group::decide`'s per-member case never got a confirmable answer.
/// Neither provenance indicates the teardown MECHANISM'S OWN plumbing broke, which is the
/// actual line this classifier draws. `group::state` produces `source: Some(io_error)` when
/// `converge` itself returned `Err` — the listing syscall (`members()`'s `sysctl`/`/proc`
/// scan) failed outright, before any member was even examined. THAT is a failure of the
/// mechanism's own plumbing, the same class as `Error::Io`/`Error::Unsupported`, not a
/// statement about any member or any input — so it, alone, is treated as a mechanism failure
/// here.
pub(crate) fn is_teardown_mechanism_failure(e: &Error) -> bool {
    matches!(e, Error::Io(_) | Error::Unsupported { .. }) || matches!(e, Error::Unassessable { source: Some(_), .. })
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return; // detached / opted out
        }
        // Hard-kill the contained tree (if any) — on Linux cgroup.kill reaches an elevated
        // subtree — then tear the direct child down. The dispatcher preserves the Unix
        // kill-before-wait order and NEVER blocks on an unkillable elevated child.
        let tree = self.attached.hard_kill();
        if let Err(e) = &tree {
            // A live member refused, or couldn't be confirmed — visible, not silently
            // discarded, on the RAII teardown path most callers actually hit. A genuine
            // mechanism failure (is_teardown_mechanism_failure) is a debug_assert instead,
            // matching the async twin's disposition for the identical condition.
            debug_assert!(
                !is_teardown_mechanism_failure(e),
                "contained-tree teardown failed on sync Drop: {e:?}"
            );
            log::warn!("Child::drop: contained-tree teardown did not fully succeed: {e}");
        }
        self.proc.teardown_on_drop();
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
