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

/// A parent-side pipe end retained for a configured descriptor.
#[derive(Debug)]
pub(crate) enum ParentEnd {
    Reader(PipeReader),
    Writer(PipeWriter),
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

    // Consumed by the sync/async POSIX spawn arms (a later elevation-plan task); the
    // rewrite that produces the report lands here first.
    #[allow(dead_code)]
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

    /// Whether the child is still running.
    pub fn is_alive(&self) -> bool {
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
    /// If both the group teardown and the handle backstop fail, the group error is returned.
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
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
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
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

    /// Test-only: return whether this child is inside our Job Object (via `IsProcessInJob` against
    /// the handle we hold, not "any job"). Exposed outside `cfg(test)` so integration tests (a
    /// separate compilation unit) can call it.
    #[cfg(windows)]
    pub fn test_job_handle_contains_self(&self) -> bool {
        crate::containment::windows::job_contains_pid(&self.attached, self.proc.id())
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return; // detached / opted out
        }
        // Hard-kill the contained tree (if any) — on Linux cgroup.kill reaches an elevated
        // subtree — then tear the direct child down. The dispatcher preserves the Unix
        // kill-before-wait order and NEVER blocks on an unkillable elevated child.
        let _ = self.attached.hard_kill();
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
