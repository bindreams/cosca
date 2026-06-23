//! The owned child handle.

use std::collections::BTreeMap;
use std::io::{PipeReader, PipeWriter};

use shared_child::SharedChild;

use crate::command::Command;
use crate::containment::Containment;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::stdio::Fd;

#[path = "child/pump.rs"]
pub(crate) mod pump;

#[path = "child/spawn.rs"]
pub(crate) mod spawn;

/// A parent-side pipe end retained for a configured descriptor.
#[derive(Debug)]
pub(crate) enum ParentEnd {
    Reader(PipeReader),
    Writer(PipeWriter),
}

/// A spawned child process the crate owns.
#[derive(Debug)]
pub struct Child {
    shared: SharedChild,
    /// Stable identity resolved immediately after spawn.
    id: ProcessId,
    pipes: BTreeMap<Fd, ParentEnd>,
    kill_on_drop: bool,
    containment: Containment,
    attached: crate::containment::Attached,
}

impl Child {
    pub(crate) fn from_parts(
        shared: SharedChild,
        id: ProcessId,
        pipes: BTreeMap<Fd, ParentEnd>,
        kill_on_drop: bool,
        containment: Containment,
        attached: crate::containment::Attached,
    ) -> Child {
        Child {
            shared,
            id,
            pipes,
            kill_on_drop,
            containment,
            attached,
        }
    }

    /// The tree-teardown mechanism actually established for this child.
    pub fn containment(&self) -> Containment {
        self.containment
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
        self.shared.wait().map_err(Error::Io)
    }

    /// Return the exit status if the child has already exited.
    pub fn try_wait(&self) -> Result<Option<std::process::ExitStatus>, Error> {
        self.shared.try_wait().map_err(Error::Io)
    }

    /// Hard-kill the process. Returns `Ok(())` if already dead.
    pub fn kill(&self) -> Result<(), Error> {
        // shared_child delegates to std::process::Child::kill, which returns
        // Ok(()) for an already-exited child on all platforms.
        self.shared.kill().map_err(Error::Io)
    }

    /// Hard-kill the contained tree (or the lone process if uncontained).
    pub fn kill_tree(&self) -> Result<(), Error> {
        let group_result = self.attached.hard_kill();
        // Also kill the direct child (covers the uncontained / nested-no-group case).
        // Discard the direct-kill result: already-dead is Ok on all platforms, and
        // an error here is superseded by a group-level error from hard_kill above.
        let _ = self.shared.kill();
        group_result
    }

    /// Send the graceful termination signal to the contained group (signal-only;
    /// does not wait or reap). Graceful escalation with a deadline is Plan 5.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.attached.terminate(self.shared.id())
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

    /// Test-only: return whether this child is inside our Job Object.
    /// Uses `IsProcessInJob` against the handle we hold (not "any job").
    /// Exposed outside `cfg(test)` so integration tests (separate compilation unit) can call it.
    #[cfg(windows)]
    pub fn test_job_handle_contains_self(&self) -> bool {
        use crate::containment::Attached;
        use windows::Win32::System::JobObjects::IsProcessInJob;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

        let Attached::JobObject(ref job) = self.attached else {
            return false;
        };
        let Some(job_handle) = job.as_handle() else {
            return false;
        };

        // Open the child process by PID; shared_child doesn't expose its handle.
        // SAFETY: standard Win32 call; handle closed below.
        let process_handle = unsafe {
            match OpenProcess(PROCESS_QUERY_INFORMATION, false, self.shared.id()) {
                Ok(h) => h,
                Err(_) => return false,
            }
        };

        let mut in_job = windows::core::BOOL(0);
        // SAFETY: both handles are valid for the duration of the call.
        let ok = unsafe { IsProcessInJob(process_handle, Some(job_handle), &mut in_job) };
        // SAFETY: process_handle was opened above and must be closed.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(process_handle);
        }
        ok.is_ok() && in_job.as_bool()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return; // detached / opted out
        }
        // Hard-kill the contained tree (if any) then also the direct child, then reap.
        // Order matters on Unix: kill BEFORE wait (reaping frees the PID).
        let _ = self.attached.hard_kill();
        let _ = self.shared.kill();
        let _ = self.shared.wait();
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
