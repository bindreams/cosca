//! The owned child handle.

use std::collections::BTreeMap;
use std::io::{PipeReader, PipeWriter};

use shared_child::SharedChild;

use crate::command::Command;
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
}

impl Child {
    pub(crate) fn from_parts(
        shared: SharedChild,
        id: ProcessId,
        pipes: BTreeMap<Fd, ParentEnd>,
        kill_on_drop: bool,
    ) -> Child {
        Child {
            shared,
            id,
            pipes,
            kill_on_drop,
        }
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

    /// Take the parent's write end of the child's stdin pipe, if configured.
    pub fn stdin(&mut self) -> Option<PipeWriter> {
        match self.pipes.remove(&Fd::STDIN) {
            Some(ParentEnd::Writer(w)) => Some(w),
            other => {
                if let Some(e) = other {
                    self.pipes.insert(Fd::STDIN, e);
                }
                None
            }
        }
    }

    /// Take the parent's read end of the child's stdout pipe, if configured.
    pub fn stdout(&mut self) -> Option<PipeReader> {
        take_reader(&mut self.pipes, Fd::STDOUT)
    }

    /// Take the parent's read end of the child's stderr pipe, if configured.
    pub fn stderr(&mut self) -> Option<PipeReader> {
        take_reader(&mut self.pipes, Fd::STDERR)
    }

    /// Consume the handle without killing or waiting for the child (opt out of
    /// kill-on-drop; see the [`Drop`] impl below).
    pub fn detach(mut self) {
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
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return; // detached / opted out
        }
        // Hard-kill the lone process (tree-wide kill is Plan 4) and reap so we
        // never leak a zombie/handle. Best-effort: `shared_child`'s kill() and
        // wait() are idempotent and safe after exit, so an already-exited child
        // is fine and a double-call cannot happen (drop runs once).
        //
        // Order matters: kill BEFORE wait. On Unix, reaping (wait) frees the PID
        // for reuse, so signaling (kill) after a reap could hit an unrelated
        // process. (shared_child serializes kill/wait under a lock but does not
        // itself impose this ordering — we do, here.)
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
