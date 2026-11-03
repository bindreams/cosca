//! A foreign process referenced by stable identity. Wraps a `ProcessId` (never a bare
//! pid) and exposes lifecycle / identity / tree — NO stdio (its pipes belong to its
//! real parent).
//! Every operation re-verifies identity. `wait()` is a death-watch yielding no
//! `ExitStatus` (the kernel hands exit status only to the real parent — contrast
//! `Child::wait`).

use std::time::Duration;

use crate::error::Error;
use crate::identity::{Existence, Liveness, ProcessId, RawPid, Resolved};

#[path = "process/graceful.rs"]
mod graceful;

/// Whether a tree query descends recursively or returns only direct children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recursive {
    /// Only direct children (one level).
    No,
    /// All descendants (the whole subtree).
    Yes,
}

/// A handle to a process identified by `(pid, start_token)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Process {
    id: ProcessId,
}

impl Process {
    /// A handle to the process with this identity. Infallible: the caller already holds the
    /// identity, so there is nothing to resolve and nothing that can fail.
    ///
    /// This deliberately does NOT check that the process is still there. Existence is
    /// ephemeral — it can change between this call and the next line — so a verdict bound to
    /// construction is stale the instant it is returned, and gating construction on it would
    /// discard a perfectly good identity whenever the OS merely declined to answer. Ask
    /// [`exists`](Self::exists) or [`is_alive`](Self::is_alive) when you want the answer, as
    /// late as you can.
    pub fn from_id(id: ProcessId) -> Process {
        Process { id }
    }

    /// Resolve the process currently holding `pid`. Fallible, unlike
    /// [`from_id`](Self::from_id): a bare pid is not an identity, so this has to obtain the
    /// start token, and that query can fail. [`Resolved::Gone`] if no process has the pid;
    /// [`Resolved::Unknown`] if the OS refused the query.
    pub fn from_pid(pid: RawPid) -> Resolved<Process> {
        ProcessId::of(pid).map(|id| Process { id })
    }

    /// This process's own handle. Infallible.
    pub fn current() -> Process {
        Process {
            id: ProcessId::current(),
        }
    }

    /// The stable identity (`(pid, start_token)`).
    pub fn id(&self) -> ProcessId {
        self.id
    }

    /// Whether this exact identity still resolves (zombie-*inclusive*; see
    /// [`ProcessId::exists`]). [`Existence::Gone`] also covers a recycled pid — a different
    /// process holding it now is not this one. [`Existence::Unknown`] when the OS refuses the
    /// query; never `Gone` for a process we could not assess.
    pub fn exists(&self) -> Existence {
        self.id.exists()
    }

    /// Whether the process is still running (zombie-exclusive; see [`ProcessId::is_alive`]).
    /// [`Liveness::Unknown`] when the OS refuses the query.
    pub fn is_alive(&self) -> Liveness {
        self.id.is_alive()
    }

    /// Block until the process exits. Death-watch — yields no `ExitStatus` (only the real
    /// parent gets one). Non-reaping. `Err` only on a wait failure; on Linux a refused
    /// `pidfd_open` is `Unsupported` (see [`Error::Unsupported`]).
    pub fn wait(&self) -> Result<(), Error> {
        let exited = crate::os_process::drive::exited_by_id(self.id, None)?;
        debug_assert!(exited);
        Ok(())
    }

    /// Block up to `timeout` for the process to exit. `Ok(true)` = exited; `Ok(false)` =
    /// still alive at expiry. `Duration::ZERO` polls once. Errors as for [`wait`](Self::wait).
    pub fn wait_timeout(&self, timeout: Duration) -> Result<bool, Error> {
        crate::os_process::drive::exited_by_id(self.id, Some(timeout))
    }

    /// Hard-kill the process by identity (`SIGKILL` / `TerminateProcess`). Already-dead ⇒
    /// `Ok`; a real failure (no rights / `EPERM` / access-denied on a live process) ⇒ `Err`.
    /// A process that reused the pid is never signalled, by a different mechanism per OS:
    /// Linux uses an identity-bound `pidfd_send_signal` and Windows pins the kernel object via
    /// its handle. macOS (14.4 and later) has no pidfd; it signals with
    /// `proc_signal_with_audittoken` (the pid plus the process's `p_idversion`, which `exec`
    /// changes), and the kernel checks the version while it holds a reference to the process.
    /// The one residual there: `p_idversion` is 32 bits, so it matches a different process only
    /// if it wrapped by a multiple of 2^32 between the read and the call while the pid was
    /// reused. On Linux a refused `pidfd_open` is `Unsupported` (see [`Error::Unsupported`]).
    pub fn kill(&self) -> Result<(), Error> {
        crate::os_process::kill_by_id(self.id)
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod process_tests;
