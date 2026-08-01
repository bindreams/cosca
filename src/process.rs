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
    /// Resolve a foreign process by a saved identity. [`Resolved::Gone`] if that exact
    /// identity is gone or the pid was recycled; [`Resolved::Unknown`] if the OS refused the
    /// query — the process may well be running.
    pub fn from_id(id: ProcessId) -> Resolved<Process> {
        match ProcessId::of(id.pid()) {
            Resolved::Found(live) if live == id => Resolved::Found(Process { id }),
            Resolved::Found(_) | Resolved::Gone => Resolved::Gone,
            Resolved::Unknown => Resolved::Unknown,
        }
    }

    /// Resolve the process currently holding `pid`. [`Resolved::Gone`] if no process has it;
    /// [`Resolved::Unknown`] if the OS refused the query.
    pub fn from_pid(pid: RawPid) -> Resolved<Process> {
        ProcessId::of(pid).map(|id| Process { id })
    }

    #[cfg(all(test, windows))]
    pub(crate) fn from_parts_for_test(id: ProcessId) -> Process {
        Process { id }
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

    /// Whether the process is still running (zombie-exclusive; see [`ProcessId::is_alive`]).
    /// [`Liveness::Unknown`] when the OS refuses the query.
    pub fn is_alive(&self) -> Liveness {
        self.id.is_alive()
    }

    /// Block until the process exits. Death-watch — yields no `ExitStatus` (only the real
    /// parent gets one). `Err` only on a wait failure (incl. `Unsupported` on Linux < 5.3).
    /// Non-reaping.
    pub fn wait(&self) -> Result<(), Error> {
        let exited = crate::wait::block_until_exit(self.id, None)?;
        debug_assert!(exited);
        Ok(())
    }

    /// Block up to `timeout` for the process to exit. `Ok(true)` = exited; `Ok(false)` =
    /// still alive at expiry. `Duration::ZERO` polls once.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<bool, Error> {
        crate::wait::block_until_exit(self.id, Some(timeout))
    }

    /// The parent process, by identity. Identity-guarded against pid-reuse: a genuine parent
    /// predates this child, so a recycled `ppid` naming a process created AFTER it (later
    /// token) is rejected by the same token rule as [`children`](Self::children) — sound,
    /// modulo the per-OS same-tick residual the whole crate shares. `None` if there is no
    /// resolvable parent or `self` itself was recycled.
    pub fn parent(&self) -> Option<Process> {
        // Anchor: a query against a recycled self pid is meaningless. An Unknown anchor
        // cannot rule that out either, so it is treated the same — the alternative is
        // enumerating a stranger's tree.
        match self.id.exists() {
            Existence::Present => {}
            Existence::Gone => return None,
            Existence::Unknown => {
                log::warn!(
                    "Process::parent: pid {} is unassessable — returning None",
                    self.id.pid()
                );
                return None;
            }
        }
        let parents = crate::containment::enumerate::process_parents();
        let ppid = parents
            .iter()
            .find(|&&(pid, _)| pid == self.id.pid())
            .map(|&(_, ppid)| ppid)?;
        // A process is never its own parent (treewalk's convention).
        if ppid == self.id.pid() {
            return None;
        }
        // The SECOND collapse point in this function: folding an access-denied parent into
        // "no parent" with no trace would reproduce the same Unknown-into-absence collapse
        // the anchor check above exists to avoid.
        let parent = match ProcessId::of(ppid) {
            Resolved::Found(p) => p,
            Resolved::Gone => return None,
            Resolved::Unknown => {
                log::warn!("Process::parent: ppid {ppid} could not be queried (access denied?) — reporting no parent");
                return None;
            }
        };
        // Identity guard: a genuine parent predates this child, so the child's start token
        // orders at-or-after the parent's. A recycled ppid names a process created AFTER
        // this one (later token) — reject it.
        crate::containment::treewalk::keeps_token(
            self.id.start_token_raw(),
            parent.start_token_raw(),
            crate::containment::treewalk::ALLOW_EQUAL_TOKEN,
        )
        .then_some(Process { id: parent })
    }

    /// The process's children. `Recursive::No` = direct children; `Recursive::Yes` = the
    /// whole subtree. Identity-guarded against pid-reuse by the tree-walk token rule (a
    /// candidate is kept only if its start token orders at-or-after this process). Snapshot;
    /// best-effort.
    pub fn children(&self, recursive: Recursive) -> Vec<Process> {
        // Anchor: a recycled self pid maps the whole query onto a stranger. An Unknown
        // anchor cannot rule that out either.
        match self.id.exists() {
            Existence::Present => {}
            Existence::Gone => return Vec::new(),
            Existence::Unknown => {
                log::warn!(
                    "Process::children: pid {} is unassessable — returning none",
                    self.id.pid()
                );
                return Vec::new();
            }
        }
        let parents = crate::containment::enumerate::process_parents();
        let ids = match recursive {
            Recursive::No => crate::containment::treewalk::children_of(self.id, &parents),
            Recursive::Yes => crate::containment::treewalk::descendants(self.id, &parents),
        };
        ids.into_iter().map(|id| Process { id }).collect()
    }

    /// Hard-kill the process by identity (`SIGKILL` / `TerminateProcess`). Already-dead ⇒
    /// `Ok`; a real failure (no rights / `EPERM` / access-denied on a live process) ⇒ `Err`.
    /// **Race-freedom is OS-dependent:** Linux uses an identity-bound `pidfd_send_signal`
    /// (atomic, zero pid-reuse race) and Windows pins the kernel object via its handle; macOS
    /// has no pidfd, so it re-verifies identity immediately before `kill(2)` with a small
    /// irreducible residual window — best-effort there, like the existing tree teardown.
    pub fn kill(&self) -> Result<(), Error> {
        crate::wait::kill(self.id)
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod process_tests;
