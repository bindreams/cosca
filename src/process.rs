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
        let exited = crate::wait::block_until_exit(self.id, None)?;
        debug_assert!(exited);
        Ok(())
    }

    /// Block up to `timeout` for the process to exit. `Ok(true)` = exited; `Ok(false)` =
    /// still alive at expiry. `Duration::ZERO` polls once. Errors as for [`wait`](Self::wait).
    pub fn wait_timeout(&self, timeout: Duration) -> Result<bool, Error> {
        crate::wait::block_until_exit(self.id, Some(timeout))
    }

    /// The parent process, by identity. Identity-guarded against pid-reuse: a genuine parent
    /// predates this child, so a recycled `ppid` naming a process created AFTER it (later
    /// token) is rejected by the same token rule as [`children`](Self::children) — sound,
    /// modulo the per-OS same-tick residual the whole crate shares.
    ///
    /// `Ok(None)` means there is none: `self` has no parent (pid 1), the parent has exited, or
    /// `self` is gone or was recycled. It is never an answer to a question that could not be
    /// asked.
    ///
    /// # Errors
    ///
    /// - [`Error::Unassessable`]: `self` (or its parent) exists but cannot be queried, `self` is
    ///   live but missing from the process table, or the table cannot be read or trusted (on Linux,
    ///   a `/proc` that is not this pid namespace's).
    /// - [`Error::Unsupported`]: on Linux, `openat2` is unavailable (Linux ≥ 5.6).
    pub fn parent(&self) -> Result<Option<Process>, Error> {
        // Snapshot first, then the anchor: a `self` that still holds its pid after the snapshot
        // held it throughout, so the edges naming it are its own. An Unknown anchor cannot rule
        // out a recycled pid either, so it is an error.
        let parents = crate::containment::enumerate::process_parents()?;
        if !crate::containment::treewalk::anchor_present(self.id)? {
            return Ok(None);
        }
        let Some(ppid) = self.parent_pid_in(&parents)? else {
            return Ok(None);
        };
        // A process is never its own parent (treewalk's convention).
        if ppid == self.id.pid() {
            return Ok(None);
        }
        // An access-denied parent is not "no parent".
        let parent = match ProcessId::of_explained(ppid) {
            (Resolved::Found(p), _) => p,
            (Resolved::Gone, _) => return Ok(None),
            (Resolved::Unknown, cause) => {
                return Err(crate::containment::treewalk::unqueryable(
                    &format!("ppid {ppid}"),
                    cause,
                ));
            }
        };
        // Identity guard: a genuine parent predates this child, so the child's start token
        // orders at-or-after the parent's. A recycled ppid names a process created AFTER
        // this one (later token) — reject it.
        Ok(crate::containment::treewalk::keeps_token(
            self.id.start_token_raw(),
            parent.start_token_raw(),
            crate::containment::treewalk::ALLOW_EQUAL_TOKEN,
        )
        .then_some(Process { id: parent }))
    }

    /// `self`'s ppid in `parents`. `self` passed its anchor, so it is live: a row missing for it
    /// was omitted, not the process gone, unless it exited since (`Ok(None)`).
    fn parent_pid_in(&self, parents: &[(RawPid, RawPid)]) -> Result<Option<RawPid>, Error> {
        match parents.iter().find(|&&(pid, _)| pid == self.id.pid()) {
            Some(&(_, ppid)) => Ok(Some(ppid)),
            None => self.absent_from_snapshot().map(|()| None),
        }
    }

    /// Why `self`, live at its anchor, has no row in the snapshot: it exited since (`Ok`), or its
    /// row was omitted, which is an error.
    fn absent_from_snapshot(&self) -> Result<(), Error> {
        if crate::containment::treewalk::anchor_present(self.id)? {
            return Err(Error::Unassessable {
                detail: format!("pid {} is live but absent from the process snapshot", self.id.pid()),
                source: None,
            });
        }
        Ok(())
    }

    /// The process's children. `Recursive::No` = direct children; `Recursive::Yes` = the
    /// whole subtree. Identity-guarded against pid-reuse by the tree-walk token rule (a
    /// candidate is kept only if its start token orders at-or-after this process). Snapshot;
    /// best-effort.
    ///
    /// An empty list means there are none (or `self` is gone or was recycled); a process table
    /// that cannot be read is an error, never an empty list.
    ///
    /// # Errors
    ///
    /// As [`parent`](Self::parent).
    pub fn children(&self, recursive: Recursive) -> Result<Vec<Process>, Error> {
        // Snapshot first, then the anchor (see `parent`).
        let parents = crate::containment::enumerate::process_parents()?;
        if !crate::containment::treewalk::anchor_present(self.id)? {
            return Ok(Vec::new());
        }
        if !parents.iter().any(|&(pid, _)| pid == self.id.pid()) {
            self.absent_from_snapshot()?;
            return Ok(Vec::new());
        }
        let ids = match recursive {
            Recursive::No => crate::containment::treewalk::children_of(self.id, &parents),
            Recursive::Yes => crate::containment::treewalk::descendants(self.id, &parents),
        };
        Ok(ids.into_iter().map(|id| Process { id }).collect())
    }

    /// Hard-kill the process by identity (`SIGKILL` / `TerminateProcess`). Already-dead ⇒
    /// `Ok`; a real failure (no rights / `EPERM` / access-denied on a live process) ⇒ `Err`.
    /// **Race-freedom is OS-dependent:** Linux uses an identity-bound `pidfd_send_signal`
    /// (atomic, zero pid-reuse race) and Windows pins the kernel object via its handle; macOS
    /// has no pidfd, so it re-verifies identity immediately before `kill(2)` with a small
    /// irreducible residual window — best-effort there, like the existing tree teardown. On
    /// Linux a refused `pidfd_open` is `Unsupported` (see [`Error::Unsupported`]).
    pub fn kill(&self) -> Result<(), Error> {
        crate::wait::kill(self.id)
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod process_tests;
