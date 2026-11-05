//! The process tree around a [`ProcessId`](super::ProcessId): its parent and its children.

use super::{HostKernel, Kernel, ProcessId, RawPid, Resolved};
use crate::error::Error;

/// Whether a tree query descends recursively or returns only direct children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recursive {
    /// Only direct children (one level).
    No,
    /// All descendants (the whole subtree).
    Yes,
}

impl ProcessId {
    /// The parent process, by identity. Identity-guarded against pid-reuse: a genuine parent
    /// predates this child, so a recycled `ppid` naming a process created AFTER it (later
    /// token) is rejected by the same token rule as [`children`](Self::children).
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
    pub fn parent(&self) -> Result<Option<ProcessId>, Error> {
        self.parent_with(&HostKernel)
    }

    /// [`parent`](Self::parent), reading through `kernel`.
    pub(crate) fn parent_with(&self, kernel: &dyn Kernel) -> Result<Option<ProcessId>, Error> {
        // Snapshot first, then the anchor: a `self` that still holds its pid after the snapshot
        // held it throughout, so the edges naming it are its own. An Unknown anchor cannot rule
        // out a recycled pid either, so it is an error.
        let parents = crate::containment::enumerate::process_parents(kernel)?;
        if !crate::containment::treewalk::anchor_present(kernel, *self)? {
            return Ok(None);
        }
        let Some(ppid) = self.parent_pid_in(kernel, &parents)? else {
            return Ok(None);
        };
        // A process is never its own parent (treewalk's convention).
        if ppid == self.pid() {
            return Ok(None);
        }
        // An access-denied parent is not "no parent".
        let parent = match ProcessId::of_with(kernel, ppid) {
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
            self.start_token_raw(),
            parent.start_token_raw(),
            crate::containment::treewalk::ALLOW_EQUAL_TOKEN,
        )
        .then_some(parent))
    }

    /// `self`'s ppid in `parents`. `self` passed its anchor, so it is live: a row missing for it
    /// was omitted, not the process gone, unless it exited since (`Ok(None)`).
    fn parent_pid_in(&self, kernel: &dyn Kernel, parents: &[(RawPid, RawPid)]) -> Result<Option<RawPid>, Error> {
        match parents.iter().find(|&&(pid, _)| pid == self.pid()) {
            Some(&(_, ppid)) => Ok(Some(ppid)),
            None => self.absent_from_snapshot(kernel).map(|()| None),
        }
    }

    /// Why `self`, live at its anchor, has no row in the snapshot: it exited since (`Ok`), or its
    /// row was omitted, which is an error.
    fn absent_from_snapshot(&self, kernel: &dyn Kernel) -> Result<(), Error> {
        if crate::containment::treewalk::anchor_present(kernel, *self)? {
            return Err(Error::Unassessable {
                detail: format!("pid {} is live but absent from the process snapshot", self.pid()),
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
    pub fn children(&self, recursive: Recursive) -> Result<Vec<ProcessId>, Error> {
        self.children_with(&HostKernel, recursive)
    }

    /// [`children`](Self::children), reading through `kernel`.
    pub(crate) fn children_with(&self, kernel: &dyn Kernel, recursive: Recursive) -> Result<Vec<ProcessId>, Error> {
        // Snapshot first, then the anchor (see `parent`).
        let parents = crate::containment::enumerate::process_parents(kernel)?;
        if !crate::containment::treewalk::anchor_present(kernel, *self)? {
            return Ok(Vec::new());
        }
        if !parents.iter().any(|&(pid, _)| pid == self.pid()) {
            self.absent_from_snapshot(kernel)?;
            return Ok(Vec::new());
        }
        Ok(match recursive {
            Recursive::No => crate::containment::treewalk::children_of(kernel, *self, &parents),
            Recursive::Yes => crate::containment::treewalk::descendants(kernel, *self, &parents),
        })
    }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tree_tests;
