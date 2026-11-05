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
    /// order key) is rejected by the same order-key rule as [`children`](Self::children).
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
        let ppid = self.parent_pid_in(&parents)?;
        // A process is never its own parent (treewalk's convention).
        if ppid == self.pid() {
            return Ok(None);
        }
        // An access-denied parent is not "no parent".
        let (parent, parent_key) = match ProcessId::of_ordered_with(kernel, ppid, None) {
            (Resolved::Found(read), _) => read,
            (Resolved::Gone, _) => return Ok(None),
            (Resolved::Unknown, cause) => {
                return Err(crate::containment::treewalk::unqueryable(
                    &format!("ppid {ppid}"),
                    cause,
                ));
            }
        };
        // `ppid` is only a number: `self`'s own read must still name it, and the parent must still
        // hold it after that read (Linux; the other platforms check neither).
        let key = match ProcessId::of_ordered_with(kernel, self.pid(), Some(parent)) {
            (Resolved::Found((read, key)), _) if read == *self => key,
            // `self` was replaced, exited, or has another parent now.
            (Resolved::Found(_) | Resolved::Gone, _) => return Ok(None),
            // The parent's proof can be what failed, not `self`'s read.
            (Resolved::Unknown, cause) => {
                return Err(crate::containment::treewalk::unqueryable_read(self.pid(), cause));
            }
        };
        // A genuine parent predates this child; a recycled ppid names a later-started process.
        Ok(
            crate::containment::treewalk::keeps_order(key, parent_key, crate::containment::treewalk::ALLOW_EQUAL_ORDER)
                .then_some(parent),
        )
    }

    /// `self`'s ppid in `parents`; an error if it has no row (see
    /// [`absent_from_snapshot`](Self::absent_from_snapshot)).
    fn parent_pid_in(&self, parents: &[(RawPid, RawPid)]) -> Result<RawPid, Error> {
        parents
            .iter()
            .find(|&&(pid, _)| pid == self.pid())
            .map(|&(_, ppid)| ppid)
            .ok_or_else(|| self.absent_from_snapshot())
    }

    /// The error for a `self` that was live at its anchor, read after the snapshot, and has no row
    /// in it: it held its pid throughout, so the row was omitted. Another read of it would only
    /// ask whether it has exited since, which does not explain the missing row (and, on Windows,
    /// would turn an exit into an empty answer with its children still running).
    fn absent_from_snapshot(&self) -> Error {
        Error::Unassessable {
            detail: format!("pid {} is live but absent from the process snapshot", self.pid()),
            source: None,
        }
    }

    /// The process's children. `Recursive::No` = direct children; `Recursive::Yes` = the
    /// whole subtree. Identity-guarded against pid-reuse by the tree-walk order-key rule (a
    /// candidate is kept only if its order key orders at-or-after this process's). Snapshot;
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
        // Snapshot first, then the anchor (see `parent`), whose one read is also the key.
        let parents = crate::containment::enumerate::process_parents(kernel)?;
        let Some(key) = crate::containment::treewalk::anchor(kernel, *self)? else {
            return Ok(Vec::new());
        };
        if !parents.iter().any(|&(pid, _)| pid == self.pid()) {
            return Err(self.absent_from_snapshot());
        }
        Ok(match recursive {
            Recursive::No => crate::containment::treewalk::children_of_from_key(kernel, *self, key, &parents),
            Recursive::Yes => crate::containment::treewalk::descendants_from_key(kernel, *self, key, &parents),
        })
    }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tree_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "tree_pidfs_tests.rs"]
mod tree_pidfs_tests;
