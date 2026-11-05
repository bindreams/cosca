//! The process tree around a [`ProcessId`](super::ProcessId): its parent and its children.

use super::{HostKernel, Kernel, ProcessId, Resolved};
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
    /// - [`Error::Unassessable`]: `self` (or its parent) exists but cannot be queried, or the
    ///   table cannot be read or trusted (on Linux, a `/proc` that is not this pid namespace's).
    /// - [`Error::Unsupported`]: on Linux, `openat2` is unavailable (Linux ≥ 5.6).
    pub fn parent(&self) -> Result<Option<ProcessId>, Error> {
        self.parent_with(&HostKernel)
    }

    /// [`parent`](Self::parent), reading through `kernel`.
    pub(crate) fn parent_with(&self, kernel: &dyn Kernel) -> Result<Option<ProcessId>, Error> {
        // The table is still read first, as `children` reads it: an unreadable one is an error
        // here too. `self`'s parent number is not in it: a live process may have no row (Toolhelp
        // omits an exited process whose handle is held), so it comes from `self`'s own read, which
        // is also the proof that `self` holds its pid. An Unknown read cannot rule out a recycled
        // pid, so it is an error.
        crate::containment::enumerate::process_parents(kernel)?;
        let ppid = match self.parent_number_with(kernel) {
            (Resolved::Found(ppid), _) => ppid,
            (Resolved::Gone, _) => return Ok(None),
            (Resolved::Unknown, cause) => {
                return Err(crate::containment::treewalk::unqueryable_read(self.pid(), cause));
            }
        };
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
        // hold it after that read.
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

    /// The process's children. `Recursive::No` = direct children; `Recursive::Yes` = the
    /// whole subtree. Identity-guarded against pid-reuse by the tree-walk order-key rule (a
    /// candidate is kept only if its order key orders at-or-after this process's). On Windows with
    /// `Recursive::Yes`, each candidate must also order after its accepted parent, and Windows
    /// compares strictly (`>`), not at-or-after. Snapshot; best-effort.
    ///
    /// An empty list means there are none (or `self` is gone or was recycled); a process table
    /// that cannot be read is an error, never an empty list, and neither is a candidate that cannot
    /// be assessed: the list is never a short one.
    ///
    /// # Errors
    ///
    /// As [`parent`](Self::parent), and [`Error::Unassessable`] (or `Unsupported`) naming the first
    /// candidate whose identity could not be read, or whose parent's could not be proved.
    pub fn children(&self, recursive: Recursive) -> Result<Vec<ProcessId>, Error> {
        self.children_with(&HostKernel, recursive)
    }

    /// [`children`](Self::children), reading through `kernel`.
    pub(crate) fn children_with(&self, kernel: &dyn Kernel, recursive: Recursive) -> Result<Vec<ProcessId>, Error> {
        // Snapshot first, then the anchor (see `parent`), whose one read is also the key.
        let parents = crate::containment::enumerate::process_parents(kernel)?;
        let Some(walk) = crate::containment::treewalk::walk_from(kernel, *self, &parents, recursive)? else {
            return Ok(Vec::new());
        };
        // A candidate the walk could not read may be a child: the list would be short, not empty.
        match walk.unassessed.into_iter().next() {
            Some((_, why)) => Err(why),
            None => Ok(walk.members),
        }
    }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tree_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "tree_pidfs_tests.rs"]
mod tree_pidfs_tests;
