//! The process tree around a [`ProcessId`](super::ProcessId): its parent and its children.

use super::{keeps, resolution_of, HostKernel, Kernel, ProcessId, ORDER_AFTER_PARENT};
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
    /// The parent, by identity. A `ppid` is accepted only with a proof that it names the real
    /// parent, not a later holder of its pid (as the walk proves each candidate):
    ///
    /// - Linux, macOS (an orphan is reparented): `self` is read again after its parent, and its
    ///   `ppid` must still name the parent, which must still hold its pid. The parent may have
    ///   started after `self` (a tracer).
    /// - Windows (the creator is never updated): `self` is read once, and must have started
    ///   strictly after the parent; a parent that started after its child is a recycled `ppid`.
    ///
    /// `Ok(None)` means there is none: `self` has no parent (pid 1), the parent has exited, or
    /// `self` is gone or was recycled, as of its read (on Windows, the one that gave the parent
    /// number). It is never an answer to a question that could not be asked.
    ///
    /// # Errors
    ///
    /// - [`Error::Unassessable`]: `self` or its parent exists but cannot be queried, at any of the
    ///   reads; so does a pid whose holder cannot be read to tell whether it is `self` (a Linux
    ///   `pidfs` id is told before the read, and is `Ok(None)`). On Linux and macOS also when the
    ///   parent's pid cannot be proved held after `self`'s second read; Windows reads `self` once
    ///   and makes no such proof.
    /// - [`Error::Unsupported`]: on Linux, `openat2` is unavailable (Linux ≥ 5.6).
    pub fn parent(&self) -> Result<Option<ProcessId>, Error> {
        self.parent_with(&HostKernel)
    }

    /// [`parent`](Self::parent), reading through `kernel`.
    pub(crate) fn parent_with(&self, kernel: &dyn Kernel) -> Result<Option<ProcessId>, Error> {
        // The number comes from `self`'s own read, as a live process may have no row in the table.
        let read = self.parent_number_and_order_with(kernel);
        let Some((ppid, own_order)) = resolution_of("pid", self.pid(), read)? else {
            return Ok(None);
        };
        // A process is never its own parent (treewalk's convention).
        if ppid == self.pid() {
            return Ok(None);
        }
        // An access-denied parent is not "no parent".
        let read = ProcessId::of_ordered_with(kernel, ppid, None, None, None);
        let Some((parent, parent_order)) = resolution_of("ppid", ppid, read)? else {
            return Ok(None);
        };
        // Where the creator is never updated, a genuine parent started before its child. Both reads
        // carry their order keys there (asserted in `read_ordered`).
        if ORDER_AFTER_PARENT {
            return Ok(keeps(own_order, parent_order).then_some(parent));
        }
        // Elsewhere `self` read after the parent must still name it, and it must still hold its pid.
        let read = ProcessId::of_ordered_with(kernel, self.pid(), Some(parent), Some(self.key), None);
        Ok(resolution_of("pid", self.pid(), read)?.map(|_| parent))
    }

    /// The process's children. `Recursive::No` = direct children; `Recursive::Yes` = the
    /// whole subtree. Identity-guarded against pid-reuse as the tree walk is (see its module docs):
    /// each candidate is read under its parent, and on Windows must also order after it. Snapshot;
    /// best-effort.
    ///
    /// An empty list means there are none (or `self` is gone or was recycled); a process table
    /// that cannot be read is an error, never an empty list.
    ///
    /// # Errors
    ///
    /// As [`parent`](Self::parent), and [`Error::Unassessable`] when the process table cannot be
    /// read or trusted (on Linux, a `/proc` that is not this pid namespace's), or naming the first
    /// candidate whose identity could not be read, or whose parent's could not be proved.
    pub fn children(&self, recursive: Recursive) -> Result<Vec<ProcessId>, Error> {
        self.children_with(&HostKernel, recursive)
    }

    /// [`children`](Self::children), reading through `kernel`.
    pub(crate) fn children_with(&self, kernel: &dyn Kernel, recursive: Recursive) -> Result<Vec<ProcessId>, Error> {
        // Snapshot first, then the anchor, whose one read is also the proof of the root.
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
