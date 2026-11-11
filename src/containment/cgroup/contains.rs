//! The cgroup leaf as a mechanism: `cgroup.kill` names the tree in the kernel.

use std::os::fd::BorrowedFd;

use super::CgroupLeaf;
use crate::child::owned::teardown::Reach;
use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::containment::drain_edge::DrainEdge;
use crate::containment::mechanism::{Contains, Release};
use crate::containment::{Containment, Root, TerminateOutcome};

// CgroupLeaf is not Debug; provide a minimal impl.
impl std::fmt::Debug for CgroupLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CgroupLeaf").finish_non_exhaustive()
    }
}

impl Contains for CgroupLeaf {
    /// `Ok` says the kernel killed every member, however it was spawned (see
    /// [`hard_kill`](CgroupLeaf::hard_kill)).
    fn send_kill(&self, _root: Option<&dyn Root>) -> TreeKillOutcome {
        TreeKillOutcome::Ran(self.hard_kill().map_err(Unkilled::from))
    }

    fn send_terminate(&self, _pid: u32, _root: Option<&dyn Root>) -> TerminateOutcome {
        TerminateOutcome::Sent {
            result: self.terminate(),
            earlier: Some("the SIGTERM"),
        }
    }

    fn drain_edge(&self) -> Option<DrainEdge<'_>> {
        Some(DrainEdge::Cgroup(self))
    }

    fn kind(&self) -> Containment {
        Containment::CgroupV2
    }

    /// The leaf's path: a kill returns the kernel's error unwrapped, so the error does not name it.
    fn subject(&self) -> String {
        format!("cgroup leaf {}", self.path().display())
    }

    /// Stops the leaf's `Drop` firing `cgroup.kill`.
    fn disarm(&self) -> std::io::Result<()> {
        CgroupLeaf::disarm(self);
        Ok(())
    }

    /// Whether the task `pid` (which `pidfd` names, when there is one) is in this leaf or a cgroup
    /// under it (see [`Subtree::holds`](super::Subtree::holds)): a `cgroup.kill` reaches it whatever
    /// its credentials.
    fn would_reach(&self, pid: u32, pidfd: Option<BorrowedFd<'_>>) -> std::io::Result<bool> {
        self.subtree()?.holds(pid, pidfd)
    }

    /// A `cgroup.kill` that landed (or found the leaf gone) and where `child` is says it was in the
    /// leaf (see [`Subtree::reached_by`](super::Subtree::reached_by)).
    fn reached(&self, child: &crate::child::owned::OwnedChild) -> std::io::Result<bool> {
        self.subtree()?.reached(child)
    }

    /// The leaf is killed through if it is armed and occupied, drained and removed.
    fn release(self) -> Release {
        Release::leaf(self)
    }
}
