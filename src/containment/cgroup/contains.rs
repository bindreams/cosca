//! The cgroup leaf as a mechanism: `cgroup.kill` names the tree in the kernel.

use std::os::fd::BorrowedFd;

use super::CgroupLeaf;
use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::containment::mechanism::{Contains, DrainEdge, Release};
use crate::containment::{Containment, Root, TerminateOutcome};

/// What names the leaf in a message about its teardown: its path.
impl std::fmt::Debug for CgroupLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cgroup leaf {}", self.path().display())
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

    /// The leaf is killed through if it is armed and occupied, drained and removed.
    fn release(self) -> Release {
        Release::leaf(self)
    }
}
