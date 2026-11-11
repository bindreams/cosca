//! The cgroup leaf as a mechanism: `cgroup.kill` names the tree in the kernel.

use std::os::fd::BorrowedFd;

use super::CgroupLeaf;
use crate::child::owned::teardown::Reach;
use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::containment::drain_edge::DrainEdge;
#[cfg(feature = "tokio")]
use crate::containment::mechanism::AwaitableRelease;
use crate::containment::mechanism::{Contains, Release};
use crate::containment::{Containment, Root, TerminateOutcome};

// The leaf's `Debug` hides its path; `subject` names it.
impl std::fmt::Debug for CgroupLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CgroupLeaf").finish_non_exhaustive()
    }
}

impl CgroupLeaf {
    /// The steps of the leaf's drop that can be awaited instead of blocked on: its first step, the
    /// one its drop takes first ([`remove_else_kill`](Self::remove_else_kill)), then the drain a
    /// landed kill bounds, so that the drop finds it drained. A drain that cannot be watched is left
    /// to the drop. The leaf stays where it is, so a future dropped mid-await leaves the whole of the
    /// teardown to the drop. `child` is the child's pid, which names it in the debug lines.
    #[cfg(feature = "tokio")]
    pub(crate) async fn step_and_await_drain(&self, child: u32) {
        // The leaf's drop makes this step again and reports what remains. A leaf that is occupied
        // is the expected failure; one already gone is proof of a drain. Any other failure
        // (EACCES, EIO) is the environment's, so it is logged, never asserted.
        if let Err(e) = self.remove_else_kill() {
            let occupied = matches!(e.raw_os_error(), Some(libc::EBUSY | libc::ENOTEMPTY));
            if !occupied && !super::removed_after_drain(&e) {
                log::debug!(
                    "child {child}: its leaf's first rmdir failed ({report})",
                    report = crate::error::Report(&e)
                );
            }
        }
        if !self.kill_landed() {
            return;
        }
        if let Err(e) = DrainEdge::Cgroup(self).wait_async(None).await {
            log::debug!(
                "child {child}: its leaf's drain cannot be watched ({report}); the teardown waits for it on this thread, blocking",
                report = crate::error::Report(&e)
            );
        }
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

    /// The leaf is killed through if it is armed and occupied, drained and removed: the release owns it.
    fn release(self) -> (Release, Option<CgroupLeaf>) {
        (Release::leaf(self), None)
    }

    /// The first step of the leaf's release and its drain, with the leaf left in place.
    #[cfg(feature = "tokio")]
    fn awaitable_release(&self) -> Option<AwaitableRelease<'_>> {
        Some(AwaitableRelease::of_leaf(self))
    }
}
