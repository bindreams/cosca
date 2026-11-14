//! The cgroup leaf as a mechanism: `cgroup.kill` names the tree in the kernel.

use std::os::fd::BorrowedFd;

use super::CgroupLeaf;
use crate::child::owned::teardown::Reach;
use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::containment::drain_edge::DrainEdge;
#[cfg(feature = "tokio")]
use crate::containment::mechanism::AwaitableRelease;
use crate::containment::mechanism::{Contains, Release};
use crate::containment::treewalk::Listing;
use crate::containment::{Containment, Root, TerminateOutcome, TreeKill};
use crate::identity::HostKernel;

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
    /// `Ok` says the kernel was told to kill every member, however it was spawned (see
    /// [`hard_kill`](CgroupLeaf::hard_kill)). The members `cgroup.procs` lists, in the leaf and in
    /// every cgroup under it, are read before the kill, each proved through its pidfd and named by
    /// its identity, so that a wait over it can wait for each member's own exit. The listing is kept
    /// because the edge alone does not prove each listed member has exited.
    ///
    /// Once the kill has landed, each listed member is placed through its pidfd
    /// ([`reached_by_kill`](CgroupLeaf::reached_by_kill)): one still in the leaf was reached whatever
    /// its credentials, and is waited for; one found outside is not waited for (see there); one that
    /// cannot be placed is an error saying its exit cannot be observed.
    fn kill(&self, root: Option<&dyn Root>) -> TreeKill<'_> {
        let (listed, mut unobserved) = self.list_members(root.map(Root::pid));
        let sent = self.send_kill(root);
        let members = match sent {
            TreeKillOutcome::Ran(Ok(())) => {
                let (reached, unplaced) = self.reached_by_kill(&HostKernel, listed);
                unobserved.extend(unplaced);
                reached
            }
            _ => listed.into_iter().map(|member| member.id).collect(),
        };
        TreeKill::listed(sent, members, unobserved, DrainEdge::Cgroup(self))
    }

    /// The bare `cgroup.kill`: no member is listed, for a caller that waits for none.
    fn send_kill(&self, _root: Option<&dyn Root>) -> TreeKillOutcome {
        TreeKillOutcome::Ran(self.hard_kill().map_err(Unkilled::from))
    }

    fn send_terminate(&self, _pid: u32, _root: Option<&dyn Root>) -> (TerminateOutcome, Option<Listing>) {
        (TerminateOutcome::of(self.terminate(), Some("the SIGTERM")), None)
    }

    fn drain_edge(&self) -> Option<DrainEdge<'_>> {
        Some(DrainEdge::Cgroup(self))
    }

    fn kind(&self) -> Containment {
        Containment::CgroupV2
    }

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
    fn would_reach(&self, pid: u32, pidfd: Option<BorrowedFd<'_>>) -> Result<bool, crate::error::Error> {
        self.subtree()?.holds(pid, pidfd)
    }

    /// A `cgroup.kill` that landed (or found the leaf gone) and where `child` is says it was in the
    /// leaf (see [`Subtree::reached_by`](super::Subtree::reached_by)).
    fn reached(&self, child: &crate::child::owned::OwnedChild) -> Result<bool, crate::error::Error> {
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
