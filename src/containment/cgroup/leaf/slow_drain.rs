//! A failed async spawn's teardown waits for a leaf to drain, and says so once it passes a threshold.

use super::*;

impl CgroupLeaf {
    /// With `after`, `Drop` warns once if the leaf has not drained that long after its kill, and
    /// keeps waiting. Messaging only: no wait ends on it. Set by a failed async spawn's teardown
    /// (principle 2); cleared once the spawn succeeds, when the handle's armed drop warns instead.
    pub(crate) fn warn_when_drain_is_slow(&mut self, after: Option<std::time::Duration>) {
        self.drain_warn_after = after;
    }

    /// What [`warn_when_drain_is_slow`](Self::warn_when_drain_is_slow) last set.
    #[cfg(test)]
    pub(crate) fn drain_warn_after_for_test(&self) -> Option<std::time::Duration> {
        self.drain_warn_after
    }

    /// [`block_until_drained`](Self::block_until_drained) for a leaf that warns (`after`).
    pub(super) fn block_until_drained_warning(
        &mut self,
        after: std::time::Duration,
    ) -> Result<(), crate::error::Error> {
        let path = &self.leaf_path;
        match self.watch.get_mut() {
            Some(watch) => watch.wait_warning(after, || {
                warn_still_draining(path, after);
                #[cfg(test)]
                fault::run_after_drain_warn();
            }),
            None => Ok(()),
        }
    }

    /// Wait for the leaf's drain, as [`wait_drained`](Self::wait_drained) with no deadline does, and
    /// warn once if it has not drained `after` into the wait. For a failed async spawn's cleanup
    /// that has killed the tree. Answers as the unbounded wait does.
    pub(crate) fn wait_drained_warning(
        &self,
        after: std::time::Duration,
    ) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        match self.wait_drained(Some(Some(crate::wait::now() + after)))? {
            crate::containment::TreeDrain::MembersRemain => {
                warn_still_draining(&self.leaf_path, after);
                #[cfg(test)]
                fault::run_after_drain_warn();
                self.wait_drained(None)
            }
            drained => Ok(drained),
        }
    }
}

/// The one `warn` of a leaf whose drain, awaited after the kill of its tree, has passed `after`.
fn warn_still_draining(path: &std::path::Path, after: std::time::Duration) {
    log::warn!(
        "cgroup leaf {} has not drained {after:?} after its kill (a member is still running, or a tracer holds it); still waiting for it to drain",
        path.display()
    );
}
