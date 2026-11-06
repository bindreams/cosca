//! A teardown's blocking waits for what it killed through a leaf, and their one warn once a wait is
//! slow.

use super::*;
use crate::wait::teardown_warn::{wait_warning, Due};

/// What a teardown's blocking waits say once they are slow (principles 2 and 3). The caller that
/// drops or abandons the leaf passes it; the leaf keeps none. [`due`](Self::due) is also the
/// threshold of the wait for the child a leaf's abandonment kills, which the child's own teardown
/// warns of.
pub(crate) trait TeardownWarn {
    /// When a wait starting now warns, or `None` if it does not.
    fn due(&self) -> Option<Due>;
    /// The one warn of the wait for the drain of the leaf at `leaf` that passed
    /// [`due`](Self::due).
    fn warn(&mut self, leaf: &std::path::Path);
}

/// No warn: every wait but an async teardown's.
pub(crate) struct NoWarn;

impl TeardownWarn for NoWarn {
    fn due(&self) -> Option<Due> {
        None
    }

    fn warn(&mut self, _: &std::path::Path) {}
}

/// A failed async spawn's teardown: each wait warns once, this long into it (principle 2).
#[cfg(feature = "tokio")]
pub(crate) struct WarnAfter(pub(crate) Option<std::time::Duration>);

#[cfg(feature = "tokio")]
impl TeardownWarn for WarnAfter {
    fn due(&self) -> Option<Due> {
        Due::in_(self.0)
    }

    fn warn(&mut self, leaf: &std::path::Path) {
        let Some(after) = self.0 else {
            return;
        };
        log::warn!(
            "cgroup leaf {} has not drained {after:?} after its kill (a member is still running, or a tracer \
             holds it); still waiting for it to drain",
            leaf.display()
        );
    }
}

impl CgroupLeaf {
    /// Block until the leaf drains, on the watch held since creation: the pump is stopped and
    /// joined first, so the wait needs no thread. Every blocking teardown wait for a leaf's drain is
    /// this one; see [`wait_warning`].
    pub(crate) fn wait_drained_then_warn(&mut self, warn: &mut dyn TeardownWarn) -> Result<(), crate::error::Error> {
        #[cfg(feature = "tokio")]
        crate::bounded::assert_may_block("waiting for a cgroup leaf to drain");
        let path = &self.leaf_path;
        match self.watch.get_mut() {
            Some(watch) => wait_warning(
                watch,
                warn.due(),
                |watch, until| watch.drained_by(until),
                |_| {
                    warn.warn(path);
                    #[cfg(test)]
                    fault::run_after_drain_warn();
                },
                DrainWatch::wait,
            ),
            None => Ok(()),
        }
    }

    /// Drop the leaf as [`Drop`] does, with `warn` for each wait.
    #[cfg(feature = "tokio")]
    pub(crate) fn drop_warning(mut self, warn: &mut dyn TeardownWarn) {
        self.tear_down(warn);
    }
}
