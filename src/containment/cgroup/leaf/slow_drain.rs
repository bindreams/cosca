//! A teardown's blocking wait for a leaf to drain, and its one warn once the wait is slow.

use super::*;

/// What a teardown's blocking wait for a leaf's drain says once it is slow (principles 2 and 3).
/// The caller that drops or waits on the leaf passes it; the leaf keeps none.
pub(crate) trait DrainWarn {
    /// When a wait starting now warns, or `None` if it does not.
    fn due(&self) -> Option<std::time::Instant>;
    /// The one warn, for the leaf at `path`.
    fn warn(&mut self, path: &std::path::Path);
}

/// No warn: every wait but an async teardown's.
pub(crate) struct NoWarn;

impl DrainWarn for NoWarn {
    fn due(&self) -> Option<std::time::Instant> {
        None
    }

    fn warn(&mut self, _: &std::path::Path) {}
}

/// A failed async spawn's teardown: the leaf's own warn, this long into the wait (principle 2).
#[cfg(feature = "tokio")]
pub(crate) struct WarnAfter(pub(crate) Option<std::time::Duration>);

#[cfg(feature = "tokio")]
impl DrainWarn for WarnAfter {
    fn due(&self) -> Option<std::time::Instant> {
        self.0.map(|after| crate::wait::now() + after)
    }

    fn warn(&mut self, path: &std::path::Path) {
        if let Some(after) = self.0 {
            log::warn!(
                "cgroup leaf {} has not drained {after:?} after its kill (a member is still running, or a tracer \
                 holds it); still waiting for it to drain",
                path.display()
            );
        }
    }
}

impl CgroupLeaf {
    /// Block until the leaf drains, on the watch held since creation: the pump is stopped and
    /// joined first, so the wait needs no thread. Once `warn` is due it runs once, and the wait goes
    /// on: the time picks the message and nothing else. Every blocking teardown wait for a leaf's
    /// drain is this one.
    pub(crate) fn wait_drained_then_warn(&mut self, warn: &mut dyn DrainWarn) -> Result<(), crate::error::Error> {
        #[cfg(feature = "tokio")]
        crate::bounded::assert_may_block("waiting for a cgroup leaf to drain");
        let path = &self.leaf_path;
        match self.watch.get_mut() {
            Some(watch) => watch.wait_warning(warn.due(), || {
                warn.warn(path);
                #[cfg(test)]
                fault::run_after_drain_warn();
            }),
            None => Ok(()),
        }
    }

    /// Drop the leaf as [`Drop`] does, with `warn` for each wait for its drain.
    #[cfg(feature = "tokio")]
    pub(crate) fn drop_warning(mut self, warn: &mut dyn DrainWarn) {
        self.tear_down(warn);
    }
}
