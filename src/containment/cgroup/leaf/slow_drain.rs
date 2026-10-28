//! A teardown's blocking waits for what it killed through a leaf, and their one warn once a wait is
//! slow.

use super::*;
use crate::wait::teardown_warn::{wait_warning, Due};

/// What a teardown's blocking wait is for.
#[cfg_attr(
    not(any(test, feature = "tokio")),
    allow(dead_code, reason = "only an async teardown's warn says what it waited for")
)]
pub(crate) enum Waiting<'a> {
    /// The drain of the leaf at the path.
    Drain(&'a std::path::Path),
    /// The exit of a child it killed, by its pid if known.
    Child(Option<u32>),
}

/// What a teardown's blocking waits say once they are slow (principles 2 and 3). The caller that
/// drops or abandons the leaf passes it; the leaf keeps none.
pub(crate) trait TeardownWarn {
    /// When a wait starting now warns, or `None` if it does not.
    fn due(&self) -> Option<Due>;
    /// The one warn of the wait that passed [`due`](Self::due).
    fn warn(&mut self, waiting: Waiting<'_>);
}

/// No warn: every wait but an async teardown's.
pub(crate) struct NoWarn;

impl TeardownWarn for NoWarn {
    fn due(&self) -> Option<Due> {
        None
    }

    fn warn(&mut self, _: Waiting<'_>) {}
}

/// A failed async spawn's teardown: each wait warns once, this long into it (principle 2).
#[cfg(any(test, feature = "tokio"))]
pub(crate) struct WarnAfter(pub(crate) Option<std::time::Duration>);

#[cfg(any(test, feature = "tokio"))]
impl TeardownWarn for WarnAfter {
    fn due(&self) -> Option<Due> {
        Due::in_(self.0)
    }

    fn warn(&mut self, waiting: Waiting<'_>) {
        let Some(after) = self.0 else {
            return;
        };
        match waiting {
            Waiting::Drain(path) => log::warn!(
                "cgroup leaf {} has not drained {after:?} after its kill (a member is still running, or a tracer \
                 holds it); still waiting for it to drain",
                path.display()
            ),
            Waiting::Child(pid) => crate::child::spawn::warn_still_waiting(pid, after),
        }
    }
}

impl CgroupLeaf {
    /// Block until the leaf drains, on the watch held since creation: the pump is stopped and
    /// joined first, so the wait needs no thread. Once `warn` is due it runs once, and the wait goes
    /// on: the time picks the message and nothing else. Every blocking teardown wait for a leaf's
    /// drain is this one.
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
                    warn.warn(Waiting::Drain(path));
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
