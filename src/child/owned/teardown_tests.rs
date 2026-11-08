//! What the rows read of a teardown's outcome and settle of its waits, which production does not:
//! the outcome's private fields, and a root's reap after a tree kill, settled.

use std::time::Duration;

use super::{Disposition, TeardownOutcome};
use crate::child::lifecycle::Wording;
use crate::child::owned::OwnedChild;
use crate::error::ChildFate;

impl TeardownOutcome {
    /// What became of the child.
    pub(crate) fn fate(&self) -> ChildFate {
        self.fate
    }

    /// What the teardown said of the child, if it said anything.
    pub(crate) fn said(&self) -> Option<&Wording> {
        self.said.as_ref()
    }
}

impl OwnedChild {
    /// [`begin_reap_after_tree_kill`](OwnedChild::begin_reap_after_tree_kill) settled, for the rows
    /// that state the teardown's outcome.
    pub(crate) fn reap_after_tree_kill(
        &self,
        subject: &str,
        disposition: Disposition,
        warn_after: Option<Duration>,
    ) -> TeardownOutcome {
        self.begin_reap_after_tree_kill(None, subject.to_owned(), disposition, warn_after)
            .settle(self)
    }
}
