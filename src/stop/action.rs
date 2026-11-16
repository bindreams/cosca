//! The stop action a child stores: what its cooperative stop runs.

use std::sync::Arc;

use super::StopTarget;
use crate::error::Error;

/// The caller's own action, shared by every child its command spawns.
type Action = Arc<dyn Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync>;

/// What a [`Child`](crate::Child)'s cooperative stop does, as its [`Command`](crate::Command) set it.
#[derive(Clone, Default)]
pub(crate) enum StopAction {
    /// [`stop::default`](crate::stop::default).
    #[default]
    Default,
    /// The caller's own, from [`Command::graceful_stop`](crate::Command::graceful_stop).
    Sync(Action),
}

impl StopAction {
    /// Runs the action on `target`.
    pub(crate) fn run(&self, target: &StopTarget<'_>) -> Result<(), Error> {
        match self {
            StopAction::Default => super::default(target),
            StopAction::Sync(action) => action(target),
        }
    }
}

impl std::fmt::Debug for StopAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopAction::Default => f.write_str("StopAction::Default"),
            StopAction::Sync(_) => f.write_str("StopAction::Sync(..)"),
        }
    }
}
