//! The stop action a child stores: what its cooperative stop runs.

use std::sync::Arc;

use super::StopTarget;
use crate::error::Error;

/// The caller's own action, shared by every child its command spawns.
type Action = Arc<dyn Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync>;

/// The caller's own async action ([`tokio::Command::graceful_stop`](crate::tokio::Command::graceful_stop)).
#[cfg(feature = "tokio")]
type AsyncAction = Arc<dyn for<'t, 'c> Fn(&'t StopTarget<'c>) -> crate::tokio::StopFuture<'t> + Send + Sync>;

/// What a [`Child`](crate::Child)'s cooperative stop does, as its command set it. A child of the sync
/// [`Command`](crate::Command) holds `Default` or `Sync`, a child of the async one `Default` or `Async`:
/// each command accepts only its own kind, and no conversion between the two children exists.
#[derive(Clone, Default)]
pub(crate) enum StopAction {
    /// [`stop::default`](crate::stop::default).
    #[default]
    Default,
    /// The caller's own, from [`Command::graceful_stop`](crate::Command::graceful_stop).
    Sync(Action),
    /// The caller's own, from [`tokio::Command::graceful_stop`](crate::tokio::Command::graceful_stop).
    #[cfg(feature = "tokio")]
    Async(AsyncAction),
}

impl StopAction {
    /// The caller's own sync action.
    pub(crate) fn sync(action: impl Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync + 'static) -> StopAction {
        StopAction::Sync(Arc::new(action))
    }

    /// The caller's own async action.
    #[cfg(feature = "tokio")]
    pub(crate) fn asynchronous(
        action: impl for<'t, 'c> Fn(&'t StopTarget<'c>) -> crate::tokio::StopFuture<'t> + Send + Sync + 'static,
    ) -> StopAction {
        StopAction::Async(Arc::new(action))
    }

    /// Runs the action on `target`, blocking.
    ///
    /// # Panics
    ///
    /// On an async action: only a child of the async `Command` holds one, and it runs it with
    /// `run_async` (feature `tokio`).
    pub(crate) fn run(&self, target: &StopTarget<'_>) -> Result<(), Error> {
        match self {
            StopAction::Default => super::default(target),
            StopAction::Sync(action) => action(target),
            #[cfg(feature = "tokio")]
            StopAction::Async(_) => {
                unreachable!("a sync child never holds an async action: each Command accepts only its own kind")
            }
        }
    }

    /// Runs the action on `target`, awaited.
    ///
    /// # Panics
    ///
    /// On a sync action: only a child of the sync `Command` holds one, and it runs it with
    /// [`run`](Self::run).
    #[cfg(feature = "tokio")]
    pub(crate) async fn run_async(&self, target: &StopTarget<'_>) -> Result<(), Error> {
        match self {
            StopAction::Default => crate::tokio::stop::default(target).await,
            StopAction::Async(action) => action(target).await,
            StopAction::Sync(_) => {
                unreachable!("an async child never holds a sync action: each Command accepts only its own kind")
            }
        }
    }
}

impl std::fmt::Debug for StopAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopAction::Default => f.write_str("StopAction::Default"),
            StopAction::Sync(_) => f.write_str("StopAction::Sync(..)"),
            #[cfg(feature = "tokio")]
            StopAction::Async(_) => f.write_str("StopAction::Async(..)"),
        }
    }
}
