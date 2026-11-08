//! The policies the rows state, beside [`SpawnPolicy::SYNC`]: production builds none of them.

use std::time::Duration;

use super::SpawnPolicy;
use crate::child::owned::unreaped::DropKind;

impl SpawnPolicy {
    /// The sync spawn's, but a teardown's wait warns the moment it starts: its threshold has
    /// already passed.
    pub(crate) const WARNS_AT_ONCE: SpawnPolicy = SpawnPolicy {
        teardown_warn_after: Some(Duration::ZERO),
        unreaped_drop: DropKind::Wait,
    };

    /// The sync spawn's, but an `Unreaped` it hands back lets the child go when dropped, as an async
    /// spawn's does.
    pub(crate) const LET_GO: SpawnPolicy = SpawnPolicy {
        teardown_warn_after: None,
        unreaped_drop: DropKind::LetGo,
    };
}
