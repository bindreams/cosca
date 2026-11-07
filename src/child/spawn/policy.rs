//! What a spawn is told about the teardowns of the child it makes.

use std::time::Duration;

use crate::child::owned::unreaped::DropKind;

/// What a spawn is told, once, at its entry ([`spawn_uncommitted`](super::spawn_uncommitted)), about
/// every teardown of the child it makes. It reaches each of them: a failed spawn's, the child's own
/// drop, the drain of its cgroup leaf, and the [`Unreaped`](crate::Unreaped) either hands back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpawnPolicy {
    /// How long into a blocking wait for what a teardown killed (the root's exit, a leaf's drain) it
    /// warns once, and keeps waiting (principle 2); `None`: it does not. Each wait starts its own
    /// clock, so this is a length, not a time.
    pub(crate) teardown_warn_after: Option<Duration>,
    /// What dropping an `Unreaped` the child's teardown hands back does.
    pub(crate) unreaped_drop: DropKind,
}

impl SpawnPolicy {
    /// The sync spawn's: no warn, and a dropped `Unreaped` waits.
    pub(crate) const SYNC: SpawnPolicy = SpawnPolicy {
        teardown_warn_after: None,
        unreaped_drop: DropKind::Wait,
    };

    /// The sync spawn's, but a teardown's wait warns the moment it starts: its threshold has
    /// already passed.
    #[cfg(test)]
    pub(crate) const WARNS_AT_ONCE: SpawnPolicy = SpawnPolicy {
        teardown_warn_after: Some(std::time::Duration::ZERO),
        unreaped_drop: DropKind::Wait,
    };
}
