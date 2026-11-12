//! Off Windows there is no frozen spawn.

use super::{Child, SuspendedChild};
use crate::child::suspended::platform::refusal;
use crate::error::Error;
use crate::tokio::Command;

/// Refused before the command is touched, and before any runtime is asked for, so no hop is made.
pub(super) async fn spawn(cmd: &mut Command) -> Result<SuspendedChild, Error> {
    Err(refusal(cmd.as_sync_mut()))
}

/// There is no `SuspendedChild` to resume here: `spawn` never returns one.
pub(super) fn release(_child: &Child) -> std::io::Result<()> {
    unreachable!("spawn_suspended never returns a SuspendedChild off Windows")
}
