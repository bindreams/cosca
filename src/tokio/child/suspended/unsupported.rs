//! Off Windows there is no frozen spawn.

use super::{Child, SuspendedChild};
use crate::child::suspended::platform::spawn_frozen;
use crate::error::Error;
use crate::tokio::Command;

pub(super) fn spawn(cmd: &mut Command) -> Result<SuspendedChild, Error> {
    let (child, wanted_kill_on_drop) = spawn_frozen(cmd.as_sync_mut(), |_| unreachable!("the refusal never spawns"))?;
    Ok(SuspendedChild {
        child,
        wanted_kill_on_drop,
    })
}

/// There is no `SuspendedChild` to resume here: `spawn` never returns one.
pub(super) fn release(_child: &Child) -> std::io::Result<()> {
    unreachable!("spawn_suspended never returns a SuspendedChild off Windows")
}
