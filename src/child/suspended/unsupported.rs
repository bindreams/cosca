//! Off Windows there is no frozen spawn.

use crate::child::spawn::SpawnFailure;
use crate::child::{Child, SuspendedChild};
use crate::command::Command;
use crate::error::Error;

/// The refusal both frozen spawns give, before anything of the command is touched.
pub(crate) fn spawn_frozen<T>(
    _cmd: &mut Command,
    _spawn: impl FnOnce(&mut Command) -> Result<T, SpawnFailure>,
) -> Result<(T, bool), Error> {
    Err(Error::Unsupported {
        op: "spawn_suspended".into(),
        platform: std::env::consts::OS,
        detail: "a suspended spawn is implemented on Windows only: a POSIX child cannot be held                  before it runs without a gate in the child before exec, which std's blocking spawn                  does not allow"
            .into(),
    })
}

pub(super) fn spawn(cmd: &mut Command) -> Result<SuspendedChild, Error> {
    spawn_frozen(cmd, crate::child::spawn::spawn_uncommitted).map(|(child, wanted_kill_on_drop)| SuspendedChild {
        child,
        wanted_kill_on_drop,
    })
}

/// There is no `SuspendedChild` to resume here: `spawn` never returns one.
pub(super) fn release(_child: &Child) -> std::io::Result<()> {
    unreachable!("spawn_suspended never returns a SuspendedChild off Windows")
}
