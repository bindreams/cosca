//! Off Windows there is no frozen spawn.

use crate::child::{Child, SuspendedChild};
use crate::command::Command;
use crate::error::Error;

pub(super) fn spawn(_cmd: &mut Command) -> Result<SuspendedChild, Error> {
    Err(Error::Unsupported {
        op: "spawn_suspended".into(),
        platform: std::env::consts::OS,
        detail: "a suspended spawn is implemented on Windows only: a POSIX child cannot be held \
                 before it runs without a gate in the child before exec, which std's blocking spawn \
                 does not allow"
            .into(),
    })
}

/// There is no `SuspendedChild` to resume here: `spawn` never returns one.
pub(super) fn release(_child: &Child) -> std::io::Result<()> {
    unreachable!("spawn_suspended never returns a SuspendedChild off Windows")
}
