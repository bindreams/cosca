//! The Windows frozen spawn: the ordinary spawn with a suspended request, and the token it leaves.

use crate::child::spawn::spawn_uncommitted;
use crate::child::{Spawned, SuspendedChild};
use crate::command::Command;
use crate::error::Error;

impl SuspendedChild {
    /// Test-only: whether the child is inside its containment job. `pub` so integration tests can
    /// call it.
    #[doc(hidden)]
    pub fn test_job_handle_contains_self(&self) -> bool {
        self.child.test_job_handle_contains_self()
    }

    /// Test-only: the containment the child has (and keeps after `resume`). `pub` so integration
    /// tests can call it.
    #[doc(hidden)]
    pub fn test_containment(&self) -> crate::Containment {
        self.child.containment()
    }

    /// Test-only: whether the child is inside its guard job (an uncontained, `TreeWalk` or nested
    /// frozen child; `false` for a Strongest root, whose containment job guards it). `pub` so
    /// integration tests can call it.
    #[doc(hidden)]
    pub fn test_guard_job_contains_self(&self) -> bool {
        self.frozen.guard_contains(self.id().pid())
    }
}

/// A command borrowed for one frozen spawn: its `kill_on_drop` forced on and the suspended request
/// set, both put back when this drops, so a panic cannot leave the builder frozen.
struct Borrowed<'a> {
    cmd: &'a mut Command,
    kill_on_drop: bool,
    suspended: bool,
}

impl<'a> Borrowed<'a> {
    fn new(cmd: &'a mut Command) -> Borrowed<'a> {
        let kill_on_drop = cmd.kill_on_drop_flag();
        cmd.kill_on_drop(true);
        let suspended = cmd.set_suspended(true);
        Borrowed {
            cmd,
            kill_on_drop,
            suspended,
        }
    }
}

impl Drop for Borrowed<'_> {
    fn drop(&mut self) {
        self.cmd.kill_on_drop(self.kill_on_drop);
        self.cmd.set_suspended(self.suspended);
    }
}

pub(super) fn spawn(cmd: &mut Command) -> Result<SuspendedChild, Error> {
    if cmd.elevation_request().enabled {
        return Err(Error::Unsupported {
            op: "spawn_suspended() with elevate()".into(),
            platform: "windows",
            detail: "an elevated spawn goes through ShellExecuteEx, which cannot create a process \
                     suspended; drop one of the two"
                .into(),
        });
    }
    let wanted_kill_on_drop = cmd.kill_on_drop_flag();
    let borrowed = Borrowed::new(cmd);
    let spawned = spawn_uncommitted(&mut *borrowed.cmd);
    drop(borrowed);
    let Spawned { child, frozen } = spawned?;
    Ok(SuspendedChild {
        child,
        frozen: frozen.expect("a frozen request always yields its token"),
        wanted_kill_on_drop,
    })
}
