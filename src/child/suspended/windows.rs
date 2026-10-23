//! The Windows frozen spawn: the ordinary spawn with a suspended request, and the token it leaves.

use crate::child::spawn::{spawn_uncommitted, SpawnFailure};
use crate::child::{Child, SuspendedChild};
use crate::command::Command;
use crate::containment::windows::{resume_initial_threads, SuspendCount};
use crate::error::Error;

/// Test-only accessors, `pub` so integration tests can call them.
impl SuspendedChild {
    /// Test-only: whether the child is inside its containment job.
    #[doc(hidden)]
    pub fn test_job_handle_contains_self(&self) -> bool {
        self.child.test_job_handle_contains_self()
    }

    /// Test-only: the containment the child has (and keeps after `resume`).
    #[doc(hidden)]
    pub fn test_containment(&self) -> crate::Containment {
        self.child.containment()
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

/// Spawn `cmd` frozen through `spawn`, which is the sync or the async uncommitted spawn. Returns
/// what it made and the command's own `kill_on_drop`, which the caller applies on resume: the child
/// itself is made with `true`.
pub(crate) fn spawn_frozen<T>(
    cmd: &mut Command,
    spawn: impl FnOnce(&mut Command) -> Result<T, SpawnFailure>,
) -> Result<(T, bool), Error> {
    if cmd.elevation_request().enabled {
        return Err(Error::Unsupported {
            op: "spawn_suspended() with elevate()".into(),
            platform: "windows",
            detail: "an elevated spawn goes through ShellExecuteEx, which cannot create a process                      suspended; drop one of the two"
                .into(),
        });
    }
    let wanted_kill_on_drop = cmd.kill_on_drop_flag();
    let borrowed = Borrowed::new(cmd);
    let spawned = spawn(&mut *borrowed.cmd);
    drop(borrowed);
    Ok((spawned?, wanted_kill_on_drop))
}

pub(super) fn spawn(cmd: &mut Command) -> Result<SuspendedChild, Error> {
    let (child, wanted_kill_on_drop) = spawn_frozen(cmd, spawn_uncommitted)?;
    Ok(SuspendedChild {
        child,
        wanted_kill_on_drop,
    })
}

/// Resume the child's initial thread, which must have been suspended exactly once.
pub(super) fn release(child: &Child) -> std::io::Result<()> {
    resume_initial_threads(child.process_handle(), SuspendCount::ExactlyOne)
}
