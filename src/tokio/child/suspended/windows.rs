//! The Windows async frozen spawn: the ordinary async spawn with a suspended request.

use super::{Child, SuspendedChild};
use crate::child::suspended::platform::spawn_frozen;
use crate::containment::windows::{resume_initial_threads, SuspendCount};
use crate::error::Error;
use crate::tokio::spawn::spawn_uncommitted;
use crate::tokio::Command;

/// Test-only accessors, `pub` so integration tests can call them.
impl SuspendedChild {
    /// Whether the child is inside its containment job.
    #[doc(hidden)]
    pub fn test_job_handle_contains_self(&self) -> bool {
        self.child.test_job_handle_contains_self()
    }

    /// Whether the child's containment job kills its members when its last handle closes.
    #[doc(hidden)]
    pub fn test_job_kills_on_close(&self) -> bool {
        self.child.test_job_kills_on_close()
    }

    /// The containment the child has (and keeps after `resume`).
    #[doc(hidden)]
    pub fn test_containment(&self) -> crate::Containment {
        self.child.containment()
    }
}

pub(super) fn spawn(cmd: &mut Command) -> Result<SuspendedChild, Error> {
    let (child, wanted_kill_on_drop) = spawn_frozen(cmd.as_sync_mut(), spawn_uncommitted)?;
    Ok(SuspendedChild {
        child,
        wanted_kill_on_drop,
    })
}

/// Resume the child's initial thread, which must have been suspended exactly once.
///
/// The backend holds the process handle until `resume`: nothing can poll or reap an unresumed
/// child, so a missing handle is a broken invariant, not a runtime failure.
pub(super) fn release(child: &Child) -> std::io::Result<()> {
    let handle = child
        .process_handle()
        .expect("a frozen child's process handle is held until it is resumed");
    resume_initial_threads(handle, SuspendCount::ExactlyOne)
}
