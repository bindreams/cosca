//! Backend-agnostic owned-process handle. A `Child` holds one of these and
//! forwards its wait/kill/identity operations to whichever backend spawned it:
//! the std path's [`SharedChild`], or (Windows only) the raw `CreateProcessW`
//! child [`RawChild`]. Keeping the fan-out here lets `Child` stay backend-blind.

use std::io;
use std::process::ExitStatus;
use std::time::Instant;

use shared_child::SharedChild;

#[cfg(windows)]
use super::spawn::windows_raw::RawChild;

/// The process backend behind an owned [`Child`](super::Child).
#[derive(Debug)]
pub(crate) enum ProcHandle {
    /// std-spawned child, adopted into `shared_child` for concurrent wait/kill.
    Std(SharedChild),
    /// Raw `CreateProcessW` child owning the process handle directly.
    #[cfg(windows)]
    Raw(RawChild),
}

impl ProcHandle {
    /// Block until the child exits.
    pub(crate) fn wait(&self) -> io::Result<ExitStatus> {
        match self {
            ProcHandle::Std(s) => s.wait(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.wait(),
        }
    }

    /// The exit status if the child has already exited, else `None`.
    pub(crate) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        match self {
            ProcHandle::Std(s) => s.try_wait(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.try_wait(),
        }
    }

    /// Block until the child exits or `deadline` passes (`Ok(None)` at expiry).
    pub(crate) fn wait_deadline(&self, deadline: Instant) -> io::Result<Option<ExitStatus>> {
        match self {
            ProcHandle::Std(s) => s.wait_deadline(deadline),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.wait_deadline(deadline),
        }
    }

    /// Hard-kill the process (already-exited is success).
    pub(crate) fn kill(&self) -> io::Result<()> {
        match self {
            ProcHandle::Std(s) => s.kill(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.kill(),
        }
    }

    /// The OS process id.
    pub(crate) fn id(&self) -> u32 {
        match self {
            ProcHandle::Std(s) => s.id(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.id(),
        }
    }
}
