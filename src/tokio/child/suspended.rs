//! The async frozen child: the window in which its identity can be recorded before it executes one
//! instruction. See [`Command::spawn_suspended`](crate::tokio::Command::spawn_suspended).

use super::Child;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::tokio::Command;

#[cfg(windows)]
#[path = "suspended/windows.rs"]
mod platform;
#[cfg(not(windows))]
#[path = "suspended/unsupported.rs"]
mod platform;

/// A child that exists but has not run: [`id`](Self::id) names it, and [`resume`](Self::resume)
/// lets it run. The async twin of [`cosca::SuspendedChild`](crate::SuspendedChild).
///
/// Dropping it before `resume` kills the child, whatever
/// [`kill_on_drop`](Command::kill_on_drop) says: a frozen child nobody can resume is a leak. That
/// opt-out applies to the [`Child`] `resume` returns. The drop is the async [`Child`]'s: it signals
/// and returns, and waits for nothing.
///
/// If this process dies while the child is frozen, what happens to the child is what the child's
/// containment gives (see [`Command::spawn_suspended`]).
#[derive(Debug)]
pub struct SuspendedChild {
    child: Child,
    /// The command's `kill_on_drop`, applied by `resume`. The child itself was made with `true`.
    wanted_kill_on_drop: bool,
}

impl Command {
    /// Spawn the configured command frozen: created, contained as the command asks, and not yet
    /// run. Record the child's [`id`](SuspendedChild::id), then [`resume`](SuspendedChild::resume)
    /// it. Mirrors [`cosca::Command::spawn_suspended`](crate::Command::spawn_suspended); see there
    /// for what a frozen child's lifetime guarantees are in each containment, and for the
    /// platform limits.
    ///
    /// Like [`spawn`](Self::spawn), a plain `fn` that must run inside a Tokio runtime with I/O
    /// enabled, and blocks until the process exists.
    ///
    /// # Errors
    ///
    /// As [`spawn`](Self::spawn), and the extra ones of
    /// [`cosca::Command::spawn_suspended`](crate::Command::spawn_suspended): [`Error::Unsupported`]
    /// off Windows and with [`elevate`](Self::elevate), before the command is touched, and
    /// [`Error::Containment`] for a [`Strongest`](crate::ContainMode::Strongest) root whose job
    /// assignment fails.
    pub fn spawn_suspended(&mut self) -> Result<SuspendedChild, Error> {
        platform::spawn(self)
    }
}

impl SuspendedChild {
    /// The child's identity. It names the same process after [`resume`](Self::resume).
    pub fn id(&self) -> ProcessId {
        self.child.id()
    }

    /// Let the child run, returning the ordinary async [`Child`].
    ///
    /// A plain `fn`, not `async`: the deferred half of a spawn. It blocks the calling thread only as
    /// long as `spawn` does (a walk over the system's threads) and waits for no process exit.
    ///
    /// # Errors
    ///
    /// [`Error::MayHaveStarted`] when the resume failed or only partly happened (a thread that
    /// something else also suspended stays suspended). The child is then torn down and the error's
    /// `fate` says how. A child killed by something else *before* the call is this error too.
    pub fn resume(self) -> Result<Child, Error> {
        let SuspendedChild {
            mut child,
            wanted_kill_on_drop,
        } = self;
        match platform::release(&child) {
            Ok(()) => {
                child.kill_on_drop = wanted_kill_on_drop;
                child.commit_kill_on_drop();
                Ok(child)
            }
            Err(e) => {
                let fate = child.tear_down_now();
                Err(crate::child::spawn::after_the_spawn(
                    Error::Containment {
                        detail: format!("could not resume the frozen child: {e}"),
                    },
                    fate,
                    child.behind_wrapper(),
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "suspended_tests.rs"]
mod suspended_tests;
