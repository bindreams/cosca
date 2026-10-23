//! A child created frozen: the window in which its identity can be recorded before it executes
//! one instruction. See [`Command::spawn_suspended`](crate::Command::spawn_suspended).

use crate::child::Child;
use crate::command::Command;
use crate::containment::frozen::Frozen;
use crate::error::Error;
use crate::identity::ProcessId;

#[cfg(windows)]
#[path = "suspended/windows.rs"]
mod platform;
#[cfg(not(windows))]
#[path = "suspended/unsupported.rs"]
mod platform;

/// A child that exists but has not run: [`id`](Self::id) names it, and [`resume`](Self::resume)
/// lets it run.
///
/// Dropping it before `resume` kills the child, whatever
/// [`kill_on_drop`](Command::kill_on_drop) says: a frozen child nobody can resume is a leak. That
/// opt-out applies to the [`Child`] `resume` returns.
#[derive(Debug)]
pub struct SuspendedChild {
    // Field order is drop order: the child is torn down first, then its guard job closes.
    child: Child,
    frozen: Frozen,
    /// The command's `kill_on_drop`, applied by `resume`. The child itself was made with `true`.
    wanted_kill_on_drop: bool,
}

impl Command {
    /// Spawn the configured command frozen: created, contained as the command asks, and not yet
    /// run. Record the child's [`id`](SuspendedChild::id), then [`resume`](SuspendedChild::resume)
    /// it.
    ///
    /// # Windows
    ///
    /// The child is created suspended and is inside its containment before it executes one
    /// instruction. A child that no cosca job holds (uncontained, a [`TreeWalk`] root, a nested
    /// member) is held by a private guard job while it is frozen, so it dies with this process if
    /// this process dies. After `resume`, that job has no kill; the child stays a member of it,
    /// which [`Child::containment`] does not show (it stays `None`, `TreeWalk` or `Delegated`).
    /// The guard permits `CREATE_BREAKAWAY_FROM_JOB` only where the job the child was already in
    /// does (or the child was in none), so the child's breakaway is allowed or denied as an
    /// ordinary spawn's would be.
    ///
    /// **A parent crash between `CreateProcessW` returning and the job assignment can leave a frozen
    /// process nothing kills.**
    ///
    /// # Other platforms
    ///
    /// [`Error::Unsupported`], before the command is touched.
    ///
    /// # Errors
    ///
    /// As [`spawn`](Self::spawn), and two more that `spawn` would not give, each an
    /// [`Error::Containment`] cause: a [`Strongest`] root whose job assignment fails (`spawn` falls
    /// back to [`TreeWalk`] there; a frozen root without a job would have nothing to kill it), and a
    /// failed assignment to the guard job. A frozen spawn that fails after the process exists
    /// reports [`Error::MayHaveStarted`].
    /// `spawn_suspended` with [`elevate`](Self::elevate) is [`Error::Unsupported`] on every platform,
    /// even for an already-elevated caller.
    ///
    /// [`Strongest`]: crate::ContainMode::Strongest
    /// [`TreeWalk`]: crate::ContainMode::TreeWalk
    pub fn spawn_suspended(&mut self) -> Result<SuspendedChild, Error> {
        platform::spawn(self)
    }
}

impl SuspendedChild {
    /// The child's identity. It names the same process after [`resume`](Self::resume).
    pub fn id(&self) -> ProcessId {
        self.child.id()
    }

    /// Let the child run, returning the ordinary [`Child`].
    ///
    /// # Errors
    ///
    /// [`Error::MayHaveStarted`] when the resume failed or only partly happened (a thread that
    /// something else also suspended stays suspended). The child is then torn down and the error's
    /// `fate` says how. A child killed by something else *before* the call is this error too.
    pub fn resume(self) -> Result<Child, Error> {
        let SuspendedChild {
            mut child,
            frozen,
            wanted_kill_on_drop,
        } = self;
        match frozen.release(&child) {
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
