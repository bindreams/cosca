//! A child created frozen: the window in which its identity can be recorded before it executes
//! one instruction. See [`Command::spawn_suspended`](crate::Command::spawn_suspended).

use crate::child::Child;
use crate::command::Command;
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
    /// it.
    ///
    /// # Windows
    ///
    /// The child is created suspended and executes no instruction until `resume`. A frozen child
    /// has exactly the lifetime guarantees of the containment the command asked for, and no more:
    ///
    /// - A [`Strongest`] root (`contain()`) is in its kill-on-close job before `spawn_suspended`
    ///   returns, so the job ends it if this process dies while it is frozen.
    /// - Any other child (no containment, a [`TreeWalk`] root, a member of an enclosing cosca tree)
    ///   gets no job of its own. **If this process dies while it is frozen, such a child stays
    ///   frozen until someone kills it**; its recorded [`id`](SuspendedChild::id) names it. A job
    ///   this process is itself in holds it as it holds any child, and ends it when that job closes,
    ///   if that job kills its members on close.
    /// - A crash between `CreateProcessW` returning and the job assignment can leave even a
    ///   [`Strongest`] root frozen with nothing to kill it.
    ///
    /// After `resume`, the child is the one an ordinary [`spawn`](Self::spawn) makes: the same jobs
    /// and the same `CREATE_BREAKAWAY_FROM_JOB` verdict.
    ///
    /// # Other platforms
    ///
    /// [`Error::Unsupported`], before the command is touched.
    ///
    /// # Errors
    ///
    /// As [`spawn`](Self::spawn), and one more that `spawn` would not give: a [`Strongest`] root
    /// whose job assignment fails is an [`Error::Containment`] (`spawn` falls back to [`TreeWalk`]
    /// there; a frozen root without a job is not worth having). A frozen spawn that fails after the
    /// process exists reports [`Error::MayHaveStarted`].
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
