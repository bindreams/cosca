//! The async frozen child: the window in which its identity can be recorded before it executes one
//! instruction. See [`Command::spawn_suspended`](crate::tokio::Command::spawn_suspended).

use super::Child;
use crate::child::owned::teardown::Disposition;
use crate::child::refused_commit;
use crate::child::spawn::failed_after_teardown;
use crate::child::suspended::could_not_resume;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::tokio::wait::{on_blocking_pool, Hop, Unjoined};

/// What `resume`'s hops are called in their errors.
const RESUME: &str = "cosca::tokio::SuspendedChild::resume";
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
/// opt-out applies to the [`Child`] `resume` returns. The drop is the async [`Child`]'s.
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
    /// Like [`spawn`](Self::spawn), an `async fn` that must run inside a Tokio runtime with I/O
    /// enabled, runs on the blocking pool until the process exists, and has the same contract for
    /// a dropped future and a runtime shutdown. A frozen child that a dropped future leaves is
    /// dropped as that contract says, and killed.
    ///
    /// # Errors
    ///
    /// As [`spawn`](Self::spawn), and the extra ones of
    /// [`cosca::Command::spawn_suspended`](crate::Command::spawn_suspended): [`Error::Unsupported`]
    /// off Windows and with [`elevate`](Self::elevate), before the command is touched, and
    /// [`Error::Containment`] for a [`Strongest`](crate::ContainMode::Strongest) or
    /// [`BestEffort`](crate::ContainMode::BestEffort) root whose job assignment fails.
    pub async fn spawn_suspended(&mut self) -> Result<SuspendedChild, Error> {
        platform::spawn(self).await
    }
}

impl SuspendedChild {
    /// The child's identity, or `None` when the OS refused to report it; see [`Child::id`]. It names
    /// the same process after [`resume`](Self::resume).
    pub fn id(&self) -> Option<ProcessId> {
        self.child.id()
    }

    /// The pid the child had at spawn; see [`Child::pid`].
    pub fn pid(&self) -> u32 {
        self.child.pid()
    }

    /// Let the child run, returning the ordinary async [`Child`].
    ///
    /// The resume itself walks one snapshot of the system's threads on the calling thread, which is
    /// bounded work that waits for no process exit; so does the commit of `kill_on_drop`, which asks
    /// the job to disarm. What can wait runs on the blocking pool, as [`spawn`](Command::spawn)'s
    /// work does: the teardown of a child whose resume failed or whose disarm was refused (a kill and
    /// the wait for the child to be reaped). A future dropped during that work leaves it running to
    /// its end on the pool.
    ///
    /// # Runtime
    ///
    /// A resume that succeeds needs no runtime: it can be polled on any thread. A teardown needs one,
    /// for its hop. Where it has none:
    ///
    /// - A refused disarm is torn down on the calling thread, as the child's drop would: the call
    ///   blocks it until the child is reaped, and the error carries the teardown's real fate and the
    ///   child it handed back.
    /// - After a failed release, the task that was to run the teardown is dropped on the calling
    ///   thread, and the child it held is dropped as its handle's drop does.
    ///
    /// Likewise when the runtime's shutdown cancels the hop (see [`spawn`](Command::spawn)'s
    /// "Runtime shutdown" for which thread drops the closure): the child's drop stands in for the
    /// teardown, and the error says so with `fate` [`ChildFate::Unknown`]. A refused disarm's child
    /// is armed first, so the drop kills it.
    ///
    /// # Errors
    ///
    /// [`Error::MayHaveStarted`] when the resume failed or only partly happened (a thread that
    /// something else also suspended stays suspended). The child is then torn down and the error's
    /// `fate` says how. A child killed by something else *before* the call is this error too. On
    /// Windows the same error, with cause [`Error::Io`], is returned when the command had
    /// `kill_on_drop(false)` and the job refused the disarm. A child whose kill is refused is left
    /// and warned, with `unreaped` `None` after a failed release, and handed back after the disarm's
    /// refusal, as for the sync [`SuspendedChild::resume`](crate::SuspendedChild::resume). The same
    /// error, with `fate` [`ChildFate::Unknown`], when a drop stood in for the teardown (see Runtime):
    /// its cause is still the release's (or the disarm's) failure, and the `cleanup` says that the
    /// teardown did not run.
    ///
    /// [`ChildFate::Unknown`]: crate::error::ChildFate::Unknown
    pub async fn resume(self) -> Result<Child, Error> {
        let SuspendedChild {
            mut child,
            wanted_kill_on_drop,
        } = self;
        let behind_front = child.inner.front().is_some();
        if let Err(e) = platform::release(&child) {
            let torn_down =
                on_blocking_pool(RESUME, move || child.inner.tear_down_or_hand_back(Disposition::Leave)).await;
            return Err(Error::from(failed_after_teardown(
                could_not_resume(e),
                behind_front,
                torn_down.map_err(dropped_instead),
            )));
        }
        child.inner.kill_on_drop = wanted_kill_on_drop;
        let Err(refusal) = child.inner.try_commit_kill_on_drop() else {
            return Ok(child);
        };
        let torn_down = match Hop::enter(RESUME) {
            // No pool to hop to: the teardown blocks this thread, as the child's drop would, and
            // reports the fate it found and the child it could not end.
            Err(_) => Ok(child.inner.tear_down_refused_commit()),
            Ok(hop) => {
                // The disarm was refused, so the job still holds the child armed, whatever the
                // command asked for. Arm the drop too before the child moves into the hop: a hop
                // the runtime's shutdown cancels drops its closure, and the child with it, and that
                // drop must kill it as the teardown would.
                child.inner.kill_on_drop = true;
                hop.run(move || child.inner.tear_down_refused_commit())
                    .await
                    .map_err(dropped_instead)
            }
        };
        Err(Error::from(refused_commit(refusal, behind_front, torn_down)))
    }
}

/// The failure of a teardown whose hop gave no result, which goes beside the error as its cleanup:
/// for a task that did not run, it says that the child was dropped in the teardown's place, as its
/// handle's drop does.
fn dropped_instead(unjoined: Unjoined) -> Error {
    match unjoined {
        Unjoined::NotRun(e) => Error::Io(crate::error::io_context(
            "the teardown did not run, and the child was dropped as its handle's drop does",
            e.into_io(),
        )),
        Unjoined::Unknown(e) => e,
    }
}

#[cfg(test)]
#[path = "suspended_tests.rs"]
mod suspended_tests;
