//! [`Unreaped`]: a child a failed spawn or a failed `status`, `output` or `read` could not end (its
//! kill was refused, or, after `status`, `output` or `read`, it is an elevation front, which is sent
//! none), handed to the caller who owns it.

use std::process::ExitStatus;

use super::slot::ChildSlot;
use super::OwnedChild;
use crate::child::lifecycle::{orphaned_note, wait_to_exit, Orphaned, WaitToExitError};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::os_process::child_named;

/// A child a failed spawn, or a sync [`Command::status`](crate::Command::status),
/// [`output`](crate::Command::output) or [`read`](crate::Command::read) that failed after it, could
/// not end: its kill was refused (`EPERM`, `ACCESS_DENIED`), or, after one of those three calls, it is
/// an elevation front, which is sent no kill because one would orphan the elevated program; and it
/// still runs. A failed spawn leaves a front running instead, with a warning. It comes back in
/// [`Error::MayHaveStarted`], which the caller owns from then on.
///
/// Settle it with [`wait`](Unreaped::wait), which blocks until the child exits and reaps it, or
/// [`leak`](Unreaped::leak), which gives it up. A value dropped otherwise does what `wait` does,
/// then logs one line naming the child. So the drop blocks: in async code, take the value off the
/// runtime thread (`spawn_blocking`) or `leak` it. For a front the wait ends when the front
/// exits, no later than the call that failed would have waited had it succeeded; `leak` is how to
/// not wait for it at all.
///
/// A value dropped while its thread is panicking does not wait: it gives the child up, which keeps
/// running unreaped until this process exits, and logs one `warn` naming its pid.
///
/// ```
/// use cosca::error::Error;
///
/// fn settle(error: Error) {
///     if let Error::MayHaveStarted { unreaped: Some(child), .. } = error {
///         eprintln!("waiting for pid {:?}", child.pid());
///         match child.wait() {
///             Ok(status) => eprintln!("it exited: {status}"),
///             Err(e) => eprintln!("could not wait for it: {e}"),
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Unreaped {
    /// Empty once `wait`, `leak` or the drop has taken the child: it is settled once.
    child: ChildSlot,
    id: Option<ProcessId>,
}

impl Unreaped {
    /// Own `child`, whose identity the spawn read as `id`, if it did.
    pub(crate) fn new(child: OwnedChild, id: Option<ProcessId>) -> Unreaped {
        Unreaped {
            child: ChildSlot::new(child),
            id,
        }
    }

    /// The child's pid; `None` for a Linux child whose spawn learned only its pidfd.
    pub fn pid(&self) -> Option<u32> {
        self.child.pid()
    }

    /// The child's identity, if the spawn read one.
    pub fn id(&self) -> Option<ProcessId> {
        self.id
    }

    /// Block until the child exits and reap it. `Err` if someone else reaped it, or the wait
    /// failed; the child is settled either way.
    pub fn wait(mut self) -> Result<ExitStatus, Error> {
        let child = self.child.take().expect("a live Unreaped holds its child");
        Ok(wait_to_exit(&child, None, Orphaned::Warn)?)
    }

    /// Give the child up, unreaped. Logs nothing.
    pub fn leak(mut self) {
        drop(self.child.take());
    }
}

impl Drop for Unreaped {
    fn drop(&mut self) {
        let Some(child) = self.child.take() else {
            return;
        };
        let pid = child.pid();
        let who = child_named(pid);
        // A destructor that blocks on a child during unwinding can hang the panic for good.
        if std::thread::panicking() {
            log::warn!("{who} was dropped without wait or leak while the thread is panicking; gave it up, unreaped");
            return;
        }
        match wait_to_exit(&child, None, Orphaned::Quiet) {
            Ok(status) => {
                log::warn!("{who} was dropped without wait or leak; waited for it and reaped it ({status})")
            }
            Err(WaitToExitError::Elsewhere(Foreign::Orphaned)) => log::warn!("{}", orphaned_note(pid)),
            Err(WaitToExitError::Elsewhere(_)) => {
                log::debug!("{who} was dropped without wait or leak; someone else had reaped it");
            }
            Err(WaitToExitError::Failed(e)) => {
                log::warn!("{who} was dropped without wait or leak, and waiting for it failed: {e}")
            }
        }
    }
}
