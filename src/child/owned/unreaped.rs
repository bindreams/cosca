//! [`Unreaped`]: a child a failed spawn could not end, handed to the caller who owns it.

use std::process::ExitStatus;

use super::{ChildWaitOutcome, OwnedChild};
use crate::child::lifecycle::{orphaned_note, status_of_outcome, wait_to_exit, Orphaned};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::os_process::child_named;

/// A child a failed spawn could not end: its kill was refused (`EPERM`, `ACCESS_DENIED`) and it
/// still runs. It comes back in [`Error::MayHaveStarted`], which the caller owns from then on.
///
/// Settle it with [`wait`](Unreaped::wait), which blocks until the child exits and reaps it, or
/// [`leak`](Unreaped::leak), which gives it up. A value dropped otherwise does what `wait` does,
/// then logs one line naming the child. So the drop blocks: in async code, take the value off the
/// runtime thread (`spawn_blocking`) or `leak` it.
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
    /// `None` once `wait`, `leak` or the drop has taken the child: it is settled once.
    child: Option<OwnedChild>,
    id: Option<ProcessId>,
}

impl Unreaped {
    /// Own `child`, whose identity the spawn read as `id`, if it did.
    #[allow(
        dead_code,
        reason = "the first spawn teardown that hands a child back lands in the next PR"
    )]
    pub(crate) fn new(child: OwnedChild, id: Option<ProcessId>) -> Unreaped {
        Unreaped { child: Some(child), id }
    }

    /// The child's pid; `None` for a Linux child whose spawn learned only its pidfd.
    pub fn pid(&self) -> Option<u32> {
        self.child
            .as_ref()
            .expect("a live Unreaped holds its child: wait and leak consume it")
            .pid()
    }

    /// The child's identity, if the spawn read one.
    pub fn id(&self) -> Option<ProcessId> {
        debug_assert!(self.child.is_some(), "only a live Unreaped is asked for its identity");
        self.id
    }

    /// Block until the child exits and reap it. `Err` if someone else reaped it, or the wait
    /// failed; the child is settled either way.
    pub fn wait(mut self) -> Result<ExitStatus, Error> {
        let child = self.child.take().expect("a live Unreaped holds its child");
        wait_to_exit(&child)
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
        match child.wait(None) {
            Ok(ChildWaitOutcome::Foreign(Foreign::Orphaned)) => log::warn!("{}", orphaned_note(pid)),
            Ok(ChildWaitOutcome::Foreign(_)) => {
                log::debug!("{who} was dropped without wait or leak; someone else had reaped it");
            }
            Ok(outcome) => match status_of_outcome(pid, outcome, Orphaned::Quiet) {
                Ok(Some(status)) => {
                    log::warn!("{who} was dropped without wait or leak; waited for it and reaped it ({status})")
                }
                Ok(None) => {
                    debug_assert!(false, "an unbounded wait ended at a deadline");
                    log::warn!("{who} was dropped without wait or leak; its wait ended with no exit");
                }
                Err(e) => log::warn!("{who} was dropped without wait or leak; its exit could not be read: {e}"),
            },
            Err(e) => log::warn!("{who} was dropped without wait or leak, and waiting for it failed: {e}"),
        }
    }
}
