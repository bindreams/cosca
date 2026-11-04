//! The teardown of a child a `Child` drops, written once for every OS: kill it, then settle what
//! became of it. What the kill answered decides.
//!
//! - **Delivered, or found nothing to signal (`Gone`):** the child is dead or dying, so the reap is
//!   a blocking wait through [`OwnedChild::wait`]. A kill cannot be caught or refused on the way, so
//!   the wait ends.
//! - **Failed, whatever the error:** nothing asked the child to exit (an elevated child a plain
//!   parent cannot signal fails with `EPERM` on Unix and `ACCESS_DENIED` on Windows, and so can a
//!   handle that lost its rights), so the teardown never blocks on it: one look at the present
//!   moment, which collects it if it has exited. A child still running is [`ChildFate::Running`]
//!   whatever the error, never `Unknown`, and the failure is returned in
//!   [`TeardownOutcome::left`] for the caller's one warn. A look that finds it reaped elsewhere is
//!   `Gone` and warns nothing; a look that fails otherwise is `Unknown` and warns with its error.
//!   The decision is on the observed answer and never on a flag saying elevation was asked for: a
//!   child that gained privilege on its own (a setuid helper) fails the kill the same way, and a
//!   blocking wait would hang the drop for ever.

use std::process::ExitStatus;

use super::{ChildWaitOutcome, OwnedChild};
use crate::child::lifecycle::{orphaned_note, status_of_outcome, Orphaned};
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::signal::{Sent, Sig};

/// What a teardown of the root did: the child's fate, and what it could not do, for the event's one
/// warn (a child it could not signal and left running, a reap that failed after the kill).
#[derive(Debug)]
pub(crate) struct TeardownOutcome {
    pub(crate) fate: ChildFate,
    pub(crate) left: Option<String>,
}

impl TeardownOutcome {
    /// A teardown with nothing to warn of.
    pub(crate) fn new(fate: ChildFate) -> TeardownOutcome {
        TeardownOutcome { fate, left: None }
    }
}

impl OwnedChild {
    /// Best-effort teardown for `kill_on_drop`: kill, then settle the child as the module doc says.
    /// Returns the child's fate, and what it could not do for the caller's one warn. It logs
    /// neither above `debug`.
    pub(crate) fn teardown_on_drop(&self, id: ProcessId) -> TeardownOutcome {
        #[cfg(test)]
        super::seams::note_root_teardown();
        let pid = id.pid();
        match self.signal(Sig::Kill) {
            Ok(sent) => {
                #[cfg(test)]
                crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterDropKill);
                match self.wait_after_kill(pid, matches!(sent, Sent::Delivered)) {
                    Ok(_status) => {
                        #[cfg(test)]
                        crate::child::spawn::fault::record_teardown_reap(pid, _status);
                        TeardownOutcome::new(ChildFate::Reaped)
                    }
                    Err(outcome) => outcome,
                }
            }
            Err(refused) => self.look_after_refused_kill(id, refused),
        }
    }

    /// Reap a child a tree kill has just ended, sending it nothing: the kill bounds the wait.
    /// A failed reap comes back in [`TeardownOutcome::left`], as for
    /// [`teardown_on_drop`](Self::teardown_on_drop).
    #[cfg(unix)]
    pub(crate) fn reap_after_tree_kill(&self, pid: u32) -> TeardownOutcome {
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        match self.wait_after_kill(pid, true) {
            Ok(_) => TeardownOutcome::new(ChildFate::Reaped),
            Err(outcome) => outcome,
        }
    }

    /// The blocking wait that follows a kill, `delivered` or not. `Ok` is the status it reaped; the
    /// `Err` is the outcome of a teardown that reaped nothing.
    fn wait_after_kill(&self, pid: u32, delivered: bool) -> Result<ExitStatus, TeardownOutcome> {
        // What a failed wait shows of the child: only a delivered kill says it is dead or dying.
        let failed = |fate_left: Option<String>| TeardownOutcome {
            fate: if delivered {
                ChildFate::Killed
            } else {
                ChildFate::Unknown
            },
            left: fate_left,
        };
        let outcome = self.wait(None).map_err(|e| failed(Some(wait_failure(pid, &e))))?;
        let status = status_of_outcome(pid, outcome, Orphaned::Quiet);
        match (outcome, status) {
            (ChildWaitOutcome::Foreign(foreign), _) => {
                log::debug!("teardown of child {pid}: it was reaped elsewhere before the reap after the kill");
                Err(TeardownOutcome {
                    fate: foreign.fate(delivered),
                    left: (foreign == Foreign::Orphaned).then(|| orphaned_note(pid)),
                })
            }
            (_, Ok(Some(status))) => Ok(status),
            (_, Ok(None)) => {
                debug_assert!(false, "an unbounded wait ended at a deadline");
                Err(failed(None))
            }
            (_, Err(e)) => Err(failed(Some(wait_failure(pid, &e)))),
        }
    }

    /// The one look after a kill that failed with `refused`, never a wait.
    fn look_after_refused_kill(&self, id: ProcessId, refused: Error) -> TeardownOutcome {
        let pid = id.pid();
        // A child reaped elsewhere is read from the typed outcome, so it is `Gone` on every OS: the
        // error `status_of_outcome` renders it as is `ECHILD` on Unix only.
        let (fate, look_failure) = match self.wait(Some(crate::wait::now())) {
            Ok(ChildWaitOutcome::Foreign(foreign)) => (foreign.fate(false), None),
            looked => {
                let looked = looked.and_then(|outcome| status_of_outcome(pid, outcome, Orphaned::Quiet));
                let failure = looked.as_ref().err().map(ToString::to_string);
                let fate =
                    crate::child::spawn::fate_of_a_look(looked.map_err(|e| e.into_io().raw_os_error()), Some(id));
                (fate, failure)
            }
        };
        // Only a child still running is "left"; a look that found it reaped elsewhere warns nothing.
        let left = match (&fate, look_failure) {
            (ChildFate::Running { .. }, _) => Some(format!(
                "child {pid} could not be terminated on drop ({refused}); leaving it running"
            )),
            (ChildFate::Unknown, Some(failure)) => Some(format!(
                "child {pid} could not be terminated on drop ({refused}), and the look at it failed: {failure}"
            )),
            _ => None,
        };
        TeardownOutcome { fate, left }
    }
}

/// A failed reap after a kill, for the caller's warn: it leaves a zombie or an unread exit.
fn wait_failure(pid: u32, e: &Error) -> String {
    format!("teardown of child {pid}: the reap after the kill failed: {e}")
}
