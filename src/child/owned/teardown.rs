//! The teardown of a child a `Child` drops, written once for every OS: kill it, then settle what
//! became of it. What the kill answered decides.
//!
//! - **Delivered, or found nothing to signal (`Gone`):** the child is dead or dying, so the reap is
//!   a blocking wait through [`OwnedChild::wait`]. A kill cannot be caught or refused on the way, so
//!   the wait ends.
//! - **Failed, whatever the error:** nothing asked the child to exit (an elevated child a plain
//!   parent cannot signal fails with `EPERM` on Unix and `ACCESS_DENIED` on Windows, and so can a
//!   handle that lost its rights), so the teardown never blocks on it: one look at the present
//!   moment, which collects it if it has exited. The decision is on the observed answer and never on a flag saying elevation was asked for: a
//!   child that gained privilege on its own (a setuid helper) fails the kill the same way, and a
//!   blocking wait would hang the drop for ever.

use std::process::ExitStatus;

use super::{ChildWaitOutcome, OwnedChild};
use crate::child::lifecycle::{child_named, orphaned_note, status_of_outcome, Orphaned};
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::signal::{Sent, Sig};
use crate::wait::teardown_warn::{wait_warning, Due};

/// What a teardown does to the child.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TeardownKind {
    /// Kill it, then settle it as the module doc says.
    Kill,
}

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
    /// Best-effort teardown, the one entry point: do what `kind` says, then settle the child. `id`
    /// is the child's identity, if the caller read one. `due` is the threshold of the slow-teardown
    /// warn on the blocking wait (`None`: no warn).
    ///
    /// Returns the child's fate, and what it could not do for the caller's one warn. It logs
    /// neither above `debug`, except that slow-teardown warn.
    pub(crate) fn tear_down(&self, id: Option<ProcessId>, kind: TeardownKind, due: Option<Due>) -> TeardownOutcome {
        match kind {
            TeardownKind::Kill => self.kill_and_settle(id, due),
        }
    }

    fn kill_and_settle(&self, id: Option<ProcessId>, due: Option<Due>) -> TeardownOutcome {
        #[cfg(test)]
        super::seams::note_root_teardown();
        match self.signal(Sig::Kill) {
            Ok(sent) => {
                #[cfg(test)]
                crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterDropKill);
                match self.wait_after_kill(matches!(sent, Sent::Delivered), due) {
                    Ok(_status) => {
                        #[cfg(test)]
                        if let Some(pid) = self.pid() {
                            crate::child::spawn::fault::record_teardown_reap(pid, _status);
                        }
                        TeardownOutcome::new(ChildFate::Reaped)
                    }
                    Err(outcome) => outcome,
                }
            }
            Err(refused) => self.look_after_refused_kill(id, refused),
        }
    }

    /// Reap a child a tree kill has just ended, sending it nothing: the kill bounds the wait.
    /// A failed reap comes back in [`TeardownOutcome::left`], as for [`tear_down`](Self::tear_down).
    #[cfg(unix)]
    pub(crate) fn reap_after_tree_kill(&self) -> TeardownOutcome {
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        match self.wait_after_kill(true, None) {
            Ok(_) => TeardownOutcome::new(ChildFate::Reaped),
            Err(outcome) => outcome,
        }
    }

    /// The blocking wait that follows a kill, `delivered` or not. `Ok` is the status it reaped; the
    /// `Err` is the outcome of a teardown that reaped nothing. With `due`, it first watches for the
    /// exit until the threshold, and warns once if the child has not exited by then.
    fn wait_after_kill(&self, delivered: bool, due: Option<Due>) -> Result<ExitStatus, TeardownOutcome> {
        let pid = self.pid();
        // What a failed wait shows of the child: only a delivered kill says it is dead or dying.
        let failed = |fate_left: Option<String>| TeardownOutcome {
            fate: if delivered {
                ChildFate::Killed
            } else {
                ChildFate::Unknown
            },
            left: fate_left,
        };
        let outcome = wait_warning(
            self,
            due,
            // A look that cannot read the exit ends the watch: the wait finds out.
            |child, until| child.exited_by(Some(until)).unwrap_or(true),
            |after| crate::child::spawn::warn_still_waiting(pid, after),
            |child| child.wait(None),
        )
        .map_err(|e| failed(Some(wait_failure(pid, &e))))?;
        let status = status_of_outcome(pid, outcome, Orphaned::Quiet);
        match (outcome, status) {
            (ChildWaitOutcome::Foreign(foreign), _) => {
                log::debug!(
                    "teardown of {}: it was reaped elsewhere before the reap after the kill",
                    child_named(pid)
                );
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

    /// The one look after a kill that failed with `refused`, never a wait. `id` is the child's
    /// identity, if the caller read one.
    pub(crate) fn look_after_refused_kill(&self, id: Option<ProcessId>, refused: Error) -> TeardownOutcome {
        let pid = self.pid();
        let who = child_named(pid);
        // A child reaped elsewhere is read from the typed outcome, so it is `Gone` on every OS: the
        // error `status_of_outcome` renders it as is `ECHILD` on Unix only.
        let (fate, look_failure) = match self.wait(Some(crate::wait::now())) {
            Ok(ChildWaitOutcome::Foreign(foreign)) => (foreign.fate(false), None),
            looked => {
                let looked = looked.and_then(|outcome| status_of_outcome(pid, outcome, Orphaned::Quiet));
                let failure = looked.as_ref().err().map(ToString::to_string);
                let fate = crate::child::spawn::fate_of_a_look(looked.map_err(|e| e.into_io().raw_os_error()), id);
                (fate, failure)
            }
        };
        let left = match (&fate, look_failure) {
            (ChildFate::Running { .. }, _) => {
                Some(format!("{who} could not be terminated ({refused}); leaving it running"))
            }
            (ChildFate::Unknown, Some(failure)) => Some(format!(
                "{who} could not be terminated ({refused}), and the look at it failed: {failure}"
            )),
            _ => None,
        };
        TeardownOutcome { fate, left }
    }
}

/// A failed reap after a kill, for the caller's warn: it leaves a zombie or an unread exit.
fn wait_failure(pid: Option<u32>, e: &Error) -> String {
    format!("teardown of {}: the reap after the kill failed: {e}", child_named(pid))
}
