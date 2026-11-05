//! The teardown of a child, written once for every OS: [`OwnedChild::tear_down`] does what its
//! [`TeardownKind`] says, then settles what became of the child.
//!
//! # Kill
//!
//! Kill it, then settle it. What the kill answered decides.
//!
//! - **Delivered, or found nothing to signal (`Gone`):** the child is dead or dying, so the reap is
//!   a blocking wait through [`OwnedChild::wait`]. A kill cannot be caught or refused on the way, so
//!   the wait ends.
//! - **Failed, whatever the error:** nothing asked the child to exit (an elevated child a plain
//!   parent cannot signal fails with `EPERM` on Unix and `ACCESS_DENIED` on Windows, and so can a
//!   handle that lost its rights), so the teardown never blocks on it: one look at the present
//!   moment, which collects it if it has exited. The decision is on the observed answer and never on a flag saying elevation was asked for: a
//!   child that gained privilege on its own (a setuid helper) fails the kill the same way, and a
//!   blocking wait would hang the drop for ever. The exception is a child that a kill sent through
//!   its containment ([`Reach::reached`]) reached: that kill is asynchronous and ends it, so a look
//!   would race it, and the reap is the wait the kill bounds.
//!
//! # Look
//!
//! An elevation front is sent nothing: a kill of it would orphan the elevated program. One look at
//! the present moment collects it if it has exited. A running front is waited for only if
//! [`Reach::reached`] says a kill sent elsewhere (a cgroup leaf's) reached it, since that kill bounds
//! the wait; otherwise it is left running. [`TeardownOutcome::look`] says how it went, as data: the
//! caller knows why the front was not killed and whether it hands a running front back
//! ([`Disposition`]), and words it.

use std::io;
use std::process::ExitStatus;

use super::{ChildWaitOutcome, OwnedChild};
use crate::child::lifecycle::{orphaned_note, status_of_outcome, wait_to_exit, Orphaned, WaitToExitError};
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::os_process::child_named;
use crate::signal::{Sent, Sig};
use crate::wait::teardown_warn::Due;

/// What the caller does with a child that still runs after its kill was refused, or after it was
/// sent none (an elevation front): `Leave` it running, or `HandBack` it as an
/// [`Unreaped`](crate::Unreaped). It words the warn of the event; the caller does what it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Leave,
    HandBack,
}

/// What a teardown does to the child.
pub(crate) enum TeardownKind<'a> {
    /// Kill it, then settle it as the module doc says. `tree` says whether a kill already sent
    /// through the child's containment reached it; `None`: there is no such kill.
    Kill {
        disposition: Disposition,
        tree: Option<&'a dyn Reach>,
    },
    /// An elevation front: sent nothing, and looked at. The reach says whether a kill sent
    /// elsewhere reached it. `Ok(None)`: there is no such kill, so a running front is always left.
    /// `Err`: the subtree that kill went through could not be read, so whether it reached the front
    /// is not known.
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "no Windows teardown looks at a front through this yet")
    )]
    Look(Result<Option<&'a dyn Reach>, io::Error>),
}

/// Whether a kill sent elsewhere (a cgroup leaf's `cgroup.kill`) reached a child.
pub(crate) trait Reach {
    /// `Ok(true)`: the kill landed and reached `child`, so its exit follows. `Err`: where `child` is
    /// could not be read, so whether the kill reached it is not known.
    fn reached(&self, child: &OwnedChild) -> io::Result<bool>;
}

/// How the look at an elevation front went ([`TeardownKind::Look`]). The policy words none of it:
/// the caller knows why the front was not killed.
#[derive(Debug)]
#[cfg_attr(
    windows,
    allow(dead_code, reason = "no Windows teardown words a front it looked at yet")
)]
pub(crate) enum LookOutcome {
    /// It had exited, or a kill sent elsewhere ended it, and it was reaped.
    Reaped(ExitStatus),
    /// Someone else reaped it, before the look or before the wait for it.
    ReapedElsewhere,
    /// The look could not read its exit.
    LookFailed(Error),
    /// A kill sent elsewhere ended it, and the reap failed.
    ReapFailed(Error),
    /// It is running and no kill reached it: it is left running and unreaped, or handed back by a
    /// caller that does ([`Disposition::HandBack`]).
    LeftRunning,
    /// It is running and where it is could not be read, so whether a kill reached it is not known:
    /// it is left unreaped, or handed back by a caller that does ([`Disposition::HandBack`]).
    PlaceUnreadable(io::Error),
    /// It is running and the subtree the kill went through could not be read, so whether it reached
    /// the front is not known: it is left unreaped, or handed back as above.
    SubtreeUnreadable(io::Error),
}

/// What a teardown of the root did: the child's fate, and what it could not do, for the event's one
/// warn (a child it could not signal and left running, a reap that failed after the kill).
#[derive(Debug)]
pub(crate) struct TeardownOutcome {
    pub(crate) fate: ChildFate,
    /// How the look at an elevation front ([`TeardownKind::Look`]) went; `None` for a child killed.
    #[cfg_attr(windows, allow(dead_code, reason = "no Windows teardown looks at a front yet"))]
    pub(crate) look: Option<LookOutcome>,
    pub(crate) left: Option<String>,
}

impl TeardownOutcome {
    /// A teardown with nothing to warn of.
    pub(crate) fn new(fate: ChildFate) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            look: None,
            left: None,
        }
    }

    /// A front's teardown, which went `look`.
    fn of_front(fate: ChildFate, look: LookOutcome) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            look: Some(look),
            left: None,
        }
    }
}

impl OwnedChild {
    /// Best-effort teardown, the one entry point: do what `kind` says, then settle the child. `id`
    /// is the child's identity, if the caller read one. `due` is the threshold of the slow-teardown
    /// warn on the blocking wait (`None`: no warn).
    ///
    /// Returns the child's fate, and what it could not do for the caller's one warn. It logs
    /// neither above `debug`, except that slow-teardown warn and, for a front it waits for, a
    /// zombie launchd holds.
    pub(crate) fn tear_down(&self, id: Option<ProcessId>, kind: TeardownKind<'_>, due: Option<Due>) -> TeardownOutcome {
        match kind {
            TeardownKind::Kill { disposition, tree } => self.kill_and_settle(id, disposition, tree, due),
            TeardownKind::Look(reach) => self.look_at_front(id, reach, due),
        }
    }

    fn kill_and_settle(
        &self,
        id: Option<ProcessId>,
        disposition: Disposition,
        tree: Option<&dyn Reach>,
        due: Option<Due>,
    ) -> TeardownOutcome {
        #[cfg(test)]
        super::seams::note_root_teardown();
        match self.signal(Sig::Kill) {
            Ok(sent) => {
                #[cfg(test)]
                crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterDropKill);
                match wait_to_exit(self, due, Orphaned::Quiet) {
                    Ok(_status) => {
                        #[cfg(test)]
                        if let Some(pid) = self.pid() {
                            crate::child::spawn::fault::record_teardown_reap(pid, _status);
                        }
                        TeardownOutcome::new(ChildFate::Reaped)
                    }
                    Err(unreaped) => self.settle_unreaped(matches!(sent, Sent::Delivered), unreaped),
                }
            }
            Err(refused) => match tree.map(|tree| tree.reached(self)) {
                // The tree's kill reached it, and is asynchronous: one look would race it. Its exit
                // follows, so the reap is the wait that kill bounds.
                Some(Ok(true)) => self.reap_after_tree_kill(),
                // No tree kill, one that missed the child, or one whose reach cannot be read: nothing
                // is shown to be ending it.
                _ => self.look_after_refused_kill(id, refused, disposition),
            },
        }
    }

    /// Reap a child a tree kill has just ended, sending it nothing: the kill bounds the wait.
    /// A failed reap comes back in [`TeardownOutcome::left`], as for [`tear_down`](Self::tear_down).
    pub(crate) fn reap_after_tree_kill(&self) -> TeardownOutcome {
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        match wait_to_exit(self, None, Orphaned::Quiet) {
            Ok(_) => TeardownOutcome::new(ChildFate::Reaped),
            Err(unreaped) => self.settle_unreaped(true, unreaped),
        }
    }

    /// The outcome of a root teardown whose wait after the kill reaped nothing, `delivered` or not.
    /// Only a delivered kill says the child is dead or dying.
    fn settle_unreaped(&self, delivered: bool, unreaped: WaitToExitError) -> TeardownOutcome {
        let pid = self.pid();
        match unreaped {
            WaitToExitError::Elsewhere(foreign) => {
                log::debug!(
                    "teardown of {}: it was reaped elsewhere before the reap after the kill",
                    child_named(pid)
                );
                TeardownOutcome {
                    fate: foreign.fate(delivered),
                    look: None,
                    left: (foreign == Foreign::Orphaned).then(|| orphaned_note(pid)),
                }
            }
            WaitToExitError::Failed(e) => TeardownOutcome {
                fate: if delivered {
                    ChildFate::Killed
                } else {
                    ChildFate::Unknown
                },
                look: None,
                left: Some(format!(
                    "teardown of {}: the reap after the kill failed: {e}",
                    child_named(pid)
                )),
            },
        }
    }

    /// The one look after a kill that failed with `refused`, never a wait. `id` is the child's
    /// identity, if the caller read one.
    pub(crate) fn look_after_refused_kill(
        &self,
        id: Option<ProcessId>,
        refused: Error,
        disposition: Disposition,
    ) -> TeardownOutcome {
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
            (ChildFate::Running { .. }, _) => Some(match disposition {
                Disposition::Leave => format!("{who} could not be terminated ({refused}); leaving it running"),
                Disposition::HandBack => {
                    format!("{who} could not be terminated ({refused}); handed back to the caller in the error")
                }
            }),
            (ChildFate::Unknown, Some(failure)) => Some(format!(
                "{who} could not be terminated ({refused}), and the look at it failed: {failure}"
            )),
            _ => None,
        };
        TeardownOutcome { fate, look: None, left }
    }

    /// The look arm of [`tear_down`](Self::tear_down). A front that has exited is reaped. One that
    /// has not is waited for if `reach` says its place is where a kill landed, and otherwise left.
    /// The outcome says how it went in [`TeardownOutcome::look`].
    fn look_at_front(
        &self,
        id: Option<ProcessId>,
        reach: Result<Option<&dyn Reach>, io::Error>,
        due: Option<Due>,
    ) -> TeardownOutcome {
        let pid = self.pid();
        let looked = match self.wait(Some(crate::wait::now())) {
            Ok(ChildWaitOutcome::Foreign(foreign)) => {
                return TeardownOutcome::of_front(foreign.fate(false), LookOutcome::ReapedElsewhere);
            }
            looked => looked.and_then(|outcome| status_of_outcome(pid, outcome, Orphaned::Quiet)),
        };
        match looked {
            Ok(Some(status)) => TeardownOutcome::of_front(ChildFate::Reaped, LookOutcome::Reaped(status)),
            Err(e) => TeardownOutcome::of_front(ChildFate::Unknown, LookOutcome::LookFailed(e)),
            Ok(None) => {
                // The look saw it running; an unreadable reach leaves open only whether the kill
                // reached it.
                let running = |look| TeardownOutcome::of_front(ChildFate::Running { id }, look);
                let reach = match reach {
                    Err(e) => return running(LookOutcome::SubtreeUnreadable(e)),
                    Ok(None) => return running(LookOutcome::LeftRunning),
                    Ok(Some(reach)) => reach,
                };
                match reach.reached(self) {
                    Ok(false) => running(LookOutcome::LeftRunning),
                    Err(e) => running(LookOutcome::PlaceUnreadable(e)),
                    // Dying: its kill is pending, so this wait ends. Nobody else reports a zombie
                    // launchd holds.
                    Ok(true) => {
                        #[cfg(test)]
                        crate::child::spawn::fault::run_between_kill_and_wait();
                        match wait_to_exit(self, due, Orphaned::Warn) {
                            Ok(status) => TeardownOutcome::of_front(ChildFate::Reaped, LookOutcome::Reaped(status)),
                            // The kill landed first: delivered, so `Killed`.
                            Err(WaitToExitError::Elsewhere(foreign)) => {
                                TeardownOutcome::of_front(foreign.fate(true), LookOutcome::ReapedElsewhere)
                            }
                            Err(WaitToExitError::Failed(e)) => {
                                TeardownOutcome::of_front(ChildFate::Killed, LookOutcome::ReapFailed(e))
                            }
                        }
                    }
                }
            }
        }
    }
}
