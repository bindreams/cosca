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
use crate::child::lifecycle::{
    left_uncollected, orphaned_note, status_of_outcome, wait_to_exit, Orphaned, WaitToExitError,
};
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

impl Disposition {
    /// Whether the caller hands back the child `torn` is the teardown of: it does under
    /// [`HandBack`](Disposition::HandBack) when the teardown left the child
    /// [uncollected](TeardownOutcome::uncollected), whatever its fate says. The one rule of every
    /// hand-back; the caller owns the child and builds the [`Unreaped`](crate::Unreaped).
    pub(crate) fn hands_back(self, torn: &TeardownOutcome) -> bool {
        self == Disposition::HandBack && torn.uncollected
    }

    /// What a warn about a child adds when the caller hands it back: where the child went. Nothing
    /// for a caller that leaves it, or for a child the teardown [collected](TeardownOutcome::uncollected)
    /// (`uncollected` false): there is none to hand back.
    pub(crate) fn handed_back_suffix(self, uncollected: bool) -> &'static str {
        match (self, uncollected) {
            (Disposition::HandBack, true) => "; handed back to the caller in the error",
            _ => "",
        }
    }
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
    /// A kill sent elsewhere ended it, and the reap consumed it but read no exit record.
    ReapUnreadable(Error),
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
    /// Whether the teardown left the child uncollected: still this process's, neither reaped by it
    /// nor shown reaped elsewhere. It is the child the caller can hand back
    /// ([`Disposition::hands_back`]). It is not [`fate`](Self::fate)'s to say: a refused kill whose
    /// look failed is `Unknown`, and a kill whose wait failed is `Killed`, and both are uncollected,
    /// while a `Killed` child someone else reaped is not, and neither is one this teardown reaped
    /// whose exit record was unreadable.
    pub(crate) uncollected: bool,
    /// How the look at an elevation front ([`TeardownKind::Look`]) went; for a child killed, `None`,
    /// or the failure of the look after a refused kill ([`look_after_refused_kill`](OwnedChild::look_after_refused_kill)).
    #[cfg_attr(windows, allow(dead_code, reason = "no Windows teardown looks at a front yet"))]
    pub(crate) look: Option<LookOutcome>,
    pub(crate) left: Option<String>,
}

impl TeardownOutcome {
    /// A teardown that collected the child, with nothing to warn of.
    pub(crate) fn new(fate: ChildFate) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            uncollected: false,
            look: None,
            left: None,
        }
    }

    /// A front's teardown, which went `look` and left it `uncollected` or not.
    fn of_front(fate: ChildFate, look: LookOutcome, uncollected: bool) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            uncollected,
            look: Some(look),
            left: None,
        }
    }
}

impl OwnedChild {
    /// Best-effort teardown, the one entry point: do what `kind` says, then settle the child. `id`
    /// is the child's identity, if the caller read one. `due` is the threshold of the slow-teardown
    /// warn on the blocking wait (`None`: no warn). The warn watches the handle's own bounded wait:
    /// a child that is visible as exited but cannot be reaped yet (a zombie a tracer holds) is still
    /// waited for when the threshold passes, and warned of.
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
                        // An unknown pid records as 0.
                        #[cfg(test)]
                        crate::child::spawn::fault::record_teardown_reap(self.pid().unwrap_or(0), _status);
                        TeardownOutcome::new(ChildFate::Reaped)
                    }
                    Err(unreaped) => self.settle_unreaped(matches!(sent, Sent::Delivered), unreaped, disposition),
                }
            }
            Err(refused) => match tree.map(|tree| tree.reached(self)) {
                // The tree's kill reached it, and is asynchronous: one look would race it. Its exit
                // follows, so the reap is the wait that kill bounds.
                Some(Ok(true)) => self.reap_after_tree_kill(disposition),
                // No tree kill, one that missed the child, or one whose reach cannot be read: nothing
                // is shown to be ending it.
                _ => self.look_after_refused_kill(id, refused, disposition),
            },
        }
    }

    /// Reap a child a tree kill has just ended, sending it nothing: the kill bounds the wait.
    /// A failed reap comes back in [`TeardownOutcome::left`], as for [`tear_down`](Self::tear_down).
    pub(crate) fn reap_after_tree_kill(&self, disposition: Disposition) -> TeardownOutcome {
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        match wait_to_exit(self, None, Orphaned::Quiet) {
            Ok(_) => TeardownOutcome::new(ChildFate::Reaped),
            Err(unreaped) => self.settle_unreaped(true, unreaped, disposition),
        }
    }

    /// The outcome of a root teardown whose wait after the kill reaped nothing, `delivered` or not.
    /// Only a delivered kill says the child is dead or dying. A child the wait failed on is left
    /// uncollected if the wait failed, and the leftover says where it goes under `disposition`.
    fn settle_unreaped(&self, delivered: bool, unreaped: WaitToExitError, disposition: Disposition) -> TeardownOutcome {
        let pid = self.pid();
        match unreaped {
            WaitToExitError::Elsewhere(foreign) => {
                log::debug!(
                    "teardown of {}: it was reaped elsewhere before the reap after the kill",
                    child_named(pid)
                );
                TeardownOutcome {
                    fate: foreign.fate(delivered),
                    uncollected: false,
                    look: None,
                    left: (foreign == Foreign::Orphaned).then(|| orphaned_note(pid)),
                }
            }
            failed => {
                let uncollected = failed.uncollected();
                // The consuming reap took the zombie: the child is reaped, and only its record is lost.
                let reaped = matches!(failed, WaitToExitError::Unreadable(_));
                let e = Error::from(failed);
                TeardownOutcome {
                    fate: if delivered {
                        ChildFate::Killed
                    } else {
                        ChildFate::Unknown
                    },
                    uncollected,
                    look: None,
                    left: Some(if reaped {
                        format!("teardown of {}: reaped it after the kill; {e}", child_named(pid))
                    } else {
                        format!(
                            "teardown of {}: the reap after the kill failed: {e}{}",
                            child_named(pid),
                            disposition.handed_back_suffix(uncollected)
                        )
                    }),
                }
            }
        }
    }

    /// The one look after a kill that failed with `refused`, never a wait. `id` is the child's
    /// identity, if the caller read one. A look that failed is also
    /// [`TeardownOutcome::look`], as [`LookOutcome::LookFailed`].
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
        let waited = self.wait(Some(crate::wait::now()));
        // The look collects a child that has exited, whatever its record says, and finds one reaped
        // elsewhere gone; any other answer is a child that is still ours and uncollected.
        let uncollected = left_uncollected(&waited);
        let (fate, look_failure) = match waited {
            Ok(ChildWaitOutcome::Foreign(foreign)) => (foreign.fate(false), None),
            looked => match looked.and_then(|outcome| status_of_outcome(pid, outcome, Orphaned::Quiet)) {
                Ok(status) => (crate::child::spawn::fate_of_a_look(Ok(status), id), None),
                Err(failure) => (
                    crate::child::spawn::fate_of_a_look(Err(failure.raw_os_error()), id),
                    Some(failure),
                ),
            },
        };
        let left = match (&fate, &look_failure) {
            (ChildFate::Running { .. }, _) => Some(match disposition {
                Disposition::Leave => format!("{who} could not be terminated ({refused}); leaving it running"),
                Disposition::HandBack => {
                    format!("{who} could not be terminated ({refused}); handed back to the caller in the error")
                }
            }),
            (ChildFate::Unknown, Some(failure)) => Some(format!(
                "{who} could not be terminated ({refused}), and the look at it failed: {failure}{}",
                disposition.handed_back_suffix(uncollected)
            )),
            _ => None,
        };
        TeardownOutcome {
            fate,
            uncollected,
            look: look_failure.map(LookOutcome::LookFailed),
            left,
        }
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
        let waited = self.wait(Some(crate::wait::now()));
        let uncollected = left_uncollected(&waited);
        let looked = match waited {
            Ok(ChildWaitOutcome::Foreign(foreign)) => {
                return TeardownOutcome::of_front(foreign.fate(false), LookOutcome::ReapedElsewhere, false);
            }
            looked => looked.and_then(|outcome| status_of_outcome(pid, outcome, Orphaned::Quiet)),
        };
        match looked {
            Ok(Some(status)) => TeardownOutcome::of_front(ChildFate::Reaped, LookOutcome::Reaped(status), false),
            Err(e) => TeardownOutcome::of_front(ChildFate::Unknown, LookOutcome::LookFailed(e), uncollected),
            Ok(None) => {
                // The look saw it running; an unreadable reach leaves open only whether the kill
                // reached it.
                let running = |look| TeardownOutcome::of_front(ChildFate::Running { id }, look, true);
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
                            Ok(status) => {
                                TeardownOutcome::of_front(ChildFate::Reaped, LookOutcome::Reaped(status), false)
                            }
                            // The kill landed first: delivered, so `Killed`.
                            Err(WaitToExitError::Elsewhere(foreign)) => {
                                TeardownOutcome::of_front(foreign.fate(true), LookOutcome::ReapedElsewhere, false)
                            }
                            // The reap consumed it, so it is not the caller's to take back.
                            Err(WaitToExitError::Unreadable(e)) => {
                                TeardownOutcome::of_front(ChildFate::Killed, LookOutcome::ReapUnreadable(e), false)
                            }
                            Err(failed) => {
                                let uncollected = failed.uncollected();
                                TeardownOutcome::of_front(
                                    ChildFate::Killed,
                                    LookOutcome::ReapFailed(failed.into()),
                                    uncollected,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
