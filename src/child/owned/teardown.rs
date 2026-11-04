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
//!   blocking wait would hang the drop for ever.
//!
//! # Look
//!
//! An elevation front is sent nothing: a kill of it would orphan the elevated program. One look at
//! the present moment collects it if it has exited. A running front is waited for only if
//! [`Reach::reached`] says a kill sent elsewhere (a cgroup leaf's) reached it, since that kill bounds
//! the wait; otherwise it is left running and unreaped, and said so.

use std::process::ExitStatus;

use super::{ChildWaitOutcome, OwnedChild};
use crate::child::lifecycle::{child_named, orphaned_note, status_of_outcome, Orphaned};
use crate::child::spawn::FrontFate;
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::signal::{Sent, Sig};
use crate::wait::teardown_warn::{wait_warning, Due};

/// What a teardown does to the child.
#[derive(Clone, Copy)]
pub(crate) enum TeardownKind<'a> {
    /// Kill it, then settle it as the module doc says.
    Kill,
    /// An elevation front: sent nothing, and looked at. `reach` says whether a kill sent elsewhere
    /// reached it; `None`: there is no such kill, so a running front is always left.
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "no Windows teardown looks at a front through this yet")
    )]
    Look(Option<&'a dyn Reach>),
}

/// Whether a kill sent elsewhere (a cgroup leaf's `cgroup.kill`) reached a child.
pub(crate) trait Reach {
    /// `Ok(true)`: the kill landed and reached `child`, so its exit follows. `Err`: where `child` is
    /// cannot be read, so whether the kill reached it is not known.
    fn reached(&self, child: &OwnedChild) -> std::io::Result<bool>;
}

/// What a teardown of the root did: the child's fate, and what it could not do, for the event's one
/// warn (a child it could not signal and left running, a reap that failed after the kill).
#[derive(Debug)]
pub(crate) struct TeardownOutcome {
    pub(crate) fate: ChildFate,
    /// What became of an elevation front ([`TeardownKind::Look`]); `None` for a child killed.
    #[cfg_attr(windows, allow(dead_code, reason = "no Windows teardown looks at a front yet"))]
    pub(crate) front: Option<FrontFate>,
    pub(crate) left: Option<String>,
}

impl TeardownOutcome {
    /// A teardown with nothing to warn of.
    pub(crate) fn new(fate: ChildFate) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            front: None,
            left: None,
        }
    }

    /// A front's teardown with nothing to warn of.
    fn of_front(fate: ChildFate, front: FrontFate) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            front: Some(front),
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
    /// neither above `debug`, except that slow-teardown warn.
    pub(crate) fn tear_down(&self, id: Option<ProcessId>, kind: TeardownKind<'_>, due: Option<Due>) -> TeardownOutcome {
        match kind {
            TeardownKind::Kill => self.kill_and_settle(id, due),
            TeardownKind::Look(reach) => self.look_at_front(id, reach, due),
        }
    }

    fn kill_and_settle(&self, id: Option<ProcessId>, due: Option<Due>) -> TeardownOutcome {
        #[cfg(test)]
        super::seams::note_root_teardown();
        match self.signal(Sig::Kill) {
            Ok(sent) => {
                #[cfg(test)]
                crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterDropKill);
                match self.wait_after_kill(Killed::Child, matches!(sent, Sent::Delivered), due) {
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
        match self.wait_after_kill(Killed::Child, true, None) {
            Ok(_) => TeardownOutcome::new(ChildFate::Reaped),
            Err(outcome) => outcome,
        }
    }

    /// The blocking wait that follows a kill, `delivered` or not; `killed` words its messages. `Ok`
    /// is the status it reaped; the `Err` is the outcome of a teardown that reaped nothing. With
    /// `due`, it first watches for the exit until the threshold, and warns once if the child has not
    /// exited by then.
    fn wait_after_kill(
        &self,
        killed: Killed,
        delivered: bool,
        due: Option<Due>,
    ) -> Result<ExitStatus, TeardownOutcome> {
        let pid = self.pid();
        // What a failed wait shows of the child: only a delivered kill says it is dead or dying.
        let failed = |fate_left: Option<String>| TeardownOutcome {
            fate: if delivered {
                ChildFate::Killed
            } else {
                ChildFate::Unknown
            },
            front: None,
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
        .map_err(|e| failed(Some(killed.reap_failed(pid, &e))))?;
        let status = status_of_outcome(pid, outcome, Orphaned::Quiet);
        match (outcome, status) {
            (ChildWaitOutcome::Foreign(foreign), _) => {
                log::debug!("{}", killed.reaped_elsewhere(pid));
                Err(TeardownOutcome {
                    fate: foreign.fate(delivered),
                    front: None,
                    left: (foreign == Foreign::Orphaned).then(|| orphaned_note(pid)),
                })
            }
            (_, Ok(Some(status))) => Ok(status),
            (_, Ok(None)) => {
                debug_assert!(false, "an unbounded wait ended at a deadline");
                Err(failed(None))
            }
            (_, Err(e)) => Err(failed(Some(killed.reap_failed(pid, &e)))),
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
        TeardownOutcome {
            fate,
            front: None,
            left,
        }
    }

    /// The look arm of [`tear_down`](Self::tear_down). A front that has exited is reaped. One that
    /// has not is waited for if `reach` says its place is where a kill landed, and otherwise left.
    fn look_at_front(&self, id: Option<ProcessId>, reach: Option<&dyn Reach>, due: Option<Due>) -> TeardownOutcome {
        let pid = self.pid();
        let front = front_named(pid);
        let reaped = |status: ExitStatus| {
            log::debug!("Child::drop: {front} was killed through its cgroup and reaped ({status})");
            TeardownOutcome::of_front(ChildFate::Reaped, FrontFate::Reaped)
        };
        // A front reaped elsewhere is read from the typed outcome, so it is `Gone` on every OS.
        let looked = match self.wait(Some(crate::wait::now())) {
            Ok(ChildWaitOutcome::Foreign(foreign)) => {
                log::debug!("Child::drop: {front} was reaped by someone else");
                return TeardownOutcome {
                    fate: foreign.fate(false),
                    front: Some(FrontFate::Unaccounted),
                    left: (foreign == Foreign::Orphaned).then(|| orphaned_note(pid)),
                };
            }
            looked => looked.and_then(|outcome| status_of_outcome(pid, outcome, Orphaned::Quiet)),
        };
        match looked {
            Ok(Some(status)) => reaped(status),
            Err(e) => TeardownOutcome {
                fate: ChildFate::Unknown,
                front: Some(FrontFate::Unaccounted),
                left: Some(format!(
                    "{front} could not be looked at after its cgroup's teardown ({e})"
                )),
            },
            Ok(None) => {
                let left_running = || TeardownOutcome {
                    fate: ChildFate::Running { id },
                    front: Some(FrontFate::LeftUnreaped),
                    left: Some(format!(
                        "{front} is left running and unreaped, and a kill of the front would orphan the elevated \
                         program"
                    )),
                };
                let Some(reach) = reach else {
                    return left_running();
                };
                match reach.reached(self) {
                    Ok(false) => left_running(),
                    Err(e) => TeardownOutcome {
                        fate: ChildFate::Unknown,
                        front: Some(FrontFate::Unplaced),
                        left: Some(format!(
                            "{front} is left unreaped: where it is cannot be read ({e}), so it is not known whether \
                             the cgroup kill ended it"
                        )),
                    },
                    // Dying: its kill is pending, so this wait ends.
                    Ok(true) => {
                        #[cfg(test)]
                        crate::child::spawn::fault::run_between_kill_and_wait();
                        match self.wait_after_kill(Killed::Front, true, due) {
                            Ok(status) => reaped(status),
                            Err(outcome) => TeardownOutcome {
                                front: Some(FrontFate::Unaccounted),
                                ..outcome
                            },
                        }
                    }
                }
            }
        }
    }
}

/// How a message names the elevation front `pid`, or what stands for an unknown pid.
fn front_named(pid: Option<u32>) -> String {
    pid.map_or_else(
        || "the elevation front (pid unknown)".to_owned(),
        |pid| format!("elevation front pid {pid}"),
    )
}

/// What a blocking wait after a kill waits for, which words the wait's messages.
#[derive(Clone, Copy)]
enum Killed {
    /// The root, killed by the teardown or by a tree kill.
    Child,
    /// An elevation front its cgroup's kill ended.
    Front,
}

impl Killed {
    /// A failed reap after a kill, for the caller's warn: it leaves a zombie or an unread exit.
    fn reap_failed(self, pid: Option<u32>, e: &Error) -> String {
        match self {
            Killed::Child => format!("teardown of {}: the reap after the kill failed: {e}", child_named(pid)),
            Killed::Front => format!(
                "{} was killed through its cgroup, and could not be reaped ({e})",
                front_named(pid)
            ),
        }
    }

    /// The `debug` line of a wait that met a reap by someone else.
    fn reaped_elsewhere(self, pid: Option<u32>) -> String {
        match self {
            Killed::Child => format!(
                "teardown of {}: it was reaped elsewhere before the reap after the kill",
                child_named(pid)
            ),
            Killed::Front => format!("Child::drop: {} was reaped by someone else", front_named(pid)),
        }
    }
}
