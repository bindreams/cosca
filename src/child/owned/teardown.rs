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

use super::OwnedChild;
use crate::child::lifecycle::{wait_to_exit, Settlement};
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
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

    /// What a clause about a child adds, for where the child goes: handed back by a caller that
    /// hands it back, left by one that leaves it. Nothing for a child the teardown
    /// [collected](TeardownOutcome::uncollected) (`uncollected` false): there is none to place.
    /// The one wording of both: every note of a child handed back or left says it this way.
    pub(crate) fn suffix(self, uncollected: bool) -> &'static str {
        match (self, uncollected) {
            (Disposition::HandBack, true) => "; handed back to the caller in the error",
            (Disposition::Leave, true) => LEFT,
            (_, false) => "",
        }
    }
}

/// What a child that a caller leaves is, after the semicolon. Unix: a zombie once it exits, until
/// someone reaps it. Windows has no zombies: what is true is that nothing waits for it.
const LEFT: &str = if cfg!(unix) {
    "; left unreaped"
} else {
    "; nothing waits for it"
};

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
    /// The look, or the wait after a kill sent elsewhere reached it, ended, and the settlement
    /// classifies how: reaped, reaped elsewhere, or failed.
    Ended(Settlement),
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
    /// or the look that ended after a refused kill ([`look_after_refused_kill`](OwnedChild::look_after_refused_kill)).
    #[cfg_attr(windows, allow(dead_code, reason = "no Windows teardown looks at a front yet"))]
    pub(crate) look: Option<LookOutcome>,
    /// What to say of how the teardown went, and at what level: [`Settlement::wording`]'s clause for
    /// a settled child. `None` for a teardown that settled nothing (a child it did not signal or
    /// wait for) and for a front, which the caller words from [`look`](Self::look). The teardown
    /// logs none of it: the caller logs it at its level or folds it into its own warn
    /// ([`take_warn`](Self::take_warn)).
    pub(crate) clause: Option<(log::Level, String)>,
}

impl TeardownOutcome {
    /// A teardown that collected the child, with nothing to say.
    #[cfg(unix)]
    pub(crate) fn new(fate: ChildFate) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            uncollected: false,
            look: None,
            clause: None,
        }
    }

    /// The outcome `settlement` states: its fate, whether it left the child uncollected, and its
    /// clause. `subject`, `running` and `disposition` word it as [`Settlement::wording`] says.
    pub(crate) fn of_settlement(
        settlement: &Settlement,
        id: Option<ProcessId>,
        subject: &str,
        running: Option<&str>,
        disposition: Disposition,
    ) -> TeardownOutcome {
        TeardownOutcome {
            fate: settlement.fate(id),
            uncollected: settlement.uncollected(),
            look: None,
            clause: Some(settlement.wording(subject, running, Some(disposition))),
        }
    }

    /// A front's teardown, which left it `uncollected` or not and went `look`.
    fn of_front(fate: ChildFate, uncollected: bool, look: LookOutcome) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            uncollected,
            look: Some(look),
            clause: None,
        }
    }

    /// Takes the clause for a caller with one warn: a clause at warn comes back to fold into that
    /// warn, and one below it is logged here at its level, led by the caller's `label` (the same
    /// one that leads the caller's warn, so every line names its caller). `label` is a name, so
    /// nothing is built when the level is off.
    pub(crate) fn take_warn(&mut self, label: &str) -> Option<String> {
        match self.clause.take()? {
            (log::Level::Warn, text) => Some(text),
            (level, text) => {
                log::log!(level, "{label}: {text}");
                None
            }
        }
    }

    /// Says the clause as a failed spawn's teardown, the caller that owns the one line of it: a
    /// clause at warn is that line, `why` (the spawn's diagnosis, if still owed) leading it, and a
    /// lower one is logged on its own. Both lines are led by the caller's name.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn say_as_failed_spawn(&mut self, why: &mut crate::child::spawn::Diagnosis) {
        let label = crate::containment::dispatch::TeardownCaller::FailedSpawn.label();
        if let Some(left) = self.take_warn(label) {
            log::warn!("{label}: {}", why.fold(&left));
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
    /// Returns the child's fate, and what to say of how it went ([`TeardownOutcome::clause`]). It
    /// logs nothing but that slow-teardown warn.
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
                let settlement = Settlement::new(wait_to_exit(self, due), matches!(sent, Sent::Delivered));
                #[cfg(test)]
                if let Some(status) = settlement.status() {
                    // An unknown pid records as 0.
                    crate::child::spawn::fault::record_teardown_reap(self.pid().unwrap_or(0), status);
                }
                self.concluded(&settlement, id, disposition)
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
    /// A failed reap comes back in [`TeardownOutcome::clause`], as for [`tear_down`](Self::tear_down).
    pub(crate) fn reap_after_tree_kill(&self, disposition: Disposition) -> TeardownOutcome {
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        self.concluded(&Settlement::new(wait_to_exit(self, None), true), None, disposition)
    }

    /// The outcome of a root teardown whose wait after a kill ended as `settlement` says.
    fn concluded(&self, settlement: &Settlement, id: Option<ProcessId>, disposition: Disposition) -> TeardownOutcome {
        let subject = format!("teardown of {}", child_named(self.pid()));
        TeardownOutcome::of_settlement(settlement, id, &subject, None, disposition)
    }

    /// The one look after a kill that failed with `refused`, never a wait. `id` is the child's
    /// identity, if the caller read one. A look that ended is also [`TeardownOutcome::look`], as
    /// [`LookOutcome::Ended`].
    pub(crate) fn look_after_refused_kill(
        &self,
        id: Option<ProcessId>,
        refused: Error,
        disposition: Disposition,
    ) -> TeardownOutcome {
        // A child reaped elsewhere is read from the typed outcome, so it is `Gone` on every OS.
        let settlement = Settlement::new(self.wait(Some(crate::wait::now())), false);
        let subject = format!("{} could not be terminated ({refused})", child_named(self.pid()));
        // Still running: the caller that leaves it says it keeps running, not that it is left unreaped.
        let running = match disposition {
            Disposition::Leave => format!("{subject}; leaving it running"),
            Disposition::HandBack => format!("{subject}{}", Disposition::HandBack.suffix(true)),
        };
        let mut torn = TeardownOutcome::of_settlement(&settlement, id, &subject, Some(&running), disposition);
        if settlement.ended() {
            torn.look = Some(LookOutcome::Ended(settlement));
        }
        torn
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
        let ended = |settlement: Settlement| {
            TeardownOutcome::of_front(
                settlement.fate(id),
                settlement.uncollected(),
                LookOutcome::Ended(settlement),
            )
        };
        let looked = Settlement::new(self.wait(Some(crate::wait::now())), false);
        if looked.ended() {
            return ended(looked);
        }
        // The look saw it running; an unreadable reach leaves open only whether the kill reached it.
        let running = |look| TeardownOutcome::of_front(ChildFate::Running { id }, true, look);
        let reach = match reach {
            Err(e) => return running(LookOutcome::SubtreeUnreadable(e)),
            Ok(None) => return running(LookOutcome::LeftRunning),
            Ok(Some(reach)) => reach,
        };
        match reach.reached(self) {
            Ok(false) => running(LookOutcome::LeftRunning),
            Err(e) => running(LookOutcome::PlaceUnreadable(e)),
            // Dying: its kill is pending, so this wait ends.
            Ok(true) => {
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                ended(Settlement::new(wait_to_exit(self, due), true))
            }
        }
    }
}
