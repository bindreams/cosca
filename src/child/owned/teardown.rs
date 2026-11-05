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
        .with_clause_asserted()
    }

    /// Asserts (debug) the contract of every outcome: a child left uncollected has a clause at warn
    /// (see [`Settlement`]'s table). Asserted once, where an outcome gets its clause
    /// ([`of_settlement`](Self::of_settlement) and `child::word_front`), so every consumer
    /// of the outcome is covered: the failed-spawn line, [`take_warn`](Self::take_warn), a pidfd
    /// teardown's [`left`](PidfdTeardown::left).
    pub(crate) fn with_clause_asserted(self) -> TeardownOutcome {
        debug_assert!(
            !self.uncollected || matches!(self.clause, Some((log::Level::Warn, _))),
            "the clause of an uncollected child is a warn: {:?}",
            self.clause
        );
        self
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

    /// The one line of a failed spawn's teardown, led by the caller's name: the clause, `why` (the
    /// spawn's diagnosis, if still owed) leading it. It is the event's one warn if the clause is at
    /// warn or `why` is owed (the diagnosis is then the warn, and says what became of the child in
    /// it, whatever the clause's level); the caller logs the returned line. Otherwise the clause is
    /// logged here at its level, on its own.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn failed_spawn_line(&mut self, why: &mut crate::child::spawn::Diagnosis) -> Option<String> {
        let label = crate::containment::dispatch::TeardownCaller::FailedSpawn.label();
        let (level, text) = self.clause.take()?;
        if level == log::Level::Warn || why.is_owed() {
            return Some(format!("{label}: {}", why.fold(&text)));
        }
        log::log!(level, "{label}: {text}");
        None
    }

    /// Says the clause as a failed spawn's teardown ([`failed_spawn_line`](Self::failed_spawn_line)),
    /// logging its line at warn.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn say_as_failed_spawn(&mut self, why: &mut crate::child::spawn::Diagnosis) {
        if let Some(line) = self.failed_spawn_line(why) {
            log::warn!("{line}");
        }
    }
}

/// What the caller of a teardown through a pidfd knows about the pidfd, which decides what the
/// teardown may come to. Stated once, where the pidfd is handed over.
///
/// Only the Linux spawn tears a child down through a pidfd and produces these.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux spawn tears a child down through a pidfd")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expect {
    /// An earlier look on the pidfd failed, or may have, so a wait on it may fail too: any outcome
    /// stands.
    Anything,
    /// No earlier look on the pidfd failed, so a wait on it does not: a child the teardown left
    /// uncollected is one whose kill was refused, and still running.
    Waited,
    /// As [`Waited`](Expect::Waited), and the child never ran the program, so it has this process's
    /// credentials: nothing but its being gone can refuse its kill, and the teardown collects it.
    Unexecuted,
}

/// What a teardown through a pidfd came to, and what its caller expected of it.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux spawn tears a child down through a pidfd")
)]
#[derive(Debug)]
pub(crate) struct PidfdTeardown {
    pub(crate) outcome: TeardownOutcome,
    pub(crate) expect: Expect,
}

#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux spawn tears a child down through a pidfd")
)]
impl PidfdTeardown {
    pub(crate) fn new(outcome: TeardownOutcome, expect: Expect) -> PidfdTeardown {
        PidfdTeardown { outcome, expect }
    }

    /// Takes the clause of a teardown that left its child uncollected, for the caller that logs the
    /// warn. The clause is at warn: the outcome's construction asserts it
    /// ([`with_clause_asserted`](TeardownOutcome::with_clause_asserted)), so the fallback text is
    /// unreachable in debug.
    pub(crate) fn left(&mut self) -> Left {
        let clause = self.outcome.clause.take();
        Left {
            clause: clause.map_or_else(|| "its teardown left it uncollected".to_owned(), |(_, clause)| clause),
            fate: self.outcome.fate,
            expect: self.expect,
        }
    }

    /// Logs `line` through [`warn_pidfd_teardown`], as this teardown came out.
    pub(crate) fn warn(&self, line: Option<&str>) {
        warn_pidfd_teardown(line, self.outcome.fate, self.outcome.uncollected, self.expect);
    }
}

/// A pidfd teardown that left its child uncollected, as an abandonment hands it on to the place that
/// logs it: the clause for the caller's one warn, and what [`warn_pidfd_teardown`] reads of the
/// teardown.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux spawn tears a child down through a pidfd")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Left {
    pub(crate) clause: String,
    pub(crate) fate: ChildFate,
    pub(crate) expect: Expect,
}

#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux spawn tears a child down through a pidfd")
)]
impl Left {
    /// Logs `line` through [`warn_pidfd_teardown`]: the teardown left the child uncollected.
    pub(crate) fn warn(&self, line: &str) {
        warn_pidfd_teardown(Some(line), self.fate, true, self.expect);
    }
}

/// The one place the warn of a pidfd teardown is logged: `line`, then the teardown's contract
/// with its caller, asserted after the warn so that a panic does not lose it. (That a child left
/// uncollected has a warn is the outcome's own contract, asserted where it is built: see
/// [`with_clause_asserted`](TeardownOutcome::with_clause_asserted).)
/// `uncollected` and `fate` are the teardown's ([`TeardownOutcome`]); `expect` is its caller's.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux spawn tears a child down through a pidfd")
)]
pub(crate) fn warn_pidfd_teardown(line: Option<&str>, fate: ChildFate, uncollected: bool, expect: Expect) {
    if let Some(line) = line {
        log::warn!("{line}");
    }
    debug_assert!(
        !uncollected || expect == Expect::Anything || matches!(fate, ChildFate::Running { .. }),
        "a wait on a child's own pidfd failed: {fate:?}"
    );
    debug_assert!(
        expect != Expect::Unexecuted || !matches!(fate, ChildFate::Running { .. }),
        "the kill of a child that never ran the program was refused"
    );
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
