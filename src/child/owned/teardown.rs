//! The teardown of a child, written once for every OS: [`OwnedChild::tear_down`] kills it and
//! settles what became of it, and [`OwnedChild::look_at_front`] looks at an elevation front.
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
//! the wait; otherwise it is left running. [`FrontLook`] says how it went, as data, and is no
//! [`TeardownOutcome`]: the caller knows why the front was not killed and whether it hands a running
//! front back ([`Disposition`]), and words the look into one.

use std::io;

use super::OwnedChild;
use crate::child::lifecycle::{wait_to_exit, Settlement, Wording};
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
    /// Whether the caller hands back the child whose teardown left `torn`: it does under
    /// [`HandBack`](Disposition::HandBack) when the teardown left the child
    /// [uncollected](Remains::uncollected), whatever its fate says. The one rule of every
    /// hand-back; the caller owns the child and builds the [`Unreaped`](crate::Unreaped).
    pub(crate) fn hands_back(self, torn: &Remains) -> bool {
        self == Disposition::HandBack && torn.uncollected
    }

    /// What a clause about a child adds, for where the child goes: handed back by a caller that
    /// hands it back, left by one that leaves it. Nothing for a child the teardown
    /// [collected](Remains::uncollected) (`uncollected` false): there is none to place.
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

/// How [`OwnedChild::tear_down`] kills the child, then settles it as the module doc says.
pub(crate) struct Kill<'a> {
    pub(crate) disposition: Disposition,
    /// Whether a kill already sent through the child's containment reached it; `None`: there is no
    /// such kill.
    pub(crate) tree: Option<&'a dyn Reach>,
}

/// Whether a kill sent elsewhere (a cgroup leaf's `cgroup.kill`) reached a child.
pub(crate) trait Reach {
    /// `Ok(true)`: the kill landed and reached `child`, so its exit follows. `Err`: where `child` is
    /// could not be read, so whether the kill reached it is not known.
    fn reached(&self, child: &OwnedChild) -> io::Result<bool>;
}

/// How the look at an elevation front went ([`OwnedChild::look_at_front`]). The policy words none
/// of it: the caller knows why the front was not killed.
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

/// How a look at an elevation front went ([`OwnedChild::look_at_front`]): the front's fate, and the
/// look as data. It is no [`TeardownOutcome`]: it has no clause until the caller, which knows why
/// the front was not killed, words it (`child::word_front`).
#[cfg_attr(
    windows,
    allow(dead_code, reason = "no Windows teardown looks at a front through this yet")
)]
#[derive(Debug)]
pub(crate) struct FrontLook {
    pub(crate) fate: ChildFate,
    pub(crate) look: LookOutcome,
}

/// What a teardown of the root did: the child's fate, and what it said of it, for the event's one
/// warn (a child it could not signal and left running, a reap that failed after the kill).
///
/// A child the teardown left uncollected (still this process's, neither reaped by it nor shown
/// reaped elsewhere: the child the caller can hand back, [`Disposition::hands_back`]) carries the
/// warn that says so, and there is no outcome of one without it. That is not the
/// [`fate`](Self::fate)'s to say: a refused kill whose look failed is `Unknown`, and a kill whose
/// wait failed is `Killed`, and both are uncollected, while a `Killed` child someone else reaped is
/// not, and neither is one this teardown reaped whose exit record was unreadable.
///
/// The teardown logs none of the clause: the caller logs it at its level or folds it into its own
/// warn, and takes it out of the outcome to do so ([`take_warn`](Self::take_warn),
/// [`say_as_failed_spawn`](Self::say_as_failed_spawn)), which leaves the [`Remains`].
#[derive(Debug)]
pub(crate) struct TeardownOutcome {
    fate: ChildFate,
    /// What the teardown said of the child; `None` for a collected child it settled nothing of
    /// (one it did not signal or wait for).
    said: Option<Wording>,
    /// The look that ended after a refused kill ([`look_after_refused_kill`](OwnedChild::look_after_refused_kill)).
    refused_look: Option<Box<Settlement>>,
    /// The kind of the error the kill was refused with, if it was.
    refused: Option<io::ErrorKind>,
}

/// What is left of a [`TeardownOutcome`] once its clause is said: the fate, whether the child is
/// uncollected, and the kind of the error its kill was refused with, if it was. The clause is gone,
/// so nothing can say it twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Remains {
    pub(crate) fate: ChildFate,
    pub(crate) uncollected: bool,
    pub(crate) refused: Option<io::ErrorKind>,
}

impl Remains {
    /// The remains of a child that was collected: `fate` is not [`Running`](ChildFate::Running).
    #[cfg(unix)]
    pub(crate) fn collected(fate: ChildFate) -> Remains {
        debug_assert!(
            !matches!(fate, ChildFate::Running { .. }),
            "a running child is not collected"
        );
        Remains {
            fate,
            uncollected: false,
            refused: None,
        }
    }
}

impl TeardownOutcome {
    /// A teardown that collected the child, with nothing to say: `fate` is not
    /// [`Running`](ChildFate::Running).
    #[cfg(unix)]
    pub(crate) fn collected(fate: ChildFate) -> TeardownOutcome {
        debug_assert!(
            !matches!(fate, ChildFate::Running { .. }),
            "a running child is not collected"
        );
        TeardownOutcome {
            fate,
            said: None,
            refused_look: None,
            refused: None,
        }
    }

    /// A teardown that left the child uncollected; `warn` says so.
    #[cfg(unix)]
    pub(crate) fn left_uncollected(fate: ChildFate, warn: String) -> TeardownOutcome {
        TeardownOutcome::new(fate, Wording::Uncollected(warn))
    }

    /// The outcome of a child whose fate is `fate`, and which `said` says what became of.
    pub(crate) fn new(fate: ChildFate, said: Wording) -> TeardownOutcome {
        TeardownOutcome {
            fate,
            said: Some(said),
            refused_look: None,
            refused: None,
        }
    }

    /// The outcome `settlement` states: its fate and its clause. `subject`, `running` and
    /// `disposition` word it as [`Settlement::wording`] says.
    pub(crate) fn of_settlement(
        settlement: &Settlement,
        id: Option<ProcessId>,
        subject: &str,
        running: Option<&str>,
        disposition: Disposition,
    ) -> TeardownOutcome {
        TeardownOutcome::new(
            settlement.fate(id),
            settlement.wording(subject, running, Some(disposition)),
        )
    }

    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only the async child reads the fate of a second teardown")
    )]
    pub(crate) fn fate(&self) -> ChildFate {
        self.fate
    }

    /// Whether the teardown left the child uncollected.
    pub(crate) fn uncollected(&self) -> bool {
        matches!(self.said, Some(Wording::Uncollected(_)))
    }

    /// The fate and whether the child is uncollected, without taking the clause.
    pub(crate) fn remains(&self) -> Remains {
        Remains {
            fate: self.fate,
            uncollected: self.uncollected(),
            refused: self.refused,
        }
    }

    /// The look that ended after a refused kill, if one did.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix cleanup words a refused kill's look")
    )]
    pub(crate) fn refused_look(&self) -> Option<&Settlement> {
        self.refused_look.as_deref()
    }

    /// What the teardown said of the child, if it said anything.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(
            dead_code,
            reason = "only the async child words a second teardown's clause into its own"
        )
    )]
    pub(crate) fn said(&self) -> Option<&Wording> {
        self.said.as_ref()
    }

    /// Takes the warn of an outcome that left the child uncollected; any other is given back.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux spawn hands an uncollected child on")
    )]
    pub(crate) fn into_uncollected(self) -> Result<String, TeardownOutcome> {
        match self.said {
            Some(Wording::Uncollected(warn)) => Ok(warn),
            said => Err(TeardownOutcome { said, ..self }),
        }
    }

    /// Takes the clause for a caller with one warn: a clause at warn comes back to fold into that
    /// warn, and one below it is logged here at its level, led by the caller's `label` (the same
    /// one that leads the caller's warn, so every line names its caller). `label` is a name, so
    /// nothing is built when the level is off.
    pub(crate) fn take_warn(self, label: &str) -> (Option<String>, Remains) {
        let remains = self.remains();
        let warn = match self.said {
            Some(Wording::Uncollected(text) | Wording::Collected(log::Level::Warn, text)) => Some(text),
            Some(Wording::Collected(level, text)) => {
                log::log!(level, "{label}: {text}");
                None
            }
            None => None,
        };
        (warn, remains)
    }

    /// The one line of a failed spawn's teardown, led by the caller's name: the clause, `why` (the
    /// spawn's diagnosis, if still owed) leading it. It is the event's one warn if the clause is at
    /// warn or `why` is owed (the diagnosis is then the warn, and says what became of the child in
    /// it, whatever the clause's level); the caller logs the returned line. Otherwise the clause is
    /// logged here at its level, on its own.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn failed_spawn_line(self, why: &mut crate::child::spawn::Diagnosis) -> (Option<String>, Remains) {
        let label = crate::containment::dispatch::TeardownCaller::FailedSpawn.label();
        let remains = self.remains();
        let Some(said) = self.said else {
            return (None, remains);
        };
        let level = said.level();
        let text = said.text();
        if level == log::Level::Warn || why.is_owed() {
            return (Some(format!("{label}: {}", why.fold(text))), remains);
        }
        log::log!(level, "{label}: {text}");
        (None, remains)
    }
}

/// What the caller of a teardown over a handle it owns (a Linux pidfd, a Windows process handle)
/// knows about the handle, which decides what the teardown may come to. Stated once, where the
/// handle is handed over.
///
/// Only the Linux and Windows spawns tear a child down over a handle and produce these.
#[cfg_attr(
    not(any(target_os = "linux", windows)),
    allow(
        dead_code,
        reason = "only the Linux and Windows spawns tear a child down over a handle"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expect {
    /// An earlier look on the handle failed, or may have, so a wait on it may fail too: any outcome
    /// stands.
    Anything,
    /// No earlier look on the handle failed, and the handle may be waited on and killed (a
    /// Windows process handle from `CreateProcess` has `SYNCHRONIZE` and `PROCESS_TERMINATE`), so a
    /// wait on it does not fail: a child the teardown left uncollected is one whose kill was
    /// refused, and still running, and a kill is refused only for want of permission.
    Waited,
    /// As [`Waited`](Expect::Waited), and the child never ran the program, so it has this process's
    /// credentials: nothing but its being gone can refuse its kill, and the teardown collects it.
    Unexecuted,
}

/// What a teardown over a handle came to, and what its caller expected of it.
#[cfg_attr(
    not(any(target_os = "linux", windows)),
    allow(
        dead_code,
        reason = "only the Linux and Windows spawns tear a child down over a handle"
    )
)]
#[derive(Debug)]
pub(crate) struct HandleTeardown {
    pub(crate) outcome: TeardownOutcome,
    pub(crate) expect: Expect,
}

#[cfg_attr(
    not(any(target_os = "linux", windows)),
    allow(
        dead_code,
        reason = "only the Linux and Windows spawns tear a child down over a handle"
    )
)]
impl HandleTeardown {
    pub(crate) fn new(outcome: TeardownOutcome, expect: Expect) -> HandleTeardown {
        HandleTeardown { outcome, expect }
    }

    /// The teardown as an abandonment hands it on, if it left its child uncollected: its warn, for
    /// the place that logs it. Any other teardown is given back.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux spawn hands a pidfd teardown's abandonment on")
    )]
    pub(crate) fn uncollected(self) -> Result<Left, HandleTeardown> {
        let expect = self.expect;
        let remains = self.outcome.remains();
        self.outcome
            .into_uncollected()
            .map(|clause| Left {
                clause,
                remains,
                expect,
            })
            .map_err(|outcome| HandleTeardown { outcome, expect })
    }

    /// Says the teardown as a failed spawn's
    /// ([`failed_spawn_line`](TeardownOutcome::failed_spawn_line)): its warn, if it has one, is
    /// logged through [`warn_teardown`], which asserts the teardown's contract with its caller.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn say_as_failed_spawn(self, why: &mut crate::child::spawn::Diagnosis) -> Remains {
        let (line, remains) = self.outcome.failed_spawn_line(why);
        warn_teardown(line.as_deref(), &remains, self.expect);
        remains
    }

    /// Logs `line` through [`warn_teardown`], as this teardown came out, for a caller that
    /// folded the clause into its line itself.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(
            dead_code,
            reason = "only the async child folds a second teardown's clause into its own line"
        )
    )]
    pub(crate) fn warn(&self, line: Option<&str>) {
        warn_teardown(line, &self.outcome.remains(), self.expect);
    }
}

/// A handle teardown that left its child uncollected, as an abandonment hands it on to the place that
/// logs it: the clause for the caller's one warn, and what [`warn_teardown`] reads of the
/// teardown.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux spawn tears a child down through a pidfd")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Left {
    pub(crate) clause: String,
    pub(crate) remains: Remains,
    pub(crate) expect: Expect,
}

#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux spawn tears a child down through a pidfd")
)]
impl Left {
    /// Logs `line` through [`warn_teardown`]: the teardown left the child uncollected.
    pub(crate) fn warn(&self, line: &str) {
        warn_teardown(Some(line), &self.remains, self.expect);
    }
}

/// The one place the warn of a handle teardown is logged: `line`, then the teardown's contract
/// with its caller, asserted after the warn so that a panic does not lose it. That a child left
/// uncollected has a warn is not asserted: an outcome of one cannot be built without it.
/// `remains` is the teardown's ([`TeardownOutcome::remains`]); `expect` is its caller's.
#[cfg_attr(
    not(any(target_os = "linux", windows)),
    allow(
        dead_code,
        reason = "only the Linux and Windows spawns tear a child down over a handle"
    )
)]
fn warn_teardown(line: Option<&str>, remains: &Remains, expect: Expect) {
    let Remains {
        fate,
        uncollected,
        refused,
    } = *remains;
    if let Some(line) = line {
        log::warn!("{line}");
    }
    debug_assert!(
        !uncollected || expect == Expect::Anything || matches!(fate, ChildFate::Running { .. }),
        "a wait on a child's own handle failed: {fate:?}"
    );
    debug_assert!(
        expect != Expect::Unexecuted || !matches!(fate, ChildFate::Running { .. }),
        "the kill of a child that never ran the program was refused"
    );
    debug_assert!(
        expect == Expect::Anything || refused.is_none_or(|kind| kind == io::ErrorKind::PermissionDenied),
        "the kill of a child's own handle was refused for a reason other than permission: {refused:?}"
    );
}

impl OwnedChild {
    /// Best-effort teardown, the one entry point: kill the child as `kill` says, then settle it. `id`
    /// is the child's identity, if the caller read one. `due` is the threshold of the slow-teardown
    /// warn on the blocking wait (`None`: no warn). The warn watches the handle's own bounded wait:
    /// a child that is visible as exited but cannot be reaped yet (a zombie a tracer holds) is still
    /// waited for when the threshold passes, and warned of.
    ///
    /// Returns the child's fate, and what to say of how it went ([`TeardownOutcome::said`]). It
    /// logs nothing but that slow-teardown warn.
    pub(crate) fn tear_down(&self, id: Option<ProcessId>, kill: Kill<'_>, due: Option<Due>) -> TeardownOutcome {
        let Kill { disposition, tree } = kill;
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
    /// A failed reap comes back in [`TeardownOutcome::said`], as for [`tear_down`](Self::tear_down).
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
    /// identity, if the caller read one. A look that ended is also
    /// [`refused_look`](TeardownOutcome::refused_look).
    pub(crate) fn look_after_refused_kill(
        &self,
        id: Option<ProcessId>,
        refused: Error,
        disposition: Disposition,
    ) -> TeardownOutcome {
        // A child reaped elsewhere is read from the typed outcome, so it is `Gone` on every OS.
        let settlement = Settlement::new(self.wait(Some(crate::wait::now())), false);
        let refused_kind = match &refused {
            Error::Io(e) => e.kind(),
            _ => io::ErrorKind::Other,
        };
        let subject = format!("{} could not be terminated ({refused})", child_named(self.pid()));
        // Still running: the caller that leaves it says it keeps running, not that it is left unreaped.
        let running = match disposition {
            Disposition::Leave => format!("{subject}; leaving it running"),
            Disposition::HandBack => format!("{subject}{}", Disposition::HandBack.suffix(true)),
        };
        let mut torn = TeardownOutcome::of_settlement(&settlement, id, &subject, Some(&running), disposition);
        torn.refused_look = settlement.ended().then(|| Box::new(settlement));
        torn.refused = Some(refused_kind);
        torn
    }

    /// Looks at the elevation front this handle is, sending it nothing. A front that has exited is
    /// reaped. One that has not is waited for if `reach` says its place is where a kill landed, and
    /// otherwise left. `reach`: `Ok(None)` is no such kill, so a running front is always left;
    /// `Err`: the subtree that kill went through could not be read, so whether it reached the front
    /// is not known. `id` and `due` are as for [`tear_down`](Self::tear_down).
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "no Windows teardown looks at a front through this yet")
    )]
    pub(crate) fn look_at_front(
        &self,
        id: Option<ProcessId>,
        reach: Result<Option<&dyn Reach>, io::Error>,
        due: Option<Due>,
    ) -> FrontLook {
        let ended = |settlement: Settlement| FrontLook {
            fate: settlement.fate(id),
            look: LookOutcome::Ended(settlement),
        };
        let looked = Settlement::new(self.wait(Some(crate::wait::now())), false);
        if looked.ended() {
            return ended(looked);
        }
        // The look saw it running; an unreadable reach leaves open only whether the kill reached it.
        let running = |look| FrontLook {
            fate: ChildFate::Running { id },
            look,
        };
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
