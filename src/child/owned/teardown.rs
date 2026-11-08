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
//! # Split
//!
//! The teardown has one wait, for the root's exit after a kill that reached it. The first half
//! ([`begin_tear_down`](OwnedChild::begin_tear_down), [`begin_look_at_front`](OwnedChild::begin_look_at_front))
//! never blocks, and answers [`BeginOutcome::Done`] or the pending [`TeardownWait`], which a driver
//! makes: [`settle`](TeardownWait::settle) blocks, and `settle_async` awaits. The wait carries what
//! the first half decided (the child, its identity, its wording), so the second half takes only the
//! child, and asserts it is the one the first half was made on. [`OwnedChild::tear_down`] is
//! `begin_tear_down` then `settle`.
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
use std::time::Duration;

use super::OwnedChild;
use crate::child::lifecycle::{wait_to_exit, Settlement, Wording};
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::os_process::child::KillRefusal;
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
pub(crate) const LEFT: &str = if cfg!(unix) {
    "; left unreaped"
} else {
    "; nothing waits for it"
};

/// What a caller that leaves a child running after its kill was refused says of it. Nothing reaps it
/// afterwards, so on Unix it is a zombie once it exits; Windows has none.
pub(crate) const LEAVING_RUNNING: &str = if cfg!(unix) {
    "; leaving it running and unreaped"
} else {
    "; leaving it running"
};

/// What every line about a refused kill says of the child, after its subject: it "could not be
/// terminated", with the error.
pub(crate) fn kill_refused(refused: &impl std::fmt::Display) -> String {
    format!("could not be terminated ({refused})")
}

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

impl FrontLook {
    /// The look that ended as `settlement` states, of a front whose identity the caller read as `id`.
    pub(crate) fn ended(settlement: Settlement, id: Option<ProcessId>) -> FrontLook {
        FrontLook {
            fate: settlement.fate(id),
            look: LookOutcome::Ended(settlement),
        }
    }
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
/// uncollected, and the kind of the error its kill was refused with, if it was.
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

/// What already happened to a handle a teardown goes over (a Linux pidfd, a Windows process handle),
/// which the caller knows and the handle does not. What the handle allows is its constructor's
/// ([`KillRefusal`]); the two make an [`Expect`].
#[cfg_attr(
    not(any(target_os = "linux", windows)),
    allow(
        dead_code,
        reason = "only the Linux and Windows spawns tear a child down over a handle"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Past {
    /// Nothing happened to the handle, which can be waited on (a Windows handle holding
    /// `SYNCHRONIZE`), so a wait on it does not fail: a child left uncollected is one whose kill was
    /// refused, and still running.
    Clean,
    /// An earlier look on the handle failed, or may have, so a wait on it may fail too: a child the
    /// teardown left uncollected need not be one whose kill was refused. What the kill may be refused
    /// for is the handle's.
    WaitMayFail,
    /// As [`Clean`](Past::Clean), and the child never ran the program, so it has this process's
    /// credentials: nothing but its being gone can refuse its kill, and the teardown collects it.
    Unexecuted,
}

/// What a teardown over a handle is expected to come to: what the handle allows, from its
/// constructor, and what already happened to it, from the caller.
#[cfg_attr(
    not(any(target_os = "linux", windows)),
    allow(
        dead_code,
        reason = "only the Linux and Windows spawns tear a child down over a handle"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Expect {
    pub(crate) refusal: KillRefusal,
    pub(crate) past: Past,
}

#[cfg(any(target_os = "linux", windows))]
impl Expect {
    /// What `past` and the allowance of `child`'s handle make of a teardown over it.
    pub(crate) fn of(child: &OwnedChild, past: Past) -> Expect {
        Expect {
            refusal: child.kill_refusal(),
            past,
        }
    }
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

    /// Says the teardown as a failed spawn's
    /// ([`failed_spawn_line`](TeardownOutcome::failed_spawn_line)): its warn, if it has one, is
    /// logged through [`warn_teardown`], which asserts the teardown's contract with its caller.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn say_as_failed_spawn(self, why: &mut crate::child::spawn::Diagnosis) -> Remains {
        let (line, remains) = self.outcome.failed_spawn_line(why);
        warn_teardown(line.as_deref(), &remains, self.expect);
        remains
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
    let Expect { refusal, past } = expect;
    if let Some(line) = line {
        log::warn!("{line}");
    }
    debug_assert!(
        !uncollected || past == Past::WaitMayFail || matches!(fate, ChildFate::Running { .. }),
        "a wait on a child's own handle failed: {fate:?}"
    );
    debug_assert!(
        past != Past::Unexecuted || !matches!(fate, ChildFate::Running { .. }),
        "the kill of a child that never ran the program was refused"
    );
    debug_assert!(
        refusal != KillRefusal::Never || refused.is_none(),
        "the kill of a handle that is never refused was refused: {refused:?}"
    );
    debug_assert!(
        refused.is_none_or(|kind| kind == io::ErrorKind::PermissionDenied),
        "the kill of a child's own handle was refused for a reason other than permission: {refused:?}"
    );
}

/// What a refused kill was refused for: what the OS refused it with, which is an I/O error. Any other
/// error is another reason.
fn refusal_kind(refused: &Error) -> io::ErrorKind {
    match refused {
        Error::Io(e) => e.kind(),
        _ => io::ErrorKind::Other,
    }
}

impl OwnedChild {
    /// Best-effort teardown, the one entry point: kill the child as `kill` says, then settle it. `id`
    /// is the child's identity, if the caller read one. `warn_after` is the threshold of the
    /// slow-teardown warn on the blocking wait (`None`: no warn). The warn watches the handle's own
    /// bounded wait: a child that is visible as exited but cannot be reaped yet (a zombie a tracer
    /// holds) is still waited for when the threshold passes, and warned of.
    ///
    /// Returns the child's fate, and what to say of how it went (the outcome's clause). It
    /// logs nothing but that slow-teardown warn.
    #[cfg_attr(
        not(any(target_os = "linux", windows)),
        allow(
            dead_code,
            reason = "only the Linux and Windows spawns tear a child down through this wrapper"
        )
    )]
    pub(crate) fn tear_down(
        &self,
        id: Option<ProcessId>,
        kill: Kill<'_>,
        warn_after: Option<Duration>,
    ) -> TeardownOutcome {
        match self.begin_tear_down(id, kill, warn_after) {
            BeginOutcome::Done(torn) => torn,
            BeginOutcome::Wait(wait) => wait.settle(self),
        }
    }

    /// The first half of [`tear_down`](Self::tear_down), which never blocks: the kill, and what can
    /// be settled without waiting. [`Done`](BeginOutcome::Done) when no wait is left (the child is
    /// reaped, or its kill was refused and one look settled it), else the pending
    /// [`TeardownWait`], which the caller [settles](TeardownWait::settle). `id` and `warn_after`
    /// are as for `tear_down`.
    pub(crate) fn begin_tear_down(
        &self,
        id: Option<ProcessId>,
        kill: Kill<'_>,
        warn_after: Option<Duration>,
    ) -> BeginOutcome<TeardownOutcome, TeardownWait> {
        let Kill { disposition, tree } = kill;
        #[cfg(test)]
        super::seams::note_root_teardown();
        match self.signal(Sig::Kill) {
            Ok(sent) => {
                #[cfg(test)]
                crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterDropKill);
                let wait = TeardownWait::new(
                    self,
                    warn_after,
                    matches!(sent, Sent::Delivered),
                    id,
                    self.teardown_subject(),
                    disposition,
                );
                // The reap is recorded for good: asking again answers it, and blocks on nothing.
                if self.is_reaped() {
                    let settlement = Settlement::new(self.wait(None), wait.pending.reached);
                    return BeginOutcome::Done(wait.outcome(self, &settlement));
                }
                BeginOutcome::Wait(wait)
            }
            Err(refused) => match tree.map(|tree| tree.reached(self)) {
                // The tree's kill reached it, and is asynchronous: one look would race it. Its exit
                // follows, so the reap is the wait that kill bounds.
                Some(Ok(true)) => BeginOutcome::Wait(self.begin_reap_after_tree_kill(
                    id,
                    self.teardown_subject(),
                    disposition,
                    warn_after,
                )),
                // No tree kill, one that missed the child, or one whose reach cannot be read: nothing
                // is shown to be ending it.
                _ => BeginOutcome::Done(self.look_after_refused_kill(id, refused, disposition)),
            },
        }
    }

    /// The wait of a child a tree kill has just ended, which is sent nothing: the kill bounds the
    /// wait, so it is always pending. `subject` is what the clause calls the child:
    /// [`teardown_subject`](Self::teardown_subject) for a plain child, and the elevation front's
    /// name for a front. `warn_after` is as for [`tear_down`](Self::tear_down).
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix teardown reaps a front a tree kill ended")
    )]
    pub(crate) fn begin_reap_after_tree_kill(
        &self,
        id: Option<ProcessId>,
        subject: String,
        disposition: Disposition,
        warn_after: Option<Duration>,
    ) -> TeardownWait {
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        TeardownWait::new(self, warn_after, true, id, subject, disposition)
    }

    /// What the clause of a root teardown calls a plain child.
    pub(crate) fn teardown_subject(&self) -> String {
        format!("teardown of {}", child_named(self.pid()))
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
        let refused_kind = refusal_kind(&refused);
        let subject = format!("{} {}", child_named(self.pid()), kill_refused(&refused));
        // Still running: the caller that leaves it says so, and that nothing reaps it.
        let running = match disposition {
            Disposition::Leave => format!("{subject}{LEAVING_RUNNING}"),
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
    /// is not known. `id` and `warn_after` are as for [`tear_down`](Self::tear_down).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux spawn looks at a front through this wrapper")
    )]
    pub(crate) fn look_at_front(
        &self,
        id: Option<ProcessId>,
        reach: Result<Option<&dyn Reach>, io::Error>,
        warn_after: Option<Duration>,
    ) -> FrontLook {
        match self.begin_look_at_front(id, reach, warn_after) {
            BeginOutcome::Done(look) => look,
            BeginOutcome::Wait(wait) => wait.settle(self),
        }
    }

    /// The first half of [`look_at_front`](Self::look_at_front), which never blocks:
    /// [`Done`](BeginOutcome::Done) unless the look finds the front dying, when the pending
    /// [`FrontWait`] is the wait that ends it.
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "no Windows teardown looks at a front through this yet")
    )]
    pub(crate) fn begin_look_at_front(
        &self,
        id: Option<ProcessId>,
        reach: Result<Option<&dyn Reach>, io::Error>,
        warn_after: Option<Duration>,
    ) -> BeginOutcome<FrontLook, FrontWait> {
        let looked = Settlement::new(self.wait(Some(crate::wait::now())), false);
        if looked.ended() {
            return BeginOutcome::Done(FrontLook::ended(looked, id));
        }
        // The look saw it running; an unreadable reach leaves open only whether the kill reached it.
        let running = |look| FrontLook {
            fate: ChildFate::Running { id },
            look,
        };
        let reach = match reach {
            Err(e) => return BeginOutcome::Done(running(LookOutcome::SubtreeUnreadable(e))),
            Ok(None) => return BeginOutcome::Done(running(LookOutcome::LeftRunning)),
            Ok(Some(reach)) => reach,
        };
        match reach.reached(self) {
            Ok(false) => BeginOutcome::Done(running(LookOutcome::LeftRunning)),
            Err(e) => BeginOutcome::Done(running(LookOutcome::PlaceUnreadable(e))),
            // Dying: its kill is pending, so this wait ends.
            Ok(true) => {
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                BeginOutcome::Wait(FrontWait {
                    pending: Pending::new(self, warn_after, true),
                    id,
                })
            }
        }
    }
}

/// What the first half of a teardown came to ([`OwnedChild::begin_tear_down`],
/// [`OwnedChild::begin_look_at_front`]): `D`, its answer, when it ended without a wait, or the
/// wait `W` it left, which carries what its second half needs.
#[must_use = "a pending wait that is dropped leaves the child unreaped"]
#[derive(Debug)]
pub(crate) enum BeginOutcome<D, W> {
    /// No wait is left.
    Done(D),
    /// The root's reap is pending.
    Wait(W),
}

/// The wait a teardown's first half left, whichever child and kill it was made on.
#[derive(Debug)]
struct Pending {
    /// The child's handle ([`OwnedChild::handle_id`]), which a wait carried across an await is
    /// checked against: a pid may be absent or shared.
    handle: usize,
    /// How long into the wait it warns that it is slow (`None`: it does not).
    warn_after: Option<Duration>,
    /// Whether a kill reached the child, as [`Settlement::new`] has it.
    reached: bool,
}

impl Pending {
    fn new(child: &OwnedChild, warn_after: Option<Duration>, reached: bool) -> Pending {
        Pending {
            handle: child.handle_id(),
            warn_after,
            reached,
        }
    }

    /// Blocks until `child` has exited and been reaped, and says how that ended. The threshold
    /// starts when the wait does (see [`wait_to_exit`]).
    fn settle(&self, child: &OwnedChild) -> Settlement {
        debug_assert_eq!(
            self.handle,
            child.handle_id(),
            "a wait is settled on the child it began on"
        );
        Settlement::new(wait_to_exit(child, Due::in_(self.warn_after)), self.reached)
    }

    /// [`settle`](Self::settle) awaited, through [`OwnedChild::wait_async`], with no warn: the
    /// threshold is about a blocked thread.
    #[cfg(feature = "tokio")]
    async fn settle_async(&self, child: &mut OwnedChild) -> Settlement {
        debug_assert_eq!(
            self.handle,
            child.handle_id(),
            "a wait is settled on the child it began on"
        );
        Settlement::new(child.wait_async().await, self.reached)
    }
}

/// The one wait of a root's teardown: for the child to exit and be reaped, which a kill that reached
/// it bounds. [`settle`](Self::settle) makes it, blocking, and words it as the first half decided.
#[must_use = "a pending wait that is dropped leaves the child unreaped"]
#[derive(Debug)]
pub(crate) struct TeardownWait {
    pending: Pending,
    /// The child's identity, if the first half's caller read one.
    id: Option<ProcessId>,
    /// What the clause calls the child.
    subject: String,
    /// As for [`Kill`].
    disposition: Disposition,
}

impl TeardownWait {
    fn new(
        child: &OwnedChild,
        warn_after: Option<Duration>,
        reached: bool,
        id: Option<ProcessId>,
        subject: String,
        disposition: Disposition,
    ) -> TeardownWait {
        TeardownWait {
            pending: Pending::new(child, warn_after, reached),
            id,
            subject,
            disposition,
        }
    }

    /// Blocks until `child`, the one the first half was made on, has exited and been reaped, and
    /// says what became of it. With a threshold, warns once past it.
    pub(crate) fn settle(self, child: &OwnedChild) -> TeardownOutcome {
        let settlement = self.pending.settle(child);
        self.outcome(child, &settlement)
    }

    /// [`settle`](Self::settle) awaited, with no warn. By reference: a caller whose future is dropped
    /// mid-wait still holds the wait, and settles it blocking, as the drop would.
    #[cfg(feature = "tokio")]
    pub(crate) async fn settle_async(&self, child: &mut OwnedChild) -> TeardownOutcome {
        let settlement = self.pending.settle_async(child).await;
        self.outcome(child, &settlement)
    }

    /// What the root teardown's `settlement`, of the wait on `child`, says of it: its fate and its
    /// clause, led by the subject.
    fn outcome(&self, child: &OwnedChild, settlement: &Settlement) -> TeardownOutcome {
        debug_assert_eq!(
            self.pending.handle,
            child.handle_id(),
            "a wait is worded for the child it was settled on"
        );
        #[cfg(test)]
        if let Some(status) = settlement.status() {
            // An unknown pid records as 0.
            crate::child::spawn::fault::record_teardown_reap(child.pid().unwrap_or(0), status);
        }
        TeardownOutcome::of_settlement(settlement, self.id, &self.subject, None, self.disposition)
    }
}

/// The one wait of a look at an elevation front: for a front a kill sent elsewhere is ending to
/// exit and be reaped. [`settle`](Self::settle) makes it, blocking.
#[must_use = "a pending wait that is dropped leaves the front unreaped"]
#[derive(Debug)]
pub(crate) struct FrontWait {
    pending: Pending,
    /// The front's identity, if the first half's caller read one.
    id: Option<ProcessId>,
}

impl FrontWait {
    /// Blocks until `child`, the front the first half was made on, has exited and been reaped, and
    /// says how the look ended. With a threshold, warns once past it.
    pub(crate) fn settle(self, child: &OwnedChild) -> FrontLook {
        FrontLook::ended(self.pending.settle(child), self.id)
    }

    /// [`settle`](Self::settle) awaited, with no warn, by reference as [`TeardownWait::settle_async`].
    #[cfg(all(feature = "tokio", unix))]
    pub(crate) async fn settle_async(&self, child: &mut OwnedChild) -> FrontLook {
        FrontLook::ended(self.pending.settle_async(child).await, self.id)
    }
}

#[cfg(test)]
#[path = "teardown_tests.rs"]
mod teardown_tests;
