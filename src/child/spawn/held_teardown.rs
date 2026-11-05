//! Linux: the teardown of the child a spawn holds through its pidfd after the handshake, when the
//! identity read or the attach that follows fails (sync and async), and of the child the handshake
//! itself abandons.

use std::os::fd::OwnedFd;

use super::{Diagnosis, FrontFate};
use crate::child::owned::teardown::{Disposition, Reach, TeardownKind, TeardownOutcome};
use crate::child::owned::OwnedChild;
use crate::containment::cgroup::Subtree;
use crate::elevation::front::Front;
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::os_process::linux::LinuxProcess;
use crate::wait::teardown_warn::Due;
use crate::Unreaped;

/// What a held child's teardown is told.
pub(crate) struct HeldTeardown<'a> {
    /// The elevation front the child is, if it is one: sent nothing and looked at.
    pub(crate) front: Option<Front>,
    /// The child's identity, if the spawn read one.
    pub(crate) id: Option<ProcessId>,
    /// Where a front's leaf's kill went. `None`: no leaf kill, so a running front is left.
    pub(crate) subtree: Option<&'a Subtree>,
    /// What the caller does with a child that still runs: hand it back, or leave it.
    pub(crate) disposition: Disposition,
    /// When the wait for a child the teardown killed, or a front its leaf's kill ended, warns.
    pub(crate) due: Option<Due>,
}

/// Tears `child` down after `error` failed the spawn, and returns `error` with what became of the
/// child, the child's fate, and the child itself if `how.disposition` hands back one that still runs.
///
/// A child that is not a front is killed and reaped. A front is sent nothing and looked at: reaped
/// if it has exited, waited for if `how.subtree`, where its leaf's kill went, shows that kill
/// reached it, and otherwise running. `why` leads the teardown's one warn, if it has one.
pub(crate) fn tear_down_held(
    child: OwnedChild,
    how: HeldTeardown<'_>,
    why: &mut Diagnosis,
    error: Error,
) -> (Error, ChildFate, Option<Unreaped>) {
    let HeldTeardown {
        front,
        id,
        subtree,
        disposition,
        due,
    } = how;
    let pid = child.pid();
    let (front_fate, mut torn) = if front.is_some() {
        let reach = Ok(subtree.map(|subtree| subtree as &dyn Reach));
        let torn = child.tear_down(id, TeardownKind::Look(reach), due);
        let fate = torn.look.as_ref().map(FrontFate::of_look);
        let worded = crate::child::word_front(pid, &"its spawn failed", disposition, torn);
        (fate, worded)
    } else {
        let tree = None;
        (None, child.tear_down(id, TeardownKind::Kill { disposition, tree }, due))
    };
    torn.say_as_failed_spawn(why);
    let unreaped = disposition.hands_back(&torn).then(|| Unreaped::new(child, id));
    let error = match front_fate {
        Some(fate) if unreaped.is_some() => fate.note_handed_back(error, front, pid),
        Some(fate) => fate.note(error, front, pid),
        None => error,
    };
    (error, torn.fate, unreaped)
}

/// What the caller of [`tear_down_pidfd`] knows about the pidfd, which decides what its teardown may
/// come to. Stated once, where the pidfd is handed over.
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

/// What a pidfd teardown came to, as its caller's [`Expect`] needs it: all that
/// [`warn_pidfd_teardown`] reads, so that it can travel with the clause to where the warn is logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub(crate) fate: ChildFate,
    uncollected: bool,
    expect: Expect,
}

impl Verdict {
    fn assert(&self) {
        debug_assert!(
            !self.uncollected || self.expect == Expect::Anything || matches!(self.fate, ChildFate::Running { .. }),
            "a wait on a child's own pidfd failed: {:?}",
            self.fate
        );
        debug_assert!(
            self.expect != Expect::Unexecuted || !matches!(self.fate, ChildFate::Running { .. }),
            "the kill of a child that never ran the program was refused"
        );
    }
}

/// The one place the warn of a pidfd teardown is logged: `line`, then the contract of the teardown's
/// [`Expect`], asserted after the warn so that a panic does not lose it. A child the teardown left
/// uncollected always has a warn, so no teardown breaks its contract unasserted.
pub(crate) fn warn_pidfd_teardown(line: std::fmt::Arguments<'_>, verdict: &Verdict) {
    log::warn!("{line}");
    verdict.assert();
}

/// A pidfd teardown that left its child uncollected, as the leaf's abandonment hands it on: the
/// clause for the caller's one warn, and the verdict for [`warn_pidfd_teardown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Left {
    pub(crate) clause: String,
    pub(crate) verdict: Verdict,
}

/// A teardown through a pidfd: its outcome, and what its caller expected of it.
#[derive(Debug)]
pub(crate) struct PidfdTeardown {
    pub(crate) outcome: TeardownOutcome,
    expect: Expect,
}

impl PidfdTeardown {
    pub(crate) fn new(outcome: TeardownOutcome, expect: Expect) -> PidfdTeardown {
        PidfdTeardown { outcome, expect }
    }

    pub(crate) fn verdict(&self) -> Verdict {
        Verdict {
            fate: self.outcome.fate,
            uncollected: self.outcome.uncollected,
            expect: self.expect,
        }
    }

    /// Takes the clause of a teardown that left its child uncollected, for the caller that logs the
    /// warn.
    pub(crate) fn left(&mut self) -> Left {
        let clause = self.outcome.clause.take().map(|(_, clause)| clause);
        Left {
            clause: clause.unwrap_or_else(|| "its teardown left it uncollected".to_owned()),
            verdict: self.verdict(),
        }
    }

    /// Says the teardown as a failed spawn's ([`TeardownOutcome::failed_spawn_line`]): a warn goes
    /// through [`warn_pidfd_teardown`].
    pub(crate) fn say_as_failed_spawn(&mut self, why: &mut Diagnosis) {
        if let Some(line) = self.outcome.failed_spawn_line(why) {
            warn_pidfd_teardown(format_args!("{line}"), &self.verdict());
        }
    }
}

/// Kills the child `pidfd` names, whose pid is `pid` if known, and reaps it, through an
/// [`OwnedChild`] over the pidfd. A child it could not collect (its kill refused and it still
/// running, a look or a wait that failed) is left, which [`TeardownOutcome::uncollected`] says, not
/// the fate; the caller owns the one warn, and logs it through [`warn_pidfd_teardown`], or says it
/// with [`PidfdTeardown::say_as_failed_spawn`]. `expect`: see [`Expect`]. With `due`, the wait for
/// the killed child warns once it passes.
pub(crate) fn tear_down_pidfd(
    pid: Option<u32>,
    pidfd: OwnedFd,
    id: Option<ProcessId>,
    expect: Expect,
    due: Option<Due>,
) -> PidfdTeardown {
    let child = OwnedChild::new(Box::new(LinuxProcess::new(pid, pidfd)));
    let kind = TeardownKind::Kill {
        disposition: Disposition::Leave,
        tree: None,
    };
    PidfdTeardown::new(child.tear_down(id, kind, due), expect)
}
