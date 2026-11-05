//! Linux: the teardown of the child a spawn holds through its pidfd after the handshake, when the
//! identity read or the attach that follows fails (sync and async), and of the child the handshake
//! itself abandons.

use std::os::fd::OwnedFd;

use super::{Diagnosis, FrontFate};
use crate::child::owned::teardown::{Disposition, Reach, TeardownKind, TeardownOutcome};
use crate::child::owned::OwnedChild;
use crate::containment::cgroup::Subtree;
use crate::containment::dispatch::TeardownCaller;
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
    let (front_fate, torn) = if front.is_some() {
        let reach = Ok(subtree.map(|subtree| subtree as &dyn Reach));
        let torn = child.tear_down(id, TeardownKind::Look(reach), due);
        let fate = torn.look.as_ref().map(FrontFate::of_look);
        let worded = crate::child::word_front(TeardownCaller::FailedSpawn, pid, &"its spawn failed", disposition, torn);
        (fate, worded)
    } else {
        let tree = None;
        (None, child.tear_down(id, TeardownKind::Kill { disposition, tree }, due))
    };
    if let Some(left) = &torn.left {
        log::warn!("{}", why.fold(left));
    }
    let unreaped = disposition.hands_back(&torn).then(|| Unreaped::new(child, id));
    let error = match front_fate {
        Some(fate) if unreaped.is_some() => fate.note_handed_back(error, front, pid),
        Some(fate) => fate.note(error, front, pid),
        None => error,
    };
    (error, torn.fate, unreaped)
}

/// Kills the child `pidfd` names, whose pid is `pid` if known, and reaps it, through an
/// [`OwnedChild`] over the pidfd. A child it could not collect (its kill refused and it still
/// running, a look or a wait that failed) is left, which [`TeardownOutcome::uncollected`] says, not
/// the fate; the caller owns the one warn, and logs `left` in it. With `due`, the wait for the
/// killed child warns once it passes.
pub(crate) fn tear_down_pidfd(
    pid: Option<u32>,
    pidfd: OwnedFd,
    id: Option<ProcessId>,
    due: Option<Due>,
) -> TeardownOutcome {
    let child = OwnedChild::new(Box::new(LinuxProcess::new(pid, pidfd)));
    let kind = TeardownKind::Kill {
        disposition: Disposition::Leave,
        tree: None,
    };
    child.tear_down(id, kind, due)
}
