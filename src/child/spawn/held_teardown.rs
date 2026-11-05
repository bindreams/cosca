//! A failed spawn's teardown of the child it holds after the spawn: on Linux, through its pidfd when
//! the identity read or the attach that follows fails (sync and async) and of the child the
//! handshake itself abandons; on Windows, the std and raw spawns' child over its process handle.

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

use super::Diagnosis;
#[cfg(target_os = "linux")]
use super::FrontFate;
use crate::child::owned::teardown::{Disposition, Kill, TeardownOutcome};
#[cfg(target_os = "linux")]
use crate::child::owned::teardown::{Expect, PidfdTeardown, Reach};
use crate::child::owned::OwnedChild;
#[cfg(target_os = "linux")]
use crate::containment::cgroup::Subtree;
#[cfg(target_os = "linux")]
use crate::elevation::front::Front;
use crate::error::ChildFate;
#[cfg(target_os = "linux")]
use crate::error::Error;
use crate::identity::ProcessId;
#[cfg(target_os = "linux")]
use crate::os_process::linux::LinuxProcess;
use crate::wait::teardown_warn::Due;
use crate::Unreaped;

/// What a held child's teardown is told.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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
    if front.is_none() {
        let (fate, unreaped) = tear_down_failed_spawn(child, id, disposition, due, why);
        return (error, fate, unreaped);
    }
    let reach = Ok(subtree.map(|subtree| subtree as &dyn Reach));
    let look = child.look_at_front(id, reach, due);
    let front_fate = FrontFate::of_look(&look.look);
    let torn = crate::child::word_front(pid, &"its spawn failed", disposition, look);
    let (fate, unreaped) = say_failed_spawn(child, id, torn, disposition, why);
    let error = if unreaped.is_some() {
        front_fate.note_handed_back(error, front, pid)
    } else {
        front_fate.note(error, front, pid)
    };
    (error, fate, unreaped)
}

/// Kills `child`, which a failed spawn holds, and reaps it, and says how that went as the failed
/// spawn's one warn, `why` leading it. The child itself comes back if `disposition` hands back one
/// the teardown could not collect. With `due`, the wait for the killed child warns once it passes.
pub(crate) fn tear_down_failed_spawn(
    child: OwnedChild,
    id: Option<ProcessId>,
    disposition: Disposition,
    due: Option<Due>,
    why: &mut Diagnosis,
) -> (ChildFate, Option<Unreaped>) {
    let kill = Kill {
        disposition,
        tree: None,
    };
    let torn = child.tear_down(id, kill, due);
    say_failed_spawn(child, id, torn, disposition, why)
}

/// The end of every failed spawn's teardown of `child`: says `torn` as the spawn's one warn, and
/// hands `child` back if `disposition` does and `torn` left it uncollected.
fn say_failed_spawn(
    child: OwnedChild,
    id: Option<ProcessId>,
    torn: TeardownOutcome,
    disposition: Disposition,
    why: &mut Diagnosis,
) -> (ChildFate, Option<Unreaped>) {
    let remains = torn.say_as_failed_spawn(why);
    let unreaped = disposition.hands_back(&remains).then(|| Unreaped::new(child, id));
    (remains.fate, unreaped)
}

/// Kills the child `pidfd` names, whose pid is `pid` if known, and reaps it, through an
/// [`OwnedChild`] over the pidfd. A child it could not collect (its kill refused and it still
/// running, a look or a wait that failed) is left, which the outcome's `uncollected` says, not the
/// fate; the caller owns the one warn, and says it with [`PidfdTeardown::say_as_failed_spawn`], or
/// logs its own line through [`PidfdTeardown::warn`]. `expect`: see [`Expect`]. With `due`, the wait for the
/// killed child warns once it passes.
#[cfg(target_os = "linux")]
pub(crate) fn tear_down_pidfd(
    pid: Option<u32>,
    pidfd: OwnedFd,
    id: Option<ProcessId>,
    expect: Expect,
    due: Option<Due>,
) -> PidfdTeardown {
    let child = OwnedChild::new(Box::new(LinuxProcess::new(pid, pidfd)));
    let kill = Kill {
        disposition: Disposition::Leave,
        tree: None,
    };
    PidfdTeardown::new(child.tear_down(id, kill, due), expect)
}
