//! A failed spawn's teardown of the child it holds after the spawn: on Linux, through its pidfd when
//! the identity read or the attach that follows fails (sync and async) and of the child the
//! handshake itself abandons; on Windows, the std and raw spawns' child over its process handle.
//! The teardown over a handle with what its caller expects of it ([`tear_down_expecting`]) and the
//! look at a front (`look_at_failed_spawn_front`) are also what a cgroup leaf's abandonment
//! builds on.

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use std::time::Duration;

use super::Diagnosis;
#[cfg(target_os = "linux")]
use super::FrontFate;
use crate::child::owned::teardown::{Disposition, Expect, HandleTeardown, Kill, Past};
#[cfg(target_os = "linux")]
use crate::child::owned::teardown::{Reach, TeardownOutcome};
use crate::child::owned::unreaped::DropKind;
use crate::child::owned::OwnedChild;
use crate::child::spawn::policy::SpawnPolicy;
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
    /// What the spawn was told of its teardowns: when the wait for a child the teardown killed, or a
    /// front its leaf's kill ended, warns, and what a child handed back does when dropped.
    pub(crate) policy: SpawnPolicy,
}

/// Tears `child` down after `error` failed the spawn, and returns `error` with what became of the
/// child, the child's fate, and the child itself if `how.disposition` hands back one that still runs.
///
/// A child that is not a front is killed and reaped. A front is sent nothing and looked at: reaped
/// if it has exited, waited for (warning once past 1 s) if `how.subtree`, where its leaf's kill went,
/// shows that kill reached it, and otherwise running. `why` leads the teardown's one warn, if it has one.
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
        policy,
    } = how;
    let pid = child.pid();
    // Nothing here states what became of the held child's handle, so a wait on it may fail: only the
    // uncollected-after-wait check is waived, not what a kill may be refused for.
    if front.is_none() {
        let (fate, unreaped) = tear_down_failed_spawn(child, id, Past::WaitMayFail, disposition, policy, why);
        return (error, fate, unreaped);
    }
    let reach = Ok(subtree.map(|subtree| subtree as &dyn Reach));
    let (front_fate, torn) = look_at_failed_spawn_front(&child, id, reach, disposition, policy.teardown_warn_after);
    let torn = HandleTeardown::new(torn, Expect::of(&child, Past::WaitMayFail));
    let (fate, unreaped) = say_failed_spawn(child, id, true, torn, disposition, policy.unreaped_drop, why);
    let error = if unreaped.is_some() {
        front_fate.note_handed_back(error, front, pid)
    } else {
        front_fate.note(error, front, pid)
    };
    (error, fate, unreaped)
}

/// Kills `child`, which a failed spawn holds, and reaps it, and says how that went as the failed
/// spawn's one warn, `why` leading it. The child itself comes back if `disposition` hands back one
/// the teardown could not collect, to do what `policy` says when dropped; the wait for the killed
/// child warns once past its threshold. `past`: what the caller knows became of the child's handle,
/// see [`Past`]; what the handle allows is its own.
pub(crate) fn tear_down_failed_spawn(
    child: OwnedChild,
    id: Option<ProcessId>,
    past: Past,
    disposition: Disposition,
    policy: SpawnPolicy,
    why: &mut Diagnosis,
) -> (ChildFate, Option<Unreaped>) {
    let kill = Kill {
        disposition,
        tree: None,
    };
    let torn = tear_down_expecting(&child, id, kill, past, policy.teardown_warn_after);
    say_failed_spawn(child, id, false, torn, disposition, policy.unreaped_drop, why)
}

/// Tears `child` down as `kill` says, over its handle, expecting `past` of it (see [`Past`]); the
/// handle's own allowance is its constructor's. The one place a teardown over a handle is paired
/// with what its caller expects of it.
pub(crate) fn tear_down_expecting(
    child: &OwnedChild,
    id: Option<ProcessId>,
    kill: Kill<'_>,
    past: Past,
    warn_after: Option<Duration>,
) -> HandleTeardown {
    HandleTeardown::new(child.tear_down(id, kill, warn_after), Expect::of(child, past))
}

/// Looks at the elevation front `child`, sent nothing, after its spawn failed: the front's fate,
/// and the look worded as the failed spawn's teardown of it (see [`OwnedChild::look_at_front`] for
/// `reach`, `id` and `warn_after`). `disposition`: what the caller does with a front it finds
/// running. The caller says the outcome.
#[cfg(target_os = "linux")]
pub(crate) fn look_at_failed_spawn_front(
    child: &OwnedChild,
    id: Option<ProcessId>,
    reach: Result<Option<&dyn Reach>, std::io::Error>,
    disposition: Disposition,
    warn_after: Option<Duration>,
) -> (FrontFate, TeardownOutcome) {
    let look = child.look_at_front(id, reach, warn_after);
    let front_fate = FrontFate::of_look(&look.look);
    let torn = crate::child::word_front(child.pid(), &"its spawn failed", disposition, look);
    (front_fate, torn)
}

/// Says `torn` as the failed spawn's one warn; hands `child` back per `disposition` if it is
/// uncollected, to do `unreaped_drop` when dropped. `front`: the child is an elevation front.
fn say_failed_spawn(
    child: OwnedChild,
    id: Option<ProcessId>,
    front: bool,
    torn: HandleTeardown,
    disposition: Disposition,
    unreaped_drop: DropKind,
    why: &mut Diagnosis,
) -> (ChildFate, Option<Unreaped>) {
    let remains = torn.say_as_failed_spawn(why);
    let unreaped = disposition
        .hands_back(&remains)
        .then(|| Unreaped::new(child, id, front, unreaped_drop));
    (remains.fate, unreaped)
}

/// Kills the child `pidfd` names, whose pid is `pid` if known, and reaps it, through an
/// [`OwnedChild`] over the pidfd. A child it could not collect (its kill refused and it still
/// running, a look or a wait that failed) is left, which the outcome's `uncollected` says, not the
/// fate; the caller owns the one warn, and says it with [`HandleTeardown::say_as_failed_spawn`], or
/// logs its own line through [`HandleTeardown::warn`]. `past`: see [`Past`]. With `warn_after`, the wait
/// for the killed child warns once it has lasted that long.
#[cfg(target_os = "linux")]
pub(crate) fn tear_down_pidfd(
    pid: Option<u32>,
    pidfd: OwnedFd,
    id: Option<ProcessId>,
    past: Past,
    warn_after: Option<Duration>,
) -> HandleTeardown {
    let child = OwnedChild::new(Box::new(LinuxProcess::new(pid, pidfd)));
    let kill = Kill {
        disposition: Disposition::Leave,
        tree: None,
    };
    tear_down_expecting(&child, id, kill, past, warn_after)
}
