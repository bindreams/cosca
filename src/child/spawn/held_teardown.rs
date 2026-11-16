//! A failed spawn's teardown of the child it holds after the spawn: on Linux, through its pidfd when
//! the identity read or the attach that follows fails (sync and async) and of the child the status
//! channel shows never ran the program (`fork_spawn`); on Windows, the std and raw
//! spawns' child over its process handle; on
//! macOS, over the `MacosChild` the spawn builds right after the child's unique id is adopted.
//! The teardown over a handle with what its caller expects of it ([`tear_down_expecting`]) and the
//! look at a front (`look_at_failed_spawn_front`) are also what a cgroup leaf's abandonment
//! builds on.

use std::time::Duration;

use super::Diagnosis;
#[cfg(unix)]
use super::FrontFate;
use crate::child::drop_teardown::Torn;
use crate::child::owned::teardown::{Disposition, Expect, HandleTeardown, Kill, Past, Remains, RootKill};
#[cfg(unix)]
use crate::child::owned::teardown::{Reach, TeardownOutcome};
use crate::child::owned::unreaped::DropKind;
use crate::child::owned::OwnedChild;
use crate::child::spawn::policy::SpawnPolicy;
use crate::identity::ProcessId;
use crate::Unreaped;

/// What a held child's teardown is told.
#[cfg(unix)]
pub(crate) struct HeldTeardown<'a> {
    /// The child's identity, if the spawn read one.
    pub(crate) id: Option<ProcessId>,
    /// Where a front's leaf's kill went. `None`: no such kill, so a running front is left. Only a
    /// Linux cgroup leaf makes one (its `Subtree`); on macOS this is always `None`.
    pub(crate) reach: Option<&'a dyn Reach>,
    /// What the caller does with a child that still runs: hand it back, or leave it.
    pub(crate) disposition: Disposition,
    /// What the spawn was told of its teardowns: when the wait for a child the teardown killed, or a
    /// front its leaf's kill ended, warns, and what a child handed back does when dropped.
    pub(crate) policy: SpawnPolicy,
}

/// Tears `child` down after a failed spawn, and returns what it did with a front (the `detail` of the
/// spawn's error; `None` for a child that is not a front), the child's fate, and the child itself if
/// `how.disposition` hands back one that still runs.
///
/// A child that is not a front is killed and reaped. A front is sent
/// nothing and looked at: reaped if it has exited, waited for (warning once past 1 s) if
/// `how.reach`, where its leaf's kill went, shows that kill reached it, and otherwise running.
/// `why` leads the teardown's one warn, if it has one.
#[cfg(unix)]
pub(crate) fn tear_down_held(child: OwnedChild, how: HeldTeardown<'_>, why: &mut Diagnosis) -> (Option<String>, Torn) {
    let HeldTeardown {
        id,
        reach,
        disposition,
        policy,
    } = how;
    let pid = child.pid();
    let front = child.tracked_kind().front();
    // Nothing here states what became of the held child's handle, so a wait on it may fail: only the
    // uncollected-after-wait check is waived, not what a kill may be refused for.
    if front.is_none() {
        let torn = tear_down_failed_spawn(child, id, Past::WaitMayFail, disposition, policy, why);
        return (None, torn);
    }
    let (front_fate, torn) = look_at_failed_spawn_front(&child, id, Ok(reach), disposition, policy.teardown_warn_after);
    let torn = HandleTeardown::new(torn, Expect::of(&child, Past::WaitMayFail));
    let torn = say_failed_spawn(child, id, torn, disposition, policy.unreaped_drop, why);
    let detail = if torn.unreaped.is_some() {
        front_fate.detail_handed_back(front, pid)
    } else {
        front_fate.detail(front, pid)
    };
    (detail, torn)
}

/// Tears `child` down after a failed spawn or attach that proved it never ran the program (on Linux
/// it ended before `exec`, as its status channel or its placement report shows; on Windows it is still
/// suspended): killed and reaped, whether or not it is an elevation front, which never ran its
/// `sudo`. Nothing but its being gone refuses its kill ([`Past::Unexecuted`]): on Linux it has this
/// process's credentials; on Windows the handle is `CreateProcess`'s own and holds
/// `PROCESS_TERMINATE` (`KillRefusal::Never`), so only an exiting child refuses, and that is
/// answered as an exit. Its failures are said in the failed spawn's one warn, led by `why`; a
/// not-started error has no place for them, and the child is never handed back.
///
/// `id`: the identity the spawn read, `None` when that read failed. `past`: what the caller knows
/// became of the handle ([`Past::Unexecuted`], or [`Past::WaitMayFail`] when a look at it failed,
/// so a child the teardown cannot collect is left, as `abandon_unreported` leaves one, and the warn
/// says so).
pub(crate) fn tear_down_unexecuted(
    child: OwnedChild,
    id: Option<ProcessId>,
    past: Past,
    policy: SpawnPolicy,
    why: &mut Diagnosis,
) -> Torn {
    let remains = tear_down_leaving(&child, id, past, policy.teardown_warn_after, why);
    Torn {
        fate: remains.fate,
        unreaped: None,
        cleanup: None,
    }
}

/// Kills and reaps `child`, which a failed spawn holds and whose answer has no place for it: one it
/// cannot end is left, not handed back. Says the teardown as the failed spawn's one warn, `why`
/// leading it, and answers what is left. `past`, `warn_after`: see [`tear_down_expecting`].
pub(crate) fn tear_down_leaving(
    child: &OwnedChild,
    id: Option<ProcessId>,
    past: Past,
    warn_after: Option<Duration>,
    why: &mut Diagnosis,
) -> Remains {
    let kill = Kill {
        disposition: Disposition::Leave,
        tree: None,
    };
    say_teardown_of_failed_spawn(tear_down_expecting(child, id, kill, past, warn_after), why)
}

/// What a Linux spawn knows of its pidfd when it ends a child that never ran: with the identity read,
/// nothing happened to it ([`Past::Unexecuted`]); without it, a look on the pidfd failed, and may have
/// left the wait on it failing too ([`Past::WaitMayFail`]).
#[cfg(target_os = "linux")]
pub(crate) fn unexecuted_past(id: Option<ProcessId>) -> Past {
    if id.is_some() {
        Past::Unexecuted
    } else {
        Past::WaitMayFail
    }
}

/// The failure of a spawn whose attach failed as `failure` says, after `child` was torn down: as
/// [`tear_down_unexecuted`] ends it (with `unexecuted`) when the attach proved the program never ran
/// ([`failed_attach`] then answers not started), and as `otherwise` ends it for any other failure.
/// `otherwise` returns what the teardown did beyond its fate (the `detail` of
/// [`Error::MayHaveStarted`](crate::Error::MayHaveStarted)) and the child's [`Torn`]; it is each
/// platform's own teardown of a child that may have run.
pub(crate) fn tear_down_after_failed_attach(
    child: OwnedChild,
    id: Option<ProcessId>,
    failure: crate::containment::dispatch::AttachFailure,
    unexecuted: Past,
    policy: SpawnPolicy,
    why: &mut Diagnosis,
    otherwise: impl FnOnce(OwnedChild, &mut Diagnosis) -> (Option<String>, Torn),
) -> super::SpawnFailure {
    let crate::containment::dispatch::AttachFailure {
        cause,
        cleanup,
        not_started,
        // Held across the teardown: the root stays suspended until it is ended.
        #[cfg(windows)]
            proven: _proven,
    } = failure;
    let (detail, torn) = if not_started {
        (None, tear_down_unexecuted(child, id, unexecuted, policy, why))
    } else {
        otherwise(child, why)
    };
    super::failure::failed_attach(not_started, cause, detail, cleanup, torn)
}

/// [`tear_down_after_failed_attach`] for a Windows spawn (std or raw): a suspended root that never ran
/// is ended with a handle nothing happened to ([`Past::Unexecuted`]); any other child is killed over
/// its handle and handed back if it cannot be ([`tear_down_failed_spawn`]).
#[cfg(windows)]
pub(crate) fn tear_down_after_failed_windows_attach(
    child: OwnedChild,
    id: Option<ProcessId>,
    failure: crate::containment::dispatch::AttachFailure,
    policy: SpawnPolicy,
    why: &mut Diagnosis,
) -> super::SpawnFailure {
    tear_down_after_failed_attach(child, id, failure, Past::Unexecuted, policy, why, |child, why| {
        let torn = tear_down_failed_spawn(child, id, Past::Clean, Disposition::HandBack, policy, why);
        (None, torn)
    })
}

/// Says `torn` as the failed spawn's one warn, and logs at warn ([`warn_of_teardown_failures`]) each
/// failure that warn does not hold.
pub(super) fn say_teardown_of_failed_spawn(torn: HandleTeardown, why: &mut super::Diagnosis) -> Remains {
    let held = torn.outcome.said_in_the_one_warn(why);
    let remains = torn.say_as_failed_spawn(why);
    warn_of_teardown_failures(&remains, held);
    remains
}

/// Logs at warn each failure of a failed spawn's teardown that the event's one warn
/// ([`say_as_failed_spawn`](HandleTeardown::say_as_failed_spawn)) does not hold. That warn holds them
/// all when it was said (`held`: its clause is at warn, or the spawn's diagnosis was owed and folded
/// into it); a clause below warn (a refused kill whose look found the child gone) is said at its
/// level only.
pub(super) fn warn_of_teardown_failures(remains: &Remains, held: bool) {
    if held {
        return;
    }
    for failure in remains.failures.iter().flat_map(|failures| failures.iter()) {
        log::warn!(
            "the failed spawn's teardown of its child failed: {report}",
            report = crate::error::Report(failure.as_ref())
        );
    }
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
) -> Torn {
    tear_down_failed_spawn_between(child, id, past, disposition, policy, why, |_, _, _| false)
}

/// [`tear_down_failed_spawn`], running `between(child, kill, why)` as [`OwnedChild::tear_down_between`]
/// does; `between` may add to `why`, which leads the one warn.
pub(crate) fn tear_down_failed_spawn_between(
    child: OwnedChild,
    id: Option<ProcessId>,
    past: Past,
    disposition: Disposition,
    policy: SpawnPolicy,
    why: &mut Diagnosis,
    between: impl FnOnce(&OwnedChild, RootKill, &mut Diagnosis) -> bool,
) -> Torn {
    let kill = Kill {
        disposition,
        tree: None,
    };
    let outcome = child.tear_down_between(id, kill, policy.teardown_warn_after, |kill| {
        between(&child, kill, &mut *why)
    });
    let torn = HandleTeardown::new(outcome, Expect::of(&child, past));
    say_failed_spawn(child, id, torn, disposition, policy.unreaped_drop, why)
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
#[cfg(unix)]
pub(crate) fn look_at_failed_spawn_front(
    child: &OwnedChild,
    id: Option<ProcessId>,
    reach: Result<Option<&dyn Reach>, crate::error::Error>,
    disposition: Disposition,
    warn_after: Option<Duration>,
) -> (FrontFate, TeardownOutcome) {
    let look = child.look_at_front(id, reach, warn_after);
    let front_fate = FrontFate::of_look(&look.look);
    let torn = crate::child::word_front(child.pid(), &"its spawn failed", disposition, look);
    (front_fate, torn)
}

/// Says `torn` as the failed spawn's one warn; hands `child` back per `disposition` if it is
/// uncollected, to do `unreaped_drop` when dropped.
fn say_failed_spawn(
    child: OwnedChild,
    id: Option<ProcessId>,
    torn: HandleTeardown,
    disposition: Disposition,
    unreaped_drop: DropKind,
    why: &mut Diagnosis,
) -> Torn {
    let remains = torn.say_as_failed_spawn(why);
    let unreaped = disposition
        .hands_back(&remains)
        .then(|| Unreaped::new(child, id, unreaped_drop));
    Torn {
        fate: remains.fate,
        unreaped,
        cleanup: remains.failures,
    }
}
