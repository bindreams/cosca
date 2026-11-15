//! macOS: the teardown of a child whose unique-id report came late (see
//! [`Report::Late`](super::unique_report)): it was spawned while at least two of this process's
//! descriptors 0 to 2 were closed, so its `exec` cannot be confirmed and the program may have started.
//! It is never adopted, but its unique id is known, so it gets a box of its own and goes through the
//! same teardown every other failed spawn does ([`held_teardown`]), with its tree swept around the
//! root's kill:
//!
//! 1. the tree, while the root is alive, so a walk from it still finds its descendants (the walk's
//!    own kill reaches the root first);
//! 2. the root, so it can add no member after its kill lands (a `setsid`, an `exec`, a fork);
//! 3. the tree again, for what the root added before it died (a child held between its report and a
//!    `setsid` escapes the first `killpg`). A skip of the root's number is read as [`Sweep`] says; a
//!    `TreeWalk` tree skips this step when the root is an unreaped zombie, since its kill reparented the
//!    children and a walk from it finds none;
//! 4. the root's reap.
//!
//! The root's waits are unbounded. The wait for the zombie, with the spawn's threshold, logs one
//! `warn` naming `pid` once it passes that long, and goes on waiting; the threshold is a message, never
//! a decision. It hands over to the reap as [`OwnedChild::tear_down_between`] says.

use std::sync::Arc;
use std::time::Duration;

use super::held_teardown::{self, HeldTeardown};
use super::{attach_or_fault, resolve_identity, Diagnosis, SpawnFailure};
use crate::child::drop_teardown::Torn;
use crate::child::owned::teardown::{Disposition, Past, RootKill};
use crate::child::owned::OwnedChild;
use crate::child::spawn::policy::SpawnPolicy;
use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::error::{Error, Failures};
use crate::identity::{ProcessId, Resolved};
use crate::os_process::child::PeekOutcome;
use crate::os_process::macos::child::MacosChild;

/// What a late child's diagnosis says of why it is torn down at all.
pub(super) const LATE: &str =
    "was spawned while at least two of this process's descriptors 0 to 2 were closed, so its \
                               exec cannot be confirmed and the program may have started; it was not adopted";

/// The note of a sweep after the root's kill that the mechanism skipped, because it could not show the
/// root ours when it looked.
const NOT_SWEPT_AGAIN: &str = "it was not shown an unreaped zombie, so its tree was not killed again by its pid: what \
                               it started after the first kill of its tree may be left running";

/// Tears down the child `child`, whose unique id `unique` arrived after its spawn returned, and
/// answers the spawn's failure `error`. A front is sent nothing: it is looked at, and handed back if
/// it still runs ([`held_teardown::tear_down_held`]). Any other child is killed and reaped through its
/// box, its tree swept through `prepared` as the module doc says; a child it cannot end is handed
/// back in the failure. A child whose box cannot be built is the spawn's stated limit
/// ([`leave_unwatched_child`](super::leave_unwatched_child)), its marker's holders swept alone.
pub(super) fn abandon_late_child(
    child: std::process::Child,
    unique: u64,
    error: Error,
    front: Option<crate::elevation::front::Front>,
    prepared: crate::containment::Prepared,
    policy: SpawnPolicy,
    kernel: crate::identity::SpawnKernel,
) -> SpawnFailure {
    let pid = child.id();
    #[cfg(test)]
    super::fault::capture(ProcessId::of(pid));
    let owned = match MacosChild::new(std::sync::Arc::clone(&kernel), pid, unique) {
        Ok(os) => {
            drop(child);
            OwnedChild::new(Box::new(os))
        }
        Err(refusal) => {
            return super::leave_unwatched_child(
                &*kernel,
                super::UnwatchedChild { child, pid, unique },
                super::UnwatchedReport {
                    front,
                    prepared,
                    refusal,
                    late: Some(error),
                },
            )
        }
    };
    abandon_boxed_late_child(owned, pid, error, front, prepared, policy)
}

/// [`abandon_late_child`] once the child has its box `owned`.
fn abandon_boxed_late_child(
    owned: OwnedChild,
    pid: u32,
    error: Error,
    front: Option<crate::elevation::front::Front>,
    prepared: crate::containment::Prepared,
    policy: SpawnPolicy,
) -> SpawnFailure {
    if front.is_some() {
        drop(prepared);
        let mut why = Diagnosis::of(format!("child {pid} {LATE}"));
        let (detail, torn) = held_teardown::tear_down_held(
            owned,
            HeldTeardown {
                front,
                id: None,
                reach: None,
                disposition: Disposition::HandBack,
                policy,
            },
            &mut why,
        );
        let Torn {
            fate,
            unreaped,
            cleanup,
        } = torn;
        return SpawnFailure::started(error, fate, unreaped)
            .with_detail(detail)
            .with_cleanup(cleanup);
    }
    #[cfg(test)]
    super::fault::run_at(super::fault::SpawnPoint::BeforeLateTeardown, pid);
    let sweeps = LateSweeps::attach(&owned, pid, prepared);
    sweep_and_tear_down(owned, pid, sweeps, error, policy)
}

/// The tree `sweeps` swept around the root's kill, and the root's teardown through its box `owned`,
/// as the module doc says; the failure answers the spawn's `error`.
fn sweep_and_tear_down(
    owned: OwnedChild,
    pid: u32,
    mut sweeps: LateSweeps,
    error: Error,
    policy: SpawnPolicy,
) -> SpawnFailure {
    sweeps.kill(&owned, pid, Sweep::Before);
    #[cfg(test)]
    super::fault::run_at(super::fault::SpawnPoint::BeforeLateRootKill, pid);
    let mut why = Diagnosis::of(format!("child {pid} {LATE}"));
    let id = sweeps.id;
    let torn = held_teardown::tear_down_failed_spawn_between(
        owned,
        id,
        Past::WaitMayFail,
        Disposition::HandBack,
        policy,
        &mut why,
        |owned, kill, why| {
            let sent = kill == RootKill::Sent;
            // A fixture that only the kill would end is released here when the kill was sent.
            #[cfg(test)]
            if sent {
                super::fault::run_between_kill_and_wait();
            }
            let waited = if sent {
                wait_until_zombie(owned, pid, policy.teardown_warn_after)
            } else {
                ZombieWait::default()
            };
            // What happened, in the order it happened: the notes of the attach, the wait's failure,
            // then the sweep after it.
            sweeps.say(why);
            if let Some(failed) = waited.failed {
                why.add(format!(
                    "the wait for its killed root to exit failed: {}",
                    crate::error::Report(&failed)
                ));
                sweeps
                    .failures
                    .push(Arc::new(failed.with_note("waiting for the killed root")));
            }
            // A walk from the zombie root finds nothing: the kill reparented its children.
            if !(waited.zombie && sweeps.is_walk()) {
                // A skip is moot only once the kill has landed: after a refused kill, or none sent, the
                // root still has what its number names.
                sweeps.kill(owned, pid, if sent { Sweep::After } else { Sweep::Before });
            }
            sweeps.say(why);
            // The root is ended unless its kill was refused.
            if let Some(note) = sweeps.failure_note(kill != RootKill::Refused) {
                why.add(note);
            }
            waited.warned || waited.zombie
        },
    );
    let Torn {
        fate,
        unreaped,
        cleanup,
    } = torn;
    // The tree's sweeps ran around the root's kill, and their failures come first, as the tree kill's
    // does everywhere.
    SpawnFailure::started(error, fate, unreaped)
        .with_cleanup(Failures::collect(std::mem::take(&mut sweeps.failures)))
        .with_cleanup(cleanup)
}

/// Waits for the killed root `pid` to be an exited child, as the handle's own look says it
/// ([`OwnedChild::exited_by`]): it reaps nothing, so the root stays a zombie whose pid still names its
/// group. With `warn_after`, the wait that passes it logs one `warn` and goes on, unbounded.
fn wait_until_zombie(owned: &OwnedChild, pid: u32, warn_after: Option<Duration>) -> ZombieWait {
    use crate::wait::teardown_warn::{wait_warning, Due};

    let mut warned = false;
    let exited = wait_warning(
        None,
        Due::in_(warn_after),
        // Anything it cannot read is left to the unbounded wait.
        |bounded, until| {
            let seen = owned.exited_by(Some(until));
            let slow = matches!(seen, Ok(false));
            *bounded = Some(seen);
            !slow
        },
        |after| {
            warned = true;
            super::warn_still_waiting(Some(pid), after);
        },
        // The bounded look that saw the exit is the answer: it is not asked again, on a second kqueue.
        |bounded| match bounded {
            Some(Ok(true)) => Ok(true),
            _ => owned.exited_by(None),
        },
    );
    let (zombie, failed) = match exited {
        Ok(exited) => (exited && matches!(owned.peek(), Ok(PeekOutcome::Exit(_))), None),
        Err(failed) => (false, Some(failed)),
    };
    ZombieWait { zombie, warned, failed }
}

#[derive(Default)]
struct ZombieWait {
    /// The root is shown an unreaped zombie of ours: a child someone else reaped, or one a tracer's
    /// exit another process holds, is not.
    zombie: bool,
    /// The wait passed its threshold and said so.
    warned: bool,
    /// The wait failed.
    failed: Option<Error>,
}

/// How [`LateSweeps::kill`] reads a skip of the root's number.
#[derive(Debug, Clone, Copy)]
enum Sweep {
    /// Before the root's kill landed (the first sweep, while the root is alive and its identity is
    /// fresh from [`LateSweeps::attach`], or one after a kill that was refused or not sent): a skip is a
    /// failure of the tree's kill.
    Before,
    /// After the root's kill landed: a skip for a reason a kill does not outlive
    /// ([`Skip::moot_after_kill`](crate::containment::Skip::moot_after_kill)) says only that what the
    /// root started since may be left.
    After,
}

/// `prepared`'s marker, when the child is a contained root with one, as a tree that names its members
/// by the marker pipe alone: its holders, not its process group nor the processes its root's pid
/// parents. The tree of a root that is not shown ours, or has no box.
pub(super) fn marker_holders(prepared: crate::containment::Prepared) -> Option<crate::containment::Tree> {
    if prepared.mode.is_none() || !prepared.is_root {
        return None;
    }
    prepared.marker.map(|marker| {
        crate::containment::Tree::contained(crate::containment::Mechanism::Marker(
            crate::containment::fdmarker::Marker::without_root(marker),
        ))
    })
}

/// The tree of a child whose report came late, and the notes its sweeps owe the teardown's `warn`.
/// The root it is swept for is the child's box: the sweeps read and send through
/// [`OwnedChild::hold`], so a send by the root's number is checked against the box's own look right
/// before it, and a root that is not shown ours (reaped elsewhere, held by launchd) is skipped, its
/// marker's holders alone swept.
struct LateSweeps {
    /// The containment, attached to the root, whose identity was read and shown ours; or, when the
    /// root is not shown ours, only its marker without the root, whose holders the kernel names by
    /// the marker pipe. `None`: no tree of its own (uncontained, or a nested member of another
    /// root's).
    tree: Option<crate::containment::Tree>,
    id: Option<ProcessId>,
    /// What each sweep left, in the order they ran. Judged together once the root's kill is known
    /// ([`failure_note`](Self::failure_note)).
    sweeps: Vec<Result<(), Unkilled>>,
    notes: Vec<String>,
    /// The failures behind `notes` that are errors, for the spawn's `cleanup`: the sweep that failed
    /// first, and the holders of a marker that were not all killed.
    failures: Vec<Arc<Error>>,
}

impl LateSweeps {
    /// Reads the identity of `pid` through `owned` and attaches `prepared` to it. A root that is gone
    /// or not shown ours keeps only its marker's holders, when it has a marker. A foreign reap after
    /// the check is the gap `Child::drop`'s tree kill accepts too.
    fn attach(owned: &OwnedChild, pid: u32, prepared: crate::containment::Prepared) -> LateSweeps {
        let mut late = LateSweeps {
            tree: None,
            id: None,
            sweeps: Vec::new(),
            notes: Vec::new(),
            failures: Vec::new(),
        };
        if prepared.mode.is_none() || !prepared.is_root {
            return late;
        }
        let (resolved, _, mut why) = resolve_identity(owned.kernel(), pid, owned);
        let unshown = match resolved {
            Resolved::Found(id) => {
                late.id = Some(id);
                match attach_or_fault(pid, Ok(id), prepared) {
                    Ok(attachment) => late.tree = Some(attachment.tree),
                    Err(failure) => {
                        super::assert_attach_cannot_fail(&failure.cause);
                        late.notes.push(format!(
                            "its tree was not killed: {}",
                            crate::error::Report(&failure.cause)
                        ));
                    }
                }
                return late;
            }
            Resolved::Gone => "the child is gone, or is not ours",
            Resolved::Unknown => "the child's identity could not be read",
        };
        match marker_holders(prepared) {
            Some(tree) => {
                late.notes.push(why.fold(format!(
                    "{unshown}, so its tree is reached only through its marker's holders, not its process group \
                     or the processes its pid parents"
                )));
                late.tree = Some(tree);
            }
            None => late.notes.push(why.fold(format!("its tree was not killed: {unshown}"))),
        }
        late
    }

    /// Moves the notes the sweeps owe so far into the warn's `why`.
    fn say(&mut self, why: &mut Diagnosis) {
        for note in self.notes.drain(..) {
            why.add(note);
        }
    }

    /// Whether the tree is a `TreeWalk`'s, found by a walk from its root.
    fn is_walk(&self) -> bool {
        matches!(&self.tree, Some(tree) if tree.containment() == crate::containment::Containment::TreeWalk)
    }

    /// Runs `sweep` over the tree, over the root `pid` of `owned`.
    fn kill(&mut self, owned: &OwnedChild, pid: u32, sweep: Sweep) {
        let Some(tree) = &self.tree else {
            return;
        };
        // A late child's tree is swept alone: nothing here waits for what the sweep killed.
        let held = owned.hold(pid);
        let outcome = tree.send_kill(Some(&held));
        match outcome {
            // The root's kill landed and the reason for the skip is one a kill does not outlive: the
            // tree's first sweep stands, and only the holders' failure is an error of this one.
            TreeKillOutcome::Skipped(skip) if matches!(sweep, Sweep::After) && skip.moot_after_kill() => {
                if matches!(skip.holders, Some(Err(_))) {
                    let held = skip.sweep_error();
                    self.notes.push(format!(
                        "its marker's holders were not all killed after its kill: {}",
                        crate::error::Report(&held)
                    ));
                    self.failures.push(Arc::new(held));
                }
                self.notes.push(NOT_SWEPT_AGAIN.to_owned());
            }
            // The sweep's own error is the holders' when theirs failed, else says what was skipped.
            TreeKillOutcome::Skipped(skip) => self.sweeps.push(Err(Unkilled::from(skip.sweep_error()))),
            other => self.sweeps.push(other.into_result()),
        }
    }

    /// The `warn`'s note for the sweeps that failed, once the root's kill is known: `root_ended` says
    /// whether it ended the root, which settles a walk that left only the root
    /// ([`Unkilled::unsettled`], as [`Tree::settle`](crate::containment::Tree::settle) does). The
    /// first failure stands: a later sweep is not shown to reach what it missed. That failure is also
    /// kept, as the error it is, in `failures`.
    fn failure_note(&mut self, root_ended: bool) -> Option<String> {
        let mut failed = None;
        let mut succeeded_after = false;
        for sweep in self.sweeps.drain(..) {
            match (sweep.or_else(|left| left.unsettled(root_ended)), &failed) {
                (Err(left), None) => {
                    failed = Some(crate::error::Report(&left).to_string());
                    self.failures.insert(0, Arc::new(left));
                }
                (Err(_), Some(_)) => succeeded_after = false,
                (Ok(()), failed) => succeeded_after = failed.is_some(),
            }
        }
        let failed = failed?;
        Some(if succeeded_after {
            format!(
                "its tree may not be fully killed: a kill of it failed ({failed}), and the later one that succeeded \
                 cannot be shown to reach what that one missed"
            )
        } else {
            format!("its tree was not fully killed: {failed}")
        })
    }
}

#[cfg(test)]
#[path = "late_child_tests.rs"]
mod late_child_tests;
