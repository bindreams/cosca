//! The spawn: resolve the crate's `Stdio` model, wire the program and arguments, and adopt the child into
//! an `OwnedChild`. On Linux the child is made by the fork-exec core (`child::spawn::fork_exec`, through
//! `fork_spawn`); on macOS it is a `std::process::Command`, and on Windows the raw backend
//! (`windows_raw`) makes it.

use std::collections::BTreeMap;
#[cfg(not(target_os = "linux"))]
use std::process::Stdio as StdStdio;
#[cfg(unix)]
use std::sync::Arc;

use crate::child::drop_teardown::Torn;
#[cfg(unix)]
use crate::child::lifecycle::{wait_to_exit, Settlement};
#[cfg(unix)]
use crate::child::owned::teardown::{Disposition, Remains, TeardownOutcome};
#[cfg(unix)]
use crate::child::owned::ChildWaitOutcome;
use crate::child::owned::OwnedChild;
#[cfg(unix)]
pub(crate) use crate::child::spawn::failure::failed_after_the_spawn;
pub(crate) use crate::child::spawn::failure::{after_the_spawn, failed_after_teardown, Classify, SpawnFailure};
use crate::child::spawn::policy::SpawnPolicy;
use crate::child::Child;
#[cfg(not(target_os = "linux"))]
use crate::command::EnvOp;
use crate::command::{Command, CommandInput};
#[cfg(unix)]
use crate::error::ChildFate;
use crate::error::Error;
#[cfg(unix)]
use crate::error::Failures;
use crate::identity::ProcessId;
use crate::pipe::ParentEnd;
use crate::stdio::{Direction, Fd, ResolvedStdio};

// A child-side descriptor handed to std via `Stdio::from`.
#[cfg(unix)]
pub(crate) type ChildEnd = std::os::unix::io::OwnedFd;
#[cfg(target_os = "linux")]
use crate::child::owned::teardown::Reach;
#[cfg(windows)]
pub(crate) use windows_child_end::ChildEnd;

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, SpawnFailure> {
    spawn_with(cmd, crate::identity::HostKernel)
}

/// [`spawn`] asking `kernel`: the one body of the spawn, whatever the kernel. `kernel` is erased
/// once, here, into a [`SpawnKernel`](crate::identity::SpawnKernel); every OS box the spawn builds
/// (the child's, the cgroup leaf's, the placement probe's) owns it or a clone of it, and the spawn's
/// own reads ask it.
pub(crate) fn spawn_with<K: crate::identity::Kernel + Send + 'static>(
    cmd: &mut Command,
    kernel: K,
) -> Result<Child, SpawnFailure> {
    spawn_uncommitted(cmd, SpawnPolicy::SYNC, kernel)?.commit_kill_on_drop()
}

/// [`spawn_with`] up to the handle it returns, whose containment resource still tears the tree down
/// on drop whatever `kill_on_drop` says. `policy` is every teardown's of the child it makes: a
/// failed spawn's, the handle's own, its cgroup leaf's drain, and the `Unreaped` they hand back.
pub(crate) fn spawn_uncommitted<K: crate::identity::Kernel + Send + 'static>(
    cmd: &mut Command,
    policy: SpawnPolicy,
    kernel: K,
) -> Result<Child, SpawnFailure> {
    spawn_over(cmd, policy, crate::identity::spawn_kernel(kernel))
}

/// [`spawn_uncommitted`] over the erased kernel.
fn spawn_over(
    cmd: &mut Command,
    policy: SpawnPolicy,
    kernel: crate::identity::SpawnKernel,
) -> Result<Child, SpawnFailure> {
    let kill_on_drop = cmd.kill_on_drop_flag();
    // Elevation runs BEFORE spawn_unelevated's std::mem::take(cmd.fds_mut()), so the
    // effect layers see/modify cmd.fds() while it is still populated (the honest Windows
    // reject gate and the POSIX derived-command build both depend on it).
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            return crate::elevation::windows::spawn_elevated(cmd, kill_on_drop, policy, kernel);
        }
        #[cfg(unix)]
        {
            let crate::elevation::posix::PosixRewrite {
                mut derived,
                password_write,
                backend_path,
            } = crate::elevation::posix::rewrite(cmd).not_started()?;
            // A failure from here is marked as a front's by `spawn_unelevated`, from the report the
            // derived command carries, and by `finish_elevated`, from the report the child carries.
            // The derived program IS the backend; remap an exec failure to
            // BackendUnavailable ONLY when the backend path is the culprit (a bad cwd
            // yields the same kind and stays a plain Io). An already-elevated derived
            // (sanitized original) has no backend path, so it is never remapped.
            let r = spawn_unelevated(&mut derived, kill_on_drop, policy, kernel);
            let child = match backend_path.as_deref() {
                Some(bp) => r.map_err(|f| f.map(|e| crate::elevation::remap_derived_spawn_error(e, bp)))?,
                None => r?,
            };
            let written = password_write.map_or(Ok(()), |pw| pw.write_after_spawn());
            // The child already carries the report, so a failed password write's cleanup kill()
            // maps EPERM to `Unkillable`.
            return finish_elevated(child, written);
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err(SpawnFailure::NotStarted(Error::Unsupported {
                op: "elevation".into(),
                platform: std::env::consts::OS,
                detail: "no elevation backend on this platform".into(),
                source: None,
            }));
        }
    }
    spawn_unelevated(cmd, kill_on_drop, policy, kernel)
}

/// Finish a POSIX elevated spawn whose deferred password write returned `written`.
///
/// On a failed write, do NOT orphan the running elevated child: kill its tree through its
/// containment when it has one, so a descendant forked before the failure dies too, then kill
/// and reap the root by its own handle, folding both outcomes into the error.
///
/// The reap follows the ROOT's kill alone. A tree kill can fail (a setuid member refusing the
/// signal) while the root dies, and a killed root must be waited for, or it stays a zombie. A
/// failed root kill (e.g. `Unkillable`) cannot be waited for, so it gets a non-blocking
/// `try_wait`. A root that look finds running, or cannot look at, is handed back to the caller in
/// the error (an `Unreaped`), and the note says so. A root already reaped (`Sent::Gone`) is
/// neither waited on nor `try_wait`ed, and is reported as "could not be terminated (it was already
/// reaped)".
///
/// A reaped root's number may name another process by now, so the tree kill is skipped when it
/// would name the tree by that number (a process group, a ppid walk), and the note says so. On Linux
/// 6.9+ the root's pidfd decides a process group instead: it is killed while it has a member. The
/// decision is one look at the root; each send by the group's number then checks the root again, as
/// for [`Child::kill_tree`].
///
/// A live front outside a cgroup (see [`Child::kill`]) is signalled by neither kill: the root's
/// kill is the typed `Unkillable`, and the note says so. A front that had already exited is reaped,
/// and the note says it had exited. A front in a cgroup is ended by the tree's cgroup kill alone,
/// read after it. The front's gate is decided once, before both kills.
///
/// The backend has run by now, so the program may have started: a backend that needed no password
/// runs it without reading one.
///
/// A root whose handle could not say whether it is reaped (`RootState::Unknown`) is killed through
/// its handle like any other, and the tree kills named by its number are skipped, as for a reaped
/// root. A root this process does not pin (`RootState::Unpinned`, macOS) is left alone: neither
/// signalled nor waited on, and the error says so; its fate is `Gone`. The event
/// warns once: the unsettled root, a failed reap and any other leftover share one record, labelled
/// `finish_elevated`.
///
/// A root the cleanup did not show collected ([`TeardownOutcome::uncollected`]) is handed back in
/// the error (an `Unreaped`) and the handle is disarmed, so its drop, which would make a tree kill
/// the cleanup's failed one left undone, does not run. After a tree kill that did not settle the
/// tree (it failed, or was skipped) the cleanup makes that drop's tree kill itself, early, and the
/// warn and the error say how it went (a skipped kill is not one that worked); principle 3 in
/// `docs/principles.md` says why that is the one early second write. The handle is also disarmed
/// once the tree is settled: killed, not for the cleanup to kill, or deliberately left alone (a
/// reaped or unpinned root). A tree that could not be vouched for (a walk saw the root running, and
/// its end came after) is no failed kill: no tree kill is made early for it, the cleanup's one
/// report says so, and the handle is disarmed. An early tree kill that itself ends unvouched is
/// reported the same way, after the first failure. Only a failed tree kill with a root not handed
/// back leaves the handle armed; its drop then makes its tree kill and does not warn of the event a
/// second time.
#[cfg(unix)]
pub(crate) fn finish_elevated(mut child: Child, written: Result<(), Error>) -> Result<Child, SpawnFailure> {
    use crate::containment::dispatch::{SettleOutcome, TreeKillOutcome};

    let Err(write_err) = written else {
        return Ok(child);
    };
    // A live front outside a cgroup is not signalled, by its group or otherwise: the root's kill
    // below then says why.
    let gate = child.kill_gate();
    // One look, shared by both tree kills.
    let view = crate::containment::DropView::read(
        crate::containment::dispatch::TeardownCaller::FinishElevated,
        child.pid(),
        child.id,
        &child.proc,
        &child.tree,
    );
    let mut report = crate::child::drop_report::DropReport::new(&view);
    let mut skipped = None;
    let front_closed = matches!(gate, crate::elevation::front::Gate::Closed(_));
    let kill_tree = || {
        let root_handle = child.proc.hold(child.pid());
        // The cleanup sends only: its waits are the root's and the leaf's own.
        let kill = {
            let seen = crate::containment::Seen::new(&root_handle, view.look());
            child.tree.send_kill(Some(&seen))
        };
        kill.log_skip(&view);
        kill
    };
    let tree = (child.containment().can_teardown() && !front_closed).then(|| {
        let kill = kill_tree();
        skipped = kill.skip_note(&view);
        kill
    });
    let tree_failure = tree.as_ref().and_then(TreeKillOutcome::incomplete);
    let exited_front = matches!(gate, crate::elevation::front::Gate::Exited);
    let pid = child.pid();
    let (root_note, torn) = if view.unpinned_root() {
        // Nothing was signalled.
        let fate = crate::os_process::child::Foreign::Gone.fate(false);
        (
            format!(
                "the elevated child was left alone, neither signalled nor waited on: {}",
                view.why_number_untrusted()
            ),
            Remains::collected(fate),
        )
    } else {
        let root = match gate {
            // Not asked again after the kill: a killed front can read as neither exited nor in its
            // cgroup, between leaving the cgroup's member list and becoming a zombie. The kill's own
            // outcome says it landed; the handle's state is settled by `settle`, below.
            crate::elevation::front::Gate::CgroupOnly(front)
                if tree.as_ref().is_some_and(TreeKillOutcome::completed) =>
            {
                child
                    .cgroup_kill_reached(front)
                    .map(|()| crate::signal::Sent::Delivered)
            }
            // No kill reached the cgroup: refused as `kill` refuses, naming why.
            // The tree's failure, if there is one, is the cleanup's entry before this refusal.
            crate::elevation::front::Gate::CgroupOnly(front) => {
                Err(crate::elevation::front::cgroup_not_killed(front, child.pid()))
            }
            crate::elevation::front::Gate::Closed(unkillable) => Err(unkillable),
            gate => child.kill_sent_gated(gate),
        };
        match root {
            Ok(crate::signal::Sent::Gone) if exited_front => (
                "the elevated child had already exited, and was reaped by someone else".to_string(),
                Remains::collected(ChildFate::Gone),
            ),
            Ok(crate::signal::Sent::Gone) => (
                "the elevated child could not be terminated (it was already reaped)".to_string(),
                Remains::collected(ChildFate::Gone),
            ),
            // A sync child's kill always verifies: the pidfd or the handle names it, and on macOS the
            // unique id every production spawn adopts is held (`MacosChild::new` takes it).
            // Were it ever not, the child may still be running.
            Ok(crate::signal::Sent::Unverified) => {
                debug_assert!(false, "a sync child's kill always verifies its target");
                let torn = TeardownOutcome::left_uncollected(
                    ChildFate::Running { id: child.id() },
                    format!(
                        "the elevated child pid {pid} could not be terminated (it could not be verified, and may \
                         still be running){}",
                        Disposition::HandBack.suffix(true)
                    ),
                );
                (
                    "the elevated child could not be terminated (it could not be verified, and may still be running)"
                        .to_string(),
                    report.fold_clause(torn),
                )
            }
            Ok(crate::signal::Sent::Delivered) => {
                #[cfg(test)]
                fault::run_between_kill_and_wait();
                let settlement = Settlement::new(wait_killed_elevated(&child), true);
                #[cfg(test)]
                if let Some(status) = settlement.status() {
                    fault::record_teardown_reap(pid, status);
                }
                let (note, torn) = root_after_a_delivered_kill(pid, child.id(), exited_front, &settlement);
                (note, report.fold_clause(torn))
            }
            Err(e) => {
                #[cfg(test)]
                fault::run_between_kill_and_wait();
                // The refusal is the teardown's failure (`torn.failures`), not the note's words.
                let note = "the elevated child could not be terminated".to_owned();
                // The non-blocking look reaps a child that has exited by now.
                let looked = child.proc.look_after_refused_kill(child.id(), e, Disposition::HandBack);
                (
                    root_after_a_refused_kill(note, looked.refused_look()),
                    report.fold_clause(looked),
                )
            }
        }
    };
    // A root not shown collected is the caller's: it is disarmed, and handed back in the error.
    let hands_back = Disposition::HandBack.hands_back(&torn);
    let fate = torn.fate;
    // What failed in the root's teardown: the refused kill, the failed wait.
    let root_failures = torn.failures;
    // After the root's kill, which settles a walk that left only the root.
    let tree = tree.map(|kill| child.tree.settle(kill, fate.not_running()).answer.map_err(Arc::new));
    // The tree is settled when no kill of it is left to try, or it was deliberately left alone because
    // the root is reaped or unpinned.
    let tree_settled = !tree_needs_another_kill(&tree) || (skipped.is_some() && view.leaves_root_alone());
    let unvouched = matches!(tree, Some(Ok(SettleOutcome::Unvouched { .. })));
    // An unvouched tree disarms the handle on the strength of the root's end (or of its being the
    // caller's): nothing is left for the drop to kill.
    debug_assert!(
        !unvouched || hands_back || fate.not_running(),
        "an unvouched tree leaves the handle disarmed only over a root that ended or went to the caller: {fate:?}"
    );
    let subject = child.tree.teardown_subject();
    // What failed in the tree's teardown, as the error's cleanup: the notes say what was done.
    let mut tree_failures: Vec<Arc<Error>> = tree
        .iter()
        .filter_map(|answer| answer.as_ref().err().cloned())
        .collect();
    // The failure of the tree kill made early, after the root's teardown.
    let mut early_failures: Vec<Arc<Error>> = Vec::new();
    let (mut tree_note, tree_warn) = report_tree_teardown(tree, &subject);
    report.tree = tree_warn;
    if let Some(note) = skipped {
        tree_note.push_str(&format!("; its contained tree was not killed: {note}"));
    }
    // A handed-back root takes the drop, which makes the tree kill, with it: that kill is made here,
    // early. The one warn and the error's note say how it went.
    if hands_back && !tree_settled {
        let early = kill_tree();
        // What the early tree kill adds to the first attempt's report, and the outcome that report is
        // built from.
        let more = match child.tree.settle(early, fate.not_running()).answer.map_err(Arc::new) {
            // A skip kills nothing: the notes of the first attempt stand.
            Ok(SettleOutcome::Skipped { .. }) => None,
            Ok(SettleOutcome::Killed) => {
                tree_note.clear();
                // The tree was killed after all: its first failure is not the error's.
                tree_failures.clear();
                report.tree = tree_failure.as_ref().map(|first| {
                    format!(
                        "tree teardown after a failed password write needed the drop's tree kill, made early \
                         ({subject}): the cleanup's kill failed: {first}"
                    )
                });
                None
            }
            // The early tree kill is the cleanup's last word on the tree: unvouched, it is reported
            // as such.
            Ok(outcome @ SettleOutcome::Unvouched { kind }) => {
                let added = format!("; on the drop's tree kill, made early, {}", kind.unvouched_text());
                Some((added.clone(), added, Ok(outcome)))
            }
            Err(again) => {
                let added_warned = format!(
                    "; the drop's tree kill, made early, failed too ({})",
                    crate::error::Report(&*again)
                );
                // Its failure is the cleanup's entry after the first's: the note says nothing of it.
                early_failures.push(Arc::clone(&again));
                Some((String::new(), added_warned, Err(again)))
            }
        };
        if let Some((added, added_warned, again)) = more {
            tree_note.push_str(&added);
            match report.tree.as_mut() {
                Some(warn) => warn.push_str(&added_warned),
                None => report.tree = report_tree_teardown(Some(again), &subject).1,
            }
        }
    }
    let warned = report.emit(&[]);
    let root_note = if hands_back {
        format!("{root_note}{}", Disposition::HandBack.suffix(true))
    } else {
        root_note
    };
    if hands_back || tree_settled {
        child.kill_on_drop = false;
    }
    // The drop, armed or not, need not warn of what the cleanup warned of again.
    child.reported = warned;
    let behind_front = child.front().is_some();
    let unreaped = hands_back.then(|| child.into_unreaped());
    // The password write's failure is the cause, with what the cleanup did in the `detail`. What failed
    // in the cleanup is beside it, in the order it happened: the tree's first kill, the root's refused
    // kill or failed wait, then the tree's kill made early.
    let cleanup = Failures::merged(
        Failures::merged(Failures::collect(tree_failures), root_failures),
        Failures::collect(early_failures),
    );
    Err(failed_after_the_spawn(
        write_err,
        Torn {
            fate,
            unreaped,
            cleanup,
        },
        behind_front,
    )
    .with_detail(Some(format!("{root_note}{tree_note}"))))
}

/// What [`finish_elevated`] says of a root its delivered kill reached, once the wait for it ended as
/// `settlement` states: the note for the error, and the outcome, whose `clause` is the cleanup's.
/// `exited_front`: the root had exited before the kill.
#[cfg(unix)]
fn root_after_a_delivered_kill(
    pid: u32,
    id: Option<ProcessId>,
    exited_front: bool,
    settlement: &Settlement,
) -> (String, TeardownOutcome) {
    let subject = if exited_front {
        format!("the elevated child pid {pid} (it had already exited)")
    } else {
        format!("the elevated child pid {pid}")
    };
    // The error says it as the warn does, less where the root goes: its note says that. A root whose
    // status was read has its own phrase.
    let note = if settlement.status().is_some() {
        if exited_front {
            "the elevated child had already exited, and was reaped".to_string()
        } else {
            "the elevated child was terminated".to_string()
        }
    } else {
        settlement.wording(&subject, None, None).text().to_owned()
    };
    let torn = TeardownOutcome::of_settlement(settlement, id, &subject, None, Disposition::HandBack);
    (note, torn)
}

/// What [`finish_elevated`] says of a root whose kill was refused, which `refusal` states, once the
/// one look at it ended as `looked` says (`None`: it did not end). A root the look found exited is said
/// as the look showed it; another answer is worded as [`Settlement::wording`] words it,
/// after the refusal; a root still running is the refusal alone. The note says where the root goes:
/// the clause does not.
#[cfg(unix)]
fn root_after_a_refused_kill(refusal: String, looked: Option<&Settlement>) -> String {
    match looked {
        Some(settlement) if matches!(settlement.fate(None), ChildFate::Reaped) => {
            format!("{refusal}: it has exited, and was reaped")
        }
        Some(settlement) => settlement.wording(&refusal, None, None).text().to_owned(),
        None => refusal,
    }
}

/// The wait for the root after its kill, which a test can force to fail. The forced failure still
/// REAPS first, so the test that asks for it leaks nothing. It warns once past the spawn's
/// threshold ([`SpawnPolicy::teardown_warn_after`]).
#[cfg(unix)]
fn wait_killed_elevated(child: &Child) -> Result<ChildWaitOutcome, Error> {
    let waited = wait_to_exit(
        &child.proc,
        crate::wait::teardown_warn::Due::in_(child.policy.teardown_warn_after),
    );
    #[cfg(test)]
    if let Some(marker) = fault::take_force_reap_failure() {
        return waited.and(Err(Error::Io(std::io::Error::other(marker))));
    }
    waited
}

/// The head of the `warn` line [`report_tree_teardown`] logs.
#[cfg(unix)]
pub(crate) const TREE_TEARDOWN_WARN: &str = "tree teardown after a failed password write failed";

/// The marker of the warning about `leaf_path`'s tree teardown: unique to that leaf, so a twin
/// test running in parallel (same message text) is never miscounted.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn teardown_warn_marker(leaf_path: &std::path::Path) -> String {
    format!("{TREE_TEARDOWN_WARN} (cgroup leaf {})", leaf_path.display())
}

/// Report a failed password write's tree teardown, for both `finish_elevated` variants: the note
/// for the error's `detail`, and the text the cleanup's one `warn` carries (the tree and the root
/// are one event). `subject` names the tree, because not every report carries a kill's error (see
/// `Tree::teardown_subject`).
///
/// `None`: no tree kill was tried, as the containment cannot tear one down. `Some(Ok(Killed))`: the
/// tree was killed. `Some(Ok(Skipped))`: a kill that killed nothing; its skip note says so (the
/// caller's). None of these is reported here. `Some(Ok(Unvouched { kind }))`: reported as `kind` says.
#[cfg(unix)]
pub(crate) fn report_tree_teardown(
    tree: Option<Result<crate::containment::dispatch::SettleOutcome, Arc<Error>>>,
    subject: &dyn std::fmt::Display,
) -> (String, Option<String>) {
    use crate::containment::dispatch::SettleOutcome;

    match tree {
        // The failure is the error's `cleanup`, whose entry names the kill that failed: the note adds
        // nothing, and the warn carries the failure's whole chain.
        Some(Err(e)) => {
            let report = crate::error::Report(&*e).to_string();
            (String::new(), Some(tree_teardown_warn(subject, &report)))
        }
        Some(Ok(SettleOutcome::Unvouched { kind })) => {
            let text = kind.unvouched_text();
            (
                format!("; {text} ({subject})"),
                Some(tree_teardown_warn(subject, &text)),
            )
        }
        None | Some(Ok(SettleOutcome::Killed | SettleOutcome::Skipped { .. })) => (String::new(), None),
    }
}

/// Whether a failed spawn's cleanup, after the tree kill it tried (`None`: none was), has another to
/// try, for both `finish_elevated` variants. Not when the tree was killed, and not when it cannot be
/// vouched for: that is no failed kill, a kill of it again could not change it, and the cleanup says so
/// once. A kill that left members, or was skipped and killed nothing, has another to try.
#[cfg(unix)]
pub(crate) fn tree_needs_another_kill(
    tree: &Option<Result<crate::containment::dispatch::SettleOutcome, Arc<Error>>>,
) -> bool {
    use crate::containment::dispatch::SettleOutcome;

    !matches!(
        tree,
        None | Some(Ok(SettleOutcome::Killed | SettleOutcome::Unvouched { .. }))
    )
}

/// The text of the cleanup's `warn` about the tree's teardown: `said`, about `subject`, under
/// [`TREE_TEARDOWN_WARN`].
#[cfg(unix)]
pub(crate) fn tree_teardown_warn(subject: &dyn std::fmt::Display, said: &dyn std::fmt::Display) -> String {
    format!("{TREE_TEARDOWN_WARN} ({subject}): {said}")
}

/// The one authority for Windows backend routing: does `cmd` go to the raw `CreateProcessW`
/// backend rather than std? Both routers read this — the sync one below and the async mirror in
/// `crate::tokio::spawn` — so the rule cannot be two copies that drift.
///
/// **Call it before `std::mem::take(cmd.fds_mut())`.** It reads `cmd.fds()`; after the take the
/// map is empty and the fd term silently evaluates false.
///
/// Pinned by `spawn_tests::routes_to_raw_backend_answers_for_executables_and_high_descriptors`,
/// which is also what makes the backend names in `tests/windows_creation_flags.rs` true for its
/// argv legs (an argv-only command reports the same `argv[0]` whichever backend spawned it).
#[cfg(windows)]
pub(crate) fn routes_to_raw_backend(cmd: &Command) -> bool {
    cmd.executable_path().is_some() || cmd.fds().keys().any(|slot| slot.raw() >= 3)
}

/// The non-elevated spawn core: resolve stdio, wire program/args, spawn, attach,
/// read identity, adopt. Shared by the ordinary path and the elevation paths'
/// already-elevated / derived-command continuations (which must spawn without
/// re-entering the elevation branch).
///
/// Every failure says whether the program could have started; see [`SpawnFailure`]. One that
/// says so is marked as a front's when the command's report names one.
pub(crate) fn spawn_unelevated(
    cmd: &mut Command,
    kill_on_drop: bool,
    policy: SpawnPolicy,
    kernel: crate::identity::SpawnKernel,
) -> Result<Child, SpawnFailure> {
    // Read now: a failed spawn's teardown needs the front before a `Child` exists.
    let elevation = cmd.elevation_report().cloned();
    let front = elevation.as_ref().and_then(crate::elevation::ElevationReport::front);
    spawn_reported(cmd, kill_on_drop, policy, elevation, front, kernel).map_err(|failure| {
        if front.is_some() {
            failure.behind_front()
        } else {
            failure
        }
    })
}

/// [`spawn_unelevated`] for the report `elevation` the command carries and the `front` it names.
fn spawn_reported(
    cmd: &mut Command,
    kill_on_drop: bool,
    policy: SpawnPolicy,
    elevation: Option<crate::elevation::ElevationReport>,
    front: Option<crate::elevation::front::Front>,
    kernel: crate::identity::SpawnKernel,
) -> Result<Child, SpawnFailure> {
    // Read the routing rule BEFORE the take, which empties the map the rule reads. Evaluated
    // after, it would collapse to "does it have an executable()", and a high-descriptor-only
    // command would take the std path — whose fd >= 3 collection is unix-only, so the
    // descriptors would be dropped with no error and no panic.
    #[cfg(windows)]
    let to_raw_backend = routes_to_raw_backend(cmd);
    let fds = std::mem::take(cmd.fds_mut());

    // Windows routing. The raw `CreateProcessW` backend owns the cases std cannot
    // express: an `executable()` loaded independently of argv[0], and arbitrary descriptors
    // (fd >= 3) via the MSVCRT `lpReserved2` fd-table. It handles both uncontained and
    // CONTAINED children (Job Object / TreeWalk).
    #[cfg(windows)]
    if to_raw_backend {
        return windows_raw::spawn_raw(cmd, fds, kill_on_drop, policy, kernel);
    }
    #[cfg(unix)]
    let mut steps = in_child::InChild::default();
    #[cfg(target_os = "linux")]
    let (invocation, later, env) = {
        let mut invocation = invocation(cmd).not_started()?;
        // Before anything is made (stdio, a cgroup leaf), so a program that is nowhere fails the spawn
        // with nothing to tear down.
        let env = child_env::child_env_of(cmd);
        let later = invocation.find(&env).not_started()?;
        if let Some(dir) = &invocation.cwd {
            enter_in_child(&mut steps, dir).not_started()?;
        }
        (invocation, later, env)
    };
    #[cfg(target_os = "macos")]
    let (mut std_cmd, report) = build_std_command_with(cmd, &mut steps, unique_report::register).not_started()?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let mut std_cmd = build_std_command(cmd).not_started()?;

    let reserved = reserved_fds(&fds);

    // Phase 1 (before spawn): root detection + pre-spawn containment setup, whose in-child steps go
    // into `steps` (order and why: see `in_child`). The hook is registered right before the spawn,
    // after the fd map's step is added.
    //
    // On macOS, `prepare` also clears FD_CLOEXEC on the marker write end for the forked
    // child only (the supervisor's own copy stays CLOEXEC — see `fdmarker::install`'s doc
    // comment). That leaves a real, bounded window — between the clear and this spawn's own
    // `exec` — where a truly concurrent, unrelated `fork()` on another thread of THIS process
    // could transiently inherit the marker fd and carry it past its own `exec`. The shared,
    // process-wide `spawn_lock` (already used to serialize against the Windows raw backend)
    // is widened on macOS to enclose `prepare` through `drop(std_cmd)`, closing that window
    // against every other cosca-originated spawn; `install`'s doc comment names the residual
    // (a spawn racing this one via a path outside cosca's own spawn functions) that no local
    // code can close.
    #[cfg(target_os = "macos")]
    let (mut prepared, child, unique, parent_ends) = {
        let (prepared, spawned, first, parent_ends) = {
            let _guard = spawn_lock();
            // Under the lock, which macOS needs to make a pipe (see `pipe::unix::child_pipe`).
            let parent_ends = resolve_into_std(&mut std_cmd, &mut steps, &fds).not_started()?;
            let prepared = crate::containment::prepare(
                &mut std_cmd,
                &mut steps,
                &cmd.contain_request(),
                cmd.flags_request(),
                &reserved,
                cmd.fd_marker_suppressed(),
                cmd.env_ops(),
                policy.teardown_warn_after,
                &kernel,
            )
            .not_started()?;
            let report = report.open(&_guard).not_started()?;
            steps.register(&mut std_cmd);

            #[allow(
                clippy::disallowed_methods,
                reason = "spawn_lock is held by `_guard`, taken at the top of this block"
            )]
            let (spawned, first) = report.run(|| std_cmd.spawn().map_err(Error::Io), |c| Some(c.id()));
            drop(std_cmd);
            (prepared, spawned, first, parent_ends)
        };
        // Outside the lock, which covers only the window before the ends are close-on-exec: the wait
        // for a report the first read missed has no bound.
        let unique = first.finish(&*kernel);
        // std collected the child of a spawn it failed, which never ran the program.
        let c = spawned
            .map_err(|e| unique_report::failed_spawn_error(e, &unique))
            .not_started()?;
        (prepared, c, unique, parent_ends)
    };
    // Linux clones the child with its pidfd and reads its status channel; see `fork_spawn`. The clone
    // and the reads are under `spawn_lock`.
    #[cfg(target_os = "linux")]
    let (mut prepared, pid, owned, parent_ends) = {
        // Before `prepare`, so a refused stdio fails before containment makes a cgroup leaf.
        let parent_ends = resolve_into_fork(&mut steps, &fds).not_started()?;
        let contain = cmd.contain_request();
        let mut prepared = crate::containment::prepare(
            &mut steps,
            &contain,
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
            policy.teardown_warn_after,
            &kernel,
        )
        .not_started()?;
        // A front this host could not place after a cgroup kill is refused before it is spawned.
        if let Some(leaf) = prepared.cgroup_leaf.as_ref().filter(|_| front.is_some()) {
            crate::containment::cgroup::front_placement(&kernel, || leaf.id()).not_started()?;
        }
        let program = fork_spawn::program(&invocation, &later, env).not_started()?;

        let guard = spawn_lock();
        let refusing_placement = prepared.refuses_failed_placement();
        let on_failure = fork_spawn::OnFailure {
            policy,
            front,
            placement: prepared.placement_leaf(),
            refusing_placement,
        };
        let started = fork_spawn::start(&program, &mut steps, kernel, on_failure, &guard);
        // The child's ends of its pipes and its fd map's sources close here, under the lock, as std's
        // spawn closed them, whether or not the spawn started: a fork that does not exec, made by
        // another thread, holds a copy of an end until it ends.
        drop(steps);
        let started = started?;
        (prepared, started.pid, started.owned, parent_ends)
    };
    #[cfg(windows)]
    let (mut prepared, child, parent_ends) = {
        // Before `prepare`, which mutates this process.
        let parent_ends = resolve_into_std(&mut std_cmd, &fds).not_started()?;
        let prepared = crate::containment::prepare(
            &mut std_cmd,
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
            policy.teardown_warn_after,
            &kernel,
        )
        .not_started()?;

        // The std Child is owned here so containment can job-assign + resume it. Serialize the
        // spawn against the raw backend's inheritable-handle window via the shared spawn lock: std's
        // own handle-inheritance marking must not overlap a raw spawn on another thread.
        let c = {
            let _guard = spawn_lock();
            // Classified at the SYSCALL, not around the whole spawn: an access-denied from stdio
            // resolution or the post-spawn attach has nothing to do with a breakaway request.
            #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard` above")]
            let spawned = std_cmd.spawn().map_err(Error::Io);
            let spawned =
                spawned.map_err(|e| crate::command::flags::classify_spawn_syscall_error(e, *cmd.flags_request()));
            spawned.not_started()?
        };
        (prepared, c, parent_ends)
    };
    // Phase 2 (after spawn, before adopt): attach the mechanism (job/cgroup/...).
    // `prepared` is consumed here: Linux cgroup leaf ownership moves to the tree's cgroup mechanism.
    // Linux holds the child through the box over the pidfd its clone gave it. Every arm below tears
    // down or adopts this one handle.
    // Windows holds it through std's process handle, which becomes the `OwnedChild`'s own.
    #[cfg(windows)]
    let (pid, owned) = {
        let pid = child.id();
        (
            pid,
            OwnedChild::new(Box::new(crate::os_process::windows::WindowsProcess::for_child(
                kernel,
                std::os::windows::io::OwnedHandle::from(child),
                pid,
            ))),
        )
    };
    #[cfg(windows)]
    let proc_handle = {
        use std::os::windows::io::AsRawHandle;
        owned.os_handle().as_raw_handle()
    };
    // macOS has no handle: the unique id the child reported before `exec` is what the `OwnedChild`
    // names it by, and the identity is checked against. The report decides first: a child that died
    // before `exec` is that, whatever an attach would find of its pid.
    #[cfg(target_os = "macos")]
    let (pid, owned) = {
        let pid = child.id();
        #[cfg(test)]
        fault::run_at(fault::SpawnPoint::BeforeAdopt, pid);
        let unique = match unique_report::adopted_id(unique, pid) {
            Ok(unique) => unique,
            Err(not_adopted) => return Err(abandon_unadopted(child, not_adopted, front, prepared, policy, kernel)),
        };
        // A refused kqueue is the one way to fail, and no box exists then ([`leave_unwatched_child`]).
        match crate::os_process::macos::child::MacosChild::new(std::sync::Arc::clone(&kernel), pid, unique) {
            Ok(os) => {
                drop(child);
                (pid, OwnedChild::new(Box::new(os)))
            }
            Err(refusal) => {
                return Err(leave_unwatched_child(
                    &*kernel,
                    UnwatchedChild { child, pid, unique },
                    UnwatchedReport {
                        front,
                        prepared,
                        refusal,
                        late: None,
                    },
                ))
            }
        }
    };
    // A front's leaf subtree, captured while it exists: a failure arm drops the leaf, killing it.
    #[cfg(target_os = "linux")]
    let subtree = front_subtree(front.and(prepared.cgroup_leaf.as_ref()));
    if front.is_some() {
        prepared.watch_front(pid);
    }
    // Read the identity while the child is still unreaped, and check the read against what the spawn
    // holds of the child: the box's pidfd on Linux, its unique id on macOS (the pid alone does not say
    // whom it names once something else has reaped the child); on Windows the process handle pins
    // the pid, so the read stands. The attach takes
    // this identity and does not re-read the root's, so a reap and reuse after the check cannot
    // make the containment name a stranger. Nothing here reaps the child, so this is also the
    // identity the adopted `OwnedChild` takes.
    #[cfg(test)]
    fault::run_at(fault::SpawnPoint::BeforeIdentity, pid);
    #[cfg(target_os = "linux")]
    let handle = crate::containment::ChildHandle {
        pid,
        pidfd: owned.os_handle(),
    };
    let (resolved, cause, mut why) = resolve_identity(
        owned.kernel(),
        pid,
        #[cfg(unix)]
        &owned,
    );
    let id = match resolved {
        crate::identity::Resolved::Found(id) => Ok(id),
        // Kept with no identity; see `Child::id`.
        crate::identity::Resolved::Unknown => Err(kept_without_identity(pid, cause, &mut why)),
        // A vanish is not a refusal: the child was reaped by another party.
        other => {
            // Settle the leaf's verdict before any kill, so the kill never races its reads.
            let never_ran = settle_before_teardown(
                &mut prepared,
                #[cfg(target_os = "linux")]
                handle,
            );
            // A child the leaf's verdict says never ran its program (its hook ended it before
            // `exec`) is the attach's not-started failure, whoever reaped it: its zombie is gone,
            // but the verdict is not.
            #[cfg(target_os = "linux")]
            if let Some(failure) = never_ran {
                drop(prepared);
                let torn = held_teardown::tear_down_unexecuted(
                    owned,
                    None,
                    held_teardown::unexecuted_past(None),
                    policy,
                    &mut why,
                );
                return Err(failure::failed_attach(true, failure.cause, None, None, torn));
            }
            // Only Linux's verdict says so.
            #[cfg(not(target_os = "linux"))]
            let _ = never_ran;
            // Linux 6.9+: the group the root may have left members in, whoever reaped the root.
            #[cfg(target_os = "linux")]
            let group_kill_failure = if front.is_none() {
                kill_group_before_teardown(&prepared, handle, &mut why)
            } else {
                None
            };
            // A front's containment goes first: a cgroup leaf's drop kills it, so the teardown below
            // waits for a contained front that kill reached, and says what became of it.
            #[cfg(target_os = "linux")]
            if front.is_some() {
                drop(prepared);
            }
            #[cfg(target_os = "macos")]
            if front.is_none() {
                note_group_left_running(&prepared, pid, &mut why);
            }
            let error = spawn_identity_error(other, cause);
            // A child the teardown could not end comes back in the error.
            #[cfg(unix)]
            let (
                detail,
                Torn {
                    fate: child_fate,
                    unreaped,
                    cleanup,
                },
            ) = held_teardown::tear_down_held(
                owned,
                held_teardown::HeldTeardown {
                    front,
                    id: None,
                    #[cfg(target_os = "linux")]
                    reach: subtree.as_ref().map(|subtree| subtree as &dyn Reach),
                    #[cfg(target_os = "macos")]
                    reach: None,
                    disposition: crate::child::owned::teardown::Disposition::HandBack,
                    policy,
                },
                &mut why,
            );
            // Windows has no elevation front to leave: every child is killed and reaped.
            #[cfg(windows)]
            let Torn {
                fate: child_fate,
                unreaped,
                cleanup,
            } = held_teardown::tear_down_failed_spawn(
                owned,
                None,
                crate::child::owned::teardown::Past::Clean,
                crate::child::owned::teardown::Disposition::HandBack,
                policy,
                &mut why,
            );
            let failure = SpawnFailure::started(error, child_fate, unreaped);
            #[cfg(unix)]
            let failure = failure.with_detail(detail);
            // The group's refused kill came before the teardown's failures.
            #[cfg(target_os = "linux")]
            let failure = failure.with_cleanup(group_kill_failure);
            return Err(failure.with_cleanup(cleanup));
        }
    };
    #[cfg(test)]
    fault::run_at(fault::SpawnPoint::BeforeAttach, pid);
    // What the attach did not consume of the identity read: what the child becomes, and what the
    // failure arms tear down by.
    let id_read = id.as_ref().ok().copied();
    let attachment = match attach_or_fault(
        #[cfg(unix)]
        pid,
        id,
        #[cfg(target_os = "linux")]
        handle,
        #[cfg(windows)]
        proc_handle,
        prepared,
    ) {
        Ok(v) => v,
        Err(failure) => {
            log::debug!("attach failed: {report}", report = crate::error::Report(&failure.cause));
            // Kill + reap, since a dropped handle neither kills nor reaps. A front is the exception:
            // it is sent nothing (on Linux a failed attach has dropped the containment, a cgroup
            // leaf's drop kills it, and the front is waited for): `tear_down_held`.
            #[cfg(target_os = "macos")]
            if id_read.is_some() {
                assert_attach_cannot_fail(&failure.cause);
            }
            #[cfg(unix)]
            return Err(held_teardown::tear_down_after_failed_attach(
                owned,
                id_read,
                failure,
                #[cfg(target_os = "linux")]
                held_teardown::unexecuted_past(id_read),
                // A macOS attach proves nothing of the program: it is never an unexecuted one.
                #[cfg(target_os = "macos")]
                crate::child::owned::teardown::Past::WaitMayFail,
                policy,
                &mut why,
                |owned, why| {
                    held_teardown::tear_down_held(
                        owned,
                        held_teardown::HeldTeardown {
                            front,
                            id: id_read,
                            #[cfg(target_os = "linux")]
                            reach: subtree.as_ref().map(|subtree| subtree as &dyn Reach),
                            #[cfg(target_os = "macos")]
                            reach: None,
                            disposition: crate::child::owned::teardown::Disposition::HandBack,
                            policy,
                        },
                        why,
                    )
                },
            ));
            #[cfg(windows)]
            return Err(held_teardown::tear_down_after_failed_windows_attach(
                owned, id_read, failure, policy, &mut why,
            ));
        }
    };
    Ok(Child::from_parts(
        owned,
        id_read,
        parent_ends,
        kill_on_drop,
        attachment,
        elevation,
        policy,
    ))
}

/// macOS: an attach given a verified identity reads nothing, so it cannot fail.
#[cfg(target_os = "macos")]
pub(crate) fn assert_attach_cannot_fail(error: &Error) {
    #[cfg(test)]
    debug_assert!(
        fault::force_attach_failure(),
        "a macOS attach cannot fail: {}",
        crate::error::Report(error)
    );
    #[cfg(not(test))]
    debug_assert!(false, "a macOS attach cannot fail: {}", crate::error::Report(error));
    let _ = error;
}

/// The one `warn` of a spawn teardown whose wait for the child it killed has passed `after`; the
/// wait goes on.
pub(crate) fn warn_still_waiting(pid: Option<u32>, after: std::time::Duration) {
    let who = pid.map_or_else(
        || "the spawned child (pid unknown)".to_owned(),
        |pid| format!("child {pid}"),
    );
    #[cfg(unix)]
    log::warn!(
        "{who} is not reapable {after:?} after its kill (it is still running, or a tracer holds its exit); still waiting for it to exit"
    );
    #[cfg(windows)]
    log::warn!("{who} has not exited {after:?} after its kill was requested; still waiting for it to exit");
}

/// macOS: `child` could not be adopted, and the spawn fails with `not_adopted.error`. A child that
/// died before `exec` is only a corpse nothing collects, and the program did not start. A child
/// whose id came late may have started the program: it is torn down through a box of its own, with
/// its tree through `prepared` ([`late_child::abandon_late_child`]). A child with no id at all
/// cannot have a box (`MacosChild` is built from the id), so it is left as
/// [`leave_unverified_child`] leaves it.
#[cfg(target_os = "macos")]
fn abandon_unadopted(
    child: std::process::Child,
    not_adopted: unique_report::NotAdopted,
    front: Option<crate::elevation::front::Front>,
    prepared: crate::containment::Prepared,
    policy: SpawnPolicy,
    kernel: crate::identity::SpawnKernel,
) -> SpawnFailure {
    use unique_report::Unadoptable;

    let pid = child.id();
    let error = not_adopted.error;
    match not_adopted.why {
        Unadoptable::DiedBeforeExec => {
            log::warn!(
                "child {pid} died before exec; nothing is signalled or waited on by pid, so its status is not collected"
            );
            drop(child);
            SpawnFailure::NotStarted(error)
        }
        Unadoptable::Late(unique) => {
            late_child::abandon_late_child(child, unique, error, front, prepared, policy, kernel)
        }
        Unadoptable::Unverified => {
            let fate = leave_unverified_child(child);
            SpawnFailure::started(error, fate, None).with_detail(FrontFate::LeftUnreaped.detail(front, Some(pid)))
        }
    }
}

/// macOS: abandon `child`, whose unique-id report is not an id (unreadable or malformed), so nothing
/// shows its pid still names it and no `MacosChild` can be built. It is not signalled or waited on
/// by pid and is left unreaped, and a warning names the pid; the spawn still fails, and the caller
/// must not assume the program did not start. Dropping the `std` `Child` closes our pipe ends only.
#[cfg(target_os = "macos")]
fn leave_unverified_child(child: std::process::Child) -> ChildFate {
    let pid = child.id();
    #[cfg(test)]
    fault::capture(ProcessId::of(pid));
    log::warn!(
        "child {pid} cannot be shown to be ours (its identity could not be read); leaving it unreaped, with \
         nothing signalled or waited on by pid, and it may still be running"
    );
    drop(child);
    ChildFate::Running { id: None }
}

/// macOS: the child [`leave_unwatched_child`] leaves: the `std` handle, its pid and the unique id it
/// reported.
#[cfg(target_os = "macos")]
struct UnwatchedChild {
    child: std::process::Child,
    pid: u32,
    unique: u64,
}

/// macOS: what [`leave_unwatched_child`]'s failure reports of the child's tree and of both refusals.
/// `refusal` is the spawn's error unless the id came `late`, when it goes in the failure's `cleanup`.
#[cfg(target_os = "macos")]
struct UnwatchedReport {
    front: Option<crate::elevation::front::Front>,
    prepared: crate::containment::Prepared,
    refusal: Error,
    late: Option<Error>,
}

/// macOS: abandon a child `MacosChild::new` refused (its kqueue, `EMFILE` and the like). It is a
/// stated limit: the child is sent `SIGKILL` through its unique id (an elevation front is sent
/// nothing), its marker's holders are swept, and it is never waited on, so it stays a zombie until this
/// process exits.
#[cfg(target_os = "macos")]
fn leave_unwatched_child(
    kernel: &dyn crate::identity::Kernel,
    unwatched: UnwatchedChild,
    report: UnwatchedReport,
) -> SpawnFailure {
    let UnwatchedChild { child, pid, unique } = unwatched;
    let UnwatchedReport {
        front,
        prepared,
        refusal,
        late,
    } = report;
    let (fate, said, killing) = unwatched_child_fate(kernel, pid, unique, front.is_some());
    // The containment is no front's to kill: its marker closes with it.
    let holders = if front.is_some() {
        None
    } else {
        late_child::marker_holders(prepared)
    };
    let swept = holders.map(|tree| tree.send_kill(None).into_result().or_else(|left| left.unsettled(true)));
    let tree = match &swept {
        None => "its tree was not killed".to_owned(),
        Some(Ok(())) => "its marker's holders were killed, and the rest of its tree (its process group, the \
                         processes its pid parents) was not"
            .to_owned(),
        Some(Err(left)) => format!(
            "its marker's holders were not all killed ({}), and the rest of its tree was not",
            crate::error::Report(left)
        ),
    };
    let lead = if late.is_some() {
        format!("child {pid} {}, and its exit could not be watched", late_child::LATE)
    } else {
        format!("child {pid}'s exit could not be watched")
    };
    log::warn!(
        "{lead} ({}), so it has no handle and {tree}: {said}; it is not waited for or reaped, so \
         it stays a zombie once it exits",
        crate::error::Report(&refusal)
    );
    drop(child);
    let (cause, refused) = match late {
        Some(late) => (late, Failures::collect([Arc::new(refusal)])),
        None => (refusal, None),
    };
    let left = Failures::collect(swept.and_then(Result::err).map(Arc::new));
    SpawnFailure::started(cause, fate, None)
        .with_detail(FrontFate::LeftUnreaped.detail(front, Some(pid)))
        .with_cleanup(refused)
        .with_cleanup(killing)
        .with_cleanup(left)
}

/// What [`leave_unwatched_child`] does to the child `pid`, whose unique id is `unique`: the fate it
/// answers, the clause that says it, and what failed (a refused kill). Nothing is sent to a `front`.
#[cfg(target_os = "macos")]
fn unwatched_child_fate(
    kernel: &dyn crate::identity::Kernel,
    pid: u32,
    unique: u64,
    front: bool,
) -> (ChildFate, String, Option<Failures>) {
    use crate::signal::{via_audit_token, Sent, Sig};

    if front {
        return (
            ChildFate::Running { id: None },
            "it is an elevation front, so nothing was sent to it".to_owned(),
            None,
        );
    }
    match via_audit_token(kernel, pid, Some(unique), Sig::Kill) {
        // `Delivered` includes a send refused because the exit had begun.
        Ok(Sent::Delivered) => (
            ChildFate::Killed,
            "it was sent SIGKILL, or its exit had begun when the send was made".to_owned(),
            None,
        ),
        Ok(Sent::Gone) => (
            ChildFate::Gone,
            "it was gone, or its pid names another process, so nothing was sent".to_owned(),
            None,
        ),
        Ok(Sent::Unverified) => {
            debug_assert!(false, "`via_audit_token` was given `Some(unique)`, so it verifies");
            (ChildFate::Running { id: None }, "it was not signalled".to_owned(), None)
        }
        Err(kill) => (
            ChildFate::Running { id: None },
            format!("it could not be killed ({})", crate::error::Report(&kill)),
            Failures::collect([Error::io_cause(crate::error::io_context("killing the child", kill))]),
        ),
    }
}

/// Serializes spawns against the process-global inheritable-handle window: on Windows both the std
/// path and the raw `CreateProcessW` backend must mark child-side handles inheritable, spawn, then
/// un-mark/close without a concurrent spawn inheriting them. Held across that window on both paths.
/// It orders cosca's own spawns only: another spawner in the process that passes `bInheritHandles`
/// TRUE with no handle list is not under it, and can take those handles while they are inheritable
/// (see the module doc of `child::spawn::windows_raw`).
/// **Poison-tolerant:** a panic mid-spawn must not wedge every future spawn, so a poisoned lock is
/// recovered rather than propagated (the guarded data is unit — there is no invariant to protect).
pub(crate) fn spawn_lock() -> SpawnLockGuard {
    acquire_spawn_lock(|| {
        #[cfg(all(test, target_os = "macos"))]
        fault::spawn_lock_contended();
    })
}

static SPAWN_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Holds [`spawn_lock`]. Under `debug_assertions` (and in test builds) it also records that this
/// thread holds the non-reentrant mutex, so a nested acquire fails with a named panic instead of
/// deadlocking.
#[must_use = "if unused the spawn lock is released immediately; bind the guard for the whole window"]
pub(crate) struct SpawnLockGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
}

thread_local! {
    /// Whether THIS thread holds `SPAWN_MUTEX`; set and cleared only by [`SpawnLockGuard`].
    /// `const`-initialized with no destructor, so reading it in a forked child is safe.
    #[cfg(any(test, debug_assertions))]
    static SPAWN_LOCK_HELD_BY_THIS_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(any(test, debug_assertions))]
impl Drop for SpawnLockGuard {
    fn drop(&mut self) {
        SPAWN_LOCK_HELD_BY_THIS_THREAD.with(|f| f.set(false));
    }
}

/// Takes `SPAWN_MUTEX`. `on_contended` runs first if it is already held, before this blocks.
fn acquire_spawn_lock(on_contended: impl FnOnce()) -> SpawnLockGuard {
    #[cfg(any(test, debug_assertions))]
    assert!(
        !spawn_lock_held_by_this_thread(),
        "spawn_lock re-entered: the mutex is not reentrant; drop the outer spawn_lock() (fork_running and cosca spawns take it themselves)"
    );
    let guard = match SPAWN_MUTEX.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => {
            on_contended();
            SPAWN_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
        }
    };
    #[cfg(any(test, debug_assertions))]
    SPAWN_LOCK_HELD_BY_THIS_THREAD.with(|f| f.set(true));
    SpawnLockGuard { _guard: guard }
}

/// Like [`spawn_lock`], but `on_contended` runs first if the lock is already held, before this
/// blocks on it.
#[cfg(all(target_os = "linux", test))]
pub(crate) fn spawn_lock_tracked(on_contended: impl FnOnce()) -> SpawnLockGuard {
    acquire_spawn_lock(on_contended)
}

/// Whether THIS thread currently holds `spawn_lock`'s mutex.
#[cfg(any(test, debug_assertions))]
pub(crate) fn spawn_lock_held_by_this_thread() -> bool {
    SPAWN_LOCK_HELD_BY_THIS_THREAD.with(|f| f.get())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn build_std_command(cmd: &Command) -> Result<std::process::Command, Error> {
    #[cfg(unix)]
    {
        let mut steps = in_child::InChild::default();
        let (mut std_cmd, ()) = build_std_command_with(cmd, &mut steps, |_| ())?;
        steps.register(&mut std_cmd);
        Ok(std_cmd)
    }
    #[cfg(not(unix))]
    build_std_command_with(cmd, |_| ()).map(|(std_cmd, ())| std_cmd)
}

/// [`build_std_command`], running `first` on the command before anything else is set on it, so a
/// hook `first` registers runs first in the child. Returns what `first` returned. On Unix this
/// registers no hook: the child's own steps go into `steps`, for the caller to register last.
#[cfg(not(target_os = "linux"))]
pub(crate) fn build_std_command_with<R>(
    cmd: &Command,
    #[cfg(unix)] steps: &mut in_child::InChild,
    first: impl FnOnce(&mut std::process::Command) -> R,
) -> Result<(std::process::Command, R), Error> {
    #[cfg_attr(not(unix), allow(unused_mut, reason = "only a unix spawn searches for its program"))]
    let mut invocation = invocation(cmd)?;
    // Found here, in the parent, over the `PATH` the child will have: std is handed a path with a `/` in
    // it, which it does not search for.
    #[cfg(unix)]
    invocation.find(&child_env::child_env_of(cmd))?;
    let mut std_cmd = invocation.std_command();
    let Invocation { cwd, enter, .. } = invocation;
    apply_env(&mut std_cmd, cmd.env_ops());
    let first = first(&mut std_cmd);
    match cwd {
        #[cfg(unix)]
        Some(dir) if enter => enter_in_child(steps, &dir)?,
        #[cfg(not(unix))]
        Some(_) if enter => unreachable!("only anchor_posix asks the child to enter its directory"),
        Some(dir) => {
            std_cmd.current_dir(dir);
        }
        None => {}
    }
    Ok((std_cmd, first))
}

/// `chdir` to `dir` in the child, after std's own setup and just before its `execvp`, so a
/// relative program is read against the directory the child runs in, both relative to the cwd it
/// inherited (see `crate::resolve::exact::anchor_posix`).
///
/// This is what std's `current_dir` would mostly do already, and it is done here because std does
/// not promise it: "If the program path is relative (e.g., `"./script.sh"`), it's ambiguous
/// whether it should be interpreted relative to the parent's working directory or relative to
/// `current_dir`. The behavior in this case is platform specific and unstable". std 1.97.1 happens
/// to read it against the new directory on both of its paths — fork/exec (which it takes on
/// Apple for this case) and glibc's `posix_spawn` with `addchdir` — but either could change. std
/// documents `pre_exec` hooks as running in the child just before the exec, so the ordering is
/// pinned. The cost is that a hook rules out `posix_spawn`, for these commands only.
#[cfg(unix)]
fn enter_in_child(steps: &mut in_child::InChild, dir: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let dir = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_dir() contains an embedded NUL",
        ))
    })?;
    steps.enter(dir);
    Ok(())
}

/// The program to load and the directory to run it in.
struct Resolved {
    program: std::ffi::OsString,
    cwd: Option<std::path::PathBuf>,
    /// The child enters `cwd` itself; see `crate::resolve::exact::Anchored::enter`.
    enter: bool,
    /// The program is a name to search for ([`Invocation::find`]); `false` for an `Exact` one.
    #[cfg(unix)]
    searched: bool,
}

// Pick the executable file to load (`executable` overrides argv[0]/first-token). On POSIX an
// `Exact` program arrives in a form no exec searches (see `crate::resolve::exact::anchor_posix`);
// on Windows a set executable never reaches this std path, routing to the raw backend instead.
fn resolve_program(cmd: &Command, fallback: std::ffi::OsString) -> Result<Resolved, Error> {
    let as_given = |exe: Option<&std::path::Path>| Resolved {
        program: exe.map_or(fallback, |p| p.as_os_str().to_os_string()),
        cwd: cmd.cwd().map(std::path::Path::to_path_buf),
        enter: false,
        #[cfg(unix)]
        searched: true,
    };
    #[cfg(unix)]
    if let Some(crate::command::ExecutableSpec::Exact(p)) = cmd.executable_spec() {
        let a = crate::resolve::exact::anchor_posix(p.as_os_str(), cmd.cwd())?;
        return Ok(Resolved {
            program: a.program.into_os_string(),
            cwd: a.cwd,
            enter: a.enter,
            searched: false,
        });
    }
    Ok(as_given(cmd.executable_path()))
}

// Program + the trailing args (argv mode). `executable` overrides the loaded file; argv[0] is the
// conventional program name otherwise — POSIX argv[0] preservation happens at the caller (see
// build_std_command). On Windows a set `executable` never reaches this std path — it routes to
// the raw `CreateProcessW` backend, which preserves argv[0] independently of the loaded image.
fn resolve_program_argv<'a>(
    cmd: &'a Command,
    argv: &'a [std::ffi::OsString],
) -> Result<(Resolved, &'a [std::ffi::OsString]), Error> {
    if argv.is_empty() && cmd.executable_path().is_none() {
        return Err(Error::Io(std::io::Error::other("empty argv")));
    }
    let fallback = if argv.is_empty() {
        std::ffi::OsString::new()
    } else {
        argv[0].clone()
    };
    let program = resolve_program(cmd, fallback)?;
    let rest = if argv.is_empty() { argv } else { &argv[1..] };
    Ok((program, rest))
}

/// What a command runs, resolved the way every spawn through the platform's own launcher needs it: the
/// program to load, the directory to run it in, and the arguments.
pub(crate) struct Invocation {
    pub(crate) program: std::ffi::OsString,
    /// POSIX: `argv[0]`, when `executable()` overrides the loaded file: the user's own name for the
    /// program, which the loaded path would otherwise replace. `None`: `argv[0]` is `program`.
    #[cfg(unix)]
    pub(crate) arg0: Option<std::ffi::OsString>,
    /// The arguments after `argv[0]`.
    pub(crate) args: Vec<std::ffi::OsString>,
    /// Windows: the command line after its first token, which std appends as it is.
    #[cfg(windows)]
    raw_args: Option<std::ffi::OsString>,
    pub(crate) cwd: Option<std::path::PathBuf>,
    /// The child enters `cwd` itself; see `crate::resolve::exact::Anchored::enter`.
    #[cfg_attr(
        target_os = "linux",
        allow(dead_code, reason = "the Linux child enters every directory itself, asked or not")
    )]
    pub(crate) enter: bool,
    /// POSIX: `program` is a name for [`find`](Invocation::find) to search for; `false` for one the
    /// caller named exactly (`raw_executable`), which is launched as it is.
    #[cfg(unix)]
    pub(crate) searched: bool,
}

impl Invocation {
    /// The `std::process::Command` of this invocation, with no environment, directory or stdio set.
    #[cfg(not(target_os = "linux"))]
    fn std_command(&self) -> std::process::Command {
        let mut c = std::process::Command::new(&self.program);
        // POSIX: when executable() overrides the loaded file, preserve the user's argv[0] via arg0() —
        // the executable as written when argv is empty. Without this, std would set argv[0] to the
        // (possibly completed) program path, silently dropping the user's intended name.
        #[cfg(unix)]
        if let Some(arg0) = &self.arg0 {
            use std::os::unix::process::CommandExt;
            c.arg0(arg0);
        }
        c.args(&self.args);
        #[cfg(windows)]
        if let Some(raw) = &self.raw_args {
            use std::os::windows::process::CommandExt;
            c.raw_arg(raw); // args only — program is prepended by std
        }
        c
    }
}

/// What `cmd` runs. Rejects .bat/.cmd (BatBadBut) on Windows, and an interior NUL everywhere: this is the
/// std backend's only NUL check, and the default Windows path. Judged on the token WE resolved, not on
/// `std_cmd.get_program()`: std's Unix constructor swaps a NUL-bearing program for a
/// `<string-with-nul>` sentinel, so reading it back would hide the exact token the gate exists to judge
/// (and would make this verdict differ by platform for reasons unrelated to Windows).
pub(crate) fn invocation(cmd: &Command) -> Result<Invocation, Error> {
    let invocation = match cmd.input() {
        CommandInput::Empty => return Err(Error::Io(std::io::Error::other("no program specified"))),
        CommandInput::Argv(argv) => {
            let (
                Resolved {
                    program,
                    cwd,
                    enter,
                    #[cfg(unix)]
                    searched,
                },
                rest,
            ) = resolve_program_argv(cmd, argv)?;
            Invocation {
                program,
                #[cfg(unix)]
                arg0: cmd.executable_path().map(|exe| {
                    argv.first()
                        .map_or(exe.as_os_str(), std::ffi::OsString::as_os_str)
                        .to_owned()
                }),
                args: rest.to_vec(),
                #[cfg(windows)]
                raw_args: None,
                cwd,
                enter,
                #[cfg(unix)]
                searched,
            }
        }
        CommandInput::CommandLine(line) => invocation_of_commandline(cmd, line)?,
    };
    reject_batch_path(std::path::Path::new(&invocation.program))?;
    Ok(invocation)
}

#[cfg(unix)]
fn invocation_of_commandline(cmd: &Command, line: &std::ffi::OsString) -> Result<Invocation, Error> {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let words = crate::quote::posix::split(line.as_bytes())?;
    // `OsStringExt::from_vec` already yields an OsString; do NOT wrap it in
    // `OsString::from(..)` (that is redundant and fails type inference).
    let mut argv: Vec<OsString> = words.into_iter().map(OsString::from_vec).collect();
    if argv.is_empty() {
        return Err(Error::Io(std::io::Error::other("empty command line")));
    }
    let Resolved {
        program,
        cwd,
        enter,
        searched,
    } = resolve_program(cmd, argv[0].clone())?;
    // When executable() overrides the loaded file, argv[0] from the command
    // line is the user's intended name.
    let arg0 = cmd.executable_path().map(|_| argv[0].clone());
    let args = argv.split_off(1);
    Ok(Invocation {
        program,
        arg0,
        args,
        cwd,
        enter,
        searched,
    })
}

#[cfg(windows)]
fn invocation_of_commandline(cmd: &Command, line: &std::ffi::OsString) -> Result<Invocation, Error> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    // Windows is command-line-native. CRITICAL: std::process always PREPENDS a
    // quoted form of the program to lpCommandLine and then appends raw_arg. So
    // raw_arg must be the ARGS portion only (the line MINUS its first token);
    // passing the whole line would duplicate the program token in the child's
    // argv. We split the first token off with first_token_and_rest_wide.
    //
    // This std path is only reached for a commandline() WITHOUT executable(): a set
    // executable() routes to the raw `CreateProcessW` backend (which sets
    // lpApplicationName independently of lpCommandLine) before `build_std_command`
    // is ever called, on both the sync and async spawn paths.
    let wide: Vec<u16> = line.encode_wide().collect();
    let (first, rest) = crate::quote::windows::first_token_and_rest_wide(&wide)
        .ok_or_else(|| Error::Io(std::io::Error::other("empty command line")))?;
    Ok(Invocation {
        program: std::ffi::OsString::from_wide(&first),
        args: Vec::new(),
        raw_args: Some(std::ffi::OsString::from_wide(&rest)),
        cwd: cmd.cwd().map(std::path::Path::to_path_buf),
        enter: false,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn apply_env(std_cmd: &mut std::process::Command, ops: &[EnvOp]) {
    for op in ops {
        match op {
            EnvOp::Set(k, v) => {
                std_cmd.env(k, v);
            }
            EnvOp::Remove(k) => {
                std_cmd.env_remove(k);
            }
            EnvOp::Clear => {
                std_cmd.env_clear();
            }
        }
    }
}

/// The child-side ends (keyed by slot) and the parent ends of the piped slots — the result of
/// [`resolve_stdio`].
pub(crate) type ResolvedStdioEnds = (BTreeMap<Fd, ChildEnd>, BTreeMap<Fd, ParentEnd>);

/// Resolves every slot of a spawn to its child end, and every piped slot to its parent end: 0/1/2
/// (inheriting when unconfigured) and every configured fd >= 3. The per-caller tails (the final
/// `Stdio` assignment, the Windows raw backend's handle table) stay with each spawn.
///
/// On macOS the caller holds `spawn_lock` (see `pipe::unix::child_pipe`).
pub(crate) fn resolve_stdio(
    fds: &BTreeMap<Fd, ResolvedStdio>,
    parent_std: ParentStd,
) -> Result<ResolvedStdioEnds, Error> {
    let slots: Vec<Fd> = [Fd::STDIN, Fd::STDOUT, Fd::STDERR]
        .into_iter()
        .chain(fds.keys().copied().filter(|f| f.raw() >= 3))
        .collect();
    // Reject merge-targeting-a-merge: the two-pass algorithm resolves only one level of
    // indirection. Transitive chaining (a fixpoint loop) is an unsupported design limit — redirect
    // to a concrete slot (pipe/file/null/inherit) instead.
    for &slot in &slots {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(&slot) {
            if matches!(fds.get(target), Some(ResolvedStdio::Merge(_))) {
                return Err(Error::Unsupported {
                    op: format!("merge {slot} -> {target} -> <another merge>"),
                    platform: std::env::consts::OS,
                    detail: "chained merges (merge-to-merge) are not supported; \
                             redirect to a concrete slot (pipe/file/null/inherit)"
                        .into(),
                    source: None,
                });
            }
        }
    }

    let mut child_ends: BTreeMap<Fd, ChildEnd> = BTreeMap::new();
    let mut parent_ends: BTreeMap<Fd, ParentEnd> = BTreeMap::new();

    // First pass: resolve non-merge slots. Std slots 0/1/2 default to inherit when unconfigured;
    // an n>=3 slot has no default, so skip an unconfigured one.
    for &slot in &slots {
        let resolved = fds.get(&slot);
        match resolved {
            Some(ResolvedStdio::Merge(_)) => continue, // second pass
            None if slot.raw() >= 3 => continue,
            _ => {
                let (child_end, parent) = resolve_non_merge(slot, resolved, parent_std)?;
                if let Some(p) = parent {
                    parent_ends.insert(slot, p);
                }
                child_ends.insert(slot, child_end);
            }
        }
    }

    // Second pass: dup each merge from its already-resolved target.
    for &slot in &slots {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(&slot) {
            let src = child_ends.get(target).ok_or_else(|| Error::Unsupported {
                op: format!("merge {slot} -> {target}"),
                platform: std::env::consts::OS,
                detail: "merge target descriptor is not configured".into(),
                source: None,
            })?;
            child_ends.insert(slot, dup(src)?);
        }
    }

    Ok((child_ends, parent_ends))
}

/// The fd map's mappings of the child ends above stdio: each `dup2`ed onto its number in the child.
#[cfg(unix)]
fn fd_mappings(child_ends: BTreeMap<Fd, ChildEnd>) -> Vec<fd_map::FdMapping> {
    child_ends
        .into_iter()
        .map(|(fd, owned)| fd_map::FdMapping {
            parent_fd: owned,
            child_fd: fd.raw(),
        })
        .collect()
}

/// [`resolve_stdio`] for the Linux spawn ([`fork_spawn`]): the child's own steps `dup2` each end onto its
/// number, 0/1/2 in a plan of their own that runs first, and each fd >= 3 end in the fd map, which runs last. Returns every parent end. The caller's `prepare` adds its
/// steps after.
#[cfg(target_os = "linux")]
fn resolve_into_fork(
    steps: &mut in_child::InChild,
    fds: &BTreeMap<Fd, ResolvedStdio>,
) -> Result<BTreeMap<Fd, ParentEnd>, Error> {
    let (mut child_ends, parent_ends) = resolve_stdio(fds, ParentStd::read())?;
    let stdio = [Fd::STDIN, Fd::STDOUT, Fd::STDERR]
        .into_iter()
        .map(|slot| fd_map::FdMapping {
            parent_fd: child_ends
                .remove(&slot)
                .unwrap_or_else(|| unreachable!("resolve_stdio resolves 0/1/2 always")),
            child_fd: slot.raw(),
        })
        .collect();
    steps.map_stdio(fd_map::Plan::stdio(stdio));
    fd_map::install(steps, fd_mappings(child_ends)).map_err(Error::Io)?;
    Ok(parent_ends)
}

/// [`resolve_stdio`] for a spawn through `std::process::Command`: 0/1/2 go to `cmd` (std closes its
/// copies at spawn), and on Unix each fd >= 3 child end goes to the fd map in `steps`, whose step
/// `dup2`s it to its number after the fork. Returns every parent end. The caller registers the hook
/// after `prepare` has added its steps.
#[cfg(not(target_os = "linux"))]
pub(crate) fn resolve_into_std(
    cmd: &mut std::process::Command,
    #[cfg(unix)] steps: &mut in_child::InChild,
    fds: &BTreeMap<Fd, ResolvedStdio>,
) -> Result<BTreeMap<Fd, ParentEnd>, Error> {
    #[cfg(windows)]
    debug_assert!(
        fds.keys().all(|f| f.raw() < 3),
        "an fd >= 3 routes to the raw backend, never the std path"
    );
    let (mut child_ends, parent_ends) = resolve_stdio(fds, ParentStd::read())?;
    for slot in [Fd::STDIN, Fd::STDOUT, Fd::STDERR] {
        let end = child_ends
            .remove(&slot)
            .unwrap_or_else(|| unreachable!("resolve_stdio resolves 0/1/2 always"));
        let stdio = StdStdio::from(end);
        match slot {
            Fd::STDIN => cmd.stdin(stdio),
            Fd::STDOUT => cmd.stdout(stdio),
            _ => cmd.stderr(stdio),
        };
    }
    // The step runs after every other, so it cannot replace a descriptor one still needs, and std
    // `dup2`s 0/1/2 before any `pre_exec` hook runs, so a mapping never clobbers stdio.
    #[cfg(unix)]
    fd_map::install(steps, fd_mappings(child_ends)).map_err(Error::Io)?;
    #[cfg(not(unix))]
    debug_assert!(child_ends.is_empty(), "the std path on Windows has no fd >= 3 end");
    Ok(parent_ends)
}

/// Every child fd number above stdio that a spawn occupies, so the macOS fd-marker install places
/// its own descriptor above all of them rather than colliding with a user mapping. `prepare` ignores
/// it elsewhere; the std path on Windows has none.
pub(crate) fn reserved_fds(fds: &BTreeMap<Fd, ResolvedStdio>) -> Vec<i32> {
    fds.keys().map(|fd| fd.raw()).filter(|&n| n >= 3).collect()
}

// Resolve a non-merge slot to its child-side end + the parent's pipe end (if any).
pub(crate) fn resolve_non_merge(
    slot: Fd,
    r: Option<&ResolvedStdio>,
    parent_std: ParentStd,
) -> Result<(ChildEnd, Option<ParentEnd>), Error> {
    match r {
        None | Some(ResolvedStdio::Inherit) => Ok((inherit_end(slot, parent_std)?, None)),
        Some(ResolvedStdio::Null) => Ok((null_end()?, None)),
        Some(ResolvedStdio::File(f)) => Ok((file_end(f)?, None)),
        Some(ResolvedStdio::Pipe(dir)) => make_pipe(*dir).map(|(child_end, parent_end)| (child_end, Some(parent_end))),
        Some(ResolvedStdio::Merge(_)) => unreachable!("merge handled in second pass"),
    }
}

/// The pipe for one piped slot, for every spawn: the child's end and the parent's.
pub(crate) fn make_pipe(dir: Direction) -> Result<(ChildEnd, ParentEnd), Error> {
    let (child_end, parent_end) = crate::pipe::child_pipe(dir).map_err(Error::Io)?;
    Ok((ChildEnd::from(child_end), parent_end))
}

pub(crate) fn dup(end: &ChildEnd) -> Result<ChildEnd, Error> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        end.as_fd().try_clone_to_owned().map_err(Error::Io)
    }
    #[cfg(windows)]
    {
        end.try_clone().map_err(Error::Io)
    }
}

fn null_end() -> Result<ChildEnd, Error> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(if cfg!(windows) { "NUL" } else { "/dev/null" })
        .map_err(Error::Io)?;
    Ok(ChildEnd::from(f))
}

fn file_end(f: &std::fs::File) -> Result<ChildEnd, Error> {
    // Dup the file so the caller's File stays usable.
    let dup = f.try_clone().map_err(Error::Io)?;
    Ok(ChildEnd::from(dup))
}

#[cfg_attr(
    not(windows),
    allow(unused_variables, reason = "only the Windows arm reads the parent's std handles")
)]
fn inherit_end(slot: Fd, parent_std: ParentStd) -> Result<ChildEnd, Error> {
    // Duplicate the parent's matching std stream. Bind the stream to a variable
    // before borrowing its descriptor (a temporary would be dropped while borrowed).
    // For n>=3, Stdio::inherit() has no defined parent stream to dup — a design limit
    // kept as a loud Unsupported on every path (the raw backend routes here too), never a
    // silent drop.
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let owned = match slot {
            Fd::STDIN => {
                let s = std::io::stdin();
                s.as_fd().try_clone_to_owned()
            }
            Fd::STDOUT => {
                let s = std::io::stdout();
                s.as_fd().try_clone_to_owned()
            }
            Fd::STDERR => {
                let s = std::io::stderr();
                s.as_fd().try_clone_to_owned()
            }
            other => {
                return Err(Error::Unsupported {
                    op: format!("Stdio::inherit() on {other}"),
                    platform: "unix",
                    detail: "inherit on fd >= 3 has no defined parent stream; \
                             use pipe/file/null instead"
                        .into(),
                    source: None,
                })
            }
        };
        owned.map_err(Error::Io)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        // A null std handle (a GUI process's or a service's) is an absent end; so is -1, which `std`
        // reports as null. `parent_std` decides null-ness, so this end and the caller's
        // `STARTF_USESTDHANDLES` decision come from one read.
        let live = parent_std.is_live(slot);
        let owned = match slot {
            Fd::STDIN => {
                let s = std::io::stdin();
                dup_std_handle(s.as_handle(), live)
            }
            Fd::STDOUT => {
                let s = std::io::stdout();
                dup_std_handle(s.as_handle(), live)
            }
            Fd::STDERR => {
                let s = std::io::stderr();
                dup_std_handle(s.as_handle(), live)
            }
            // fd >= 3 has no defined parent std stream to dup (mirrors the Unix arm). Retained design
            // limit: the raw backend routes fd >= 3 inherit through here and rejects it too.
            other => {
                return Err(Error::Unsupported {
                    op: format!("Stdio::inherit() on {other}"),
                    platform: "windows",
                    detail: "inherit on fd >= 3 has no defined parent stream; \
                             use pipe/file/null instead"
                        .into(),
                    source: None,
                })
            }
        };
        owned.map_err(Error::Io)
    }
}

/// A dup of this process's std handle `h`; absent when `live` is false (it was null when
/// [`ParentStd`] was read).
#[cfg(windows)]
fn dup_std_handle(h: std::os::windows::io::BorrowedHandle<'_>, live: bool) -> std::io::Result<ChildEnd> {
    use std::os::windows::io::AsRawHandle;
    if !live || h.as_raw_handle().is_null() {
        return Ok(ChildEnd::absent());
    }
    h.try_clone_to_owned().map(ChildEnd::from)
}

/// Which of this process's stdin, stdout and stderr handles were non-null when a spawn began.
///
/// Read once per spawn: the inherited ends and the Windows `STARTF_USESTDHANDLES` decision both
/// come from it, so a concurrent `SetStdHandle` cannot make them disagree. Empty off Windows.
#[derive(Clone, Copy)]
pub(crate) struct ParentStd {
    #[cfg(windows)]
    live: [bool; 3],
}

impl ParentStd {
    pub(crate) fn read() -> ParentStd {
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsHandle, AsRawHandle};
            ParentStd {
                live: [
                    !std::io::stdin().as_handle().as_raw_handle().is_null(),
                    !std::io::stdout().as_handle().as_raw_handle().is_null(),
                    !std::io::stderr().as_handle().as_raw_handle().is_null(),
                ],
            }
        }
        #[cfg(not(windows))]
        {
            ParentStd {}
        }
    }

    /// Whether the handle for std `slot` (0, 1 or 2) was non-null; `false` for any other slot,
    /// which has no parent stream (`inherit_end` refuses it).
    #[cfg(windows)]
    pub(crate) fn is_live(self, slot: Fd) -> bool {
        usize::try_from(slot.raw())
            .ok()
            .and_then(|i| self.live.get(i).copied())
            .unwrap_or(false)
    }

    /// Whether any of the three was non-null.
    #[cfg(windows)]
    pub(crate) fn any_live(self) -> bool {
        self.live.iter().any(|&l| l)
    }
}

/// The error for a spawn whose child could not be identified. `Gone` is an absence;
/// `Unknown` is an OS refusal about a child that may be running fine - never report the
/// second as the first.
///
/// `cause` is what the read that answered `Unknown` found out. An unavailable Linux `/proc` view is
/// named; any other refusal is the OS's.
pub(crate) fn spawn_identity_error(
    outcome: crate::identity::Resolved<ProcessId>,
    cause: crate::identity::UnknownCause,
) -> Error {
    match outcome {
        crate::identity::Resolved::Unknown => {
            cause
                .into_error("the spawned child")
                .unwrap_or_else(|| Error::Unassessable {
                    detail: "the OS refused to report the spawned child's identity".into(),
                    source: None,
                })
        }
        _ => Error::Io(std::io::Error::other(
            "the spawned child exited and was reaped by another party, or its zombie is held by one, before its \
             identity could be read",
        )),
    }
}

/// Read the spawned child's stable identity, then check through `through`, the box held since the
/// spawn (on Unix), that the read named our child.
///
/// - **Linux:** the key is read from the box's pidfd, with no second `pidfd_open` of the pid: on
///   pidfs (6.9+) its inode, else (no inode of its own) the `/proc` `starttime` by pid. Then a peek
///   through the pidfd. `Running` and `Exit` keep the read (a reap is irreversible, so the pid
///   named our child throughout); `Foreign` is `Gone`; a failed peek is `Unknown`, and the child is
///   kept without an identity ([`kept_without_identity`]): the check is logged at debug, and warned
///   only if a failing attach's teardown folds it into its warn. On pidfs the pidfd, not the pid,
///   named the read, so the peek does not check it: it shows whether another party reaped the child.
/// - **macOS:** the same, but the peek compares the pid's current unique id with the one the box
///   carries; a mismatch is `Foreign`, an unreadable id is an error (`Unknown`), and `Orphaned`
///   (held by launchd after its tracer died) is `Gone`, as every foreign verdict is.
/// - **Windows:** the process handle pins the pid, so the read stands and there is no check.
///
/// What the check found out, when it could not show the read named our child, comes back as a
/// [`Diagnosis`]: the failed spawn's teardown carries it in its one `warn`, unless the child is kept
/// (see the `Diagnosis` keep rule). The
/// [`UnknownCause`](crate::identity::UnknownCause) is the read's own, for [`spawn_identity_error`].
pub(crate) fn resolve_identity(
    kernel: &dyn crate::identity::Kernel,
    pid: u32,
    #[cfg(unix)] through: &OwnedChild,
) -> (
    crate::identity::Resolved<ProcessId>,
    crate::identity::UnknownCause,
    Diagnosis,
) {
    use crate::identity::Resolved;

    #[cfg(target_os = "linux")]
    let (read, cause) = resolve_identity_unchecked(kernel, pid, through.os_handle());
    #[cfg(not(target_os = "linux"))]
    let (read, cause) = resolve_identity_unchecked(kernel, pid);
    let Resolved::Found(_) = read else {
        return (read, cause, Diagnosis::default());
    };
    #[cfg(test)]
    fault::run_at(fault::SpawnPoint::AfterIdentityRead, pid);
    #[cfg(unix)]
    {
        use crate::os_process::child::PeekOutcome;
        match through.peek().map_err(Error::into_io) {
            Ok(PeekOutcome::Running | PeekOutcome::Exit(_)) => (read, cause, Diagnosis::default()),
            // Orphaned: `Gone`, warned.
            Ok(PeekOutcome::Foreign(crate::os_process::child::Foreign::Orphaned)) => (
                Resolved::Gone,
                cause,
                Diagnosis::of(format!(
                    "child {pid}: launchd holds its zombie, so its tracer died; it is not ours to reap"
                )),
            ),
            Ok(PeekOutcome::Foreign(_)) => (Resolved::Gone, cause, Diagnosis::default()),
            Err(e) => (
                Resolved::Unknown,
                cause,
                Diagnosis::of_failed_check(
                    format!(
                        "child {pid}: its identity could not be checked against its handle ({}); it is not shown to be ours",
                        crate::error::Report(&e)
                    ),
                    e,
                ),
            ),
        }
    }
    #[cfg(windows)]
    {
        (read, cause, Diagnosis::default())
    }
}

/// What the identity check found when it could not show the spawned child to be ours, owed to the
/// failed spawn's one `warn`, and the notes the failed spawn's teardown adds.
///
/// The spawn's failure arm hands it to the teardown it runs. A step of that teardown that warns
/// [`fold`](Diagnosis::fold)s it into its text, so the check and the teardown are one record. When
/// no step warns, the diagnosis is logged on its own when it is dropped.
///
/// The keep rule: a child kept without an identity ([`kept_without_identity`]) owes no failure for
/// the check that left it so, so that text is held apart. It leads a fold, and is logged at `debug`
/// if nothing folds it. A note added after the keep is the failure's own, and still warns.
#[derive(Debug, Default)]
pub(crate) struct Diagnosis {
    owed: Option<String>,
    /// The text of the check that left the child kept, taken out of `owed` by the keep.
    kept_check: Option<String>,
    /// The error of the failed check, until [`kept_without_identity`] builds the spawn's error from it.
    failed_check: Option<std::io::Error>,
}

impl Diagnosis {
    /// A diagnosis to carry.
    #[cfg(unix)]
    fn of(text: String) -> Diagnosis {
        Diagnosis {
            owed: Some(text),
            kept_check: None,
            failed_check: None,
        }
    }

    /// A diagnosis of a check that failed with `error`.
    #[cfg(unix)]
    fn of_failed_check(text: String, error: std::io::Error) -> Diagnosis {
        Diagnosis {
            owed: Some(text),
            kept_check: None,
            failed_check: Some(error),
        }
    }

    /// Owe `text` too: the next [`fold`](Diagnosis::fold) leads with it, after what was owed.
    #[cfg(unix)]
    pub(crate) fn add(&mut self, text: impl std::fmt::Display) {
        match &mut self.owed {
            Some(owed) => owed.push_str(&format!("; {text}")),
            None => self.owed = Some(text.to_string()),
        }
    }

    /// Whether the diagnosis is still owed, so a warn that folds it is the event's one warn. The
    /// kept check counts: a teardown only runs for a failed spawn, which it is then part of.
    pub(crate) fn is_owed(&self) -> bool {
        self.owed.is_some() || self.kept_check.is_some()
    }

    /// `text`, led by the kept check and the diagnosis if either is still owed, which they then no
    /// longer are.
    pub(crate) fn fold(&mut self, text: impl std::fmt::Display) -> String {
        let mut parts: Vec<String> = [self.kept_check.take(), self.owed.take()]
            .into_iter()
            .flatten()
            .collect();
        parts.push(text.to_string());
        parts.join("; ")
    }
}

impl Drop for Diagnosis {
    fn drop(&mut self) {
        // Not while unwinding: a logger that panics there would abort.
        if std::thread::panicking() {
            return;
        }
        if let Some(check) = self.kept_check.take() {
            log::debug!("{check}");
        }
        if let Some(diagnosis) = self.owed.take() {
            log::warn!("{diagnosis}");
        }
    }
}

/// The `Unknown` arm of an identity read, for every spawn: the child is kept with no identity, and
/// a containment that needs one fails the attach with the returned error. The error is the failed
/// check's own when the read was `Found` and the check through the handle failed (its error is the
/// source), and the read's `cause` otherwise. The keep is logged at `debug`. The failed check then
/// warns only if a failed attach's teardown folds it in; a note added after the keep warns as usual.
pub(crate) fn kept_without_identity(pid: u32, cause: crate::identity::UnknownCause, why: &mut Diagnosis) -> Error {
    let (error, said) = match why.failed_check.take() {
        // `kept_check` logs the check's error once; this line says only its own layer.
        Some(source) => {
            let error = Error::Unassessable {
                detail: "the spawned child's identity could not be checked against its handle".into(),
                source: Some(Error::io_cause(source)),
            };
            let said = error.to_string();
            (error, said)
        }
        None => {
            let error = spawn_identity_error(crate::identity::Resolved::Unknown, cause);
            let said = crate::error::Report(&error).to_string();
            (error, said)
        }
    };
    log::debug!("child {pid}: {said}; the child is kept without an identity");
    why.kept_check = why.owed.take();
    error
}

/// The unchecked half of [`resolve_identity`]: the read, which nothing has yet shown to name our
/// child, and why it was `Unknown` when the read itself knows. Only `resolve_identity` and tests
/// call it. A test-only fault seam (`fault`) can force the vanished or unreadable branch.
///
/// On Linux the read is of the held pidfd `held`, not a second open of `pid`. Elsewhere it is by
/// pid.
pub(crate) fn resolve_identity_unchecked(
    kernel: &dyn crate::identity::Kernel,
    pid: u32,
    #[cfg(target_os = "linux")] held: std::os::fd::BorrowedFd<'_>,
) -> (crate::identity::Resolved<ProcessId>, crate::identity::UnknownCause) {
    #[cfg(test)]
    {
        if fault::force_identity_unknown() {
            fault::capture(ProcessId::of(pid));
            return (crate::identity::Resolved::Unknown, Default::default());
        }
        if fault::force_identity_vanished() {
            // Capture the child's real identity for the test to check what became of the child,
            // then simulate a vanish so `spawn` takes the identity-failure arm.
            fault::capture(ProcessId::of(pid));
            // The seam simulates a VANISH, not a refusal.
            return (crate::identity::Resolved::Gone, Default::default());
        }
    }
    #[cfg(target_os = "linux")]
    {
        ProcessId::of_held_with(kernel, pid, held)
    }
    #[cfg(not(target_os = "linux"))]
    {
        ProcessId::of_with(kernel, pid)
    }
}

/// `containment::attach` for the child `pid`, whose identity the spawn read (`id`) or could not read
/// (`id` is the read's error, which a containment that needs the identity fails with), with a
/// test-only seam to force its failure.
pub(crate) fn attach_or_fault(
    #[cfg(unix)] pid: u32,
    id: Result<ProcessId, Error>,
    #[cfg(target_os = "linux")] child: crate::containment::ChildHandle<'_>,
    #[cfg(windows)] proc_handle: std::os::windows::io::RawHandle,
    prepared: crate::containment::Prepared,
) -> Result<crate::containment::Attachment, crate::containment::dispatch::AttachFailure> {
    #[cfg(test)]
    if fault::force_attach_failure() {
        // Capture identity for the test to check what became of the child, then simulate an attach
        // failure so `spawn` takes the attach-error arm. The caller still holds the child, so the
        // verdict is taken before `prepared` drops, as a real attach takes it.
        if let Ok(id) = &id {
            fault::capture(crate::identity::Resolved::Found(*id));
        }
        let mut prepared = prepared;
        prepared.settle_verdict(
            #[cfg(target_os = "linux")]
            child,
        );
        // Model a REAL attach failure, which surfaces as `Error::Containment` (not `Error::Io`), so
        // the tests assert production behavior rather than the seam's fabricated variant.
        return Err(Error::Containment {
            detail: "forced attach failure (test seam)".into(),
            source: None,
        }
        .into());
    }
    crate::containment::attach(
        #[cfg(unix)]
        pid,
        id,
        #[cfg(target_os = "linux")]
        child,
        #[cfg(windows)]
        proc_handle,
        prepared,
    )
}

/// `pid {pid}`, or what stands for an unknown one.
#[cfg(target_os = "linux")]
pub(crate) fn named(pid: Option<u32>) -> String {
    match pid {
        Some(pid) => format!("pid {pid}"),
        None => "the spawned child (pid unknown)".to_string(),
    }
}

/// What a failed spawn's teardown did with its child, when that child is an elevation front (see
/// [`crate::elevation::front`]), which it never signals: a kill of it would orphan the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrontFate {
    /// It had exited, or a cgroup leaf's kill ended it, and was reaped.
    Reaped,
    /// It was running, and is left unreaped (it stays a zombie once it exits).
    LeftUnreaped,
    /// It could not be waited on: reaped by someone else, or the wait failed.
    Unaccounted,
    /// Where it is could not be read, so it is not known whether its cgroup's kill ended it. It is
    /// left unreaped.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only a Linux cgroup leaf places a front")
    )]
    Unplaced,
}

impl FrontFate {
    /// The fate of the front a look ([`OwnedChild::look_at_front`](crate::child::owned::OwnedChild::look_at_front))
    /// found: one that is running, or whose place or subtree could not be read, is left (or handed
    /// back) with the elevated program possibly running.
    #[cfg(unix)]
    pub(crate) fn of_look(look: &crate::child::owned::teardown::LookOutcome) -> FrontFate {
        use crate::child::owned::teardown::LookOutcome;
        match look {
            LookOutcome::Ended(settlement) => settlement.front_fate(),
            LookOutcome::LeftRunning => FrontFate::LeftUnreaped,
            LookOutcome::PlaceUnreadable(_) | LookOutcome::SubtreeUnreadable(_) => FrontFate::Unplaced,
        }
    }

    /// The [`Error::MayHaveStarted`] `detail` for the front `pid`; `None` if the child is not a front.
    #[cfg(unix)]
    pub(crate) fn detail(self, front: Option<crate::elevation::front::Front>, pid: Option<u32>) -> Option<String> {
        self.detailing(front, pid, false)
    }

    /// [`detail`](Self::detail) for a front the failed spawn hands back to the caller, in the error,
    /// where `detail` says it is left unreaped.
    #[cfg(unix)]
    pub(crate) fn detail_handed_back(
        self,
        front: Option<crate::elevation::front::Front>,
        pid: Option<u32>,
    ) -> Option<String> {
        self.detailing(front, pid, true)
    }

    #[cfg(unix)]
    fn detailing(
        self,
        front: Option<crate::elevation::front::Front>,
        pid: Option<u32>,
        handed_back: bool,
    ) -> Option<String> {
        let front = front?;
        let what = crate::elevation::front::describe(front, pid);
        // Where the front goes, in the one wording of every teardown (`Disposition::suffix`).
        use crate::child::owned::teardown::Disposition;
        let left = if handed_back {
            Disposition::HandBack
        } else {
            Disposition::Leave
        }
        .suffix(true);
        let fate = match self {
            FrontFate::Reaped => {
                "it was sent no signal of its own; it had exited, or its cgroup's kill ended it, and it was reaped"
                    .to_owned()
            }
            FrontFate::LeftUnreaped => {
                format!("it was sent nothing, so the elevated program may be running{left}")
            }
            FrontFate::Unaccounted if handed_back => {
                format!("it was sent nothing and could not be waited on, so the elevated program may be running{left}")
            }
            FrontFate::Unaccounted => {
                "it was sent nothing and could not be waited on, so the elevated program may be running".to_owned()
            }
            FrontFate::Unplaced => format!(
                "it was sent nothing, and where it is cannot be read, so the elevated program may be running{left}"
            ),
        };
        Some(format!("{what}; {fate}"))
    }
}

/// Settle `prepared`'s placement verdict in a failure arm after the fork, before the child is torn
/// down, so the teardown never races the verdict's reads. A verdict that says the program never ran
/// comes back as the attach's not-started failure.
pub(crate) fn settle_before_teardown(
    prepared: &mut crate::containment::Prepared,
    #[cfg(target_os = "linux")] child: crate::containment::ChildHandle<'_>,
) -> Option<crate::containment::dispatch::AttachFailure> {
    prepared.settle_verdict(
        #[cfg(target_os = "linux")]
        child,
    )
}

/// Linux 6.9+: kill the process group of a failed spawn's root before its teardown, as
/// [`Prepared::kill_group_before_attach`](crate::containment::Prepared::kill_group_before_attach)
/// decides. A refused kill is owed to `why`, the teardown's one warn, which says the group's
/// members may be left running, and which is a failure of the teardown, returned for the error's
/// `cleanup`. Not for an elevation front, which is sent nothing.
#[cfg(target_os = "linux")]
pub(crate) fn kill_group_before_teardown(
    prepared: &crate::containment::Prepared,
    child: crate::containment::ChildHandle<'_>,
    why: &mut Diagnosis,
) -> Option<Failures> {
    let refusal = prepared.kill_group_before_attach(child).err()?;
    note_refused_group_kill(Some(child.pid), refusal, false, why);
    refused_group_kill_failure(child.pid, refusal)
}

/// The failure of a kernel's refusal (`refusal`) of the kill of the process group of the root `pid`.
#[cfg(target_os = "linux")]
pub(crate) fn refused_group_kill_failure(pid: u32, refusal: nix::errno::Errno) -> Option<Failures> {
    Failures::collect([Error::io_cause(crate::error::io_context(
        format!("killing the process group of {}", named(Some(pid))),
        std::io::Error::from(refusal),
    ))])
}

/// Owes `why` a refused kill of the process group of `pid`'s root through its pidfd, which says the
/// group's members may be left running. `reaped`: the root was already reaped, so it may never have
/// run the program. A std-collected failed exec cannot be told from a foreign reap (tokio does not
/// report std's failure), so both warn.
#[cfg(target_os = "linux")]
pub(crate) fn note_refused_group_kill(pid: Option<u32>, refusal: nix::errno::Errno, reaped: bool, why: &mut Diagnosis) {
    let named = named(pid);
    let reaped = if reaped {
        "; the child was already reaped, so it may never have run the program"
    } else {
        ""
    };
    match refusal {
        nix::errno::Errno::EINVAL => why.add(format!(
            "members of the process group of {named} may be left running: the kernel refused \
             PIDFD_SIGNAL_PROCESS_GROUP (EINVAL, expected below Linux 6.9), so nothing was sent to the \
             group, whose number may name another group{reaped}"
        )),
        e => why.add(format!(
            "spawn teardown could not kill the process group of {named} through its pidfd ({}); its \
             members may be left running{reaped}",
            crate::error::Report(&e)
        )),
    }
}

/// macOS: owes `why` that a failed spawn's cleanup sends the process group of the root `pid` nothing,
/// since macOS has no exact kill of a group, so its members may be left running. Only for a root
/// whose group is its containment, which is not an elevation front's.
#[cfg(target_os = "macos")]
pub(crate) fn note_group_left_running(prepared: &crate::containment::Prepared, pid: u32, why: &mut Diagnosis) {
    if prepared.group_is_containment() {
        why.add(format!(
            "members of the process group of pid {pid} may be left running: macOS has no exact kill of a \
             process group, so the group is sent nothing"
        ));
    }
}

/// The subtree of the leaf of an elevation front, captured while the leaf exists: a failure arm
/// drops the leaf, killing it. One that cannot be read leaves the front unplaceable by the arm,
/// which then leaves it unreaped.
#[cfg(target_os = "linux")]
pub(crate) fn front_subtree(
    leaf: Option<&crate::containment::cgroup::CgroupLeaf>,
) -> Option<crate::containment::cgroup::Subtree> {
    match leaf?.subtree() {
        Ok(subtree) => Some(subtree),
        Err(e) => {
            log::debug!(
                "spawn: an elevation front's leaf subtree cannot be read ({report}); its teardown cannot place it",
                report = crate::error::Report(&e)
            );
            None
        }
    }
}

/// Test-only fault injection + assertions for the spawn error-teardown paths, shared by both spawns.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    use crate::identity::ProcessId;
    use crate::relayed_probe::{self, Probe};

    thread_local! {
        static FORCE_VANISH: Cell<bool> = const { Cell::new(false) };
        static FORCE_UNKNOWN: Cell<bool> = const { Cell::new(false) };
        static FORCE_ATTACH_FAIL: Cell<bool> = const { Cell::new(false) };
        #[cfg(unix)]
        static FORCE_REAP_FAIL: Cell<Option<&'static str>> = const { Cell::new(None) };
        static CAPTURED: Cell<Option<crate::identity::Resolved<ProcessId>>> = const { Cell::new(None) };
        static BETWEEN_KILL_AND_WAIT: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static SPAWN_PID: Cell<Option<u32>> = const { Cell::new(None) };
        static BEFORE_IDENTITY: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static BEFORE_ATTACH: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static AFTER_IDENTITY_READ: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        #[cfg(target_os = "macos")]
        static BEFORE_ADOPT: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        #[cfg(target_os = "macos")]
        static BEFORE_LATE_TEARDOWN: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        #[cfg(target_os = "macos")]
        static BEFORE_LATE_ROOT_KILL: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static TEARDOWN_REAPS: std::cell::RefCell<Option<Vec<TeardownReap>>> = const { std::cell::RefCell::new(None) };
    }

    pub(crate) fn set_force_identity_vanished(on: bool) {
        FORCE_VANISH.with(|f| f.set(on));
    }
    /// As [`set_force_identity_vanished`], but the identity read is refused (`Unknown`).
    #[cfg(unix)]
    pub(crate) fn set_force_identity_unknown(on: bool) {
        FORCE_UNKNOWN.with(|f| f.set(on));
    }
    pub(crate) fn force_identity_unknown() -> bool {
        FORCE_UNKNOWN.with(|f| f.get())
    }
    pub(crate) fn force_identity_vanished() -> bool {
        FORCE_VANISH.with(|f| f.get())
    }
    pub(crate) fn set_force_attach_failure(on: bool) {
        FORCE_ATTACH_FAIL.with(|f| f.set(on));
    }
    pub(crate) fn force_attach_failure() -> bool {
        FORCE_ATTACH_FAIL.with(|f| f.get())
    }
    /// Make the next teardown reap on this thread fail with `marker` as its error. TAKE semantics:
    /// the teardown consumes it, and a test that set it asserts it was consumed, so it cannot
    /// outlive the spawn it was meant for.
    #[cfg(unix)]
    pub(crate) fn set_force_reap_failure(marker: &'static str) {
        FORCE_REAP_FAIL.with(|f| f.set(Some(marker)));
    }
    #[cfg(unix)]
    pub(crate) fn take_force_reap_failure() -> Option<&'static str> {
        FORCE_REAP_FAIL.with(|f| f.take())
    }
    pub(crate) fn capture(id: crate::identity::Resolved<ProcessId>) {
        CAPTURED.with(|c| c.set(Some(id)));
    }
    pub(crate) fn take_captured() -> Option<crate::identity::Resolved<ProcessId>> {
        CAPTURED.with(|c| c.take())
    }

    /// Run `hook` at the next kill-then-blocking-wait teardown on this thread, once the kill has
    /// returned `Ok` and before the wait, wherever a spawn's own code waits after its kill.
    /// (`OwnedChild::tear_down` runs the hook of
    /// [`HookPoint::AfterDropKill`](crate::graceful_hooks::HookPoint) there instead.) See
    /// [`release_between_kill_and_wait`] and [`record_teardown_reaps`].
    pub(crate) fn set_between_kill_and_wait(hook: impl FnOnce() + 'static) -> ArmedBetweenKillAndWait {
        crate::oneshot_hook::arm(&BETWEEN_KILL_AND_WAIT, hook)
    }
    pub(crate) fn run_between_kill_and_wait() {
        crate::oneshot_hook::fire(&BETWEEN_KILL_AND_WAIT);
    }
    pub(crate) type ArmedBetweenKillAndWait = crate::oneshot_hook::Armed;

    /// What runs when a thread finds `spawn_lock` held, on any thread.
    #[cfg(target_os = "macos")]
    static ON_SPAWN_LOCK_CONTENDED: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> = std::sync::Mutex::new(None);

    /// Runs `hook` once, on the first thread of this process that then finds `spawn_lock` held, before
    /// that thread blocks on it. The guard drops an unfired hook.
    #[cfg(target_os = "macos")]
    pub(crate) fn on_spawn_lock_contended(hook: impl FnOnce() + Send + 'static) -> ContendedHook {
        let previous = ON_SPAWN_LOCK_CONTENDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(Box::new(hook));
        debug_assert!(previous.is_none(), "a contention hook is already armed");
        ContendedHook(())
    }

    #[cfg(target_os = "macos")]
    #[must_use = "the hook is dropped as soon as the guard is dropped"]
    pub(crate) struct ContendedHook(());

    #[cfg(target_os = "macos")]
    impl Drop for ContendedHook {
        fn drop(&mut self) {
            ON_SPAWN_LOCK_CONTENDED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn spawn_lock_contended() {
        let hook = ON_SPAWN_LOCK_CONTENDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// A point in a spawn where a test can run a hook.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum SpawnPoint {
        /// Right before the spawn reads the child's identity.
        BeforeIdentity,
        /// Right before the spawn attaches the containment.
        BeforeAttach,
        /// Right after the spawn read the child's identity, before it checks the read against the
        /// child's handle.
        AfterIdentityRead,
        /// macOS: right before the spawn adopts the unique id its child reported (builds its
        /// `MacosChild`, or abandons a child it cannot adopt, as a late one), after every descriptor
        /// the spawn held for the report is closed.
        #[cfg(target_os = "macos")]
        BeforeAdopt,
        /// macOS: right before the teardown of a child whose unique id came late.
        #[cfg(target_os = "macos")]
        BeforeLateTeardown,
        /// macOS: in that teardown, after the first kill of the tree and before the root's kill.
        #[cfg(target_os = "macos")]
        BeforeLateRootKill,
    }

    fn hook_at(point: SpawnPoint) -> &'static std::thread::LocalKey<crate::oneshot_hook::OneShotHook> {
        match point {
            SpawnPoint::BeforeIdentity => &BEFORE_IDENTITY,
            SpawnPoint::BeforeAttach => &BEFORE_ATTACH,
            SpawnPoint::AfterIdentityRead => &AFTER_IDENTITY_READ,
            #[cfg(target_os = "macos")]
            SpawnPoint::BeforeAdopt => &BEFORE_ADOPT,
            #[cfg(target_os = "macos")]
            SpawnPoint::BeforeLateTeardown => &BEFORE_LATE_TEARDOWN,
            #[cfg(target_os = "macos")]
            SpawnPoint::BeforeLateRootKill => &BEFORE_LATE_ROOT_KILL,
        }
    }

    /// Run `hook` once at the next `point` on this thread; the guard clears it on drop.
    #[cfg_attr(
        not(any(all(feature = "tokio", target_os = "linux"), windows)),
        allow(
            dead_code,
            reason = "only the Linux async spawn's and the Windows spawn's tests arm a spawn point"
        )
    )]
    pub(crate) fn set_at(point: SpawnPoint, hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
        crate::oneshot_hook::arm(hook_at(point), hook)
    }

    /// Which thread ran the spawn, and whom it had forked, at each [`SpawnPoint`] it passed: a
    /// [`relayed_probe`], so it follows the async spawn onto the blocking pool.
    pub(crate) struct Ran;
    impl Probe for Ran {
        type Event = RanAt;
    }

    /// One report of [`Ran`]: the spawn is at `point` on `thread`, with the child `id` names.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only the async spawn's tests read it")
    )]
    pub(crate) struct RanAt {
        pub(crate) point: SpawnPoint,
        pub(crate) thread: std::thread::ThreadId,
        pub(crate) id: crate::identity::Resolved<ProcessId>,
    }

    /// Install `tx` as this thread's [`Ran`] probe until the guard drops.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only the async spawn's tests install it")
    )]
    pub(crate) fn install_ran(tx: std::sync::mpsc::Sender<RanAt>) -> relayed_probe::Guard<Ran> {
        relayed_probe::install(tx)
    }

    /// Fire the hook armed for `point`, if any. Called by both spawns with the child's pid, which
    /// the hook reads through [`spawn_pid`].
    pub(crate) fn run_at(point: SpawnPoint, pid: u32) {
        if relayed_probe::is_installed::<Ran>() {
            relayed_probe::notify::<Ran>(RanAt {
                point,
                thread: std::thread::current().id(),
                id: ProcessId::of(pid),
            });
        }
        SPAWN_PID.with(|p| p.set(Some(pid)));
        crate::oneshot_hook::fire(hook_at(point));
        SPAWN_PID.with(|p| p.set(None));
    }

    /// The pid of the child the spawn that fired the running hook has just forked.
    #[cfg_attr(
        not(any(all(feature = "tokio", target_os = "linux"), windows)),
        allow(
            dead_code,
            reason = "only the Linux async spawn's and the Windows spawn's tests arm a spawn point"
        )
    )]
    pub(crate) fn spawn_pid() -> u32 {
        SPAWN_PID.with(Cell::get).expect("spawn_pid is read from a spawn hook")
    }

    /// A reaped teardown child's pid and exit status.
    type TeardownReap = (u32, std::process::ExitStatus);

    /// Record the pid and status of every child the teardowns listed at
    /// [`set_between_kill_and_wait`] wait on for real on this thread until the returned guard
    /// drops. A failed wait records nothing.
    pub(crate) fn record_teardown_reaps() -> TeardownReaps {
        let previous = TEARDOWN_REAPS.with(|r| r.borrow_mut().replace(Vec::new()));
        debug_assert!(previous.is_none(), "teardown reaps are already being recorded");
        TeardownReaps
    }
    pub(crate) fn record_teardown_reap(pid: u32, status: std::process::ExitStatus) {
        TEARDOWN_REAPS.with(|r| {
            if let Some(reaps) = r.borrow_mut().as_mut() {
                reaps.push((pid, status));
            }
        });
    }
    /// Stops the [`record_teardown_reaps`] recording on drop.
    #[must_use]
    pub(crate) struct TeardownReaps;
    impl TeardownReaps {
        /// The `(pid, status)` of each reap recorded so far, oldest first.
        pub(crate) fn recorded(&self) -> Vec<TeardownReap> {
            TEARDOWN_REAPS.with(|r| r.borrow().clone().unwrap_or_default())
        }

        /// At least one child was reaped, and each died of `SIGKILL` (Unix) or exit code 1
        /// (Windows): killed by the teardown, not merely reaped once it exited on its own.
        pub(crate) fn assert_killed(&self) {
            let reaps = self.recorded();
            assert!(!reaps.is_empty(), "the teardown must have reaped the child");
            for (pid, status) in reaps {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt as _;
                    assert_eq!(
                        status.signal(),
                        Some(libc::SIGKILL),
                        "pid {pid} must be SIGKILLed by its teardown kill, not merely reaped once it exits on its own: {status:?}"
                    );
                }
                #[cfg(windows)]
                assert_eq!(
                    status.code(),
                    Some(1),
                    "pid {pid} must be terminated by its teardown kill (`TerminateProcess` exits 1), not merely reaped once it exits on its own: {status:?}"
                );
            }
        }
    }
    impl Drop for TeardownReaps {
        fn drop(&mut self) {
            let reaps = TEARDOWN_REAPS.with(|r| r.borrow_mut().take());
            drop(reaps);
        }
    }

    /// A stdin for a child only a kill ends, its writer released as [`release_between_kill_and_wait`]
    /// does. Keep the guard alive through the assertion: dropping it clears the hook and recorder.
    ///
    /// The child is a `BLOCKER_ARGV` one, with a null stdout on Windows, because `more` echoes. Use
    /// [`teardown_blocker_parts`] to get the whole child.
    pub(crate) fn teardown_blocker_stdin() -> (crate::stdio::Stdio, TeardownBlocker) {
        let (reader, writer) = std::io::pipe().expect("pipe");
        #[cfg(unix)]
        let reader = std::os::fd::OwnedFd::from(reader);
        #[cfg(windows)]
        let reader = std::os::windows::io::OwnedHandle::from(reader);
        (
            crate::stdio::Stdio::from_file(std::fs::File::from(reader)),
            release_between_kill_and_wait(writer),
        )
    }

    /// [`teardown_blocker_stdin`] for a child a test already spawned; `held` is whatever only a kill
    /// ends the child without (its stdin writer, a control socket). It is dropped between the code
    /// under test's kill and its blocking wait ([`set_between_kill_and_wait`]), so a kill that sent
    /// nothing exits 0 and fails [`TeardownBlocker::assert_killed`] instead of hanging the wait.
    /// The reaps it makes are recorded. Arm it before the code under test runs and keep the guard
    /// through the assertion.
    ///
    /// The kill-then-wait of `OwnedChild::tear_down` runs its release at the root kill's return
    /// ([`release_at_drop_kill`]'s point), so `held` is released there too: whichever point the
    /// teardown reaches first drops it.
    pub(crate) fn release_between_kill_and_wait(held: impl Sized + 'static) -> TeardownBlocker {
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let held = std::rc::Rc::new(std::cell::Cell::new(Some(held)));
        let hook = || {
            let (held, fired) = (std::rc::Rc::clone(&held), std::rc::Rc::clone(&fired));
            move || {
                drop(held.take());
                fired.set(true);
            }
        };
        let between = set_between_kill_and_wait(hook());
        let after_kill = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterDropKill, hook());
        TeardownBlocker {
            _release: vec![between, after_kill],
            fired,
            reaps: record_teardown_reaps(),
        }
    }

    /// [`release_between_kill_and_wait`] for the sync `Child`'s kill-on-drop teardown, whose root
    /// kill is followed by a blocking wait inside `drop`: `held` is dropped once that kill returned.
    pub(crate) fn release_at_drop_kill(held: impl Sized + 'static) -> TeardownBlocker {
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let release = crate::graceful_hooks::at(
            crate::graceful_hooks::HookPoint::AfterDropKill,
            release_hook(held, &fired),
        );
        TeardownBlocker {
            _release: vec![release],
            fired,
            reaps: record_teardown_reaps(),
        }
    }

    /// Releases the writer in `held` at every point where a sync teardown, a failed spawn's cleanup
    /// or a graceful shutdown waits for a root it has killed: after the drop's kill, before the
    /// shutdown's reap, between a kill and its wait. Once the kill returned, a root held only by
    /// that writer exits by itself, so a kill that sent nothing fails the test's assertion on what
    /// the kill should have ended instead of hanging the wait. Keep the guard through the teardown.
    /// `held` is a shared cell so the test can also release it by hand.
    #[cfg(target_os = "linux")]
    pub(crate) fn release_when_a_teardown_waits<T: 'static>(
        held: &std::rc::Rc<std::cell::Cell<Option<T>>>,
    ) -> Box<dyn std::any::Any> {
        use crate::graceful_hooks::{at, HookPoint};
        let release = || {
            let held = std::rc::Rc::clone(held);
            move || drop(held.take())
        };
        Box::new((
            at(HookPoint::AfterDropKill, release()),
            at(HookPoint::BeforeReap, release()),
            set_between_kill_and_wait(release()),
        ))
    }

    fn release_hook(held: impl Sized + 'static, fired: &std::rc::Rc<std::cell::Cell<bool>>) -> impl FnOnce() + 'static {
        let fired = std::rc::Rc::clone(fired);
        move || {
            drop(held);
            fired.set(true);
        }
    }

    /// Everything a test needs to configure a [`teardown_blocker_stdin`] child on either
    /// `Command` type: apply `argv`, `stdin`, and `stdout` when it is `Some`.
    pub(crate) struct TeardownBlockerParts {
        pub(crate) argv: Vec<std::ffi::OsString>,
        pub(crate) stdin: crate::stdio::Stdio,
        pub(crate) stdout: Option<crate::stdio::Stdio>,
        pub(crate) guard: TeardownBlocker,
    }

    /// The argv and stdio of a [`teardown_blocker_stdin`] child, for the sync and async `Command`.
    pub(crate) fn teardown_blocker_parts() -> TeardownBlockerParts {
        let (stdin, guard) = teardown_blocker_stdin();
        #[cfg(unix)]
        let stdout = None;
        #[cfg(windows)]
        let stdout = Some(crate::stdio::Stdio::null());
        TeardownBlockerParts {
            argv: crate::test_child::BLOCKER_ARGV.iter().map(Into::into).collect(),
            stdin,
            stdout,
            guard,
        }
    }

    /// See [`teardown_blocker_stdin`].
    #[must_use]
    pub(crate) struct TeardownBlocker {
        _release: Vec<crate::oneshot_hook::Armed>,
        fired: std::rc::Rc<std::cell::Cell<bool>>,
        reaps: TeardownReaps,
    }
    impl TeardownBlocker {
        /// The `(pid, status)` of each reap the teardown recorded so far.
        #[cfg(unix)]
        pub(crate) fn recorded(&self) -> Vec<TeardownReap> {
            self.reaps.recorded()
        }

        /// The teardown's kill fired the release hook, and every child it reaped died of
        /// `SIGKILL` (Unix) or exit code 1 (Windows).
        pub(crate) fn assert_killed(&self) {
            assert!(
                self.fired.get(),
                "the teardown must have reached its release hook (the kill returned)"
            );
            self.reaps.assert_killed();
        }

        /// The release hook fired: the teardown's kill returned. For a teardown whose reap is not
        /// recorded (the kernel's, or forced to fail).
        #[cfg(target_os = "macos")]
        pub(crate) fn assert_released(&self) {
            assert!(
                self.fired.get(),
                "the teardown must have reached its release hook (the kill returned)"
            );
        }

        /// [`assert_killed`](Self::assert_killed) without requiring the release hook to have fired,
        /// for a teardown whose own kill may find the child already dying (a job object's close).
        #[cfg(windows)]
        pub(crate) fn assert_reaps_killed(&self) {
            self.reaps.assert_killed();
        }
    }

    /// Assert the spawned child was fully torn down — reuse-immune, via the child's stable identity
    /// (pid + start token). On Unix a not-yet-reaped zombie keeps that identity (Linux /proc
    /// persists; macOS `sysctl KERN_PROC` resolves zombies) → caught on ALL Unix; a reaped pid
    /// resolves to `None` or a *different* identity → passes, so a
    /// recycled pid never false-fails. Windows has no zombies, and its process-object cleanup is not
    /// synchronous with `wait()`, so there we assert only that the child is dead (`!is_alive()`, also
    /// reuse-immune via the start token).
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn assert_child_reaped(captured: crate::identity::Resolved<ProcessId>) {
        let crate::identity::Resolved::Found(captured) = captured else {
            panic!("the seam must capture a resolved identity, got {captured:?}");
        };
        #[cfg(unix)]
        match ProcessId::of(captured.pid()) {
            crate::identity::Resolved::Found(id) => assert_ne!(
                id, captured,
                "a failed spawn must fully reap its child (no lingering zombie at its identity)"
            ),
            crate::identity::Resolved::Gone => {}
            // NOT a panic: once the child is reaped its pid is free host-wide, so a recycle
            // between the failed `/proc` read and the `kill(pid, 0)` probe legitimately
            // yields Unknown. What matters is only that the pid no longer resolves to OUR
            // identity, and an unreadable stranger is not our child either.
            crate::identity::Resolved::Unknown => {}
        }
        #[cfg(windows)]
        assert_eq!(
            captured.is_alive(),
            crate::identity::Liveness::Dead,
            "a failed spawn must leave the child dead"
        );
    }
}

// The `.bat`/`.cmd` refusal every backend runs before it spawns.
#[path = "spawn/batch_gate.rs"]
mod batch_gate;
pub(crate) use batch_gate::reject_batch_path;

// cosca-owned fd mapping (replaces `command-fds` — see the module docs).
#[cfg(unix)]
#[path = "spawn/fd_map.rs"]
pub(crate) mod fd_map;

// The environment a unix child gets, and the one search that reads its `PATH`.
#[cfg(unix)]
#[path = "spawn/child_env.rs"]
mod child_env;
#[cfg(unix)]
#[path = "spawn/lookup.rs"]
mod lookup;

// Every in-child step of a spawn: one `pre_exec` hook on macOS, the steps of the fork-exec core on Linux.
#[cfg(unix)]
#[path = "spawn/in_child.rs"]
pub(crate) mod in_child;

// macOS: the `pre_exec` fd-channel primitive of `unique_report`.
#[cfg(target_os = "macos")]
#[path = "spawn/fd_channel.rs"]
pub(crate) mod fd_channel;

// Linux: the one fork that execs, on `fork_with_pidfd`.
#[cfg(target_os = "linux")]
#[path = "spawn/fork_exec.rs"]
pub(crate) mod fork_exec;

// Linux: the ordinary spawn, on the fork-exec core.
#[cfg(target_os = "linux")]
#[path = "spawn/fork_spawn.rs"]
mod fork_spawn;

// A failed spawn's answer to whether the program could have started.
#[path = "spawn/failure.rs"]
pub(crate) mod failure;

// What a spawn is told about the teardowns of the child it makes.
#[path = "spawn/policy.rs"]
pub(crate) mod policy;

#[path = "spawn/held_teardown.rs"]
pub(crate) mod held_teardown;

#[cfg(target_os = "macos")]
#[path = "spawn/late_child.rs"]
mod late_child;

// Windows raw `CreateProcessW` spawn backend.
#[cfg(windows)]
#[path = "spawn/windows_raw.rs"]
pub(crate) mod windows_raw;

// Windows: a child-side handle that may be absent.
#[cfg(windows)]
#[path = "spawn/windows_child_end.rs"]
mod windows_child_end;

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;

#[cfg(test)]
#[path = "spawn/spawn_lock_tests.rs"]
mod spawn_lock_tests;

#[cfg(all(test, unix))]
#[path = "spawn/exact_posix_tests.rs"]
mod exact_posix_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/identity_error_tests.rs"]
mod identity_error_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "spawn/identity_macos_tests.rs"]
pub(crate) mod identity_macos_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "spawn/late_report_tests.rs"]
pub(crate) mod late_report_tests;

#[cfg(target_os = "macos")]
#[path = "spawn/unique_report.rs"]
pub(crate) mod unique_report;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/held_teardown_tests.rs"]
mod held_teardown_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/identity_group_tests.rs"]
pub(crate) mod identity_group_tests;
