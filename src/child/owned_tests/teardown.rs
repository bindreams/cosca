//! The teardown policy of `OwnedChild` over a `FakeProcess` (see `owned::teardown`).

use std::process::ExitStatus;

use crate::child::owned::teardown::{Disposition, TeardownKind, TeardownOutcome};
use crate::child::owned::OwnedChild;
use crate::error::ChildFate;
use crate::identity::ProcessId;
use crate::os_process::child::{ExitRecord, Foreign};
use crate::os_process::fake::{Answer, FakeProcess, ReapAnswer};
use crate::signal::Sent;
use crate::wait::teardown_warn::Due;

pub(super) const PID: u32 = 4242;

pub(super) fn id() -> ProcessId {
    ProcessId::from_parts(PID, 1)
}

/// A fake that states the pid, and nothing else.
pub(super) fn fake() -> FakeProcess {
    FakeProcess::new([]).with_pid(PID)
}

pub(super) fn exit() -> ExitRecord {
    ExitRecord::Status(ExitStatus::default())
}

/// What `tear_down(id, Kill, due)` returned over `fake`, and everything it logged on this thread.
fn tear_down_logged(
    fake: &FakeProcess,
    id: Option<ProcessId>,
    due: Option<Due>,
) -> (TeardownOutcome, Vec<(log::Level, String)>) {
    crate::log_capture::install();
    let child = OwnedChild::new(Box::new(fake.clone()));
    let mark = crate::log_capture::mark();
    let torn = child.tear_down(id, TeardownKind::Kill(Disposition::Leave), due);
    (torn, crate::log_capture::records_since_on_current_thread(mark, ""))
}

/// [`tear_down_logged`] for a child of identity [`id`] and no threshold, with the levels it logged
/// for its child.
fn teardown(fake: &FakeProcess) -> (TeardownOutcome, Vec<log::Level>) {
    let (torn, records) = tear_down_logged(fake, Some(id()), None);
    let levels = records
        .into_iter()
        .filter(|(_, text)| text.contains(&PID.to_string()))
        .map(|(level, _)| level)
        .collect();
    (torn, levels)
}

/// [`teardown`] with the kill delivered and the reap after it answering `reap`.
fn teardown_when_the_reap_answers(reap: ReapAnswer) -> (TeardownOutcome, Vec<log::Level>) {
    teardown(&fake().reaps([reap]).signals([Ok(Sent::Delivered)]))
}

/// Turns a wait that blocks into a recorded fact: the fake's wait is fired as the block begins, so
/// a teardown that waits where it must not fails the count instead of hanging. The count starts
/// empty: a block an earlier test left on this thread is dropped.
pub(super) fn fire_on_block(fake: &FakeProcess) -> crate::wait::block_probe::Armed {
    crate::wait::block_probe::take();
    let fake = fake.clone();
    crate::wait::block_probe::on_blocking(move || fake.wake())
}

/// A reap that fails after the kill is not dropped silently: it is returned for the caller's one
/// warn, and logged by nobody here.
///
/// Mutants: `_ = s.wait()`; the teardown warns on its own.
#[skuld::test]
fn a_failed_teardown_reap_is_returned_and_not_logged() {
    let (torn, levels) = teardown_when_the_reap_answers(ReapAnswer::Err(std::io::ErrorKind::Other));
    assert!(
        torn.left
            .as_deref()
            .is_some_and(|text| text.contains("the reap after the kill failed")),
        "{torn:?}"
    );
    assert_eq!(torn.fate, ChildFate::Killed, "the kill was delivered: {torn:?}");
    assert_eq!(levels, Vec::<log::Level>::new());
}

/// A reap that finds the child collected by someone else is logged at `debug` and returns nothing.
///
/// Mutant: every failure is returned; or none logged.
#[skuld::test]
fn a_teardown_reap_that_meets_a_foreign_reap_is_debug() {
    let (torn, levels) = teardown_when_the_reap_answers(ReapAnswer::Foreign(Foreign::Gone));
    assert_eq!(torn.left, None);
    assert_eq!(levels, vec![log::Level::Debug]);
}

/// A reap after a delivered kill that finds launchd holding the child's zombie: the child is
/// `Killed`, and the launchd note comes back for the caller's one warn, not logged here.
///
/// Mutants: the foreign arm drops the note; the teardown warns of it on its own.
#[skuld::test]
fn a_reap_after_a_delivered_kill_that_meets_launchd_returns_the_note_and_logs_nothing_above_debug() {
    let (torn, levels) = teardown_when_the_reap_answers(ReapAnswer::Foreign(Foreign::Orphaned));
    assert_eq!(torn.fate, ChildFate::Killed, "{torn:?}");
    assert!(
        torn.left
            .as_deref()
            .is_some_and(|text| text.contains(&PID.to_string()) && text.contains("launchd")),
        "{torn:?}"
    );
    assert!(levels.iter().all(|level| *level >= log::Level::Debug), "{levels:?}");
}

/// A reap after a tree kill that was delivered meets a foreign reap: someone else collected the
/// exit after the kill, which is `Killed`, never `Gone` (the fate of a child cosca delivered
/// nothing to).
///
/// Mutant: the foreign arm answers `Gone`.
#[cfg(unix)]
#[skuld::test]
fn a_reap_after_a_delivered_tree_kill_that_meets_a_foreign_reap_is_killed() {
    let fake = fake().reaps([ReapAnswer::Foreign(Foreign::Gone)]);
    let torn = OwnedChild::new(Box::new(fake)).reap_after_tree_kill();
    assert_eq!(torn.fate, ChildFate::Killed);
    assert_eq!(torn.left, None);
}

/// A reap after a tree kill reaps the child once, with a blocking wait, and says so.
///
/// Mutant: the reap is a look at the present moment, so a child still dying is `Running`.
#[cfg(unix)]
#[skuld::test]
fn a_reap_after_a_tree_kill_waits_for_the_exit() {
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let _fire = fire_on_block(&fake);
    let torn = OwnedChild::new(Box::new(fake.clone())).reap_after_tree_kill();
    assert_eq!(torn.fate, ChildFate::Reaped);
    assert_eq!(torn.left, None);
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A kill that delivered nothing (the child was reaped behind the handle's back), then a wait that
/// fails for another reason, shows nothing of what became of the child: `Unknown`, not `Killed`.
/// The same on every OS.
///
/// Mutant: a failed wait is `Killed` whatever the kill did.
#[skuld::test]
fn a_failed_wait_after_a_kill_that_delivered_nothing_is_unknown() {
    let fake = fake()
        .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
        .signals([Ok(Sent::Gone)]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Unknown);
}

/// A kill that was delivered is followed by a blocking wait through the child's own `try_reap`, and
/// the exit it finds is `Reaped`.
///
/// Mutants: the wait is a look at the present moment; the teardown never waits.
#[skuld::test]
fn teardown_after_a_delivered_kill_waits_through_try_reap() {
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _fire = fire_on_block(&fake);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Reaped);
    assert_eq!(torn.left, None);
    assert_eq!(fake.looks(), 2, "a look, then the look the wait woke to");
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A kill that found nothing to signal (the child is exiting or reaped) is followed by the same
/// blocking wait.
///
/// Mutant: the wait follows `Delivered` only.
#[skuld::test]
fn teardown_after_a_kill_that_found_nothing_to_signal_waits_too() {
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Gone)]);
    let _fire = fire_on_block(&fake);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Reaped);
    assert_eq!(fake.looks(), 2);
}

/// The `left` text of a teardown whose kill is refused and whose child still runs, under `disposition`.
fn left_of_a_refused_kill_of_a_running_child(disposition: Disposition) -> String {
    let fake = fake()
        .reaps([ReapAnswer::Running])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let child = OwnedChild::new(Box::new(fake));
    let torn = child.tear_down(Some(id()), TeardownKind::Kill(disposition), None);
    assert_eq!(torn.fate, ChildFate::Running { id: Some(id()) }, "{torn:?}");
    torn.left.expect("a refused kill of a running child is warned of")
}

/// A child to be handed back says so, and does not say it is left running.
///
/// Mutants: the text ignores the disposition; it drops the child or the refusal.
#[skuld::test]
fn a_refused_kill_of_a_child_to_be_handed_back_says_so() {
    let refusal = std::io::Error::from(std::io::ErrorKind::PermissionDenied).to_string();
    let left = left_of_a_refused_kill_of_a_running_child(Disposition::HandBack);
    assert!(
        left.contains(&PID.to_string()) && left.contains(&refusal) && left.contains("handed back to the caller"),
        "{left}"
    );
    assert!(!left.contains("leaving it running"), "{left}");
}

/// A child to be left says so.
///
/// Mutant: the text always says the child is handed back.
#[skuld::test]
fn a_refused_kill_of_a_child_to_be_left_says_it_is_left_running() {
    let left = left_of_a_refused_kill_of_a_running_child(Disposition::Leave);
    assert!(left.contains("leaving it running"), "{left}");
    assert!(!left.contains("handed back"), "{left}");
}

/// A kill that failed, whatever the error, is followed by one look and no wait, and a child still
/// running is `Running` with the failure named for the caller's one warn.
///
/// Mutants: the failed kill is followed by a wait; the look is skipped; only `PermissionDenied`
/// names its error; the warn drops the error or the pid.
#[skuld::test]
fn teardown_after_a_refused_kill_looks_once_and_never_waits() {
    use std::io::ErrorKind::{InvalidInput, NotFound, Other, PermissionDenied};

    for kind in [PermissionDenied, NotFound, InvalidInput, Other] {
        let fake = fake()
            .reaps([ReapAnswer::Running])
            .signals([Err(std::io::Error::new(kind, "refused for the test"))]);
        let _fire = fire_on_block(&fake);
        let (torn, _) = teardown(&fake);
        assert_eq!(torn.fate, ChildFate::Running { id: Some(id()) }, "{kind:?}: {torn:?}");
        let left = torn.left.as_deref().unwrap_or_default();
        assert!(
            left.contains(&PID.to_string()) && left.contains("refused for the test"),
            "{kind:?}: the warning names the child and the error: {torn:?}"
        );
        assert_eq!(fake.looks(), 1, "{kind:?}: one look");
        assert_eq!(
            crate::wait::block_probe::take(),
            [],
            "{kind:?}: a failed kill is never followed by a wait"
        );
    }
}

/// A kill that failed on a child that has exited: the look collects it, and there is nothing to
/// warn of.
///
/// Mutant: the warning is returned whenever the kill failed.
#[skuld::test]
fn teardown_after_a_refused_kill_of_an_exited_child_reaps_it_silently() {
    let fake = fake()
        .reaps([ReapAnswer::Reaped(exit())])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Reaped);
    assert_eq!(torn.left, None);
    assert_eq!(fake.looks(), 1);
}

/// The look after a failed kill that fails itself is `Unknown`, and the warning names the look's
/// error: the child is not shown to be running, so it does not claim to leave it running.
///
/// Mutants: a failed look is read as an exit; the warning claims the child runs, or drops the look's
/// error.
#[skuld::test]
fn teardown_after_a_refused_kill_with_a_failed_look_is_unknown() {
    let look_error = std::io::Error::from(std::io::ErrorKind::Other).to_string();
    let fake = fake()
        .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Unknown);
    let left = torn.left.as_deref().expect("a failed look is warned of");
    assert!(
        left.contains(&PID.to_string()) && left.contains(&look_error),
        "{torn:?}"
    );
    assert!(!left.contains("leaving it running"), "{torn:?}");
}

/// A kill that failed on a child someone else already reaped: the look finds `ECHILD`, the child is
/// `Gone`, and there is no warning that it is left running.
///
/// Mutant: the warning is returned for every look that did not collect an exit; the fate is read
/// from the look's raw OS error, which only Unix has.
#[skuld::test]
fn teardown_after_a_refused_kill_of_a_child_reaped_elsewhere_is_gone_and_silent() {
    let fake = fake()
        .reaps([ReapAnswer::Foreign(Foreign::Gone)])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Gone);
    assert_eq!(torn.left, None);
    assert_eq!(fake.looks(), 1);
}

/// A kill that failed on a child launchd holds the zombie of: the look finds `Orphaned`, the child is
/// `Gone`, and nothing is warned of or logged above `debug`.
///
/// Mutants: the look warns of the launchd orphan; it reads the fate from the error (`Unknown` off
/// Unix).
#[skuld::test]
fn teardown_after_a_refused_kill_of_a_child_launchd_holds_is_gone_and_silent() {
    let fake = fake()
        .reaps([ReapAnswer::Foreign(Foreign::Orphaned)])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, levels) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Gone);
    assert_eq!(torn.left, None);
    assert!(levels.iter().all(|level| *level >= log::Level::Debug), "{levels:?}");
    assert_eq!(fake.looks(), 1);
}

/// A threshold that has already passed: the wait warns unless the child has exited.
pub(super) fn due_now() -> Due {
    Due {
        until: crate::wait::now(),
        after: std::time::Duration::from_secs(7),
    }
}

/// The records that are the slow-teardown warn.
pub(super) fn slow_warns(records: &[(log::Level, String)]) -> Vec<&String> {
    records
        .iter()
        .filter(|(level, text)| *level == log::Level::Warn && text.contains("after its kill"))
        .map(|(_, text)| text)
        .collect()
}

/// A refused kill with no identity read leaves a running child without one.
///
/// Mutant: the outcome carries a made-up identity.
#[skuld::test]
fn a_kill_teardown_without_an_id_leaves_a_running_child_without_one() {
    let fake = fake()
        .reaps([ReapAnswer::Running])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = tear_down_logged(&fake, None, None);
    assert_eq!(torn.fate, ChildFate::Running { id: None });
}

/// A child with no pid is named without a number.
///
/// Mutants: a pid is made up; the message is built with a number.
#[skuld::test]
fn a_pidless_child_is_named_without_a_number() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = tear_down_logged(&fake, None, None);
    let left = torn.left.as_deref().expect("a refused kill is warned of");
    assert!(left.contains(crate::os_process::PIDLESS_CHILD), "{left}");
    assert!(!left.chars().any(|c| c.is_ascii_digit()), "{left}");
}

/// Without a threshold the wait is the blocking wait alone: nothing looks for the exit first.
///
/// Mutant: the teardown looks for the exit whatever the threshold (the empty `exited` table
/// panics).
#[skuld::test]
fn a_teardown_without_a_threshold_never_looks_for_the_exit() {
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _fire = fire_on_block(&fake);
    let (torn, _) = tear_down_logged(&fake, Some(id()), None);
    assert_eq!(torn.fate, ChildFate::Reaped);
    assert_eq!(fake.looks(), 2);
}

/// A child that has not exited by the threshold is warned of once, before the wait blocks, and the
/// wait still ends with its exit.
///
/// Mutants: the warn comes after the block; no warn; the wait ends at the threshold.
#[skuld::test]
fn a_teardown_past_its_threshold_warns_once_before_it_blocks() {
    let fake = FakeProcess::new([Answer::Running])
        .with_pid(PID)
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _fire = fire_on_block(&fake);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate, ChildFate::Reaped);
    let warns = slow_warns(&records);
    assert!(
        warns.len() == 1 && warns[0].contains(&format!("child {PID}")),
        "{records:?}"
    );
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A child that exits before the threshold is not warned of.
///
/// Mutant: the warn is not conditional on the look.
#[skuld::test]
fn a_wait_that_ends_before_the_threshold_does_not_warn() {
    let fake = FakeProcess::new([Answer::Exited])
        .with_pid(PID)
        .reaps([ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate, ChildFate::Reaped);
    assert_eq!(slow_warns(&records), Vec::<&String>::new());
}

/// A refused kill is followed by one look and never a wait, so it never looks for the exit, whatever
/// the threshold.
///
/// Mutant: the refused kill's look goes through the threshold's wait (the empty `exited` table
/// panics).
#[skuld::test]
fn a_refused_kill_never_looks_for_the_exit_whatever_the_threshold() {
    let fake = fake()
        .reaps([ReapAnswer::Running])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate, ChildFate::Running { id: Some(id()) });
    assert_eq!(fake.looks(), 1);
    assert_eq!(slow_warns(&records), Vec::<&String>::new());
}

/// A kill teardown counts as one root teardown.
///
/// Mutant: the count is dropped from the policy.
#[skuld::test]
fn a_kill_teardown_counts_one_root_teardown() {
    let recorder = crate::child::owned::seams::record_root_teardowns();
    let fake = fake()
        .reaps([ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _ = teardown(&fake);
    assert_eq!(recorder.count(), 1);
}

/// A look at the exit that cannot be read does not stop the wait: it answers "ended" and the wait
/// finds out. The failed look is logged at `debug`.
///
/// Mutant: a failed look is an exit that is never waited for, or aborts the teardown; or is dropped
/// unlogged.
#[skuld::test]
fn an_unreadable_exit_look_does_not_stop_the_wait() {
    let fake = FakeProcess::new([Answer::Err(std::io::ErrorKind::Other)])
        .with_pid(PID)
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _fire = fire_on_block(&fake);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate, ChildFate::Reaped);
    assert_eq!(slow_warns(&records), Vec::<&String>::new());
    assert_eq!(crate::wait::block_probe::take(), [None], "the wait still ran");
    let cause = std::io::Error::from(std::io::ErrorKind::Other).to_string();
    assert!(
        records
            .iter()
            .any(|(level, text)| *level == log::Level::Debug && text.contains("child 4242") && text.contains(&cause)),
        "{records:?}"
    );
}
