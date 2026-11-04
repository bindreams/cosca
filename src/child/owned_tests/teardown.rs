//! The teardown policy of `OwnedChild` over a `FakeProcess`: one policy for every OS, decided by
//! what the kill answered. A kill that was delivered, or found nothing to signal, is followed by a
//! blocking wait; a kill that failed by one non-blocking look.

use std::process::ExitStatus;

use crate::child::owned::teardown::TeardownOutcome;
use crate::child::owned::OwnedChild;
use crate::error::ChildFate;
use crate::identity::ProcessId;
use crate::os_process::child::{ExitRecord, Foreign};
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::signal::Sent;

const PID: u32 = 4242;

fn id() -> ProcessId {
    ProcessId::from_parts(PID, 1)
}

fn exit() -> ExitRecord {
    ExitRecord::Status(ExitStatus::default())
}

/// What `teardown_on_drop` returned over `fake`, and the levels it logged for its child.
fn teardown(fake: &FakeProcess) -> (TeardownOutcome, Vec<log::Level>) {
    crate::log_capture::install();
    let child = OwnedChild::new(Box::new(fake.clone()));
    let mark = crate::log_capture::mark();
    let torn = child.teardown_on_drop(id());
    let levels = crate::log_capture::records_since_on_current_thread(mark, &format!("teardown of child {PID}"))
        .into_iter()
        .map(|(level, _)| level)
        .collect();
    (torn, levels)
}

/// What the teardown returned and the levels it logged, with the kill delivered and the reap after
/// it answering `reap`.
fn teardown_when_the_reap_answers(reap: ReapAnswer) -> (TeardownOutcome, Vec<log::Level>) {
    teardown(&FakeProcess::new([]).reaps([reap]).signals([Ok(Sent::Delivered)]))
}

/// Turns a wait that blocks into a recorded fact: the fake's wait is fired as the block begins, so
/// a teardown that waits where it must not fails the count instead of hanging.
fn fire_on_block(fake: &FakeProcess) -> crate::wait::block_probe::Armed {
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

/// A reap after a tree kill that was delivered meets a foreign reap: someone else collected the
/// exit after the kill, which is `Killed`, never `Gone` (the fate of a child cosca delivered
/// nothing to).
///
/// Mutant: the foreign arm answers `Gone`.
#[cfg(unix)]
#[skuld::test]
fn a_reap_after_a_delivered_tree_kill_that_meets_a_foreign_reap_is_killed() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Foreign(Foreign::Gone)]);
    let torn = OwnedChild::new(Box::new(fake)).reap_after_tree_kill(PID);
    assert_eq!(torn.fate, ChildFate::Killed);
    assert_eq!(torn.left, None);
}

/// A reap after a tree kill reaps the child once, with a blocking wait, and says so.
///
/// Mutant: the reap is a look at the present moment, so a child still dying is `Running`.
#[cfg(unix)]
#[skuld::test]
fn a_reap_after_a_tree_kill_waits_for_the_exit() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let _fire = fire_on_block(&fake);
    let torn = OwnedChild::new(Box::new(fake.clone())).reap_after_tree_kill(PID);
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
    let fake = FakeProcess::new([])
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
    let fake = FakeProcess::new([])
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
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Gone)]);
    let _fire = fire_on_block(&fake);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Reaped);
    assert_eq!(fake.looks(), 2);
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
        let fake = FakeProcess::new([])
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
    let fake = FakeProcess::new([])
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
    let fake = FakeProcess::new([])
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
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Foreign(Foreign::Gone)])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate, ChildFate::Gone);
    assert_eq!(torn.left, None);
    assert_eq!(fake.looks(), 1);
}
