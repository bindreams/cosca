//! `Unreaped` over a `FakeProcess`: a call past a fake's table panics, which is how a test notices
//! a second wait on a child that was already consumed.

use super::teardown::{exit, fake, fire_on_block, id, PID};
use crate::child::owned::unreaped::Unreaped;
use crate::child::owned::OwnedChild;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::os_process::PIDLESS_CHILD;

// `Error` carries an `Unreaped`, and users move errors across threads.
static_assertions::assert_impl_all!(Unreaped: Send, Sync);

fn unreaped(fake: &FakeProcess, id: Option<ProcessId>) -> Unreaped {
    Unreaped::new(OwnedChild::new(Box::new(fake.clone())), id)
}

/// What dropping an `Unreaped` over a child that runs and then answers `reap` logged on this
/// thread, and the timeouts of the blocks it made.
fn dropped_when_the_reap_answers(
    fake: FakeProcess,
    reap: ReapAnswer,
) -> (Vec<(log::Level, String)>, Vec<Option<std::time::Duration>>) {
    crate::log_capture::install();
    let fake = fake.reaps([ReapAnswer::Running, reap]);
    let _fire = fire_on_block(&fake);
    let child = unreaped(&fake, Some(id()));
    let mark = crate::log_capture::mark();
    drop(child);
    (
        crate::log_capture::records_since_on_current_thread(mark, ""),
        crate::wait::block_probe::take(),
    )
}

/// `wait` blocks once, without a deadline, for the exit and returns its status; the consumed value
/// then looks at nothing more.
///
/// Mutants: `wait` is a look; the drop that follows waits again (the fake's table is empty).
#[skuld::test]
fn wait_blocks_until_the_child_exits_and_returns_its_status() {
    crate::log_capture::install();
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let _fire = fire_on_block(&fake);
    let child = unreaped(&fake, Some(id()));
    let mark = crate::log_capture::mark();
    let status = child.wait().expect("the child exits");
    assert!(status.success());
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
    assert_eq!(crate::log_capture::records_since_on_current_thread(mark, ""), []);
}

/// A failed `wait` is returned once; the drop of the consumed value does not wait again.
///
/// Mutant: `wait` leaves the child in the value for the drop (the one-entry table panics).
#[skuld::test]
fn a_failed_wait_is_returned_once_and_the_drop_does_not_wait_again() {
    let fake = fake().reaps([ReapAnswer::Err(std::io::ErrorKind::Other)]);
    let result = unreaped(&fake, Some(id())).wait();
    assert!(result.is_err(), "{result:?}");
}

/// A child someone else reaped is an error, not a hang.
///
/// Mutant: `wait` answers a status, or waits on.
#[skuld::test]
fn a_wait_on_a_child_reaped_elsewhere_is_an_error_and_does_not_hang() {
    let fake = fake().reaps([ReapAnswer::Foreign(Foreign::Gone)]);
    let result = unreaped(&fake, Some(id())).wait();
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
}

/// The drop waits for the child, reaps it, and says so in one `warn` naming it.
///
/// Mutants: the drop does not wait; it logs nothing, or logs twice, or logs below `warn`.
#[skuld::test]
fn dropping_waits_for_the_child_and_logs_one_warn_naming_it() {
    let (records, blocks) = dropped_when_the_reap_answers(fake(), ReapAnswer::Reaped(exit()));
    assert_eq!(blocks, [None], "one unbounded block");
    assert!(
        matches!(records.as_slice(), [(log::Level::Warn, text)] if text.contains(&PID.to_string())),
        "{records:?}"
    );
}

/// A child reaped by someone else before the drop's wait is a handled case: one line at `debug`.
///
/// Mutant: the drop warns of a foreign reap.
#[skuld::test]
fn a_drop_that_meets_a_foreign_reap_logs_one_debug_line() {
    let (records, _) = dropped_when_the_reap_answers(fake(), ReapAnswer::Foreign(Foreign::Gone));
    assert!(
        matches!(records.as_slice(), [(log::Level::Debug, text)] if text.contains(&PID.to_string())),
        "{records:?}"
    );
}

/// A zombie launchd holds is not ours to reap: one `warn` with the launchd text.
///
/// Mutant: the drop treats it as a foreign reap (`debug`).
#[skuld::test]
fn a_drop_that_meets_launchd_logs_one_warn_saying_so() {
    let (records, _) = dropped_when_the_reap_answers(fake(), ReapAnswer::Foreign(Foreign::Orphaned));
    assert!(
        matches!(
            records.as_slice(),
            [(log::Level::Warn, text)] if text.contains(&PID.to_string()) && text.contains("launchd")
        ),
        "{records:?}"
    );
}

/// A wait that fails is one `warn` with the failure.
///
/// Mutant: the failure is swallowed, or logged at `debug`.
#[skuld::test]
fn a_drop_whose_wait_fails_logs_one_warn_with_the_failure() {
    let (records, _) = dropped_when_the_reap_answers(fake(), ReapAnswer::Err(std::io::ErrorKind::Other));
    assert!(
        matches!(
            records.as_slice(),
            [(log::Level::Warn, text)] if text.contains(&PID.to_string()) && text.contains("failed")
        ),
        "{records:?}"
    );
}

/// `leak` gives the child up: no look, no wait, no line (any call on the empty fake panics).
///
/// Mutant: `leak` lets the drop wait.
#[skuld::test]
fn leak_calls_nothing_and_logs_nothing() {
    crate::log_capture::install();
    let child = unreaped(&fake(), Some(id()));
    let mark = crate::log_capture::mark();
    child.leak();
    assert_eq!(crate::log_capture::records_since_on_current_thread(mark, ""), []);
}

/// A child whose pid the spawn never learned (a Linux pidfd with no number) is named without one.
///
/// Mutant: the line prints a number, or panics on the missing pid.
#[skuld::test]
fn a_pidless_child_is_named_without_a_number() {
    crate::log_capture::install();
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())]);
    let child = unreaped(&fake, None);
    assert_eq!(child.pid(), None);
    let mark = crate::log_capture::mark();
    drop(child);
    let records = crate::log_capture::records_since_on_current_thread(mark, "");
    assert!(
        matches!(records.as_slice(), [(log::Level::Warn, text)] if text.contains(PIDLESS_CHILD)),
        "{records:?}"
    );
}

/// `pid` is the child's, and `id` is what the spawn read, absent or not.
///
/// Mutant: `id` is derived from the pid, or `pid` is stored beside the child.
#[skuld::test]
fn pid_comes_from_the_child_and_id_from_the_spawn() {
    let with_id = unreaped(&fake(), Some(id()));
    assert_eq!(with_id.pid(), Some(PID));
    assert_eq!(with_id.id(), Some(id()));
    with_id.leak();
    let without_id = unreaped(&fake(), None);
    assert_eq!(without_id.pid(), Some(PID));
    assert_eq!(without_id.id(), None);
    without_id.leak();
}

/// A real child that is still running when its `Unreaped` drops is waited for and reaped: the drop
/// blocks, the child exits (its stdin closes as the wait is about to block), and its pid is gone.
///
/// Mutant: the drop leaves the child a zombie, or does not wait for it.
#[cfg(unix)]
#[skuld::test]
fn dropping_an_unreaped_blocker_waits_for_it_and_reaps_it() {
    use super::fixtures::{identity_of, spawn_std_blocker};
    use crate::identity::Existence;

    let (child, stdin) = spawn_std_blocker();
    let blocker_id = identity_of(&child);
    let owned = OwnedChild::adopt(child, blocker_id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let unreaped = Unreaped::new(owned, Some(blocker_id));
    crate::wait::block_probe::take();
    let _end = crate::wait::block_probe::on_blocking(move || drop(stdin));
    drop(unreaped);
    assert_eq!(blocker_id.exists(), Existence::Gone, "the drop reaped the child");
}
