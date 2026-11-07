//! `Unreaped` over a `FakeProcess`: a call past a fake's table panics, which is how a test notices
//! a second wait on a child that was already consumed.

use super::teardown::{exit, fake, fire_on_block, id, PID};
use crate::child::owned::unreaped::Unreaped;
use crate::error::Error;
use crate::os_process::child::Foreign;
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::os_process::PIDLESS_CHILD;
use crate::test_child::over_fake::unreaped_over as unreaped;

// `Error` carries an `Unreaped`, and users move errors across threads.
static_assertions::assert_impl_all!(Unreaped: Send, Sync);

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

/// A failed `wait` returns the failure once and logs nothing; the drop of the consumed value does
/// not wait or log again.
///
/// Mutants: `wait` leaves the child in the value for the drop (the one-entry table panics, or the
/// drop logs); `wait` answers another error.
#[skuld::test]
fn a_failed_wait_is_returned_once_and_the_drop_does_not_wait_again() {
    crate::log_capture::install();
    let fake = fake().reaps([ReapAnswer::Err(std::io::ErrorKind::Other)]);
    let child = unreaped(&fake, Some(id()));
    let mark = crate::log_capture::mark();
    let result = child.wait();
    assert!(
        matches!(result, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::Other),
        "{result:?}"
    );
    assert_eq!(crate::log_capture::records_since_on_current_thread(mark, ""), []);
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

/// A zombie launchd holds is an error from `wait`, which has nobody else to say so: one `warn` with
/// the launchd text.
///
/// Mutants: `wait` is quiet about it; it warns twice.
#[skuld::test]
fn a_wait_on_a_zombie_launchd_holds_is_an_error_and_warns_once() {
    crate::log_capture::install();
    let fake = fake().reaps([ReapAnswer::Foreign(Foreign::Orphaned)]);
    let child = unreaped(&fake, Some(id()));
    let mark = crate::log_capture::mark();
    let result = child.wait();
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
    let records = crate::log_capture::records_since_on_current_thread(mark, "");
    assert!(
        matches!(
            records.as_slice(),
            [(log::Level::Warn, text)] if text.contains(&PID.to_string()) && text.contains("launchd")
        ),
        "{records:?}"
    );
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

/// An `Unreaped` dropped while its thread panics gives the child up without waiting for it: one
/// `warn` naming the pid and the panic, no block, and the child still runs. The stdin that ends the
/// child stays with the test; a drop that waited anyway would close it from the blocking hook and
/// reap the child, so a regression fails by assertion, not by a hang. The given-up child is not
/// reaped (it has no owner left): the test closes its stdin so it exits, and the process exit
/// collects its zombie.
///
/// Mutants: the drop waits though the thread is panicking (blocks, reaps, warns of the reap); it
/// logs nothing, or twice; it kills the child.
#[skuld::test]
fn dropping_an_unreaped_while_panicking_gives_the_child_up_without_waiting() {
    use std::cell::RefCell;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::rc::Rc;

    use super::fixtures::{identity_of, spawn_std_blocker};
    use crate::child::owned::OwnedChild;
    use crate::identity::Liveness;

    crate::log_capture::install();
    let (child, stdin) = spawn_std_blocker();
    let blocker_id = identity_of(&child);
    let owned = OwnedChild::adopt(child, blocker_id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let unreaped = Unreaped::new(owned, Some(blocker_id), false);
    let stdin = Rc::new(RefCell::new(Some(stdin)));
    crate::wait::block_probe::take();
    let _end = crate::wait::block_probe::on_blocking({
        let stdin = Rc::clone(&stdin);
        move || drop(stdin.borrow_mut().take())
    });
    let mark = crate::log_capture::mark();

    let outcome = catch_unwind(AssertUnwindSafe(move || {
        let _held = unreaped;
        panic!("the thread panics while it holds the Unreaped");
    }));

    assert!(outcome.is_err());
    assert_eq!(crate::wait::block_probe::take(), [], "the drop did not block");
    let records = crate::log_capture::records_since_on_current_thread(mark, "");
    assert!(
        matches!(
            records.as_slice(),
            [(log::Level::Warn, text)]
                if text.contains(&blocker_id.pid().to_string()) && text.contains("panicking")
        ),
        "{records:?}"
    );
    assert_eq!(blocker_id.is_alive(), Liveness::Alive, "the child was given up running");
    drop(stdin.borrow_mut().take());
}

/// A real child that is still running when its `Unreaped` drops is waited for and reaped: the drop
/// blocks, the child exits (its stdin closes as the wait is about to block), and it is gone.
///
/// Mutant: the drop leaves the child a zombie (Unix), or does not wait for it.
#[skuld::test]
fn dropping_an_unreaped_blocker_waits_for_it_and_reaps_it() {
    use super::fixtures::{identity_of, spawn_std_blocker};
    use crate::child::owned::OwnedChild;

    let (child, stdin) = spawn_std_blocker();
    let blocker_id = identity_of(&child);
    let owned = OwnedChild::adopt(child, blocker_id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let unreaped = Unreaped::new(owned, Some(blocker_id), false);
    crate::wait::block_probe::take();
    let _end = crate::wait::block_probe::on_blocking(move || drop(stdin));
    drop(unreaped);
    // A Windows process object outlives its last handle for a moment, so only Unix can ask for
    // the reap itself; on Windows the drop's wait shows as the child having exited.
    #[cfg(unix)]
    assert_eq!(
        blocker_id.exists(),
        crate::identity::Existence::Gone,
        "the drop reaped the child"
    );
    #[cfg(windows)]
    assert_eq!(
        blocker_id.is_alive(),
        crate::identity::Liveness::Dead,
        "the drop waited for the child"
    );
}

// `wait_async` =====

/// The same status `wait` gives, for a real child that is still running at the first poll.
///
/// Mutant: the status is not the child's.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn wait_async_returns_the_status_wait_would() {
    use super::wait_async::exits_three_on_eof;
    use crate::tokio::drive::drive_tests::poll_once;

    crate::log_capture::install();
    let (owned, stdin) = exits_three_on_eof();
    let child = Unreaped::new(owned, None, false);
    let mark = crate::log_capture::mark();
    let mut wait = std::pin::pin!(child.wait_async());
    assert!(poll_once(wait.as_mut()).is_pending(), "a running child is waited for");
    drop(stdin);
    assert_eq!(wait.await.expect("the child exits").code(), Some(3));
    assert_eq!(
        crate::log_capture::records_since_on_current_thread(mark, ""),
        [],
        "the settled value's drop is silent"
    );
}

/// A child reaped elsewhere is the error `wait` gives for it, not a status and not a hang.
///
/// Mutant: `wait_async` maps the outcome another way.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn wait_async_on_a_child_reaped_elsewhere_is_the_error_wait_gives() {
    crate::log_capture::install();
    let gone = || fake().reaps([ReapAnswer::Foreign(Foreign::Gone)]);
    let sync = unreaped(&gone(), Some(id())).wait().expect_err("reaped elsewhere");
    let fake = gone();
    let mark = crate::log_capture::mark();
    let asynchronous = unreaped(&fake, Some(id()))
        .wait_async()
        .await
        .expect_err("reaped elsewhere");
    assert_eq!(
        crate::log_capture::records_since_on_current_thread(mark, ""),
        [],
        "the settled value's drop is silent"
    );
    assert_eq!(fake.looks(), 1, "the drop made no further look");
    let (Error::Io(sync), Error::Io(asynchronous)) = (&sync, &asynchronous) else {
        panic!("{sync:?} / {asynchronous:?}");
    };
    assert_eq!(asynchronous.kind(), sync.kind());
    assert_eq!(asynchronous.raw_os_error(), sync.raw_os_error());
}

/// A cancelled `wait_async` lets the child go: the drop on the runtime thread returns without
/// waiting (the child's stdin stays open, so a drop that waited would hang the test), the child was
/// sent one kill and looked at once, and the one line says it was reaped or, if it had not exited
/// yet, names its pid as given up.
///
/// Mutants: the drop waits; it sends no kill; it looks more than once; it says nothing, or twice.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn a_cancelled_wait_async_lets_the_child_go_without_blocking() {
    use crate::child::owned::OwnedChild;
    use crate::os_process::child::adopted_blocker;
    use crate::signal::Sig;
    use crate::tokio::drive::drive_tests::poll_once;

    crate::log_capture::install();
    let (os, blocker_id, stdin) = adopted_blocker();
    let fake = FakeProcess::over(os);
    let child = Unreaped::new(OwnedChild::new(Box::new(fake.clone())), Some(blocker_id), false);
    let mark = crate::log_capture::mark();
    {
        let mut wait = std::pin::pin!(child.wait_async());
        assert!(poll_once(wait.as_mut()).is_pending(), "a running child is waited for");
        assert_eq!(fake.looks(), 1);
    }
    assert_eq!(fake.signal_calls(), [Sig::Kill], "one kill");
    assert_eq!(fake.looks(), 2, "one look");
    let records = crate::log_capture::records_since_on_current_thread(mark, "");
    assert!(
        matches!(
            records.as_slice(),
            [(log::Level::Debug, text)] if text.contains("reaped it")
        ) || matches!(
            records.as_slice(),
            [(log::Level::Warn, text)]
                if text.contains(&blocker_id.pid().to_string()) && text.contains("gave it up")
        ),
        "{records:?}"
    );
    drop(stdin);
}

/// A future that was never polled still lets the child go when it drops: the kind is set when
/// `wait_async` is called, not at its first poll.
///
/// Mutant: the kind is set inside the future's body.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn an_unpolled_wait_async_lets_the_child_go_when_it_drops() {
    use crate::signal::{Sent, Sig};

    let fake = fake()
        .signals([Ok(Sent::Delivered)])
        .reaps([ReapAnswer::Reaped(exit())]);
    drop(unreaped(&fake, Some(id())).wait_async());
    assert_eq!(fake.signal_calls(), [Sig::Kill]);
    assert_eq!(fake.looks(), 1, "one look, which does not wait");
}

/// A cancelled `wait_async` over an elevation front sends it nothing: it is looked at once and, if
/// it still runs, given up with one `warn` naming the pid.
///
/// Mutant: the drop kills a front.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn a_cancelled_wait_async_sends_a_front_nothing() {
    use crate::child::owned::OwnedChild;
    use crate::tokio::drive::drive_tests::poll_once;

    crate::log_capture::install();
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Running]);
    let child = Unreaped::new(OwnedChild::new(Box::new(fake.clone())), Some(id()), true);
    let mark = crate::log_capture::mark();
    {
        let mut wait = std::pin::pin!(child.wait_async());
        assert!(poll_once(wait.as_mut()).is_pending(), "a running front is waited for");
    }
    assert_eq!(fake.signal_calls(), [], "a front is sent nothing");
    assert_eq!(fake.looks(), 2, "one look");
    let records = crate::log_capture::records_since_on_current_thread(mark, "");
    assert!(
        matches!(
            records.as_slice(),
            [(log::Level::Warn, text)]
                if text.contains(&PID.to_string()) && text.contains("gave it up")
        ),
        "{records:?}"
    );
}
