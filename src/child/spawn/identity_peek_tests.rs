//! The sync spawn's identity check on Linux: a peek through the child's pidfd that fails.

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::error::Error;
use crate::wait::exit_only::seams::force_peeks;

/// A peek that fails cannot show the read named our child, but the pidfd pins the child whatever
/// the peek said: the spawn fails `Unassessable`, warns once naming the error, and kills and reaps
/// the child through the pidfd.
///
/// Mutants: the failed check is `Ok` (the spawn succeeds); the warn drops the error, or is never
/// logged when the teardown has nothing to say; the teardown leaves the child alone (no reap is
/// recorded, and the child is not killed).
#[skuld::test]
fn a_failed_identity_peek_is_unknown_and_kills_and_reaps_the_child() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    crate::log_capture::install();
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let pid = Rc::new(Cell::new(0));
    let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, armed) = (Rc::clone(&pid), Rc::clone(&armed));
        move || {
            pid.set(fault::spawn_pid());
            *armed.borrow_mut() = Some(Box::new(force_peeks([Err(std::io::Error::other(
                "forced identity-check failure 3b7e",
            ))])));
        }
    });
    let reaps = fault::record_teardown_reaps();
    let mark = crate::log_capture::mark();

    let outcome = cmd.spawn();

    crate::wait::exit_only::seams::assert_peeks_exhausted();
    drop(armed);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a failed identity peek fails the spawn"),
    );
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "the pidfd pins the child, so it is reaped"
    );
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a failed peek is Unassessable, not a vanish: {err:?}"
    );
    // The teardown has nothing to warn of, so the diagnosis is logged on its own: one warn.
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("could not be checked against its handle (forced identity-check failure 3b7e)"),
        "the failed peek is warned, naming its own error: {warns:?}"
    );
    let recorded = reaps.recorded();
    assert_eq!(
        recorded.len(),
        1,
        "the teardown must have reaped the child: {recorded:?}"
    );
    assert_eq!(recorded[0].0, pid.get(), "the teardown reaped another process");
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&recorded[0].1),
        Some(libc::SIGKILL),
        "the teardown must have killed the child through its pidfd"
    );
}

/// The `warn`-or-worse records logged since `mark` on this thread.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// A failed identity check and the teardown it leads to are one event, so they share one `warn`.
/// Here the teardown's kill is refused (`EPERM`, as a setuid child answers), which it warns of: that
/// warn carries the diagnosis, and the check does not warn on its own.
///
/// Mutants: the check warns at the call (two warns); the teardown's warn drops the diagnosis.
#[skuld::test]
fn a_failed_identity_peek_and_a_refused_kill_share_one_warn() {
    use std::cell::RefCell;
    use std::rc::Rc;

    crate::log_capture::install();
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let armed = Rc::clone(&armed);
        move || {
            *armed.borrow_mut() = Some(Box::new(force_peeks([Err(std::io::Error::other(
                "forced identity-check failure 6c1d",
            ))])));
        }
    });
    // The seam kills and reaps the child first, so nothing is left running.
    fault::set_force_kill_failure("kill refused 6c1d", std::io::ErrorKind::PermissionDenied);
    let mark = crate::log_capture::mark();

    let outcome = cmd.spawn();

    crate::wait::exit_only::seams::assert_peeks_exhausted();
    drop(armed);
    assert!(
        fault::take_force_kill_failure().is_none(),
        "the teardown must have consumed the refused kill"
    );
    let (err, _fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a failed identity peek fails the spawn"),
    );
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("could not be checked against its handle (forced identity-check failure 6c1d)")
            && warns[0].contains("failed to kill"),
        "the one warn names the failed check and the refused kill: {warns:?}"
    );
}
