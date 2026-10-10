//! The sync spawn's identity check on Linux: a peek through the child's pidfd that fails.

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::error::Error;
use crate::wait::exit_only::seams::force_peeks;

/// A peek that fails cannot show the read named our child, but the pidfd pins the child whatever
/// the peek said: the spawn fails `Unassessable`, warns at the call naming the error, and kills and
/// reaps the child through the pidfd.
///
/// Mutants: the failed check is `Ok` (the spawn succeeds); the call-site warn drops the error; the
/// teardown leaves the child alone (no reap is recorded, and the child is not killed).
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
    let err = outcome.expect_err("a failed identity peek fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a failed peek is Unassessable, not a vanish: {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(
            mark,
            "could not be checked against its handle (forced identity-check failure 3b7e)"
        ),
        "the failed peek is warned at the call, naming its own error"
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
