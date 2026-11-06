//! The sync spawn's identity check on Linux: a peek through the child's pidfd that fails.

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::log_capture::warns_since;
use crate::test_child::Console;
use crate::wait::exit_only::seams::force_peeks;

/// A peek that fails cannot show the read named our child, but the pidfd pins the child whatever
/// the peek said: the spawn keeps the child with no identity, and warns once naming the error. The
/// child is killed and waited for through its pidfd like any other.
///
/// Mutants: the failed check is `Ok` (the child has an identity); the warn drops the error, or is
/// never logged; the spawn fails, or kills the child.
#[skuld::test]
fn a_failed_identity_peek_keeps_the_child_without_an_identity() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    crate::log_capture::install();
    let (stdin, _teardown) = fault::teardown_blocker_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
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
    let mark = crate::log_capture::mark();

    let outcome = cmd.spawn();

    crate::wait::exit_only::seams::assert_peeks_exhausted();
    drop(armed);
    let child = outcome.expect("a failed identity peek keeps the child");
    assert_eq!(
        child.id(),
        None,
        "the read could not be checked, so the child has no identity"
    );
    assert_eq!(child.pid(), pid.get(), "the pid is the spawned child's");
    // The failed check is the event's one warn, logged when the spawn ends.
    let warns = warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("could not be checked against its handle (forced identity-check failure 3b7e)"),
        "the failed peek is warned, naming its own error: {warns:?}"
    );
    child.kill().expect("a kept child is killed through its pidfd");
    let status = child.wait().expect("a kept child is waited on");
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL),
        "the kill ended the child"
    );
}
