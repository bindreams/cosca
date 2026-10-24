//! `kill_tree` and `terminate_tree` of a group whose root was reaped behind its handle's back. Only
//! the handle can tell: the root's number names nothing, or (macOS) nothing the number shows to be
//! another process. The group recorders stand in for `killpg`, so a mutant that still sends one
//! reaches no process.

use crate::containment::unix::fault::{record_kill_group, record_term_group};
use crate::test_child::reaped_elsewhere::{
    assert_one_reaped_elsewhere_warn, assert_one_untrusted_number_warn, foreign_reaped_group_root, session_sleep,
};

/// Mutants: `killpg` sent; the decision taken on the number alone (it shows no recycle).
#[skuld::test]
fn kill_tree_after_a_foreign_reap_sends_no_killpg() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let (child, pgid) = foreign_reaped_group_root();

    let mark = crate::log_capture::mark();
    let err = child
        .kill_tree()
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pgid);
}

/// The twin of [`kill_tree_after_a_foreign_reap_sends_no_killpg`]. Same mutants.
#[skuld::test]
fn terminate_tree_after_a_foreign_reap_sends_no_signal() {
    crate::log_capture::install();
    let recorder = record_term_group();
    let (child, pgid) = foreign_reaped_group_root();

    let mark = crate::log_capture::mark();
    let err = child
        .terminate_tree()
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pgid);
}

/// After this handle's own reap, a pid that cannot be read may name another process (a pid that
/// names none reads `Gone`): `kill_tree` sends no `killpg` and answers `Unassessable`.
///
/// Mutant: an unreadable pid after our own reap is taken as free, and `killpg` is sent.
#[skuld::test]
fn kill_tree_after_own_wait_whose_pid_reads_unknown_sends_no_killpg() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().expect("this handle reaps the root");
    let _unknown = crate::child::fault::force_next_root_read(crate::identity::Resolved::Unknown);

    let mark = crate::log_capture::mark();
    let err = child
        .kill_tree()
        .expect_err("a group whose root's pid cannot be read is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "no killpg by a number that may name another process"
    );
    assert_one_untrusted_number_warn(mark, pid);
}

/// A root whose own handle cannot say whether it was reaped: its pid may name another process, so
/// `kill_tree` sends no `killpg` and answers `Unassessable`. (macOS answers this earlier, through
/// its untrusted-root path.)
///
/// Mutant: a `RootState::Unknown` root's group is signalled.
#[cfg(target_os = "linux")]
#[skuld::test]
fn kill_tree_of_a_root_its_handle_cannot_read_sends_no_killpg() {
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    let err = child
        .kill_tree()
        .expect_err("a group whose root nothing can answer for is not assessable");
    assert_peeks_exhausted();
    drop(forced);

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "no killpg by a number that may name another process"
    );
    assert_one_untrusted_number_warn(mark, pid);
    child.kill().expect("kill the root");
    child.wait().expect("reap the root");
}
