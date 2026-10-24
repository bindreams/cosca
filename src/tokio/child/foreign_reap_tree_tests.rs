//! Async twins of `child/foreign_reap_tree_tests.rs`: `kill_tree` and `terminate_tree` of a group
//! whose root was reaped behind its handle's back. The recorders are thread-local and skuld's
//! default runtime is current-thread, so the sends are recorded on this thread.

use crate::containment::unix::fault::{record_kill_group, record_term_group};
use crate::test_child::reaped_elsewhere::{
    assert_one_reaped_elsewhere_warn, assert_one_untrusted_number_warn, reap_behind,
};

/// A `sleep` in its own session: `Attached::ProcessGroup`, or on macOS an fd marker with a group.
fn session_sleep() -> crate::tokio::Command {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sleep", "300"]);
    cmd.contain_with(crate::ContainMode::Session);
    cmd
}

/// A [`session_sleep`] child, killed and reaped behind its back, and its group's id.
fn foreign_reaped_group_root() -> (crate::tokio::Child, u32) {
    let mut child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    reap_behind(pid);
    (child, pid)
}

/// Mutants: `killpg` sent; the decision taken on the number alone (it shows no recycle).
#[skuld::test]
async fn tokio_kill_tree_after_a_foreign_reap_sends_no_killpg() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let recorder = record_kill_group();
    let (mut child, pgid) = foreign_reaped_group_root();

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

/// The twin of [`tokio_kill_tree_after_a_foreign_reap_sends_no_killpg`]. Same mutants.
#[skuld::test]
async fn tokio_terminate_tree_after_a_foreign_reap_sends_no_signal() {
    crate::tokio::test_runtime::assert_current_thread();
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

/// The sync `kill_tree_after_own_wait_whose_pid_reads_unknown_sends_no_killpg`'s twin. Same
/// mutant.
#[skuld::test]
async fn tokio_kill_tree_after_own_wait_whose_pid_reads_unknown_sends_no_killpg() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let recorder = record_kill_group();
    let mut child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().await.expect("this handle reaps the root");
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

/// The sync `kill_tree_of_a_root_its_handle_cannot_read_sends_no_killpg`'s twin. Same mutant.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_kill_tree_of_a_root_its_handle_cannot_read_sends_no_killpg() {
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let recorder = record_kill_group();
    let mut child = session_sleep().spawn().expect("spawn");
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
    child.wait().await.expect("reap the root");
}
