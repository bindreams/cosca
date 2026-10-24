//! Async twins of `child/foreign_reap_tree_tests.rs`: `kill_tree` and `terminate_tree` of a group
//! whose root was reaped behind its handle's back. The recorders are thread-local and skuld's
//! default runtime is current-thread, so the sends are recorded on this thread.

use crate::containment::unix::fault::{record_kill_group, record_term_group};
use crate::test_child::reaped_elsewhere::{
    assert_one_reaped_elsewhere_warn, assert_one_untrusted_number_warn, reap_behind, warns_since, MAY_STILL_RUN,
    REAPED_ELSEWHERE,
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

/// The sync `graceful_shutdown_tree_after_a_foreign_reap_warns_once_and_ends`'s twin. Same mutant.
#[skuld::test]
async fn tokio_graceful_shutdown_tree_after_a_foreign_reap_warns_once_and_ends() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let (mut child, pgid) = foreign_reaped_group_root();

    let mark = crate::log_capture::mark();
    let err = child
        .graceful_shutdown_tree(std::time::Duration::from_secs(1))
        .await
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        killed.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pgid);
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn: {warns:?}");
    assert!(
        !warns[0].contains("was sent before it"),
        "no SIGTERM was sent: {warns:?}"
    );
}

/// A backend forgotten because it could not be shown to be ours may still be running: `kill_tree`
/// treats its root as `Unknown`, never as reaped elsewhere. On macOS that is the identity path: the
/// marker holders, the root among them, are killed by the pipe they hold.
///
/// Mutant: a backend forgotten unproven reads as `Reaped`.
#[skuld::test]
async fn tokio_kill_tree_of_a_backend_forgotten_unproven_treats_the_root_as_unknown() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let groups = record_kill_group();
    #[cfg(target_os = "macos")]
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    child.proc_mut().forget_as("was forgotten by a test", false);

    let mark = crate::log_capture::mark();
    let result = child.kill_tree();

    assert_eq!(
        crate::log_capture::records_since_on_current_thread(mark, REAPED_ELSEWHERE),
        [],
        "a root not shown reaped is not called reaped"
    );
    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "no killpg by a number that may name another process"
    );
    #[cfg(target_os = "linux")]
    {
        let err = result.expect_err("a group whose root nothing can answer for is not assessable");
        assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "exactly one warn: {warns:?}");
        assert!(
            warns[0].contains(MAY_STILL_RUN),
            "it says the root may still be running: {warns:?}"
        );
        assert!(
            warns[0].contains(&format!("pgid {pid}")),
            "it names the group: {warns:?}"
        );
    }
    #[cfg(target_os = "macos")]
    {
        let _ = MAY_STILL_RUN;
        result.expect("every marker holder was reached");
        assert!(
            holders.killed().contains(&pid),
            "the root holds the marker: {:?}",
            holders.killed()
        );
    }
    drop(writer);
    reap_behind(pid);
}

/// A root that leaves a marker holder outside its process group: see
/// [`ESCAPED_HOLDER_SCRIPT`](crate::test_child::reaped_elsewhere::ESCAPED_HOLDER_SCRIPT). Returns the
/// child, the holder's pid, the held stdin and the stderr the holder's death closes.
#[cfg(target_os = "macos")]
async fn escaped_holder_tree() -> (
    crate::tokio::Child,
    u32,
    crate::tokio::ChildStdin,
    crate::tokio::ChildStderr,
) {
    use ::tokio::io::AsyncBufReadExt as _;
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sh", "-c", crate::test_child::reaped_elsewhere::ESCAPED_HOLDER_SCRIPT]);
    cmd.contain_with(crate::ContainMode::Session);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::pipe_out()).expect("stderr pipe");
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), crate::Containment::FdMarker);
    let mut line = String::new();
    ::tokio::io::BufReader::new(child.stdout().expect("stdout pipe"))
        .read_line(&mut line)
        .await
        .expect("read the holder's pid");
    let holder: u32 = line.trim().parse().expect("the holder's pid");
    crate::test_child::reaped_elsewhere::assert_left_the_group(holder, child.id().pid());
    let stdin = child.stdin().expect("stdin pipe");
    let stderr = child.stderr().expect("stderr pipe");
    (child, holder, stdin, stderr)
}

/// Blocks until the holder is gone: its stderr reaches EOF. Call only once the test has shown the
/// holder was signalled, so a missed kill fails an assertion rather than hanging here.
#[cfg(target_os = "macos")]
async fn assert_holder_dies(mut stderr: crate::tokio::ChildStderr) {
    use ::tokio::io::AsyncReadExt as _;
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .await
        .expect("the holder's stderr reaches EOF");
    assert!(rest.is_empty(), "unexpected stderr from the holder: {rest:?}");
}

/// The sync `kill_tree_after_own_wait_and_reuse_kills_a_holder_that_left_the_group`'s twin. Same
/// mutants.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn tokio_kill_tree_after_own_wait_and_reuse_kills_a_holder_that_left_the_group() {
    use crate::identity::{ProcessId, Resolved};
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let groups = record_kill_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree().await;
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().await.expect("this handle reaps the root");
    let other = ProcessId::from_parts_for_test(pid, child.id().start_token_raw() + 1);
    let _reused = crate::child::fault::force_next_root_read(Resolved::Found(other));

    child.kill_tree().expect("every holder was reached");

    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert!(
        holders.killed().contains(&holder),
        "the holder that left the group is killed: {:?}",
        holders.killed()
    );
    let mark = crate::log_capture::mark();
    drop(child);
    assert_eq!(
        warns_since(mark),
        Vec::<String>::new(),
        "the tree was killed: the drop does not warn"
    );
    assert_holder_dies(stderr).await;
}

/// The sync `kill_tree_after_a_foreign_reap_kills_a_holder_that_left_the_group`'s twin. Same mutant.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn tokio_kill_tree_after_a_foreign_reap_kills_a_holder_that_left_the_group() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let groups = record_kill_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree().await;
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    reap_behind(pid);

    let mark = crate::log_capture::mark();
    let err = child
        .kill_tree()
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert!(
        holders.killed().contains(&holder),
        "the holder that left the group is killed: {:?}",
        holders.killed()
    );
    assert_one_reaped_elsewhere_warn(mark, pid);
    assert_holder_dies(stderr).await;
}
