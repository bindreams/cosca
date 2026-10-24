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

/// The sync `kill_tree_of_a_root_its_handle_cannot_read_kills_it_through_its_pidfd_alone`'s twin.
/// Same mutants.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_kill_tree_of_a_root_its_handle_cannot_read_kills_it_through_its_pidfd_alone() {
    use crate::test_child::reaped_elsewhere::ROOT_KILLED_BY_PIDFD;
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use std::os::unix::process::ExitStatusExt as _;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let recorder = record_kill_group();
    let mut child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let sends = crate::send_log::Capture::start();
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
    assert_eq!(
        sends.entries(),
        [(pid, crate::signal::Sig::Kill, crate::send_log::Via::Pidfd)],
        "the root is killed through its pidfd, and nothing else is sent"
    );
    assert_one_untrusted_number_warn(mark, pid);
    let warns = warns_since(mark);
    assert!(warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    let status = child.wait().await.expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "the pidfd kill ended the root");
}

/// [`session_sleep`] that ignores `SIGTERM` (an ignored signal stays ignored across `exec`), so only
/// a kill ends it.
#[cfg(target_os = "linux")]
fn term_ignoring_session_sleep() -> crate::tokio::Command {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sh", "-c", r#"trap "" TERM; echo ready; exec sleep 300"#]);
    cmd.contain_with(crate::ContainMode::Session);
    cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
    cmd
}

/// The sync `terminate_tree_of_a_root_its_handle_cannot_read_terms_it_through_its_pidfd_alone`'s
/// twin. Same mutants.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_terminate_tree_of_a_root_its_handle_cannot_read_terms_it_through_its_pidfd_alone() {
    use crate::test_child::reaped_elsewhere::ROOT_TERMED_BY_PIDFD;
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use std::os::unix::process::ExitStatusExt as _;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let termed = record_term_group();
    let mut child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let sends = crate::send_log::Capture::start();
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    let err = child
        .terminate_tree()
        .expect_err("a group whose root nothing can answer for is not assessable");
    assert_peeks_exhausted();
    drop(forced);

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a number that may name another process"
    );
    assert_eq!(
        sends.entries(),
        [(pid, crate::signal::Sig::Term, crate::send_log::Via::Pidfd)],
        "the root is signalled through its pidfd, and nothing else is sent"
    );
    assert_one_untrusted_number_warn(mark, pid);
    let warns = warns_since(mark);
    assert!(warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
    let status = child.wait().await.expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "the pidfd SIGTERM ended the root");
}

/// The sync `graceful_shutdown_tree_of_a_root_its_handle_cannot_read_escalates_through_its_pidfd_alone`'s
/// twin. Same mutants.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_graceful_shutdown_tree_of_a_root_its_handle_cannot_read_escalates_through_its_pidfd_alone() {
    use crate::signal::Sig::{Kill, Term};
    use crate::test_child::reaped_elsewhere::{ROOT_KILLED_BY_PIDFD, ROOT_TERMED_BY_PIDFD};
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use std::os::unix::process::ExitStatusExt as _;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let mut child = term_ignoring_session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    let mut ready = String::new();
    ::tokio::io::AsyncBufReadExt::read_line(
        &mut ::tokio::io::BufReader::new(child.stdout().expect("stdout pipe")),
        &mut ready,
    )
    .await
    .expect("the root ignores SIGTERM");

    let mark = crate::log_capture::mark();
    let sends = crate::send_log::Capture::start();
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    // A root that ignores the SIGTERM is alive after any grace, so the kill follows.
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .await
        .expect_err("a group whose root nothing can answer for is not assessable");
    assert_peeks_exhausted();
    drop(forced);

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(killed.killed(), Vec::<i32>::new(), "no killpg by the root's number");
    assert_eq!(termed.termed(), Vec::<i32>::new(), "no SIGTERM by the root's number");
    let via_pidfd = crate::send_log::Via::Pidfd;
    assert_eq!(
        sends.entries(),
        [(pid, Term, via_pidfd), (pid, Kill, via_pidfd)],
        "the SIGTERM, then the kill, both through the pidfd"
    );
    assert_one_untrusted_number_warn(mark, pid);
    let warns = warns_since(mark);
    assert!(warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
    assert!(warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    let status = child.wait().await.expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "the kill ended the root");
}

/// The sync `graceful_shutdown_tree_of_a_root_its_handle_cannot_read_sends_no_kill_to_one_that_exited`'s
/// twin. The grace's deadline has passed when its wait arms (the clock it is computed on lags an
/// hour), so the timer wins the first poll, before the reactor reports the exit: only the one look at
/// the pidfd at expiry can see it.
///
/// Mutants: the sync twin's; no look at the pidfd at expiry.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_graceful_shutdown_tree_of_a_root_its_handle_cannot_read_sends_no_kill_to_one_that_exited() {
    use crate::signal::Sig::Term;
    use crate::test_child::reaped_elsewhere::{ROOT_KILLED_BY_PIDFD, ROOT_TERMED_BY_PIDFD};
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use std::os::unix::process::ExitStatusExt as _;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let mut child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let sends = std::rc::Rc::new(crate::send_log::Capture::start());
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    let exited_first = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, {
        let sends = std::rc::Rc::clone(&sends);
        move || {
            assert_eq!(
                sends.entries(),
                [(pid, Term, crate::send_log::Via::Pidfd)],
                "the SIGTERM went out before the grace"
            );
            crate::test_child::wait_until_zombie(pid);
        }
    });
    let past = crate::tokio::wait::tokio_now()
        .checked_sub(std::time::Duration::from_secs(3600))
        .expect("an hour before now");
    let lagging = crate::tokio::wait::now_override::install(past);
    let err = child
        .graceful_shutdown_tree(std::time::Duration::from_secs(60))
        .await
        .expect_err("a group whose root nothing can answer for is not assessable");
    drop(lagging);
    drop(exited_first);
    assert_peeks_exhausted();
    drop(forced);

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        sends.entries(),
        [(pid, Term, crate::send_log::Via::Pidfd)],
        "only the SIGTERM, through the pidfd"
    );
    assert_one_untrusted_number_warn(mark, pid);
    let warns = warns_since(mark);
    assert!(warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
    assert!(!warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    let status = child.wait().await.expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "the SIGTERM ended the root");
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

/// The sync `graceful_shutdown_tree_after_own_wait_claims_no_sigterm_it_did_not_send`'s twin. Same
/// mutant.
#[skuld::test]
async fn tokio_graceful_shutdown_tree_after_own_wait_claims_no_sigterm_it_did_not_send() {
    use crate::child::fault::force_next_root_read;
    use crate::identity::{ProcessId, Resolved};
    use crate::test_child::reaped_elsewhere::UNTRUSTED_NUMBER;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let mut child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().await.expect("this handle reaps the root");
    let other = ProcessId::from_parts_for_test(pid, child.id().start_token_raw() + 1);
    // The shutdown's look finds another process; the sweep's, after the terminate, cannot read the
    // pid. This guard clears the second force too, should it go unconsumed.
    let _reads = force_next_root_read(Resolved::Found(other));
    let _unreadable = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, || {
        std::mem::forget(force_next_root_read(Resolved::Unknown))
    });

    let mark = crate::log_capture::mark();
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .await
        .expect_err("a sweep whose root's pid cannot be read is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_eq!(
        killed.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn: {warns:?}");
    assert!(warns[0].contains(UNTRUSTED_NUMBER), "{warns:?}");
    #[cfg(target_os = "linux")]
    assert!(
        !warns[0].contains("was sent before it"),
        "no SIGTERM was sent: {warns:?}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        warns[0].contains("though the SIGTERM to any marker holders was sent before it"),
        "the SIGTERM went to the marker holders alone: {warns:?}"
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
/// [`escaped_holder_script`](crate::test_child::reaped_elsewhere::escaped_holder_script). Returns the
/// child, the holder's pid, the held stdin and the stderr the holder's death closes.
#[cfg(target_os = "macos")]
async fn escaped_holder_tree(
    mode: crate::ContainMode,
    ignore_term: bool,
) -> (
    crate::tokio::Child,
    u32,
    crate::tokio::ChildStdin,
    crate::tokio::ChildStderr,
) {
    use ::tokio::io::AsyncBufReadExt as _;
    let mut cmd = crate::tokio::Command::new();
    cmd.args([
        "sh",
        "-c",
        &crate::test_child::reaped_elsewhere::escaped_holder_script(ignore_term),
    ]);
    cmd.contain_with(mode);
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
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree(crate::ContainMode::Session, false).await;
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

/// The sync `kill_tree_after_own_wait_of_a_marker_with_a_group_is_ok_and_marks_the_tree_killed`'s
/// twin. Same mutants.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn tokio_kill_tree_after_own_wait_of_a_marker_with_a_group_is_ok_and_marks_the_tree_killed() {
    use crate::identity::Resolved;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let groups = record_kill_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree(crate::ContainMode::Session, false).await;
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().await.expect("this handle reaps the root");
    let _gone = crate::child::fault::force_root_reads(Resolved::Gone);

    child.kill_tree().expect("the group and every holder were reached");

    // Routed: the killpg by a pid that names nothing (bindreams/cosca#382).
    let by_id = groups.killed();
    assert!(
        !by_id.is_empty() && by_id.iter().all(|g| *g == pid as i32),
        "the group is killed by its id: {by_id:?}"
    );
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert_eq!(
        holders.signals_to(holder),
        [nix::sys::signal::Signal::SIGKILL],
        "the holder that left the group is killed"
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

/// The sync `graceful_shutdown_tree_after_own_wait_of_a_marker_with_a_group_answers_the_collected_status`'s
/// twin. Same mutants.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn tokio_graceful_shutdown_tree_after_own_wait_of_a_marker_with_a_group_answers_the_collected_status() {
    use crate::identity::Resolved;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree(crate::ContainMode::Session, true).await;
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    let collected = child.wait().await.expect("this handle reaps the root");
    let _gone = crate::child::fault::force_root_reads(Resolved::Gone);

    let status = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .await
        .expect("the group and every holder were reached");

    assert_eq!(status, collected, "the status the wait collected");
    // Routed: the group's signals by a pid that names nothing (bindreams/cosca#382).
    for (what, by_id) in [("SIGTERM", termed.termed()), ("kill", killed.killed())] {
        assert!(
            !by_id.is_empty() && by_id.iter().all(|g| *g == pid as i32),
            "the group's {what} by its id: {by_id:?}"
        );
    }
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert_eq!(
        holders.signals_to(holder),
        [nix::sys::signal::Signal::SIGTERM, nix::sys::signal::Signal::SIGKILL],
        "the SIGTERM, then the kill"
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
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree(crate::ContainMode::Session, false).await;
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

/// The sync `graceful_shutdown_tree_after_a_foreign_reap_kills_a_holder_that_ignores_sigterm`'s
/// twin. Same mutants.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn tokio_graceful_shutdown_tree_after_a_foreign_reap_kills_a_holder_that_ignores_sigterm() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree(crate::ContainMode::Session, true).await;
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    reap_behind(pid);

    let mark = crate::log_capture::mark();
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
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
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert_eq!(
        holders.signals_to(holder),
        [nix::sys::signal::Signal::SIGTERM, nix::sys::signal::Signal::SIGKILL],
        "the SIGTERM, then the kill"
    );
    assert_one_reaped_elsewhere_warn(mark, pid);
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn: {warns:?}");
    assert_holder_dies(stderr).await;
}

/// The sync `kill_tree_of_a_walk_marker_after_a_foreign_reap_walks_nothing_and_kills_the_holder`'s
/// twin. Same mutant.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn tokio_kill_tree_of_a_walk_marker_after_a_foreign_reap_walks_nothing_and_kills_the_holder() {
    use crate::test_child::reaped_elsewhere::assert_one_reaped_elsewhere_walk_warn;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree(crate::ContainMode::TreeWalk, false).await;
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    reap_behind(pid);

    let mark = crate::log_capture::mark();
    let result = child.kill_tree();

    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    assert!(
        matches!(result, Err(crate::error::Error::Unassessable { .. })),
        "a walk whose root was reaped elsewhere is not assessable: {result:?}"
    );
    assert!(
        holders.killed().contains(&holder),
        "the holder is killed: {:?}",
        holders.killed()
    );
    assert_one_reaped_elsewhere_walk_warn(mark, pid);
    assert_holder_dies(stderr).await;
}

/// The sync `kill_tree_of_a_walk_marker_after_own_wait_and_reuse_walks_nothing_and_kills_the_holder`'s
/// twin. Same mutant.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn tokio_kill_tree_of_a_walk_marker_after_own_wait_and_reuse_walks_nothing_and_kills_the_holder() {
    use crate::identity::{ProcessId, Resolved};
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let walks = crate::containment::treewalk::fault::record_walks();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (mut child, holder, _stdin, stderr) = escaped_holder_tree(crate::ContainMode::TreeWalk, false).await;
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().await.expect("this handle reaps the root");
    let other = ProcessId::from_parts_for_test(pid, child.id().start_token_raw() + 1);
    let _reused = crate::child::fault::force_next_root_read(Resolved::Found(other));

    let result = child.kill_tree();

    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk from a reaped root's number");
    result.expect("every holder was reached");
    assert!(
        holders.killed().contains(&holder),
        "the holder is killed: {:?}",
        holders.killed()
    );
    assert_holder_dies(stderr).await;
}
