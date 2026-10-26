//! Async twin of `child/group_exact_tests.rs`'s foreign-reap case: on Linux 6.9+ the root's pidfd
//! names its group exactly, whoever reaped the root.

use ::tokio::io::AsyncReadExt as _;

use crate::send_log::{Capture, GroupStep, Route};
use crate::test_child::reaped_elsewhere::reap_behind;
use crate::test_groups::{pidfd_group_signal, Group};
use crate::tokio::{ChildStderr, ChildStdin};

/// A session root `sh` that leaves a `cat` in its group, then sleeps, and the pipes that keep the
/// `cat` alive and report its end. The `cat` holds stderr's write end: once the root is gone,
/// stderr reaches EOF exactly when the `cat` is.
pub(crate) async fn root_with_a_cat() -> (crate::tokio::Child, ChildStdin, ChildStderr) {
    let mut cmd = crate::tokio::Command::new();
    cmd.args([
        "sh",
        "-c",
        "exec 3<&0; cat <&3 3<&- >/dev/null & echo started; exec sleep 300 <&-",
    ]);
    cmd.contain_with(crate::ContainMode::Session);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::pipe_out()).expect("stderr pipe");
    let mut child = cmd.spawn().expect("spawn");
    let mut started = [0u8; 8];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut started)
        .await
        .expect("read `started`");
    assert_eq!(&started, b"started\n");
    let stdin = child.stdin().expect("stdin pipe");
    let stderr = child.stderr().expect("stderr pipe");
    (child, stdin, stderr)
}

/// Waits until the `cat` of [`root_with_a_cat`] is gone. Call it only once the kill that ends it is
/// shown sent: the `cat` outlives anything else.
pub(crate) async fn await_the_cat_gone(mut stderr: ChildStderr) {
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .await
        .expect("read stderr to the cat's end");
}

/// Mutant: "a root reaped elsewhere is never signalled".
#[skuld::test]
async fn tokio_kill_tree_kills_the_group_of_a_root_reaped_elsewhere(#[fixture(pidfd_group_signal)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _stdin, stderr) = root_with_a_cat().await;
    let pid = child.id().pid();
    child.kill().expect("kill the root alone");
    reap_behind(pid);

    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    result.expect("the group is killed through the root's pidfd");
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd)), "{steps:?}");
    await_the_cat_gone(stderr).await;
}

/// How this handle observes a foreign reap of its root: any way it then holds no tokio `Child`.
#[derive(Debug, Clone, Copy)]
enum Seen {
    ByTryWait,
    ByWait,
    /// A second `kill`, which finds the root gone and sends nothing.
    ByKill,
}

/// Kills `child`'s root alone, has another reaper reap it, and has `seen` observe that.
async fn reap_behind_and_observe(child: &mut crate::tokio::Child, seen: Seen) {
    child.kill().expect("kill the root alone");
    reap_behind(child.id().pid());
    match seen {
        Seen::ByTryWait => drop(child.try_wait().expect_err("a foreign reap answers ECHILD")),
        Seen::ByWait => drop(child.wait().await.expect_err("a foreign reap answers ECHILD")),
        Seen::ByKill => child.kill().expect("a root reaped elsewhere has nothing left to kill"),
    }
}

/// 6.9+: a root whose foreign reap this handle has observed still names its group exactly through
/// its pidfd, so `kill_tree` kills the group. Mutant: "observing a foreign reap drops the pidfd".
async fn kill_tree_after_a_seen_foreign_reap(seen: Seen) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _stdin, stderr) = root_with_a_cat().await;
    reap_behind_and_observe(&mut child, seen).await;

    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    result.expect("the group is killed through the root's pidfd");
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd)), "{steps:?}");
    assert!(
        !steps.contains(&GroupStep::Group(Route::Number)),
        "nothing went by the group's number: {steps:?}"
    );
    await_the_cat_gone(stderr).await;
}

/// The `SIGTERM` twin of [`kill_tree_after_a_seen_foreign_reap`]. Same mutant.
async fn terminate_tree_after_a_seen_foreign_reap(seen: Seen) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _stdin, stderr) = root_with_a_cat().await;
    reap_behind_and_observe(&mut child, seen).await;

    let capture = Capture::start();
    let result = child.terminate_tree();
    let steps = capture.group_steps();
    result.expect("the group is termed through the root's pidfd");
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd)), "{steps:?}");
    assert!(
        !steps.contains(&GroupStep::Group(Route::Number)),
        "nothing went by the group's number: {steps:?}"
    );
    await_the_cat_gone(stderr).await;
}

/// The graceful twin of [`kill_tree_after_a_seen_foreign_reap`]: the `SIGTERM` goes through the
/// pidfd, and the call ends with the root's status unknown. Same mutant.
async fn graceful_shutdown_tree_after_a_seen_foreign_reap(seen: Seen) {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, _stdin, stderr) = root_with_a_cat().await;
    reap_behind_and_observe(&mut child, seen).await;

    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    let result = child.graceful_shutdown_tree(std::time::Duration::ZERO).await;
    let steps = capture.group_steps();
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd)), "{steps:?}");
    assert!(
        !steps.contains(&GroupStep::Group(Route::Number)),
        "nothing went by the group's number: {steps:?}"
    );
    await_the_cat_gone(stderr).await;
    crate::child::group_exact_tests::assert_down_without_status(result, mark);
}

/// Below 6.9 the old behaviour holds: nothing goes out by the reaped root's number, the call is
/// unassessable, and the member lives on. Mutant: "a refused flag still lets the call signal the
/// group by number".
async fn kill_tree_below_6_9_after_a_seen_foreign_reap(seen: Seen) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin, stderr) = root_with_a_cat().await;
    reap_behind_and_observe(&mut child, seen).await;
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    drop(old_kernel);
    let err = result.expect_err("a group whose root was reaped elsewhere is not assessable");
    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert!(
        !steps.contains(&GroupStep::Group(Route::Number)),
        "nothing went by the group's number: {steps:?}"
    );
    // Closing its stdin ends the `cat`.
    drop(stdin);
    await_the_cat_gone(stderr).await;
}

#[skuld::test]
async fn tokio_kill_tree_kills_the_group_after_a_foreign_reap_seen_by_try_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kill_tree_after_a_seen_foreign_reap(Seen::ByTryWait).await;
}

#[skuld::test]
async fn tokio_kill_tree_kills_the_group_after_a_foreign_reap_seen_by_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kill_tree_after_a_seen_foreign_reap(Seen::ByWait).await;
}

#[skuld::test]
async fn tokio_terminate_tree_terminates_the_group_after_a_foreign_reap_seen_by_try_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    terminate_tree_after_a_seen_foreign_reap(Seen::ByTryWait).await;
}

#[skuld::test]
async fn tokio_terminate_tree_terminates_the_group_after_a_foreign_reap_seen_by_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    terminate_tree_after_a_seen_foreign_reap(Seen::ByWait).await;
}

#[skuld::test]
async fn tokio_kill_tree_kills_the_group_after_a_foreign_reap_seen_by_kill(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kill_tree_after_a_seen_foreign_reap(Seen::ByKill).await;
}

#[skuld::test]
async fn tokio_kill_tree_below_6_9_sends_nothing_by_number_after_a_foreign_reap_seen_by_kill() {
    kill_tree_below_6_9_after_a_seen_foreign_reap(Seen::ByKill).await;
}

#[skuld::test]
async fn tokio_kill_tree_below_6_9_sends_nothing_by_number_after_a_foreign_reap_seen_by_try_wait() {
    kill_tree_below_6_9_after_a_seen_foreign_reap(Seen::ByTryWait).await;
}

#[skuld::test]
async fn tokio_kill_tree_below_6_9_sends_nothing_by_number_after_a_foreign_reap_seen_by_wait() {
    kill_tree_below_6_9_after_a_seen_foreign_reap(Seen::ByWait).await;
}

#[skuld::test]
async fn tokio_graceful_shutdown_tree_shuts_the_group_down_after_a_foreign_reap_seen_by_try_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    graceful_shutdown_tree_after_a_seen_foreign_reap(Seen::ByTryWait).await;
}

#[skuld::test]
async fn tokio_graceful_shutdown_tree_shuts_the_group_down_after_a_foreign_reap_seen_by_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    graceful_shutdown_tree_after_a_seen_foreign_reap(Seen::ByWait).await;
}

/// A `sleep` in its own session, killed and reaped behind its handle's back.
fn foreign_reaped_group_root() -> crate::tokio::Child {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sleep", "300"]);
    cmd.contain_with(crate::ContainMode::Session);
    let mut child = cmd.spawn().expect("spawn");
    child.kill().expect("kill the root");
    reap_behind(child.id().pid());
    child
}

/// [`root_with_a_cat`], its root killed and reaped behind its handle's back.
async fn foreign_reaped_root_with_a_cat() -> (crate::tokio::Child, ChildStdin, ChildStderr) {
    let (mut child, stdin, stderr) = root_with_a_cat().await;
    child.kill().expect("kill the root alone");
    reap_behind(child.id().pid());
    (child, stdin, stderr)
}

/// The sync `terminate_tree_signals_the_group_of_a_root_reaped_elsewhere`'s twin. Same mutant.
#[skuld::test]
async fn tokio_terminate_tree_signals_the_group_of_a_root_reaped_elsewhere(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    crate::tokio::test_runtime::assert_current_thread();
    let (child, _stdin, stderr) = foreign_reaped_root_with_a_cat().await;
    let capture = Capture::start();
    let result = child.terminate_tree();
    let steps = capture.group_steps();
    result.expect("the group is signalled through the root's pidfd");
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd)), "{steps:?}");
    await_the_cat_gone(stderr).await;
}

/// The sync `terminate_tree_of_a_root_reaped_elsewhere_with_no_member_left_sends_nothing`'s twin.
/// Same mutants.
#[skuld::test]
async fn tokio_terminate_tree_of_a_root_reaped_elsewhere_with_no_member_left_sends_nothing(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    crate::tokio::test_runtime::assert_current_thread();
    let child = foreign_reaped_group_root();
    let capture = Capture::start();
    let result = child.terminate_tree();
    let steps = capture.group_steps();
    result.expect("an empty group has nothing to signal");
    assert_eq!(steps, [], "nothing was sent");
}

/// The sync `graceful_shutdown_tree_shuts_down_the_group_of_a_root_reaped_elsewhere`'s twin. Same
/// mutants.
#[skuld::test]
async fn tokio_graceful_shutdown_tree_shuts_down_the_group_of_a_root_reaped_elsewhere(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    use crate::child::group_exact_tests::assert_down_without_status;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, _stdin, stderr) = foreign_reaped_root_with_a_cat().await;
    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    let result = child.graceful_shutdown_tree(std::time::Duration::from_secs(1)).await;
    let steps = capture.group_steps();
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd)), "{steps:?}");
    await_the_cat_gone(stderr).await;
    assert_down_without_status(result, mark);
}

/// The sync `graceful_shutdown_tree_of_a_root_reaped_elsewhere_with_no_member_left_sends_nothing`'s
/// twin. Same mutants.
#[skuld::test]
async fn tokio_graceful_shutdown_tree_of_a_root_reaped_elsewhere_with_no_member_left_sends_nothing(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    use crate::child::group_exact_tests::assert_down_without_status;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let mut child = foreign_reaped_group_root();
    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    let result = child.graceful_shutdown_tree(std::time::Duration::from_secs(1)).await;
    let steps = capture.group_steps();
    assert_eq!(steps, [], "nothing was sent");
    assert_down_without_status(result, mark);
}
