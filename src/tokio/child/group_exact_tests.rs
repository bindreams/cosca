//! Async twin of `child/group_exact_tests.rs`'s foreign-reap case: on Linux 6.9+ the root's pidfd
//! names its group exactly, whoever reaped the root.

use crate::child::group_exact_tests::{await_started, EndedAtTheSigterm, Member, ROOT_WITH_A_MEMBER};
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture, GroupStep, Route};
use crate::test_child::reaped_elsewhere::reap_behind;
use crate::test_groups::{pidfd_group_signal, Group};

/// The sync `root_with_a_member`'s twin.
pub(crate) fn root_with_a_member() -> (crate::tokio::Child, Member) {
    let (stdio, started, member) = Member::pipes();
    let child = {
        let mut cmd = crate::tokio::Command::new();
        cmd.args(ROOT_WITH_A_MEMBER);
        cmd.contain_with(crate::ContainMode::Session);
        cmd.stdin(stdio.stdin).expect("set stdin");
        cmd.stdout(stdio.stdout).expect("set stdout");
        cmd.stderr(stdio.stderr).expect("set stderr");
        cmd.spawn().expect("spawn")
    };
    await_started(started);
    (child, member)
}

#[skuld::test]
async fn tokio_kill_tree_kills_the_group_of_a_root_reaped_elsewhere(#[fixture(pidfd_group_signal)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member) = root_with_a_member();
    let pid = child.id().pid();
    child.kill().expect("kill the root alone");
    reap_behind(pid);

    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    result.expect("the group is killed through the root's pidfd");
    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGKILL)),
        "{steps:?}"
    );
    member.assert_killed();
}

/// How this handle observes a foreign reap of its root: any way it then holds no tokio `Child`.
#[derive(Debug, Clone, Copy)]
enum Seen {
    TryWait,
    Wait,
    /// A second `kill`, which finds the root gone and sends nothing.
    Kill,
    /// A second `kill` whose look at the root fails: the handle forgets tokio's `Child` as not
    /// shown to be ours.
    KillWithAFailedPeek,
}

/// Kills `child`'s root alone, has another reaper reap it, and has `seen` observe that.
async fn reap_behind_and_observe(child: &mut crate::tokio::Child, seen: Seen) {
    child.kill().expect("kill the root alone");
    reap_behind(child.id().pid());
    match seen {
        Seen::TryWait => drop(child.try_wait().expect_err("a foreign reap answers ECHILD")),
        Seen::Wait => drop(child.wait().await.expect_err("a foreign reap answers ECHILD")),
        Seen::Kill => child.kill().expect("a root reaped elsewhere has nothing left to kill"),
        Seen::KillWithAFailedPeek => {
            use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
            let failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));
            child.kill().expect("a root reaped elsewhere has nothing left to kill");
            assert_peeks_exhausted();
            drop(failed);
            assert!(
                matches!(child.root_state(), crate::signal::RootState::Unknown(_)),
                "the handle forgot its root as not shown to be ours"
            );
        }
    }
}

/// 6.9+: a root whose foreign reap this handle has observed still names its group exactly through
/// its pidfd, so `kill_tree` kills the group. Mutant: "observing a foreign reap drops the pidfd".
async fn kill_tree_after_a_seen_foreign_reap(seen: Seen) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member) = root_with_a_member();
    reap_behind_and_observe(&mut child, seen).await;

    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    result.expect("the group is killed through the root's pidfd");
    assert_group_signalled_first_through_the_pidfd(&steps, libc::SIGKILL);
    member.assert_killed();
}

/// The `SIGTERM` twin of [`kill_tree_after_a_seen_foreign_reap`]. Same mutant.
async fn terminate_tree_after_a_seen_foreign_reap(seen: Seen) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member) = root_with_a_member();
    reap_behind_and_observe(&mut child, seen).await;

    let capture = Capture::start();
    let result = child.terminate_tree();
    let steps = capture.group_steps();
    result.expect("the group is termed through the root's pidfd");
    assert_group_signalled_first_through_the_pidfd(&steps, libc::SIGTERM);
    member.assert_killed();
}

/// The graceful twin of [`kill_tree_after_a_seen_foreign_reap`]: the `SIGTERM` goes through the
/// pidfd, and the call ends with the root's status unknown. Same mutant.
async fn graceful_shutdown_tree_after_a_seen_foreign_reap(seen: Seen) {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, member) = root_with_a_member();
    reap_behind_and_observe(&mut child, seen).await;

    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    let result = child.graceful_shutdown_tree(std::time::Duration::ZERO).await;
    let steps = capture.group_steps();
    assert_group_signalled_first_through_the_pidfd(&steps, libc::SIGTERM);
    member.assert_killed();
    crate::child::group_exact_tests::assert_down_without_status(result, mark);
}

/// Below 6.9 the old behaviour holds: nothing goes out by the reaped root's number, the call is
/// unassessable, and the member lives on. Mutant: "a refused flag still lets the call signal the
/// group by number".
async fn kill_tree_below_6_9_after_a_seen_foreign_reap(seen: Seen) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member) = root_with_a_member();
    reap_behind_and_observe(&mut child, seen).await;
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    drop(old_kernel);
    let err = result.expect_err("a group whose root was reaped elsewhere is not assessable");
    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert!(
        !steps.iter().any(|s| matches!(s, GroupStep::Group(Route::Number, _))),
        "nothing went by the group's number: {steps:?}"
    );
    member.assert_survived();
}

#[skuld::test]
async fn tokio_kill_tree_kills_the_group_after_a_foreign_reap_seen_by_try_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kill_tree_after_a_seen_foreign_reap(Seen::TryWait).await;
}

#[skuld::test]
async fn tokio_kill_tree_kills_the_group_after_a_foreign_reap_seen_by_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kill_tree_after_a_seen_foreign_reap(Seen::Wait).await;
}

#[skuld::test]
async fn tokio_terminate_tree_terminates_the_group_after_a_foreign_reap_seen_by_try_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    terminate_tree_after_a_seen_foreign_reap(Seen::TryWait).await;
}

#[skuld::test]
async fn tokio_terminate_tree_terminates_the_group_after_a_foreign_reap_seen_by_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    terminate_tree_after_a_seen_foreign_reap(Seen::Wait).await;
}

#[skuld::test]
async fn tokio_kill_tree_kills_the_group_after_a_foreign_reap_seen_by_kill(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kill_tree_after_a_seen_foreign_reap(Seen::Kill).await;
}

#[skuld::test]
async fn tokio_terminate_tree_terminates_the_group_after_a_foreign_reap_seen_by_kill(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    terminate_tree_after_a_seen_foreign_reap(Seen::Kill).await;
}

#[skuld::test]
async fn tokio_graceful_shutdown_tree_shuts_the_group_down_after_a_foreign_reap_seen_by_kill(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    graceful_shutdown_tree_after_a_seen_foreign_reap(Seen::Kill).await;
}

/// A handle that forgot its root as not shown to be ours still holds the root's pidfd, which names
/// it exactly whatever the look said. Mutant: "only a child shown reaped elsewhere keeps its pidfd".
#[skuld::test]
async fn tokio_kill_tree_kills_the_group_after_a_foreign_reap_seen_by_a_kill_whose_look_failed(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kill_tree_after_a_seen_foreign_reap(Seen::KillWithAFailedPeek).await;
}

#[skuld::test]
async fn tokio_terminate_tree_terminates_the_group_after_a_foreign_reap_seen_by_a_kill_whose_look_failed(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    terminate_tree_after_a_seen_foreign_reap(Seen::KillWithAFailedPeek).await;
}

#[skuld::test]
async fn tokio_kill_tree_below_6_9_sends_nothing_by_number_after_a_foreign_reap_seen_by_kill() {
    kill_tree_below_6_9_after_a_seen_foreign_reap(Seen::Kill).await;
}

#[skuld::test]
async fn tokio_kill_tree_below_6_9_sends_nothing_by_number_after_a_foreign_reap_seen_by_try_wait() {
    kill_tree_below_6_9_after_a_seen_foreign_reap(Seen::TryWait).await;
}

#[skuld::test]
async fn tokio_kill_tree_below_6_9_sends_nothing_by_number_after_a_foreign_reap_seen_by_wait() {
    kill_tree_below_6_9_after_a_seen_foreign_reap(Seen::Wait).await;
}

#[skuld::test]
async fn tokio_graceful_shutdown_tree_shuts_the_group_down_after_a_foreign_reap_seen_by_try_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    graceful_shutdown_tree_after_a_seen_foreign_reap(Seen::TryWait).await;
}

#[skuld::test]
async fn tokio_graceful_shutdown_tree_shuts_the_group_down_after_a_foreign_reap_seen_by_wait(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    graceful_shutdown_tree_after_a_seen_foreign_reap(Seen::Wait).await;
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

/// [`root_with_a_member`], its root killed and reaped behind its handle's back.
fn foreign_reaped_root_with_a_member() -> (crate::tokio::Child, Member) {
    let (mut child, member) = root_with_a_member();
    child.kill().expect("kill the root alone");
    reap_behind(child.id().pid());
    (child, member)
}

/// The sync `terminate_tree_signals_the_group_of_a_root_reaped_elsewhere`'s twin. Same mutant.
#[skuld::test]
async fn tokio_terminate_tree_signals_the_group_of_a_root_reaped_elsewhere(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    crate::tokio::test_runtime::assert_current_thread();
    let (child, member) = foreign_reaped_root_with_a_member();
    let capture = Capture::start();
    let result = child.terminate_tree();
    let steps = capture.group_steps();
    result.expect("the group is signalled through the root's pidfd");
    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGTERM)),
        "{steps:?}"
    );
    member.assert_killed();
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
    let (mut child, member) = foreign_reaped_root_with_a_member();
    let mark = crate::log_capture::mark();
    let ended = EndedAtTheSigterm::new(member);
    let capture = Capture::start();
    let result = child.graceful_shutdown_tree(std::time::Duration::from_secs(1)).await;
    let steps = capture.group_steps();
    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGTERM)),
        "{steps:?}"
    );
    ended.assert_killed_by_the_sigterm();
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
