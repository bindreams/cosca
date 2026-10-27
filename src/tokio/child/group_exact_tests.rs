//! Async twin of `child/group_exact_tests.rs`'s foreign-reap case: on Linux 6.9+ the root's pidfd
//! names its group exactly, whoever reaped the root.

use crate::child::group_exact_tests::{await_started, EndedAtTheSigterm, Member};
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture, GroupStep, Route};
use crate::test_child::reaped_elsewhere::{kill_own_child, reap_behind_status};
use crate::test_groups::{pidfd_group_signal, Group};

/// The sync `ROOT_WITH_A_MEMBER`, its root blocked on fd 4 instead of sleeping: it exits `0` once the
/// writer of that pipe is dropped, which the member's stdin does not share.
const RELEASABLE_ROOT_WITH_A_MEMBER: [&str; 3] = [
    "sh",
    "-c",
    "exec 3<&0; (cat <&3 3<&- >/dev/null && echo survived >&2) & echo started; exec cat <&4 4<&- 3<&- >/dev/null 2>/dev/null",
];

/// The sync `root_with_a_member`'s twin, and the writer whose drop ends its root with status `0`;
/// drop it right after the kill.
pub(crate) fn releasable_root_with_a_member() -> (crate::tokio::Child, Member, std::io::PipeWriter) {
    releasable_root_with_a_member_contained(|cmd| {
        cmd.contain_with(crate::ContainMode::Session);
    })
}

/// [`releasable_root_with_a_member`] with the containment `contain` sets.
pub(crate) fn releasable_root_with_a_member_contained(
    contain: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, Member, std::io::PipeWriter) {
    let (stdio, started, member) = Member::pipes();
    let (gate, release) = crate::test_child::held_writer_stdin();
    let child = {
        let mut cmd = crate::tokio::Command::new();
        cmd.args(RELEASABLE_ROOT_WITH_A_MEMBER);
        cmd.fd(4, gate).expect("set the root's release pipe");
        contain(&mut cmd);
        cmd.stdin(stdio.stdin).expect("set stdin");
        cmd.stdout(stdio.stdout).expect("set stdout");
        cmd.stderr(stdio.stderr).expect("set stderr");
        cmd.spawn().expect("spawn")
    };
    await_started(started);
    (child, member, release)
}

/// A [`BLOCKER_ARGV`](crate::test_child::BLOCKER_ARGV) root in its own session, and the writer
/// whose drop ends it with status `0`. Its group has no other member.
pub(crate) fn releasable_group_root() -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, release) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    (cmd.spawn().expect("spawn"), release)
}

/// Ends `child`'s root alone and reaps it behind the handle's back. The kill is setup, so it is
/// [`kill_own_child`], which no route under test can turn into a no-op. `release` is dropped once
/// the root is dead.
pub(crate) fn kill_and_reap_behind(child: &mut crate::tokio::Child, release: std::io::PipeWriter) {
    let pid = child.id().pid();
    kill_own_child(pid);
    drop(release);
    crate::test_child::assert_killed("the root", reap_behind_status(pid));
}

#[skuld::test]
async fn tokio_kill_tree_kills_the_group_of_a_root_reaped_elsewhere(#[fixture(pidfd_group_signal)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member, release) = releasable_root_with_a_member();
    kill_and_reap_behind(&mut child, release);

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

/// Kills `child`'s root alone, has another reaper reap it, and has `seen` observe that (see
/// [`kill_and_reap_behind`] for `release`).
async fn reap_behind_and_observe(child: &mut crate::tokio::Child, release: std::io::PipeWriter, seen: Seen) {
    kill_and_reap_behind(child, release);
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
    let (mut child, member, release) = releasable_root_with_a_member();
    reap_behind_and_observe(&mut child, release, seen).await;

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
    let (mut child, member, release) = releasable_root_with_a_member();
    reap_behind_and_observe(&mut child, release, seen).await;

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
    let (mut child, member, release) = releasable_root_with_a_member();
    reap_behind_and_observe(&mut child, release, seen).await;

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
    let (mut child, member, release) = releasable_root_with_a_member();
    reap_behind_and_observe(&mut child, release, seen).await;
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

/// A [`releasable_group_root`], killed and reaped behind its handle's back.
fn foreign_reaped_group_root() -> crate::tokio::Child {
    let (mut child, release) = releasable_group_root();
    kill_and_reap_behind(&mut child, release);
    child
}

/// [`releasable_root_with_a_member`], its root killed and reaped behind its handle's back.
fn foreign_reaped_root_with_a_member() -> (crate::tokio::Child, Member) {
    let (mut child, member, release) = releasable_root_with_a_member();
    kill_and_reap_behind(&mut child, release);
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
