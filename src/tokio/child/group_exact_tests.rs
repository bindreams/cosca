//! Async twin of `child/group_exact_tests.rs`'s foreign-reap case: on Linux 6.9+ the root's pidfd
//! names its group exactly, whoever reaped the root.

use crate::child::group_exact_tests::{await_started, EndedAtTheSigterm, Member};
use crate::send_log::{Capture, GroupStep, Route};
use crate::test_child::reaped_elsewhere::reap_behind_status;
use crate::test_groups::{pidfd_group_signal, Group};

/// The sync `ROOT_WITH_A_MEMBER`, its root blocked on fd 4 instead of sleeping: it exits `0` once the
/// writer of that pipe is dropped, which the member's stdin does not share.
const RELEASABLE_ROOT_WITH_A_MEMBER: [&str; 3] = [
    "sh",
    "-c",
    "exec 3<&0; (cat <&3 3<&- >/dev/null; echo survived >&2) & echo started; exec cat <&4 4<&- 3<&- >/dev/null 2>/dev/null",
];

/// The sync `root_with_a_member`'s twin, and the writer whose drop ends its root with status `0`:
/// for a test that kills the root as setup, dropped right after the kill, so a kill that sent
/// nothing leaves the root to exit `0` and fails the check on its status, instead of hanging the
/// wait for it.
pub(crate) fn releasable_root_with_a_member() -> (crate::tokio::Child, Member, std::io::PipeWriter) {
    let (stdio, started, member) = Member::pipes();
    let (gate, release) = crate::test_child::held_writer_stdin();
    let child = {
        let mut cmd = crate::tokio::Command::new();
        cmd.args(RELEASABLE_ROOT_WITH_A_MEMBER);
        cmd.fd(4, gate).expect("set the root's release pipe");
        cmd.contain_with(crate::ContainMode::Session);
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

/// Kills `child`'s root alone and reaps it behind the handle's back. `release` ends a root nothing
/// killed with status `0`: the kill's `SIGKILL` is already pending when it drops, so a root that
/// died otherwise fails the check instead of the reap waiting for it.
pub(crate) fn kill_and_reap_behind(child: &mut crate::tokio::Child, release: std::io::PipeWriter) {
    child.kill().expect("kill the root alone");
    drop(release);
    crate::test_child::assert_killed("the root", reap_behind_status(child.id().pid()));
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
