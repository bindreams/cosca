//! Linux 6.9+: each of the sync `Child`'s group sends goes through the root's pidfd, so nothing
//! names its process group by number. Mutant for each: "the call gives no pidfd".

use crate::child::spawn::fault::{release_at_drop_kill, release_between_kill_and_wait};
use crate::send_log::{assert_group_signalled_first_through_the_pidfd as assert_through_the_pidfd, Capture};
use crate::test_groups::{pidfd_group_signal, Group};

/// A root that leads its own group (a session), blocked on a pipe whose write end is returned.
fn group_root() -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    (cmd.spawn().expect("spawn"), writer)
}

#[skuld::test]
fn kill_tree_signals_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    use std::os::unix::process::ExitStatusExt as _;
    let (child, writer) = group_root();
    let capture = Capture::start();
    child.kill_tree().expect("kill_tree");
    assert_through_the_pidfd(&capture.group_steps(), libc::SIGKILL);
    // Released only after the kill: a kill that sent nothing lets the root end by itself, which
    // shows in its status instead of leaving the wait to block.
    drop(writer);
    let status = child.wait().expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "the group's kill ended the root");
}

/// Its `SIGTERM` kills the group's member. Mutant: "the send through the pidfd carries signal 0".
#[skuld::test]
fn terminate_tree_signals_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (child, member) = crate::child::group_exact_tests::root_with_a_member();
    let capture = Capture::start();
    child.terminate_tree().expect("terminate_tree");
    assert_through_the_pidfd(&capture.group_steps(), libc::SIGTERM);
    member.assert_killed();
}

/// Its `SIGTERM` kills the group's member before the sweep could. Mutant: "graceful sends no
/// `SIGTERM`".
#[skuld::test]
fn graceful_shutdown_tree_signals_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    use crate::child::group_exact_tests::{root_with_a_member, EndedAtTheSigterm};
    let (child, member) = root_with_a_member();
    let ended = EndedAtTheSigterm::new(member);
    let capture = Capture::start();
    child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect("graceful_shutdown_tree");
    let steps = capture.group_steps();
    assert_through_the_pidfd(&steps, libc::SIGTERM);
    ended.assert_killed_by_the_sigterm();
}

#[skuld::test]
fn a_drop_kills_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (child, writer) = group_root();
    let blocker = release_at_drop_kill(writer);
    let capture = Capture::start();
    drop(child);
    assert_through_the_pidfd(&capture.group_steps(), libc::SIGKILL);
    blocker.assert_killed();
}

#[skuld::test]
fn a_failed_elevated_spawns_cleanup_kills_the_group_through_the_root_pidfd(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (child, writer) = group_root();
    let blocker = release_between_kill_and_wait(writer);
    let capture = Capture::start();
    let failed = crate::child::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Io(std::io::Error::other("no password"))),
    );
    assert!(failed.is_err(), "the password write failed");
    assert_through_the_pidfd(&capture.group_steps(), libc::SIGKILL);
    blocker.assert_killed();
}
