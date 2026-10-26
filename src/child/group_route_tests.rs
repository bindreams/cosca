//! Linux 6.9+: each of the sync `Child`'s group sends goes through the root's pidfd, so nothing
//! names its process group by number. Mutant for each: "the call gives no pidfd".

use crate::send_log::{Capture, GroupStep, Route};
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

#[track_caller]
fn assert_through_the_pidfd(steps: &[GroupStep]) {
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd)), "{steps:?}");
    assert!(
        !steps.contains(&GroupStep::Group(Route::Number)),
        "nothing went by the group's number: {steps:?}"
    );
}

#[skuld::test]
fn kill_tree_signals_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (child, _writer) = group_root();
    let capture = Capture::start();
    child.kill_tree().expect("kill_tree");
    assert_through_the_pidfd(&capture.group_steps());
}

/// Its `SIGTERM` kills the group's member. Mutant: "the send through the pidfd carries signal 0".
#[skuld::test]
fn terminate_tree_signals_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (child, member) = crate::child::group_exact_tests::root_with_a_member();
    let capture = Capture::start();
    child.terminate_tree().expect("terminate_tree");
    assert_through_the_pidfd(&capture.group_steps());
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
    assert_through_the_pidfd(&steps);
    ended.assert_killed_by_the_sigterm();
}

#[skuld::test]
fn a_drop_kills_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (child, _writer) = group_root();
    let capture = Capture::start();
    drop(child);
    assert_through_the_pidfd(&capture.group_steps());
}

#[skuld::test]
fn a_failed_elevated_spawns_cleanup_kills_the_group_through_the_root_pidfd(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (child, _writer) = group_root();
    let capture = Capture::start();
    let failed = crate::child::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Io(std::io::Error::other("no password"))),
    );
    assert!(failed.is_err(), "the password write failed");
    assert_through_the_pidfd(&capture.group_steps());
}
