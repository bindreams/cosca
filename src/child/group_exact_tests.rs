//! Linux: a tree call on a process group whose root is reaped. On 6.9+ the root's pidfd names the
//! group exactly, whoever reaped the root; below 6.9 the root's own handle decides what goes out by
//! the group's number.

use std::io::Read as _;

use crate::send_log::{Capture, GroupStep, Route};
use crate::test_child::reaped_elsewhere::{foreign_reaped_group_root, reap_behind};
use crate::test_groups::{pidfd_group_signal, Group};

/// A session root `sh` that leaves a `cat` in its group, then sleeps, and the pipes that keep the
/// `cat` alive and report its end. `exec 3<&0` because `sh` points a background job's stdin at
/// `/dev/null` otherwise. The `cat` holds stderr's write end: once the root is gone, stderr reaches
/// EOF exactly when the `cat` is.
pub(crate) fn root_with_a_cat() -> (crate::Child, std::io::PipeWriter, std::io::PipeReader) {
    let mut cmd = crate::Command::new();
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
        .expect("read `started`");
    assert_eq!(&started, b"started\n");
    let stdin = child.stdin().expect("stdin pipe");
    let stderr = child.stderr().expect("stderr pipe");
    (child, stdin, stderr)
}

/// Blocks until the `cat` of [`root_with_a_cat`] is gone. Call it only once the kill that ends it
/// is shown sent: the `cat` outlives anything else.
pub(crate) fn await_the_cat_gone(mut stderr: std::io::PipeReader) {
    let mut rest = Vec::new();
    stderr.read_to_end(&mut rest).expect("read stderr to the cat's end");
}

/// 6.9+: a root reaped by another reaper still names its group through its pidfd, so `kill_tree`
/// kills the members left. Mutant: "a root reaped elsewhere is never signalled".
#[skuld::test]
fn kill_tree_kills_the_group_of_a_root_reaped_elsewhere(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (child, _stdin, stderr) = root_with_a_cat();
    let pid = child.id().pid();
    child.kill().expect("kill the root alone");
    reap_behind(pid);
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    result.expect("the group is killed through the root's pidfd");
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd)), "{steps:?}");
    await_the_cat_gone(stderr);
}

/// 6.9+: a root reaped by another reaper whose group has no member left has no tree to kill:
/// `kill_tree` sends nothing and succeeds. Mutants: "a group with no member left is still
/// unassessable", "it is signalled through the pidfd regardless".
#[skuld::test]
fn kill_tree_of_a_root_reaped_elsewhere_with_no_member_left_sends_nothing(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (child, _pgid) = foreign_reaped_group_root();
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    result.expect("an empty group is killed already");
    assert_eq!(steps, [], "nothing was sent");
}

/// Below 6.9, after this handle's own reap, a root pid that names no process is still the id of the
/// root's group while a member is left: the group is killed by that number, right after its check.
/// Mutant: "after this handle's own reap, a pid that names nothing fails the check".
#[skuld::test]
fn kill_tree_below_6_9_kills_the_group_by_number_after_this_handles_own_reap() {
    let (child, _stdin, stderr) = root_with_a_cat();
    child.kill().expect("kill the root alone");
    child.wait().expect("this handle reaps the root");
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    drop(old_kernel);
    result.expect("the group is killed by its number");
    assert_eq!(
        steps.get(..3),
        Some(
            &[
                GroupStep::Group(Route::Pidfd),
                GroupStep::Check,
                GroupStep::Group(Route::Number)
            ][..]
        ),
        "{steps:?}"
    );
    await_the_cat_gone(stderr);
}
