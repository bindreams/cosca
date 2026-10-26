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
