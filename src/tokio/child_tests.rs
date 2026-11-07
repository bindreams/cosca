//! Rows for what the async `Child` adds to the sync one it holds: its awaited teardown. What the
//! teardown decides is the sync policy's, with its own rows.

use std::future::Future as _;
use std::task::Poll;

use crate::identity::Liveness;
use crate::os_process::fake::ReapAnswer;
use crate::test_child::{held_blocker_async, Console};

/// The async spawn tells the one spawn the async policy: the child it made carries it, so every
/// teardown of that child warns past the threshold the async side reads when the spawn starts, and
/// an `Unreaped` it hands back lets the child go. The failed-spawn arms' own pass-through is pinned
/// by the rows of `spawn/slow_teardown_*_tests`.
///
/// Mutant: `spawn_uncommitted` is given the sync policy.
#[skuld::test]
async fn the_async_spawn_hands_its_child_the_async_policy() {
    use crate::child::owned::unreaped::DropKind;
    use crate::child::spawn::policy::SpawnPolicy;

    crate::tokio::test_runtime::assert_current_thread();
    let _warn = super::fault::warn_slow_teardowns_after(std::time::Duration::ZERO);
    let (child, _stdin) = held_blocker_async(crate::Stdio::null(), Console::Hidden, |_| {});

    assert_eq!(
        child.inner.policy,
        SpawnPolicy {
            teardown_warn_after: Some(std::time::Duration::ZERO),
            unreaped_drop: DropKind::LetGo,
        }
    );
}

/// A teardown future dropped at its wait settles it as a drop does: the drop blocks until the root
/// is reaped, so no child is left behind by a cancelled `status`, `output` or `read`. The first look
/// at the root's exit is stated `Running`, and nothing wakes that wait, so the teardown is pending
/// at its wait, after its kill went to the real child.
///
/// Mutant: the awaited teardown's guard does nothing when the future is dropped, leaving the child
/// killed and unreaped.
#[skuld::test]
async fn a_teardown_future_dropped_at_its_wait_settles_as_a_drop_does() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _stdin) = held_blocker_async(crate::Stdio::null(), Console::Hidden, |_| {});
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    child.inner.proc.script_over(|f| f.reaps([ReapAnswer::Running]));
    let mut teardown = Box::pin(child.tear_down_awaiting());

    let first = std::future::poll_fn(|cx| Poll::Ready(teardown.as_mut().poll(cx))).await;
    assert!(first.is_pending(), "the teardown waits for the root");
    drop(teardown);

    assert_eq!(id.is_alive(), Liveness::Dead, "the dropped teardown reaped the root");
}
