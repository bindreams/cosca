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

/// The awaited teardown awaits its cgroup leaf's drain and never blocks the thread on it: a drain
/// that is pending leaves the teardown pending. A fake leaf that no one empties holds the drain
/// open. The rows fail only by hanging (a teardown that blocks on the drain never returns), so
/// they are `death_watch_` rows, which nextest bounds.
#[cfg(target_os = "linux")]
mod leaf_drain {
    use std::task::Poll;

    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::elevation::front::Front;
    use crate::test_child::{held_blocker_async, Console};

    /// A fake leaf `populated 1` until [`drain`](Self::drain), under an async child's spawn.
    struct UndrainedLeaf {
        fake: FakeLeaf,
    }

    impl UndrainedLeaf {
        fn new(name: &str) -> UndrainedLeaf {
            let fake = FakeLeaf::new(name, true);
            let (path, events) = (fake.leaf.clone(), fake.events.clone());
            leaf_fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&path, &events));
            UndrainedLeaf { fake }
        }

        /// The held blocker, spawned into the leaf.
        fn spawn(&self) -> (crate::tokio::Child, crate::tokio::ChildStdin) {
            crate::child::spawn::fault::set_attachment_override(crate::containment::Attachment {
                containment: crate::containment::Containment::CgroupV2,
                attached: crate::containment::Attached::Cgroup(entered_leaf_at(self.fake.leaf.clone())),
                graceful: crate::graceful::GracefulMechanism::Process,
            });
            held_blocker_async(crate::Stdio::null(), Console::Hidden, |_| {})
        }

        fn drain(&self) {
            FakeLeaf::set_populated(&self.fake.events, false);
        }
    }

    impl Drop for UndrainedLeaf {
        fn drop(&mut self) {
            leaf_fault::take_rmdir_hook();
        }
    }

    /// Polls `future` once.
    async fn poll_once<F: std::future::Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        std::future::poll_fn(|cx| Poll::Ready(std::pin::Pin::new(&mut *future).poll(cx))).await
    }

    /// A root that is reaped already ends the teardown at its first half, with the leaf's kill
    /// written: the drain it bounds is awaited, not left to the leaf's drop.
    ///
    /// Mutant: the teardown returns at its first half without awaiting the drain.
    #[skuld::test]
    async fn death_watch_a_teardown_of_a_reaped_root_awaits_the_leafs_drain() {
        crate::tokio::test_runtime::assert_current_thread();
        let leaf = UndrainedLeaf::new("cosca-awaited-reaped-root");
        let (mut child, stdin) = leaf.spawn();
        drop(stdin);
        child.wait().await.expect("the blocker ends at EOF");
        let mut teardown = Box::pin(child.tear_down_awaiting());

        let first = poll_once(&mut teardown).await;
        assert!(first.is_pending(), "the leaf has not drained, so the teardown waits");
        leaf.drain();
        let (fate, unreaped) = teardown.await;

        assert_eq!(fate, crate::error::ChildFate::Reaped);
        assert!(unreaped.is_none());
        assert!(!leaf.fake.leaf.exists(), "the drained leaf is removed");
    }

    /// A front behind a closed gate: the leaf is killed through and its drain awaited, then the front
    /// is looked at.
    ///
    /// Mutant: the closed-gate arm drops the leaf in the first half, which waits for the drain.
    #[skuld::test]
    async fn death_watch_a_teardown_of_a_front_behind_a_closed_gate_awaits_the_leafs_drain() {
        crate::tokio::test_runtime::assert_current_thread();
        let leaf = UndrainedLeaf::new("cosca-awaited-closed-gate");
        let (mut child, _stdin) = leaf.spawn();
        // The fake leaf holds no member, so the gate finds no cgroup kill that reaches the front.
        child.inner.front = Some(Front::Sudo);
        let mut teardown = Box::pin(child.tear_down_awaiting());

        let first = poll_once(&mut teardown).await;
        assert!(first.is_pending(), "the leaf has not drained, so the teardown waits");
        leaf.drain();
        let (fate, unreaped) = teardown.await;

        assert!(!leaf.fake.leaf.exists(), "the drained leaf is removed");
        // The fake leaf's kill reaches nothing, so the front still runs and is handed back.
        assert!(matches!(fate, crate::error::ChildFate::Running { .. }), "got {fate:?}");
        assert!(unreaped.is_some(), "a front left running is the caller's");
    }
}
