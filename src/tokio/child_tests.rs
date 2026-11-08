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
    #[cfg(unix)]
    let pid = child.pid();
    child.inner.proc.script_over(|f| f.reaps([ReapAnswer::Running]));
    let mut teardown = Box::pin(child.tear_down_awaiting());

    let first = std::future::poll_fn(|cx| Poll::Ready(teardown.as_mut().poll(cx))).await;
    assert!(first.is_pending(), "the teardown waits for the root");
    drop(teardown);

    assert_eq!(id.is_alive(), Liveness::Dead, "the dropped teardown ended the root");
    // A killed root that nobody reaped reads as dead too: it is the reap that says it was settled.
    #[cfg(unix)]
    assert_eq!(
        crate::child::front_kill_tests::reap(pid),
        None,
        "the dropped teardown reaped the root"
    );
}

/// `wait` closes the untaken stdin before it waits, so a child that reads stdin to EOF can exit.
///
/// Mutant: `wait` leaves stdin open.
#[skuld::test]
async fn death_watch_wait_closes_the_untaken_stdin() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    child.wait().await.expect("the child ends on the EOF wait made");
}

/// The same when another slot merges into the stdin pipe: the merge is a copy of the child's end,
/// so the parent's end is still the only writer and closes with the wait.
///
/// Mutant: the merge's resolution keeps a second parent end of the pipe open.
#[skuld::test]
async fn death_watch_wait_closes_an_untaken_stdin_another_slot_merges_into() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::merge(crate::Fd::STDIN)).expect("merge fd 3");
    let mut child = cmd.spawn().expect("spawn");
    child.wait().await.expect("the child ends on the EOF wait made");
}

/// The same beside a pipe at fd 3, which the Windows spawn carries in its own attribute list: the
/// untaken stdin closes with the wait, beside the fd 3 pipe it leaves open.
///
/// Mutant: the pipes `wait` closes are not the ones the spawn made.
#[cfg(windows)]
#[skuld::test]
async fn death_watch_wait_closes_the_untaken_stdin_beside_an_fd_3_pipe() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("fd 3 pipe");
    let mut child = cmd.spawn().expect("spawn");
    child.wait().await.expect("the child ends on the EOF wait made");
}

/// A teardown future dropped by an unwind (a sibling branch panicked) does not block on the root: it
/// gives the child up, as an `Unreaped`'s drop does, and says so with the child's pid.
///
/// Mutant: the guard's drop gives the child up without a word.
#[skuld::test]
async fn a_teardown_future_dropped_while_panicking_gives_the_child_up_and_warns() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, _stdin) = held_blocker_async(crate::Stdio::null(), Console::Hidden, |_| {});
    let pid = child.pid();
    child.inner.proc.script_over(|f| f.reaps([ReapAnswer::Running]));
    let mut teardown = Box::pin(child.tear_down_awaiting());
    let first = std::future::poll_fn(|cx| Poll::Ready(teardown.as_mut().poll(cx))).await;
    assert!(first.is_pending(), "the teardown waits for the root");

    let mark = crate::log_capture::mark();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _teardown = teardown;
        panic!("a sibling branch panicked");
    }));

    assert!(unwound.is_err());
    let warns = crate::log_capture::records_since_on_current_thread(mark, "while the thread is panicking");
    assert_eq!(warns.len(), 1, "one warn, got {warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn);
    assert!(warns[0].1.contains(&format!("child {pid}")), "names the pid: {warns:?}");
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

    /// A drain that cannot be watched is left to the leaf's drop: the teardown ends, says at debug
    /// that it did not wait, and the leaf's own drop reports the leaf left behind. The leaf's
    /// `cgroup.events` is unreadable as a state, so neither wait for the drain can run.
    ///
    /// Mutant: the awaited drain's failure ends the teardown with an error, or is not said.
    #[skuld::test]
    async fn a_teardown_whose_leafs_drain_cannot_be_watched_leaves_it_to_the_drop() {
        crate::tokio::test_runtime::assert_current_thread();
        crate::log_capture::install();
        let leaf = UndrainedLeaf::new("cosca-awaited-unwatchable");
        // The leaf is never removed: nothing it holds drains.
        leaf_fault::set_rmdir_hook(|_| Err(std::io::Error::from_raw_os_error(libc::EBUSY)));
        let (mut child, stdin) = leaf.spawn();
        drop(stdin);
        child.wait().await.expect("the blocker ends at EOF");
        std::fs::write(&leaf.fake.events, "garbled\n").expect("garble cgroup.events");
        let mark = crate::log_capture::mark();

        let (fate, unreaped) = child.tear_down_awaiting().await;

        assert_eq!(fate, crate::error::ChildFate::Reaped);
        assert!(unreaped.is_none());
        let said = crate::log_capture::records_since(mark, "its leaf's drain cannot be watched");
        assert_eq!(said.len(), 1, "{said:?}");
        let warned = crate::log_capture::records_since(mark, "its drain could not be watched");
        assert_eq!(warned.len(), 1, "the leaf's drop reports it left behind: {warned:?}");
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
