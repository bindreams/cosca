//! `cosca::tokio::Unreaped`'s contract: `wait` is cancel-safe and leaves the caller holding the
//! child, `leak` gives it up unreaped, and `Drop` blocks until the child exits.

use super::Unreaped;
use crate::child::unreaped::Held;
use crate::identity::{ProcessId, Resolved};

/// `reap_failed` and `classify_tokio_wait` are the async side of cosca's single Unix ownership
/// classification (see `crate::child::unreaped::releases_ownership`): only `ECHILD` — something
/// else already reaped the child — makes a failed reap release it (`Failed::Uncertain`); any other
/// errno, including a too-old kernel's `EINVAL` from `waitid(P_PIDFD)`, leaves it held
/// (`Failed::Unawaitable`), for the caller to keep.
#[cfg(unix)]
#[test]
fn reap_failed_releases_only_on_echild() {
    assert!(
        matches!(
            super::reap_failed(std::io::Error::from_raw_os_error(libc::ECHILD)),
            super::Failed::Uncertain(_)
        ),
        "ECHILD means something else already reaped the child"
    );
    assert!(
        matches!(
            super::reap_failed(std::io::Error::from_raw_os_error(libc::EINVAL)),
            super::Failed::Unawaitable(_)
        ),
        "EINVAL (a too-old kernel's waitid(P_PIDFD)) says nothing about ownership"
    );
    assert!(
        matches!(
            super::classify_tokio_wait(std::io::Error::from_raw_os_error(libc::ECHILD)),
            super::Failed::Uncertain(_)
        ),
        "ECHILD means something else already reaped the child"
    );
    assert!(
        matches!(
            super::classify_tokio_wait(std::io::Error::other("transient failure")),
            super::Failed::Unawaitable(_)
        ),
        "a non-ECHILD error says nothing about ownership"
    );
}

/// A tokio child blocked reading stdin until the returned end drops, and its identity. Spawn it
/// inside a runtime.
fn blocked_child() -> (::tokio::process::Child, ::tokio::process::ChildStdin, ProcessId) {
    let mut child = {
        // Raw tokio bypasses cosca's spawn path and its internal `spawn_lock()`, so it is taken
        // here by hand.
        let _guard = crate::child::spawn::spawn_lock();
        let mut cmd = if cfg!(windows) {
            let mut cmd = ::tokio::process::Command::new("findstr");
            cmd.arg("x");
            cmd
        } else {
            ::tokio::process::Command::new("cat")
        };
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child blocked on stdin")
    };
    let stdin = child.stdin.take().expect("piped stdin");
    let Resolved::Found(id) = ProcessId::of(child.id().expect("an unreaped child has a pid")) else {
        panic!("an unreaped child resolves");
    };
    (child, stdin, id)
}

/// Poll `wait` once, assert it is pending — so it really started waiting — and drop it, as the
/// losing arm of a `select!` is dropped.
fn cancel_after_one_pending_poll(unreaped: &mut Unreaped) {
    use std::future::Future;
    let mut wait = std::pin::pin!(unreaped.wait());
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        wait.as_mut().poll(&mut cx).is_pending(),
        "the child is still running, so its wait is pending"
    );
}

/// Cancel a `wait` after it has started, then wait again: the caller still holds the child, and
/// the second wait reaps it. A later `wait` returns the same status.
async fn a_cancelled_wait_leaves_the_caller_holding<S>(mut unreaped: Unreaped, stdin: S, id: ProcessId) {
    // Rebound, so a failing assertion drops it before `unreaped`, whose drop waits for the child
    // that is reading it: the test fails instead of hanging.
    let stdin = stdin;
    cancel_after_one_pending_poll(&mut unreaped);
    assert_eq!(unreaped.pid(), id.pid(), "still held after the cancelled wait");
    drop(stdin);
    let status = unreaped.wait().await.expect("wait for the child");
    // Its own exit, on end of input: `cat` succeeds, and `findstr` finds no match.
    assert_eq!(status.code(), Some(if cfg!(windows) { 1 } else { 0 }), "{status:?}");
    assert_eq!(unreaped.wait().await.expect("wait again"), status);
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

#[tokio::test]
async fn a_cancelled_wait_leaves_the_caller_holding_a_tokio_child() {
    let (child, stdin, id) = blocked_child();
    a_cancelled_wait_leaves_the_caller_holding(Unreaped::new(Held::Tokio(Box::new(child))), stdin, id).await;
}

/// A child no `Child` holds — as a cgroup leaf hands back — waited on through its own pidfd.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_cancelled_wait_leaves_the_caller_holding_a_bare_child() {
    let (child, stdin, id) = std_blocked_child();
    let pid = child.id();
    // Only the pidfd holds it now: nothing else may reap it.
    std::mem::forget(child);
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(pid as i32).expect("a child's pid is never 0"),
        rustix::process::PidfdFlags::empty(),
    )
    .expect("pidfd_open");
    let held = Held::Bare {
        pid,
        pidfd: Some(pidfd),
    };
    a_cancelled_wait_leaves_the_caller_holding(Unreaped::new(held), stdin, id).await;
}

/// A raw `CreateProcessW` handle, waited on through the async raw backend.
#[cfg(windows)]
#[tokio::test]
async fn a_cancelled_wait_leaves_the_caller_holding_a_raw_child() {
    let (child, stdin, id) = std_blocked_child();
    let pid = child.id();
    let raw = crate::child::spawn::windows_raw::RawChild::new(std::os::windows::io::OwnedHandle::from(child), pid);
    a_cancelled_wait_leaves_the_caller_holding(Unreaped::new(Held::Raw(raw)), stdin, id).await;
}

/// `Drop` blocks until the child exits, then reaps it — here on the blocking pool, as the type's
/// doc tells a caller to.
#[tokio::test]
async fn drop_blocks_until_the_child_exits_and_reaps_it() {
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Tokio(Box::new(child)));
    drop(stdin);
    ::tokio::task::spawn_blocking(move || drop(unreaped))
        .await
        .expect("drop on the blocking pool");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// `leak` gives a tokio child up by dropping it, which releases tokio's handles on it rather than
/// leaking them. tokio's own `Drop` reaps a child that has exited — here one already a zombie when
/// it is leaked — so the drop is observable as that reap.
#[cfg(unix)]
#[tokio::test]
async fn leak_drops_a_tokio_child_releasing_its_handles() {
    let (child, stdin, id) = blocked_child();
    drop(stdin);
    // Awaited without reaping, until it is reapable.
    crate::child::unreaped::block_until_reapable(id.pid()).expect("wait for the child's exit");
    Unreaped::new(Held::Tokio(Box::new(child))).leak();
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// `leak` on a child whose blocking-pool task has already claimed it (state `Running`) — not
/// still `NotStarted`, not yet `Finished` — hits the `Running -> Leaked` arm: it marks the state
/// `Leaked` and returns, leaving the task's own `report` (once its reap completes) to release the
/// held child and disarm what it retained.
///
/// Goes through the real `spawn_blocking_reap` (via the same cancelled-wait,
/// `force_not_yet_reapable` path `a_cancelled_blocking_reap_is_resumed_by_the_next_wait` uses),
/// not a hand-built `ReapTask`, so this exercises the same task construction production does —
/// including `after_claim` now being read from the `fault` seam by `spawn_blocking_reap` itself,
/// rather than set directly on a `ReapTask` this test built by hand.
///
/// The `after_claim` hook runs inside the task's real `run`, right after its real `claim`
/// succeeds and before it waits for the exit, and blocks there until this test releases it. That
/// makes the state deterministically `Running` when `leak` is called below — `claim` updates it
/// strictly before the hook that unblocks the `recv` runs — rather than racing the task's own
/// progress toward `Finished`.
///
/// `leak` consumes `self`, taking `self.blocking`'s `Arc<BlockingReap>` half but discarding its
/// `oneshot::Receiver` half — so this test swaps a dummy receiver into that slot first and keeps
/// the real one, to await after `leak` returns. `leak` only ever reads the `Arc` half, so the
/// swap does not change what it does; awaiting the real receiver afterward proves the gated task's
/// own `report` — the disarm under test — has run, the same as awaiting the task's own
/// `JoinHandle` would. That alone still races the task's own unwind, though: `report` sends this
/// signal from inside a `&mut self` call, before `ReapTask::run` itself returns and so before its
/// own clone of the `Arc` actually drops. A clone of the `Arc` kept here, and waited on past that
/// unwind (see the loop below), closes that window before the assertion reads the file.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn leaking_while_the_blocking_reap_is_running_disarms_what_it_retained() {
    let (child, stdin, id) = std_blocked_child();
    drop(stdin); // the child exits at once, so the task's own reap below does not hang
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-leaked-running-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    let leaf = crate::containment::cgroup::test_support::entered_leaf_at(leaf_path.clone());
    let retained = crate::child::unreaped::Retained {
        attached: crate::containment::Attached::Cgroup(leaf),
    };
    let mut unreaped = Unreaped::from_sync(crate::Unreaped::with_retained(Held::Std(child), Some(retained)));

    let (claimed_tx, claimed_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    // `Sender`/`Receiver` are not `Sync`, but the hook's trait object bound requires it (an
    // `Unreaped` carrying one must stay `Send + Sync` for `Error<Unreaped>`); the `Mutex` costs
    // nothing here, since the hook only ever touches them once, from the one thread that runs it.
    let claimed_tx = std::sync::Mutex::new(claimed_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    super::fault::set_after_claim(Box::new(move || {
        claimed_tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(())
            .expect("the test thread is waiting for the claim");
        release_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv()
            .expect("the test thread releases the gate");
    }));
    super::fault::set_force_not_yet_reapable();
    cancel_after_one_pending_poll(&mut unreaped);
    assert!(
        unreaped.hands_child_to_blocking_task(),
        "the real spawn_blocking_reap must have handed the child to a blocking-pool task"
    );

    // Swap the real `finished` receiver out for a dummy: `leak` below only reads the `Arc`
    // half of the tuple, so this does not change what it does, and it lets this test keep the
    // real one to await once `leak` has consumed `self`. Also keep our own clone of the `Arc`
    // itself, independent of the one `leak` drops and the one the task's own `ReapTask` holds.
    let (_dummy_tx, dummy_rx) = ::tokio::sync::oneshot::channel();
    let (shared, real_finished) = {
        let blocking = unreaped.blocking.as_mut().expect("just handed to a blocking task");
        (blocking.0.clone(), std::mem::replace(&mut blocking.1, dummy_rx))
    };

    claimed_rx
        .recv()
        .expect("the task reaches the gate once it has claimed the child");
    unreaped.leak();
    release_tx.send(()).expect("let the gated task proceed");
    let _ = real_finished.await;

    // Close the signal-before-release race: `report` sends this signal from inside a method call
    // on the task, while the task itself — and so its own clone of `shared` — is still alive on
    // its blocking-pool stack frame; only once `ReapTask::run` itself returns, just after, does
    // that clone actually drop. Waiting for `shared`'s count to fall back to what only this test
    // holds — cooperatively, no sleep, no arbitrary retry bound — proves the task (and whatever
    // else its own drop might still be holding) is actually gone before this reads the file its
    // report already decided the outcome of.
    while std::sync::Arc::strong_count(&shared) > 1 {
        ::tokio::task::yield_now().await;
    }

    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"",
        "a leak while the blocking reap is running must disarm what it retained, not kill through it"
    );
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// A tokio child of uncertain ownership is forgotten on Unix, never dropped: tokio's `Drop` would
/// reap — or queue to reap — a pid that may be another process's. Here the child is this test's own
/// zombie, still reapable by the test only if nothing reaped it.
#[cfg(unix)]
#[tokio::test]
async fn a_tokio_child_of_uncertain_ownership_is_released_without_tokios_drop() {
    let (child, stdin, id) = blocked_child();
    drop(stdin);
    // Awaited without reaping, until it is reapable.
    crate::child::unreaped::block_until_reapable(id.pid()).expect("wait for the child's exit");
    Held::Tokio(Box::new(child)).release_uncertain();
    let pid = nix::unistd::Pid::from_raw(id.pid() as i32);
    nix::sys::wait::waitpid(pid, None).expect("the released child is left for this test to reap");
}

/// A child handed back with a pidfd is waited on through that pidfd alone: its wait needs no
/// identity read, which `/proc` mounted with `hidepid=2` refuses for a setuid child. Every identity
/// read on this thread fails here, and the wait still reaps the child.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_bare_child_is_waited_on_through_its_pidfd_without_an_identity_read() {
    let (child, stdin, id) = std_blocked_child();
    let pid = child.id();
    std::mem::forget(child);
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(pid as i32).expect("a child's pid is never 0"),
        rustix::process::PidfdFlags::empty(),
    )
    .expect("pidfd_open");
    crate::identity::unreadable::set(true);
    let mut unreaped = Unreaped::new(Held::Bare {
        pid,
        pidfd: Some(pidfd),
    });
    drop(stdin);
    let waited = unreaped.wait().await;
    crate::identity::unreadable::set(false);
    waited.expect("the wait must not depend on an identity read");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// A child the sync teardown held by std's `Child` — as `?` converts a sync spawn's error into
/// `cosca::tokio::Error` — is awaitable once converted: through a pidfd on Linux, a kqueue filter
/// on macOS, its process handle on Windows. Cancelled after a pending poll, it is still held.
#[tokio::test]
async fn a_converted_std_child_is_awaitable_and_cancel_safe() {
    let (child, stdin, id) = std_blocked_child();
    let unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
    a_cancelled_wait_leaves_the_caller_holding(unreaped, stdin, id).await;
}

/// A wait whose exit watch cannot be set up — a pidfd that cannot be duplicated (`EMFILE`), a
/// cancel event that cannot be created, a runtime shutting down — says nothing about the child's
/// ownership: the caller keeps holding it, and a later wait reaps it.
#[tokio::test]
async fn a_wait_whose_watch_fails_keeps_the_child() {
    let (child, stdin, id) = std_blocked_child();
    let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
    // Rebound, so a failing assertion drops it before `unreaped`, whose drop waits for the child.
    let stdin = stdin;
    super::fault::set_force_watch_failure();
    let failed = unreaped.wait().await;
    assert!(
        !super::fault::take_force_watch_failure(),
        "the forced failure must be consumed"
    );
    failed.expect_err("the watch failed");
    assert_eq!(unreaped.pid(), id.pid(), "still held");
    drop(stdin);
    unreaped.wait().await.expect("a later wait reaps it");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// A std child blocked reading stdin until the returned end drops, and its identity.
fn std_blocked_child() -> (std::process::Child, std::process::ChildStdin, ProcessId) {
    let mut child = {
        let _guard = crate::child::spawn::spawn_lock();
        let mut cmd = if cfg!(windows) {
            let mut cmd = std::process::Command::new("findstr");
            cmd.arg("x");
            cmd
        } else {
            std::process::Command::new("cat")
        };
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child blocked on stdin")
    };
    let stdin = child.stdin.take().expect("piped stdin");
    let Resolved::Found(id) = ProcessId::of(child.id()) else {
        panic!("an unreaped child resolves");
    };
    (child, stdin, id)
}

/// An exit watch can fire before the kernel has made the child reapable: macOS's `NOTE_EXIT`
/// arrives before the zombie exists, so a `try_wait` right after it can still find the child
/// running. That is not uncertain ownership — the exit is certain — so the wait blocks until the
/// child is reapable, and reaps it. The seam makes the first reap after the watch find it
/// not yet reapable, as that window does.
#[cfg(unix)]
#[tokio::test]
async fn a_reap_that_races_the_exit_edge_waits_for_the_zombie_rather_than_releasing() {
    let (child, stdin, id) = std_blocked_child();
    let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
    drop(stdin);
    super::fault::set_force_not_yet_reapable();
    let status = unreaped.wait().await;
    assert!(
        !super::fault::take_force_not_yet_reapable(),
        "the forced window must be consumed"
    );
    status.expect("a certain exit is reaped, never released as uncertain");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// After a wait that released the child for uncertain ownership, a later wait says so — the child
/// was not leaked, `leak` was never called — and repeats nothing.
#[cfg(unix)]
#[tokio::test]
async fn a_wait_after_an_uncertain_release_says_the_child_was_released() {
    let (child, stdin, id) = std_blocked_child();
    let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
    drop(stdin);
    super::fault::set_force_uncertain();
    unreaped.wait().await.expect_err("the forced uncertain outcome");
    assert!(
        !super::fault::take_force_uncertain(),
        "the forced outcome must be consumed"
    );
    let again = unreaped.wait().await.expect_err("the child is gone from the holder");
    assert!(
        again.to_string().contains("ownership uncertain") && !again.to_string().contains("leaked"),
        "the later wait must name the release, got {again}"
    );
    // Released, never reaped: this test's own child.
    crate::child::unreaped::block_until_reapable(id.pid()).expect("wait for the child's exit");
    let pid = nix::unistd::Pid::from_raw(id.pid() as i32);
    nix::sys::wait::waitpid(pid, None).expect("the released child is left for this test to reap");
}

/// Once the wait hands a not-yet-reapable child to the blocking pool, that task owns it — no wait
/// there is keyed on a pid the holder could reap and free — and a cancelled wait leaves the task's
/// result with the holder: the next wait takes it. The seam sends the wait straight to that task
/// while the child is still running, so the first poll is pending with the task holding it.
#[cfg(unix)]
#[tokio::test]
async fn a_cancelled_blocking_reap_is_resumed_by_the_next_wait() {
    let (child, stdin, id) = std_blocked_child();
    let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
    // Rebound, so a failing assertion drops it before `unreaped`, whose drop waits for the child.
    let stdin = stdin;
    super::fault::set_force_not_yet_reapable();
    cancel_after_one_pending_poll(&mut unreaped);
    assert!(
        unreaped.hands_child_to_blocking_task(),
        "the blocking task owns the child now"
    );
    drop(stdin);
    let status = unreaped.wait().await.expect("the next wait takes the task's reap");
    assert_eq!(status.code(), Some(0), "{status:?}");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// Dropped while a cancelled wait's blocking reap holds the child, an `Unreaped` blocks until that
/// reap finishes, as it blocks for a child it holds itself: nothing is left to finish detached.
///
/// An `after_claim` gate holds the task in `Running` (claimed, not yet reported) until this test
/// releases it, so `Drop` deterministically finds the task already claimed and must wait on
/// `take_blocking` — not take `reclaim_before_start`'s fast path, which a `Drop` racing an
/// unclaimed task could otherwise hit instead, proving nothing about the wait under test. The
/// assertion right before `drop(unreaped)` checks the state is `Running` for exactly that reason.
/// The `before_blocking_drop` hook then runs as `Drop` commits to blocking on the reap: it lets
/// the child exit (so the gated task's own reap, once released, succeeds) and releases the gate.
#[cfg(unix)]
#[test]
fn dropping_during_a_blocking_reap_waits_for_it() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (child, stdin, id) = std_blocked_child();
    let blocked = std::sync::Arc::new(AtomicBool::new(false));
    let (claimed_tx, claimed_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    // `Sender`/`Receiver` are not `Sync`, but the hook's trait object bound requires it; the
    // `Mutex` costs nothing here, since the hook only ever touches them once.
    let claimed_tx = std::sync::Mutex::new(claimed_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    runtime.block_on(async {
        let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
        super::fault::set_after_claim(Box::new(move || {
            claimed_tx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .send(())
                .expect("the test thread is waiting for the claim");
            release_rx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv()
                .expect("the test thread releases the gate");
        }));
        super::fault::set_force_not_yet_reapable();
        cancel_after_one_pending_poll(&mut unreaped);
        assert!(
            unreaped.hands_child_to_blocking_task(),
            "the blocking task owns the child now"
        );

        claimed_rx
            .recv()
            .expect("the task reaches the gate once it has claimed the child");
        // The branch this test exists to exercise: confirm the task has claimed the child
        // (state `Running`) before `Drop` runs, so `Drop` must go through `take_blocking`.
        {
            let (shared, _) = unreaped.blocking.as_ref().expect("the blocking task owns the child");
            assert!(
                matches!(*shared.state(), super::ReapState::Running),
                "the gate must hold the task in Running before Drop runs"
            );
        }

        let flag = blocked.clone();
        unreaped.before_blocking_drop(Box::new(move || {
            flag.store(true, Ordering::SeqCst);
            drop(stdin);
            release_tx
                .send(())
                .expect("let the gated task proceed to its real reap");
        }));
        // Kept so this can check the state `Drop` leaves behind, immediately after `Drop` itself
        // returns — not merely that `Drop` didn't hang, which `blocked` alone already proves.
        let shared = unreaped
            .blocking
            .as_ref()
            .expect("the blocking task owns the child")
            .0
            .clone();
        drop(unreaped);
        assert!(
            matches!(*shared.state(), super::ReapState::Taken),
            "Drop must not return before take_blocking has settled the state to Taken"
        );
    });
    assert!(blocked.load(Ordering::SeqCst), "the drop blocked on the blocking reap");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// A blocking reap that claimed the child, then ended without finishing — it panicked mid-reap —
/// hands the child back unreaped: the wait says so, the holder keeps the child, and the next wait
/// reaps it. The task is built with the child already claimed (state `Running`) and dropped here,
/// as such a panic's unwind drops it.
#[cfg(unix)]
#[tokio::test]
async fn a_blocking_reap_that_panicked_after_claiming_hands_the_child_back() {
    let (child, stdin, id) = std_blocked_child();
    let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
    // Rebound, so a failing assertion drops it before `unreaped`, whose drop waits for the child.
    let stdin = stdin;
    let shared = std::sync::Arc::new(super::BlockingReap {
        state: std::sync::Mutex::new(super::ReapState::Running),
        finished: std::sync::Condvar::new(),
    });
    let (signal, finished) = ::tokio::sync::oneshot::channel();
    let task = super::ReapTask {
        shared: shared.clone(),
        held: unreaped.held.take(),
        retained: unreaped.retained.take(),
        signal: Some(signal),
        after_claim: None,
    };
    unreaped.blocking = Some((shared, finished));
    drop(task);
    let err = unreaped.wait().await.expect_err("the reap never finished");
    assert!(err.to_string().contains("ended without reaping"), "{err}");
    assert!(unreaped.held.is_some(), "the holder keeps the child");
    drop(stdin);
    unreaped.wait().await.expect("the next wait reaps it");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// A blocking reap that never ran at all — the runtime shut down before its task was ever
/// scheduled, so it was dropped still queued — hands the child back unreaped too, with an error
/// saying so: unlike the panicked-after-claiming case above, `ReapTask::drop` reports nothing here
/// (it only does once `run` has claimed the child from `NotStarted`), so `finished`'s sender is
/// simply dropped and `ReapState` stays `NotStarted` forever. Reading `take_blocking` past this
/// point would panic instead of waiting on pool scheduling that will never come (its own
/// `debug_assert`, in a debug build); reaching `take_reap` past it would hit its own
/// `unreachable!` in release. The regression this test guards against is exactly that: either of
/// those panics, instead of the child handed back.
#[cfg(unix)]
#[test]
fn a_blocking_reap_that_never_ran_hands_the_child_back() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    let handle = runtime.handle().clone();
    // Shut down before any work runs: `spawn_blocking`'s task is queued, then dropped unrun,
    // rather than ever claiming the child.
    runtime.shutdown_background();
    let (child, stdin, id) = std_blocked_child();
    drop(stdin); // the child exits at once, so Drop's own fallback wait below does not hang
    let err = handle.block_on(async {
        let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
        super::fault::set_force_not_yet_reapable();
        let err = unreaped
            .wait()
            .await
            .expect_err("a runtime shut down before scheduling the reap must not hand back a status");
        // `unreaped` drops here, inside the still-live `block_on` call: its own fallback
        // synchronous wait reaps the child it was just handed back.
        err
    });
    assert!(err.to_string().contains("the blocking reap never ran"), "{err}");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// Dropping on a saturated blocking pool, as the type's own doc recommends, must not deadlock:
/// a cancelled wait leaves the child with a `ReapTask` queued but not yet claimed, and if the
/// pool's only thread is the one `Drop` itself runs on, that task can never be scheduled. `Drop`
/// must reclaim the child directly instead of waiting for the task, which then does nothing when
/// it eventually runs.
///
/// `rx.recv()` below has no timeout of its own: syncing on a wall clock is forbidden. The bound on
/// a genuine deadlock is instead nextest's own `slow-timeout`/`terminate-after` for this test (see
/// `.config/nextest.toml`), a human-facing failure bound, not a synchronization device.
#[cfg(unix)]
#[test]
fn drop_on_a_saturated_blocking_pool_does_not_deadlock() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("build a runtime with a single blocking thread");
    let (tx, rx) = std::sync::mpsc::channel();
    let (child, stdin, id) = std_blocked_child();
    drop(stdin); // the child exits at once
    runtime.spawn_blocking(move || {
        let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
        super::fault::set_force_not_yet_reapable();
        cancel_after_one_pending_poll(&mut unreaped);
        // Drops on the only blocking thread: the queued ReapTask must not be waited for.
        drop(unreaped);
        let _ = tx.send(());
    });
    let finished = rx.recv().is_ok();
    // If this deadlocked, the runtime's own drop would hang on the same stuck thread too.
    std::mem::forget(runtime);
    assert!(
        finished,
        "DEADLOCK: Unreaped::drop on the only blocking thread never returned"
    );
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// H1 (round-5 review): cancelling `wait` while it awaits the retained drain — queued behind an
/// occupied blocking pool, after the real reap has already run inside `reaped` — must not lose the
/// exit status, nor detach the drain task. A second `wait` must return the real status (not the
/// bogus "released elsewhere" fallback a lost status would produce), and `Drop` must actually wait
/// for the drain rather than return while it is still running elsewhere.
///
/// The cancellation point is reached deterministically, not via any wall-clock wait: `_blocker`
/// occupies the pool's one thread on a real channel gate (`gate_rx.recv()`, released only once this
/// test sends to `gate_tx`), and the `select!`'s losing arm polls a raw `waitid(P_PID, WEXITED |
/// WNOWAIT)` — cooperatively, via `yield_now`, no sleep — until it reports `ECHILD`. That only
/// happens once the real reap inside `wait_on` (called from `wait`'s own first poll) has actually
/// run; since the pool's one thread is occupied, that having happened is exactly the moment `wait`'s
/// own future is parked awaiting the still-queued, unclaimed drain — the same moment `reaped` (now
/// synchronous) already set `status`, before spawning it.
#[cfg(unix)]
#[test]
fn cancel_during_retained_drain_preserves_status_and_drop_waits() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("build a runtime with a single blocking thread");
    let (child, stdin, id) = std_blocked_child();
    drop(stdin); // the child exits at once
    crate::child::unreaped::block_until_reapable(id.pid()).expect("zombie");
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    runtime.block_on(async {
        let (occ_tx, occ_rx) = ::tokio::sync::oneshot::channel::<()>();
        // Occupies the pool's only blocking thread until this test releases `gate_tx`.
        let _blocker = ::tokio::task::spawn_blocking(move || {
            let _ = occ_tx.send(());
            let _ = gate_rx.recv();
        });
        occ_rx.await.expect("the blocker parked");

        let mut u = Unreaped::with_retained(
            Held::Std(child),
            Some(crate::child::unreaped::Retained {
                attached: crate::containment::Attached::None,
            }),
        );
        let raw = id.pid() as libc::id_t;
        let reaped_by_us = move || unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let r = libc::waitid(
                libc::P_PID,
                raw,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            );
            r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
        };
        ::tokio::select! {
            biased;
            r = u.wait() => panic!("wait completed while the drain is queued behind the occupied pool: {r:?}"),
            _ = async { loop { if reaped_by_us() { break } ::tokio::task::yield_now().await } } => {}
        }

        // H1: the cancelled wait must not have lost the status, nor detached the drain task.
        assert_eq!(
            u.status.and_then(|s| s.code()),
            Some(0),
            "status must survive the cancelled drain-await"
        );
        assert!(
            u.hands_retained_to_draining_task(),
            "the drain must still be tracked (queued behind the occupied pool), not detached"
        );

        // Free the pool's one thread, so the queued drain task can actually run, then re-await it.
        gate_tx.send(()).expect("the blocker is still parked on this receiver");
        let again = u.wait().await;
        assert!(
            matches!(again, Ok(s) if s.code() == Some(0)),
            "a second wait after a cancelled drain-await must return the real status, not a bogus \
             \"released elsewhere\" error: {again:?}"
        );
        assert!(
            !u.hands_retained_to_draining_task(),
            "the second wait must have consumed the drain"
        );

        // Drop must not hang: nothing is left to await, since the second `wait` already consumed
        // the drain above — this proves the now-idle handle's ordinary Drop contract still holds.
        drop(u);
        crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
    });
}

/// The same cancellation point as `cancel_during_retained_drain_preserves_status_and_drop_waits`,
/// but this time nothing re-awaits the drain before the handle drops: `Drop` itself must block
/// until the still-running drain task actually finishes, per H1's recipe step 4.
#[cfg(unix)]
#[test]
fn drop_after_a_cancelled_wait_waits_for_the_running_drain() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("build a runtime with a single blocking thread");
    let (child, stdin, id) = std_blocked_child();
    drop(stdin);
    crate::child::unreaped::block_until_reapable(id.pid()).expect("zombie");
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let (tx, rx) = std::sync::mpsc::channel();
    runtime.block_on(async {
        let (occ_tx, occ_rx) = ::tokio::sync::oneshot::channel::<()>();
        let _blocker = ::tokio::task::spawn_blocking(move || {
            let _ = occ_tx.send(());
            let _ = gate_rx.recv();
        });
        occ_rx.await.expect("the blocker parked");

        let mut u = Unreaped::with_retained(
            Held::Std(child),
            Some(crate::child::unreaped::Retained {
                attached: crate::containment::Attached::None,
            }),
        );
        let raw = id.pid() as libc::id_t;
        let reaped_by_us = move || unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let r = libc::waitid(
                libc::P_PID,
                raw,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            );
            r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
        };
        ::tokio::select! {
            biased;
            r = u.wait() => panic!("wait completed while the drain is queued behind the occupied pool: {r:?}"),
            _ = async { loop { if reaped_by_us() { break } ::tokio::task::yield_now().await } } => {}
        }
        assert!(u.hands_retained_to_draining_task(), "the drain must still be tracked");

        // Free the pool's one thread so the drain can run, then drop `u` on a fresh blocking
        // thread of its own — `Drop` blocks the thread it runs on, so it must not run here on this
        // async task.
        gate_tx.send(()).expect("the blocker is still parked on this receiver");
        ::tokio::task::spawn_blocking(move || {
            drop(u);
            let _ = tx.send(());
        })
        .await
        .expect("the drop task did not panic");
    });
    assert!(
        rx.recv().is_ok(),
        "Drop must return once the drain it waited for has actually finished"
    );
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}
