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
    let (child, stdin, id) = blocked_std_child();
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
    let (child, stdin, id) = blocked_std_child();
    let pid = child.id();
    let raw = crate::child::spawn::windows_raw::RawChild::new(std::os::windows::io::OwnedHandle::from(child), pid);
    a_cancelled_wait_leaves_the_caller_holding(Unreaped::new(Held::Raw(raw)), stdin, id).await;
}

/// A std child blocked reading stdin until the returned end drops, and its identity.
#[cfg(any(target_os = "linux", windows))]
fn blocked_std_child() -> (std::process::Child, std::process::ChildStdin, ProcessId) {
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
    // Its own exit, awaited without reaping.
    // Awaited without reaping, until it is reapable.
    crate::child::unreaped::block_until_reapable(id.pid()).expect("wait for the child's exit");
    Unreaped::new(Held::Tokio(Box::new(child))).leak();
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
    let (child, stdin, id) = blocked_std_child();
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
/// reap finishes, as it blocks for a child it holds itself: nothing is left to finish detached. The
/// hook runs as the drop starts to block, and lets the child exit.
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
    runtime.block_on(async {
        let mut unreaped = Unreaped::from_sync(crate::Unreaped::new(Held::Std(child)));
        super::fault::set_force_not_yet_reapable();
        cancel_after_one_pending_poll(&mut unreaped);
        assert!(
            unreaped.hands_child_to_blocking_task(),
            "the blocking task owns the child now"
        );
        let flag = blocked.clone();
        unreaped.before_blocking_drop(Box::new(move || {
            flag.store(true, Ordering::SeqCst);
            drop(stdin);
        }));
        drop(unreaped);
    });
    assert!(blocked.load(Ordering::SeqCst), "the drop blocked on the blocking reap");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// A blocking reap that ends without running — the runtime shut down before it started, or it
/// panicked — hands the child back unreaped: the wait says so, the holder keeps the child, and the
/// next wait reaps it. The task is built and dropped here, as such a runtime drops it.
#[cfg(unix)]
#[tokio::test]
async fn a_blocking_reap_that_never_ran_hands_the_child_back() {
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
    };
    unreaped.blocking = Some((shared, finished));
    drop(task);
    let err = unreaped.wait().await.expect_err("the reap never ran");
    assert!(err.to_string().contains("ended without reaping"), "{err}");
    assert!(unreaped.held.is_some(), "the holder keeps the child");
    drop(stdin);
    unreaped.wait().await.expect("the next wait reaps it");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// Dropping on a saturated blocking pool, as the type's own doc recommends, must not deadlock:
/// a cancelled wait leaves the child with a `ReapTask` queued but not yet claimed, and if the
/// pool's only thread is the one `Drop` itself runs on, that task can never be scheduled. `Drop`
/// must reclaim the child directly instead of waiting for the task, which then does nothing when
/// it eventually runs.
///
/// The 10s bound is a human-facing failure bound on a genuine hang, not a synchronization device:
/// success is `rx.recv()` returning promptly, well under it.
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
    let finished = rx.recv_timeout(std::time::Duration::from_secs(10)).is_ok();
    // If this deadlocked, the runtime's own drop would hang on the same stuck thread too.
    std::mem::forget(runtime);
    assert!(
        finished,
        "DEADLOCK: Unreaped::drop on the only blocking thread never returned"
    );
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}
