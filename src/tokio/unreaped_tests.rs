//! `cosca::tokio::Unreaped`'s contract: `wait` is cancel-safe and leaves the caller holding the
//! child, `leak` gives it up unreaped, and `Drop` blocks until the child exits.

use super::Unreaped;
use crate::child::unreaped::Held;
#[cfg(unix)]
use crate::child::unreaped::Retained;
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

/// The async twin of `crate::child::unreaped_tests`'s
/// `wait_sweeps_a_retained_recyclable_marker_while_its_root_pid_is_still_a_zombie` — see that
/// test's doc for the hazard this guards against. Here the sweep runs off the tokio blocking pool
/// (see `ReapTask::run`'s doc), not inline on the caller's own thread, which is exactly why
/// `fault::set_hard_kill_hook`'s registry is process-global rather than thread-local.
#[cfg(target_os = "macos")]
#[::tokio::test]
async fn wait_sweeps_a_retained_recyclable_marker_while_its_root_pid_is_still_a_zombie() {
    use std::os::unix::process::CommandExt;

    // See `blocked_child`'s own guard: a real install()+spawn() must not race a concurrent fork
    // elsewhere in this shared test binary while the marker's write end is open. Scoped to a block
    // so the guard drops before this function's own `.await` below — clippy's
    // `await_holding_lock` is right that holding a std `Mutex` guard across an await point is a
    // hazard in general, even though nothing else here ever awaits while holding it.
    let (mut child, prepared) = {
        let _guard = crate::child::spawn::spawn_lock();
        let mut std_cmd = std::process::Command::new("cat");
        std_cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .process_group(0); // a fresh pgid == this child's own pid, with no other members
        let prepared = crate::containment::fdmarker::install(&mut std_cmd, &[]).expect("install");
        let mut tcmd = ::tokio::process::Command::new(std::ffi::OsStr::new(""));
        *tcmd.as_std_mut() = std_cmd;
        let child = tcmd.spawn().expect("spawn a child blocked on stdin");
        // `install`'s own contract: drop the command promptly, so this supervisor's copy of the
        // marker's write end (which the command itself still owns post-spawn) does not linger and
        // get found as a "holder" by this marker's own sweep below.
        drop(tcmd);
        (child, prepared)
    };
    let stdin = child.stdin.take().expect("piped stdin");
    let pid = child.id().expect("an unreaped child has a pid");

    let marker = crate::containment::fdmarker::Marker::new(prepared, None, Some(pid as i32), false);
    let key = marker.hard_kill_test_key();

    let zombie_at_sweep: std::sync::Arc<std::sync::Mutex<Option<bool>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let flag = std::sync::Arc::clone(&zombie_at_sweep);
    crate::containment::fdmarker::fault::set_hard_kill_hook(
        key,
        Box::new(move || {
            // SAFETY: a well-formed `waitid`; `info` is an owned, zeroed `siginfo_t`. `WNOWAIT`
            // never reaps, so this can never disturb the reap that follows this sweep. `WNOHANG`
            // makes this a genuine PROBE rather than a second wait: without it, a mutant that
            // deletes the confirmatory `block_until_reapable` this hook exists to catch would just
            // have this call block until the same exit instead, still observing a zombie and
            // passing regardless (round-3 finding 1's test-quality gap) — `si_pid` stays `0` on a
            // `WNOHANG` call that found nothing yet, which is what actually distinguishes "already
            // a zombie" from "not yet", not merely `rc == 0`.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            };
            *flag.lock().unwrap_or_else(|e| e.into_inner()) = Some(rc == 0 && info.si_pid == pid as libc::pid_t);
        }),
    );

    let retained = Retained {
        attached: crate::containment::Attached::FdMarker(marker),
    };
    let mut unreaped = Unreaped::with_retained(Held::Tokio(Box::new(child)), Some(retained));
    drop(stdin); // let the child exit on EOF
    let status = unreaped.wait().await.expect("wait for the child");

    assert_eq!(
        crate::containment::fdmarker::fault::take_hard_kill_calls(key),
        1,
        "the retained marker must be swept exactly once on this path"
    );
    assert_eq!(
        *zombie_at_sweep.lock().unwrap_or_else(|e| e.into_inner()),
        Some(true),
        "the sweep must run while the root pid is still a zombie (reapable, unrecycled) — before \
         the reap frees it for a new process group to take. Got the pid already reaped \
         (Some(false)), or the sweep never ran at all (None)."
    );
    assert_eq!(
        status.code(),
        Some(0),
        "the child exited normally on EOF ({status:?}); a sweep that reached the root itself \
         (rather than only what it retained) would show up here as a signal, not a normal exit"
    );
}

/// Regression test for adversarial round-3 finding 2: a drain that never ran (a runtime shutdown
/// before its `DrainTask` claimed anything) hands an unswept recyclable retention back into
/// `self.retained` via `await_draining`, with `self.held` already `None` and `self.status`
/// already `Some` — the root already reaped (see `reaped`'s doc). Before the fix, `Drop`'s own
/// fallback swept it anyway, against a pid that may already have been recycled onto a live,
/// unrelated process group. This constructs that exact state directly — the state
/// `await_draining` produces, without needing a saturated blocking pool to reproduce it — against
/// a REAL, still-running child in its own process group, so an incorrect sweep would kill it for
/// real.
#[cfg(unix)]
#[test]
fn drop_does_not_resweep_a_retention_whose_root_is_already_reaped() {
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    let _guard = crate::child::spawn::spawn_lock();
    let mut cmd = std::process::Command::new("cat");
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .process_group(0); // a fresh pgid == this child's own pid, with no other members
    let mut child = cmd.spawn().expect("spawn a child blocked on stdin");
    let pid = child.id();
    let stdin = child.stdin.take().expect("piped stdin");

    let retained = Box::new(Retained {
        attached: crate::containment::Attached::ProcessGroup(pid as i32),
    });
    let unreaped = Unreaped {
        held: None,
        retained: Some(retained),
        pid,
        status: Some(std::process::ExitStatus::from_raw(0)),
        released: None,
        blocking: None,
        draining: None,
        #[cfg(all(test, unix))]
        before_blocking_drop: None,
    };
    drop(unreaped);

    assert_eq!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None),
        Ok(()),
        "the child must still be alive: `Drop`'s fallback must not sweep a retention once \
         `held` is already `None` — the root reap already happened, so its pgid may already \
         have been recycled onto a live, unrelated process group"
    );

    drop(stdin); // let the child exit on EOF; this test's own doing, not `Drop`'s
    child.wait().expect("the child exits once stdin closes");
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

/// Regression test for adversarial round-3 finding 3: before the fix, a recyclable retention on a
/// `Held::Tokio` child forced `wait`'s outcome straight to `Err(Failed::NotYetReapable)` — a
/// synchronous value needing no `.await` to produce — so the very first poll already fell through
/// to `spawn_blocking_reap` and committed to a blocking-pool `ReapTask` before there was any chance
/// to cancel anything. That task's `block_until_reapable` then blocks its pool thread for the
/// child's entire remaining lifetime: for an ordinary, still-running child (nothing tracing it),
/// `leak` afterwards would find the task `Running` and block right there until the child exited —
/// contradicting `leak`'s own doc, `NotYetReapable`'s doc, and the PR body, all of which reserve
/// that blocking case for a tracer holding the child, not an ordinary live one.
///
/// After the fix, `wait` first awaits a non-reaping exit watch — cancel-safe, and pending for as
/// long as the child is running — before ever routing to the blocking pool. So one poll on a still-
/// running child must leave no blocking-pool task pinned at all, and `leak` afterwards must return
/// promptly rather than block.
#[cfg(unix)]
#[tokio::test]
async fn leak_after_a_cancelled_wait_on_a_live_recyclable_child_neither_blocks_nor_pins_a_pool_thread() {
    let (child, stdin, id) = blocked_child();
    let retained = Retained {
        attached: crate::containment::Attached::ProcessGroup(id.pid() as i32),
    };
    let mut unreaped = Unreaped::with_retained(Held::Tokio(Box::new(child)), Some(retained));

    // The child is still alive for this poll — that is the scenario under test. What
    // `self.blocking` ends up holding is decided synchronously within it (a blocking-pool task,
    // once spawned, is not un-spawned by anything that happens afterward), so it is safe — and
    // does not weaken the test — to let the child exit right away, before checking it: this way,
    // if a later assertion panics or `leak` turns out to still block (the very bug under test),
    // the ensuing `Drop`/`leak` wait is bounded by the child's own real exit, not by nothing.
    cancel_after_one_pending_poll(&mut unreaped);
    drop(stdin);

    assert!(
        unreaped.blocking.is_none(),
        "a cancelled wait on a still-running child must not have pinned a blocking-pool task \
         waiting on its exit — the exit had not happened yet at the time of the poll, so nothing \
         must have been parked waiting for it off this future"
    );
    assert!(
        unreaped.held.is_some(),
        "the child is still held after the cancelled wait"
    );

    // Safe to call directly, not merely inferred: `blocking` being `None` above means `leak`
    // cannot take the branch that would otherwise block on that task's own report (see `leak`'s
    // doc) — there is no such task.
    unreaped.leak();
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
/// still `NotStarted`, not yet `Finished` — now blocks on that task's own report instead of
/// marking it `Leaked` and returning early: this proves `leak` does not return until the task has
/// actually finished and its own disarm has already happened, so by the time this test's call to
/// `leak` itself returns, the assertion below needs no further synchronization.
///
/// Goes through the real `spawn_blocking_reap` (via the same cancelled-wait,
/// `force_not_yet_reapable` path `a_cancelled_blocking_reap_is_resumed_by_the_next_wait` uses),
/// not a hand-built `ReapTask`, so this exercises the same task construction production does —
/// including `after_claim` now being read from the `fault` seam by `spawn_blocking_reap` itself,
/// rather than set directly on a `ReapTask` this test built by hand.
///
/// The `after_claim` hook runs inside the task's real `run`, right after its real `claim`
/// succeeds and before it waits for the exit, and blocks there until released — pinning the state
/// at `Running` for as long as the test wants, since nothing else can move it while the task is
/// parked there.
///
/// The release itself happens from INSIDE `take_blocking`'s own wait loop, via
/// `fault::set_before_reap_take_blocking_wait` — not before `leak` is even scheduled onto the
/// blocking pool, as an earlier version of this test did. Releasing early only proves the gated
/// task will EVENTUALLY finish; it races that finish against `leak`'s own task being scheduled at
/// all, and on a fast schedule the gated task usually reaches `Finished` first — a `leak` that
/// returned immediately for a `Running` task would still pass this test, undetected, because by
/// the time it ran the state was never observed `Running` to begin with. Gating the release behind
/// the seam instead means the task CANNOT reach `Finished` until `leak`'s own `take_blocking` call
/// has already found `Running` and entered its wait loop for real — proven by `seam_rx` below,
/// without which the test fails rather than passing on an unproven premise.
///
/// `leak` is itself a blocking call once it reaches this path, so it runs on the blocking pool
/// here too — matching how this crate's own docs tell a caller to run it, and leaving this test's
/// own worker thread free for the runtime machinery `cancel_after_one_pending_poll` (and, before
/// it, the real `spawn_blocking_reap`) already depends on. The seam is set from inside that same
/// `spawn_blocking` closure, immediately before calling `leak`: `take_blocking` runs synchronously
/// on whichever thread calls it, and the seam's thread-local must be set on that same thread.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn leaking_while_the_blocking_reap_is_running_blocks_until_it_finishes_then_disarms() {
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
    let (seam_tx, seam_rx) = std::sync::mpsc::channel::<()>();
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
            .expect("leak's own take_blocking releases the gate from inside its wait loop");
    }));
    super::fault::set_force_not_yet_reapable();
    cancel_after_one_pending_poll(&mut unreaped);
    assert!(
        unreaped.hands_child_to_blocking_task(),
        "the real spawn_blocking_reap must have handed the child to a blocking-pool task"
    );

    claimed_rx
        .recv()
        .expect("the task reaches the gate once it has claimed the child");

    // `leak` now blocks until the gated task's own `report` has run: by the time this returns,
    // the disarm under test has already happened, with no further synchronization needed.
    ::tokio::task::spawn_blocking(move || {
        super::fault::set_before_reap_take_blocking_wait(Box::new(move || {
            seam_tx.send(()).expect("the test thread is waiting for the seam");
            release_tx.send(()).expect("let the gated task proceed");
        }));
        unreaped.leak()
    })
    .await
    .expect("leak on the blocking pool");

    assert!(
        matches!(seam_rx.try_recv(), Ok(())),
        "leak must reach take_blocking's own wait loop before returning; a leak that returns \
         immediately on a Running task would never trigger this seam, and nothing below would \
         tell that mutant apart from the correct implementation"
    );
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
fn cancel_during_retained_drain_preserves_status_and_a_later_wait_consumes_it() {
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

/// M4 (round-6 review): `Drop`'s own claim-slot wait (`take_blocking`) must genuinely block on a
/// drain a cancelled `wait` left running, not merely appear to — the reviewer showed the previous
/// version of this test passed even with `take_blocking`'s body replaced by `{}`, because on this
/// test's own zero-length child the queued drain task typically finished well before `Drop` ran,
/// so nothing about `Drop`'s own wait was ever exercised.
///
/// Deterministic instead, the same way `dropping_during_a_blocking_reap_waits_for_it` is: an
/// `after_drain_claim` gate holds the task claimed (state `Committed`, not yet `Finished`) until
/// this test releases it, so `Drop` deterministically finds the task already claimed and must go
/// through `take_blocking`, not `reclaim_before_start`'s direct-drop fast path.
///
/// Checking the shared state after forcing the gated task to finish is not enough on its own
/// (round-7 review, mutant B): a `take_blocking` whose wait loop never runs still ends by
/// unconditionally writing `Taken` — the same value a correct wait settles on — so once *something*
/// forces the gated task's own `Finished` write to happen, the final state is a race between that
/// write and `take_blocking`'s own `Taken` write, and whichever runs last wins, on any schedule.
/// This was tried (joining a dedicated runtime, so every `spawn_blocking` task it ever queued had
/// certainly returned, then reading the final state) and found empirically flaky: mutant B passed
/// on some runs because `take_blocking`'s immediate `Taken` write occasionally landed after the
/// join's forced `Finished` write, not before it — a genuine, unsynchronized race between two
/// writers to the same mutex, not something a corrected wait vs. a not-corrected one on their own.
///
/// `before_take_blocking_wait` fixes this by moving the fork *inside* `take_blocking`'s wait loop
/// body, so it fires if and only if the loop condition has already found `Committed` and is about
/// to park — something mutant B's `while false && ...` can never reach, on any schedule, since it
/// is dead code under that mutant, not merely code that usually loses a race. `Drop` (and so
/// `take_blocking`) runs on a dedicated thread; a single channel carries one of two events — the
/// hook firing, or that thread's `drop(u)` call returning — and the first one received settles the
/// question outright: for correct code, `Taken` cannot be written until the gate below is released,
/// which happens only after this test has already received the hook's event, so "drop finished"
/// cannot arrive first; for mutant B, the hook can never fire at all, so "drop finished" is the only
/// event that can ever arrive. Neither outcome is a race to be won — each is the only one possible
/// under its respective code.
#[cfg(unix)]
#[test]
fn drop_after_a_cancelled_wait_waits_for_the_running_drain() {
    enum Event {
        EnteredWait,
        DropFinished,
    }

    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    let (child, stdin, id) = std_blocked_child();
    drop(stdin); // the child exits at once
    crate::child::unreaped::block_until_reapable(id.pid()).expect("zombie");

    let (claimed_tx, claimed_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    // `Sender`/`Receiver` are not `Sync`, but the hook's trait object bound requires it; the
    // `Mutex` costs nothing here, since each hook only ever touches its own once.
    let claimed_tx = std::sync::Mutex::new(claimed_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    super::fault::set_after_drain_claim(Box::new(move || {
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

    let u = runtime.block_on(async {
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
            r = u.wait() => panic!("wait completed instead of being cancelled: {r:?}"),
            _ = async { loop { if reaped_by_us() { break } ::tokio::task::yield_now().await } } => {}
        }
        assert!(
            u.hands_retained_to_draining_task(),
            "the drain must still be tracked after the cancelled wait"
        );

        // Deterministic: wait for the drain task's own claim signal before dropping, so `Drop`
        // below exercises the "wait for a claimed drain" branch of `take_blocking`, not "drop an
        // unclaimed one inline". The task is now parked in the gate, claimed but not yet finished.
        claimed_rx
            .recv()
            .expect("the drain task reaches the gate once it has claimed what it must drop");
        {
            let (shared, _) = u.draining.as_ref().expect("the drain task owns what was retained");
            assert!(
                matches!(*shared.state(), super::DrainState::Committed),
                "the gate must hold the task Committed before Drop runs"
            );
        }
        u
    });

    // `Drop` (and so `take_blocking`) runs on its own thread, since `before_take_blocking_wait` —
    // unlike the other fault hooks — fires on whichever thread calls `take_blocking`, and must be
    // set on that same thread (see its doc); the drain task itself already runs independently on
    // the runtime's blocking pool, so nothing here needs the runtime's own thread.
    let (event_tx, event_rx) = std::sync::mpsc::channel::<Event>();
    let hook_tx = event_tx.clone();
    let drop_thread = std::thread::spawn(move || {
        super::fault::set_before_take_blocking_wait(Box::new(move || {
            let _ = hook_tx.send(Event::EnteredWait);
        }));
        drop(u);
        let _ = event_tx.send(Event::DropFinished);
    });

    match event_rx.recv().expect("the drop thread reports one of the two events") {
        Event::EnteredWait => {
            release_tx
                .send(())
                .expect("let the gated task proceed to the real drop");
            drop_thread.join().expect("the drop thread must not panic");
        }
        Event::DropFinished => panic!(
            "Drop returned via take_blocking without ever reaching the wait loop \
             (round-7 review, mutant B)"
        ),
    }

    drop(runtime);
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// L-1 (round-7 review): `leak` of a drain already claimed by its task used to log one message for
/// both `Committed` (still running the real kill-through) and `Finished` (already ran it), even
/// though the two are very different news. Since then, `leak` was also required to never abandon a
/// `Committed` drain unowned: it must block on the task's own report exactly as `Drop` does (see
/// `leak`'s own doc), not merely log and return while the kill-through it can no longer stop keeps
/// running unbounded on the blocking pool. This test proves both: the log still tells `Committed`
/// apart from `Finished` at the moment `leak` peeks, and `leak` itself does not return until the
/// real kill-through the task committed to has actually run — checked here through a real cgroup
/// leaf's `cgroup.kill`, the same way
/// `leaking_while_the_blocking_reap_is_running_blocks_until_it_finishes_then_disarms` checks the
/// reap-side twin.
///
/// Gated via `after_drain_claim`, so the peek deterministically sees `Committed`, not a race
/// against the task's own progress. `before_take_blocking_wait` — the same seam
/// `drop_after_a_cancelled_wait_waits_for_the_running_drain` uses for `Drop` — proves `leak`
/// genuinely reached `take_blocking`'s wait loop rather than skipping it (round-7 review, mutant
/// B's `while false && ...` can never reach this line on any schedule).
///
/// A real cgroup leaf is Linux-only, the same as `test_support::entered_leaf_at` and
/// `leaking_while_the_blocking_reap_is_running_blocks_until_it_finishes_then_disarms` above.
#[cfg(target_os = "linux")]
#[test]
fn leak_of_a_committed_drain_blocks_until_the_real_kill_through_runs() {
    enum Event {
        EnteredWait,
        LeakFinished,
    }

    crate::log_capture::install();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    let (child, stdin, id) = std_blocked_child();
    drop(stdin); // the child exits at once
    crate::child::unreaped::block_until_reapable(id.pid()).expect("zombie");

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-leaked-committed-drain-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    let leaf = crate::containment::cgroup::test_support::entered_leaf_at(leaf_path.clone());

    let (claimed_tx, claimed_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let claimed_tx = std::sync::Mutex::new(claimed_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    super::fault::set_after_drain_claim(Box::new(move || {
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

    let u = runtime.block_on(async {
        let mut u = Unreaped::with_retained(
            Held::Std(child),
            Some(crate::child::unreaped::Retained {
                attached: crate::containment::Attached::Cgroup(leaf),
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
            r = u.wait() => panic!("wait completed instead of being cancelled: {r:?}"),
            _ = async { loop { if reaped_by_us() { break } ::tokio::task::yield_now().await } } => {}
        }
        assert!(
            u.hands_retained_to_draining_task(),
            "the drain must still be tracked after the cancelled wait"
        );
        claimed_rx
            .recv()
            .expect("the drain task reaches the gate once it has claimed what it must drop");
        {
            let (shared, _) = u.draining.as_ref().expect("the drain task owns what was retained");
            assert!(
                matches!(*shared.state(), super::DrainState::Committed),
                "the gate must hold the task Committed before leak runs"
            );
        }
        u
    });

    let mark = crate::log_capture::mark();
    let (event_tx, event_rx) = std::sync::mpsc::channel::<Event>();
    let hook_tx = event_tx.clone();
    let leak_thread = std::thread::spawn(move || {
        super::fault::set_before_take_blocking_wait(Box::new(move || {
            let _ = hook_tx.send(Event::EnteredWait);
        }));
        u.leak();
        let _ = event_tx.send(Event::LeakFinished);
    });

    match event_rx.recv().expect("the leak thread reports one of the two events") {
        Event::EnteredWait => {
            assert_eq!(
                std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
                b"",
                "the real kill-through must not have run yet: leak is still parked on the gate"
            );
            release_tx
                .send(())
                .expect("let the gated task proceed to the real kill-through");
            leak_thread.join().expect("the leak thread must not panic");
        }
        Event::LeakFinished => panic!(
            "leak returned via take_blocking without ever reaching the wait loop \
             (round-7 review, mutant B)"
        ),
    }

    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"1",
        "leak of a Committed drain must block until the real kill-through has actually run"
    );
    let records = crate::log_capture::records_since(mark, &format!("child {}", id.pid()));
    assert!(
        records
            .iter()
            .any(|r| r.contains("is killing through it on the blocking pool")),
        "leak of a Committed drain must say it is still running: {records:?}"
    );
    assert!(
        !records.iter().any(|r| r.contains("finished killing through")),
        "must not claim the drain already finished while it was still Committed at the peek: {records:?}"
    );

    drop(runtime);
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// L-1 (round-7 review): the `Finished` case, the converse of
/// `leak_of_a_committed_drain_logs_that_it_is_still_running` above: `leak` runs only once the task
/// has moved past `Committed` on its own — waited for here on the very same condvar
/// `RetainedDrain::take_blocking` itself waits on, so this is a real synchronization wait for the
/// state this test needs, not a race against the task's own settle.
#[cfg(unix)]
#[test]
fn leak_of_a_finished_drain_logs_that_it_already_ran() {
    crate::log_capture::install();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    let (child, stdin, id) = std_blocked_child();
    drop(stdin); // the child exits at once
    crate::child::unreaped::block_until_reapable(id.pid()).expect("zombie");

    let (claimed_tx, claimed_rx) = std::sync::mpsc::channel::<()>();
    let claimed_tx = std::sync::Mutex::new(claimed_tx);
    super::fault::set_after_drain_claim(Box::new(move || {
        let _ = claimed_tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(());
    }));

    runtime.block_on(async {
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
            r = u.wait() => panic!("wait completed instead of being cancelled: {r:?}"),
            _ = async { loop { if reaped_by_us() { break } ::tokio::task::yield_now().await } } => {}
        }
        assert!(
            u.hands_retained_to_draining_task(),
            "the drain must still be tracked after the cancelled wait"
        );

        // Guarantees the task has at least reached `Committed` (never reverts to `NotStarted`),
        // then blocks until it moves past that, on the same condvar `take_blocking` waits on.
        claimed_rx
            .recv()
            .expect("the drain task reaches the gate once it has claimed what it must drop");
        {
            let (shared, _) = u.draining.as_ref().expect("the drain task owns what was retained");
            let mut state = shared.state();
            while matches!(*state, super::DrainState::Committed) {
                state = shared
                    .finished
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }

        let mark = crate::log_capture::mark();
        u.leak();
        let records = crate::log_capture::records_since(mark, &format!("child {}", id.pid()));
        assert!(
            records
                .iter()
                .any(|r| r.contains("finished killing through it before leak ran")),
            "leak of a Finished drain must say it already finished: {records:?}"
        );
        assert!(
            !records
                .iter()
                .any(|r| r.contains("is killing through it on the blocking pool")),
            "must not claim the drain is still running once it has Finished: {records:?}"
        );
    });
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// M3 (round-6 review): `wait` must not return before the drain task it queued has actually
/// dropped what it retained — the real kill-through, or the real release on a merely disarmed
/// leaf. Deterministic and cross-platform, unlike the flaky, Linux-cgroup-only test it replaces:
/// `after_drop` gates `DrainTask::finish` right after `drop(retained)` has already run, and before
/// the state settles to `Finished` and notifies (unlike
/// `crate::containment::cgroup::fault::set_next_kill_thread_hook`, which reaches that same moment
/// only on a Linux cgroup leaf's `cgroup.kill` write, `after_drop` reaches it for every `Attached`
/// kind, on every platform). Gating strictly after the drop — rather than before it — is the
/// point (round-7 review, mutant A): a mutant that moves the notify earlier, to anywhere between
/// the claim and this gate, has already notified by the time the gate is even reached, so `wait`'s
/// future is already ready when the `select!` below polls it, and the `biased` losing arm catches
/// that. A before-drop gate cannot tell such a mutant apart from a correct one, because
/// `Attached::None`'s drop has no observable side effect for the reordering to disturb.
#[tokio::test]
async fn wait_returns_only_after_the_retained_drop_ran() {
    let (child, stdin, id) = blocked_child();
    drop(stdin); // the child exits at once
    let mut unreaped = Unreaped::with_retained(
        Held::Tokio(Box::new(child)),
        Some(crate::child::unreaped::Retained {
            attached: crate::containment::Attached::None,
        }),
    );
    let (after_drop_tx, after_drop_rx) = ::tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    super::fault::set_after_drain_drop(Box::new(move || {
        let _ = after_drop_tx.send(());
        let _ = release_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv();
    }));

    let mut wait = std::pin::pin!(unreaped.wait());
    ::tokio::select! {
        biased;
        r = &mut wait => panic!("wait returned while the settle-and-notify is parked after the retained drop: {r:?}"),
        r = after_drop_rx => r.expect("the drain reached the post-drop hook"),
    }
    release_tx.send(()).expect("the drain is parked on the gate");
    let status = wait.await.expect("wait for the child");
    // `blocked_child`'s Windows child is `findstr x`: closed stdin gives it no input to match, so
    // it exits `1`, not `0` — the same platform split `a_cancelled_wait_leaves_the_caller_holding`
    // already accounts for.
    assert_eq!(status.code(), Some(if cfg!(windows) { 1 } else { 0 }), "{status:?}");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}
