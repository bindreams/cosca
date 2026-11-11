//! Unit tests for the public `Job` wrapper: delegation to `JobHandle`, not the suspend/resume
//! contract (that needs a genuine `CREATE_SUSPENDED` process and lives in the integration suite,
//! `tests/windows_job_object.rs`). These use a plain, already-running `cmd /C more` — mirroring
//! `windows_tests.rs`'s `wait_drained_raw_tracks_a_real_member_through_exit`.

use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};

use super::Job;

/// `cmd /C more`: blocks reading its stdin until EOF, then exits. No new external dependency —
/// this is the OS shell, exactly like `windows_tests.rs`'s fixture.
fn spawn_blocker() -> std::process::Child {
    crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "more"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn cmd /C more")
}

#[skuld::test]
fn assign_then_kill_tree_terminates_the_process() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.kill_tree().expect("kill_tree");

    let status = child.wait().expect("wait for the killed child");
    assert!(
        !status.success(),
        "a job-killed process must not report success: {status:?}"
    );
}

#[skuld::test]
fn disarm_clears_kill_on_job_close() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.disarm().expect("disarm");

    assert_eq!(
        crate::test_frozen::limit_flags(&job.0).0,
        0,
        "disarm() must clear every limit flag, including KILL_ON_JOB_CLOSE"
    );

    // Cleanup: disarm() means dropping `job` will NOT kill this real process.
    drop(job);
    _ = child.kill();
    _ = child.wait();
}

#[skuld::test]
fn wait_tree_reports_members_remain_then_all_exited() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    // An already-elapsed deadline reads as `Duration::ZERO` without blocking (see
    // `crate::wait::remaining`) — a live member reports `MembersRemain` instantly.
    let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
    // `wait_tree_deadline` is private to `job`, but `job_tests` is its child module, so it's
    // reachable directly — no need for a test-only public wrapper.
    let verdict = job
        .wait_tree_deadline(Some(past))
        .expect("wait_tree (elapsed deadline)");
    assert_eq!(verdict, crate::containment::TreeDrain::MembersRemain);

    // Let the child exit on its own terms (EOF on stdin) — a real synchronization point.
    drop(child.stdin.take());
    child.wait().expect("wait for cmd /C more to exit");

    let verdict = job.wait_tree().expect("wait_tree (no deadline, already drained)");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
}

/// `wait_tree` after `kill_tree` waits for the members to exit and reports the drain. A member
/// assigned after the kill is alive when the wait starts and exits only once the wait has blocked
/// and re-armed, so the verdict comes after its exit, not before.
///
/// Mutant: report `AllMembersExited` without waiting for the live members -> no re-arm, and the
/// member is still alive at the verdict.
#[skuld::test]
fn wait_tree_after_kill_tree_waits_for_the_members_and_returns() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.kill_tree().expect("kill_tree");
    let mut late = spawn_blocker();
    job.0.assign_for_test(late.as_raw_handle());
    let stdin = late.stdin.take().expect("piped stdin");
    crate::wait::wait_ms_probe::take();
    let _clamp = crate::wait::wait_clamp_seam::set(5);
    crate::wait::wait_ms_probe::on_second_arm(move || drop(stdin)); // EOF -> the member exits for real

    let verdict = job.wait_tree_timeout(std::time::Duration::from_secs(3600));
    let arms = crate::wait::wait_ms_probe::take();
    let exited = late.try_wait().expect("poll the late member");
    _ = child.wait();
    late.wait().expect("reap the late member");
    assert_eq!(
        verdict.expect("wait_tree after kill_tree"),
        crate::containment::TreeDrain::AllMembersExited
    );
    assert!(
        arms.len() >= 2,
        "the wait must have blocked and re-armed: {} arm(s)",
        arms.len()
    );
    assert!(exited.is_some(), "the verdict came before the member exited");
}

#[skuld::test]
fn assign_to_an_invalid_handle_is_an_error() {
    // A real, valid, open handle — just not a process handle. `BorrowedHandle::borrow_raw`
    // requires a genuinely live handle (never null / INVALID_HANDLE_VALUE), which a plain
    // file satisfies; `AssignProcessToJobObject` still rejects it deterministically, since the
    // kernel object behind it isn't a process.
    let file = std::fs::File::open(std::env::current_exe().expect("current_exe")).expect("open self as a plain file");
    assert!(
        Job::assign(file.as_handle()).is_err(),
        "assigning a non-process handle must fail, not succeed"
    );
}

/// `Job` is shared across threads by callers. Pinning the bound here means a future change that
/// makes `Job` thread-hostile fails at compile time rather than silently narrowing what callers
/// may do — the same assertion `Process` carries.
#[skuld::test]
fn job_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Job>();
}

/// `disarm` after `kill_tree` really clears `KILL_ON_JOB_CLOSE`.
#[skuld::test]
fn disarm_after_kill_tree_clears_kill_on_job_close() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives the borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.kill_tree().expect("kill_tree");
    job.disarm().expect("disarm after kill_tree");

    assert_eq!(crate::test_frozen::limit_flags(&job.0).0, 0);

    _ = child.wait();
}

/// A `disarm` the OS refuses is the caller's error: the public `Job::disarm` returns it as
/// `Error::Io`, with the Win32 code.
///
/// Mutant: `Job::disarm` drops the error.
#[skuld::test]
fn a_refused_disarm_is_returned_as_an_io_error() {
    let job = Job(crate::containment::windows::JobHandle::create_without_set_access_for_test());

    let err = job
        .disarm()
        .expect_err("the OS refuses SetInformationJobObject on this handle");

    let crate::error::Error::Io(io) = err else {
        panic!("expected Io, got {err:?}");
    };
    assert_eq!(
        io.raw_os_error(),
        Some(windows::Win32::Foundation::ERROR_ACCESS_DENIED.0 as i32),
        "{io:?}"
    );
}

/// A zero timeout on a live tree reports `MembersRemain` rather than blocking or guessing.
#[skuld::test]
fn wait_tree_timeout_zero_reports_members_remain() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives the borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    let drain = job
        .wait_tree_timeout(std::time::Duration::ZERO)
        .expect("a zero-timeout drain query must succeed");
    assert_eq!(
        drain,
        crate::containment::TreeDrain::MembersRemain,
        "a live member must be reported as remaining"
    );

    job.kill_tree().expect("kill_tree");
    _ = child.wait();
}
