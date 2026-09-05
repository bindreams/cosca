//! Unit tests for the public `Job` wrapper: delegation to `JobHandle`, not the suspend/resume
//! contract (that needs a genuine `CREATE_SUSPENDED` process and lives in the integration suite,
//! `tests/windows_job_object.rs`). These use a plain, already-running `cmd /C more` — mirroring
//! `windows_tests.rs`'s `wait_drained_raw_tracks_a_real_member_through_exit`.

use std::mem::size_of;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};

use windows::Win32::System::JobObjects::{
    JobObjectExtendedLimitInformation, QueryInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
};

use super::Job;

/// `cmd /C more`: blocks reading its stdin until EOF, then exits. No new external dependency —
/// this is the OS shell, exactly like `windows_tests.rs`'s fixture.
fn spawn_blocker() -> std::process::Child {
    std::process::Command::new("cmd")
        .args(["/C", "more"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn cmd /C more")
}

#[test]
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

#[test]
fn disarm_clears_kill_on_job_close() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");
    let handle = job.0.as_handle().expect("freshly assigned job handle must be live");

    job.disarm();

    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut returned = 0u32;
    // SAFETY: `handle` is live; `info` is sized for the class being queried.
    unsafe {
        QueryInformationJobObject(
            Some(handle),
            JobObjectExtendedLimitInformation,
            std::ptr::addr_of_mut!(info).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            Some(&mut returned),
        )
    }
    .expect("QueryInformationJobObject after disarm");
    assert_eq!(
        info.BasicLimitInformation.LimitFlags.0, 0,
        "disarm() must clear every limit flag, including KILL_ON_JOB_CLOSE"
    );

    // Cleanup: disarm() means dropping `job` will NOT kill this real process.
    drop(job);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
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
        .wait_tree_deadline(Some(Some(past)))
        .expect("wait_tree (elapsed deadline)");
    assert_eq!(verdict, crate::containment::TreeDrain::MembersRemain);

    // Let the child exit on its own terms (EOF on stdin) — a real synchronization point.
    drop(child.stdin.take());
    child.wait().expect("wait for cmd /C more to exit");

    let verdict = job.wait_tree().expect("wait_tree (no deadline, already drained)");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
}

#[test]
fn wait_tree_after_kill_tree_is_unassessable() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.kill_tree().expect("kill_tree");
    let _ = child.wait();

    let err = job
        .wait_tree()
        .expect_err("wait_tree after kill_tree must not guess a drain verdict");
    assert!(
        matches!(err, crate::error::Error::Unassessable { .. }),
        "expected Unassessable, got {err:?}"
    );
}

#[test]
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

#[test]
fn job_debug_differs_before_and_after_kill_tree() {
    let mut child = spawn_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    let live = format!("{job:?}");
    job.kill_tree().expect("kill_tree");
    let killed = format!("{job:?}");

    assert_ne!(
        live, killed,
        "Debug must reflect the handle being consumed by kill_tree, not print the same thing regardless"
    );
    let _ = child.wait();
}
