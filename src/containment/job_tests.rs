//! Unit tests for the public `Job` wrapper: delegation to `JobHandle`, not the suspend/resume
//! contract (that needs a genuine `CREATE_SUSPENDED` process and lives in the integration suite,
//! `tests/windows_job_object.rs`). These use a plain, already-running `cmd /C more` — mirroring
//! `windows_tests.rs`'s `wait_drained_raw_tracks_a_real_member_through_exit`.

use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};

use super::Job;
use crate::test_child::spawn_more_blocker;

#[skuld::test]
fn assign_then_kill_tree_terminates_the_process() {
    let mut child = spawn_more_blocker();
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

/// `kill_tree` returns once the member it terminated has exited: its identity reads `Dead` the moment
/// the call returns, before any wait of the test's own.
#[skuld::test]
fn kill_tree_returns_with_the_member_exited() {
    let child = spawn_more_blocker();
    let id = crate::identity::ProcessId::of(child.id())
        .found()
        .expect("the member's identity");
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.kill_tree().expect("kill_tree");

    assert_eq!(
        id.is_alive(),
        crate::identity::Liveness::Dead,
        "the member has exited when kill_tree returns"
    );
}

/// The wait over a job's listed members blocks on a member that is running, and ends once it has exited
/// and the job has drained. The kill is stated, not made: a real kill ends the member before the wait
/// looks at it, so only a member the kill left running shows that the wait blocks.
#[skuld::test]
fn the_wait_over_a_jobs_listed_members_blocks_on_a_running_member() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::containment::dispatch::TreeKillOutcome;
    use crate::containment::drain_edge::DrainEdge;
    use crate::containment::TreeKill;

    let mut child = spawn_more_blocker();
    let id = crate::identity::ProcessId::of(child.id())
        .found()
        .expect("the member's identity");
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");
    let (members, unobserved) = job.0.list_members(None);
    assert!(members.contains(&id), "the member is listed: {members:?}");
    let stdin = Cell::new(child.stdin.take());
    let blocked = Rc::new(Cell::new(false));
    let _blocking = crate::wait::block_probe::on_blocking({
        let blocked = blocked.clone();
        move || {
            blocked.set(true);
            drop(stdin.take());
        }
    });

    let (_, wait) = TreeKill::listed(
        TreeKillOutcome::Ran(Ok(())),
        members,
        unobserved,
        DrainEdge::Job(&job.0),
        &crate::identity::HostKernel,
    )
    .split();
    wait.wait(None).expect("the member exited and the job drained");

    assert!(blocked.get(), "the wait did not block on a member that was running");
}

/// `send_kill_tree` terminates the member and returns without waiting for it: nothing blocks in the
/// call, and `wait_tree` after it finds the member's exit.
///
/// Mutant: `send_kill_tree` waits for the members.
#[skuld::test]
fn send_kill_tree_terminates_the_member_and_waits_for_nothing() {
    use std::cell::Cell;
    use std::rc::Rc;

    let mut child = spawn_more_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    let blocked = Rc::new(Cell::new(false));
    let blocking = crate::wait::block_probe::on_blocking({
        let blocked = blocked.clone();
        move || blocked.set(true)
    });
    job.send_kill_tree().expect("send_kill_tree");
    drop(blocking);

    assert!(!blocked.get(), "send_kill_tree blocked on a member");
    let verdict = job.wait_tree().expect("wait_tree after send_kill_tree");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
    let status = child.wait().expect("reap the killed member");
    assert!(!status.success(), "the member was killed: {status:?}");
}

#[skuld::test]
fn disarm_clears_kill_on_job_close() {
    let child = spawn_more_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.disarm().expect("disarm");

    assert_eq!(
        crate::test_frozen::limit_flags(&job.0).0,
        0,
        "disarm() must clear every limit flag, including KILL_ON_JOB_CLOSE"
    );
}

#[skuld::test]
fn wait_tree_reports_members_remain_then_all_exited() {
    let mut child = spawn_more_blocker();
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

/// `wait_tree` after `kill_tree` reports the drain once the killed member has exited.
#[skuld::test]
fn wait_tree_after_kill_tree_reports_the_drain() {
    let mut child = spawn_more_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.kill_tree().expect("kill_tree");
    let verdict = job.wait_tree().expect("wait_tree after kill_tree");

    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
    let status = child.wait().expect("reap the killed member");
    assert!(!status.success(), "the member was killed: {status:?}");
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
    let child = spawn_more_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives the borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    job.kill_tree().expect("kill_tree");
    job.disarm().expect("disarm after kill_tree");

    assert_eq!(crate::test_frozen::limit_flags(&job.0).0, 0);
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
    let child = spawn_more_blocker();
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
}

/// A job names the members of its tree for a send that reaches each by itself, the root among them.
///
/// Mutant: the listing leaves the root out, as a kill's wait does (its owner waits for it).
#[skuld::test]
fn a_jobs_member_ids_name_the_root_among_its_members() {
    use crate::containment::Contains as _;

    let child = spawn_more_blocker();
    let id = crate::identity::ProcessId::of(child.id())
        .found()
        .expect("the member's identity");
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");

    let members = job.0.member_ids().expect("the job lists its members");

    assert!(members.named.contains(&id), "the root is a member: {members:?}");
}

/// A job whose members cannot be listed answers the listing's error: it names no member, and an empty list
/// would read as a tree with nothing to ask. Its text says what a listing did, not what a kill did.
///
/// Mutants: the failed listing is an empty list of members; the text is the kill's ("before the kill, so
/// their exit cannot be observed").
#[skuld::test]
fn a_jobs_member_ids_are_an_error_when_the_job_cannot_be_listed() {
    use windows::Win32::System::SystemServices::JOB_OBJECT_TERMINATE;

    use crate::containment::Contains as _;

    let child = spawn_more_blocker();
    let raw = child.as_raw_handle();
    // SAFETY: `child` outlives this borrow.
    let job = Job::assign(unsafe { BorrowedHandle::borrow_raw(raw) }).expect("assign to job");
    // A handle that may terminate the job and not query it: the OS refuses the listing.
    let unlistable = job.0.duplicate_with_access_for_test(JOB_OBJECT_TERMINATE);

    let error = unlistable.member_ids().expect_err("the listing is refused");

    assert!(
        matches!(&error, crate::error::Error::Unassessable { detail, .. }
            if detail.as_str() == "the members of the job could not be listed, so no member is asked"),
        "{error:?}"
    );
}
