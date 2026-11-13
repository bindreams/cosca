//! Unit tests for Windows Job Object containment helpers.
//! Substantive runtime coverage is in the integration tests (tests/spawn_io.rs).

use crate::test_child::{let_member_exit, spawn_job_member, spawn_job_with_two_members, Console};

#[skuld::test]
fn job_handle_debug_does_not_panic() {
    use super::JobHandle;
    let h = JobHandle::create_empty_for_test();
    let s = format!("{h:?}");
    assert!(s.contains("JobHandle"), "debug output: {s}");
}

/// `wait_drained` after `hard_kill` asks the kernel and reports the drain once the killed member
/// has exited.
#[skuld::test]
fn wait_drained_after_hard_kill_reports_the_drain() {
    let (mut child, job) = spawn_job_member();
    job.hard_kill().expect("hard_kill on a live job");
    let verdict = job.wait_drained(None).expect("wait_drained after hard_kill");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
    let status = child.wait().expect("reap the killed member");
    assert!(!status.success(), "the member was killed: {status:?}");
}

/// Against the real OS, with no forced listing: once `wait_drained` answers `AllMembersExited` after
/// the job's kill, every member the job held (each opened before the kill) is signalled.
///
/// Mutant: an empty listing answers `AllMembersExited` without the snapshot's members.
#[skuld::test]
fn after_the_job_kill_the_drain_answers_only_once_every_member_is_signalled() {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};

    use crate::containment::Contains as _;

    let (mut members, job) = crate::test_child::spawn_job_with_members(3);
    let pids = super::query_job_pid_list(HANDLE(job.handle().as_raw_handle())).expect("list the job's members");
    assert!(pids.len() >= members.len(), "the job holds its members: {pids:?}");
    let held: Vec<(u32, OwnedHandle)> = pids
        .into_iter()
        .map(|pid| {
            // SAFETY: a standard Win32 call; the handle returned is ours and owned from here.
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }.expect("open a member of the job");
            // SAFETY: `OpenProcess` returned an open handle that nothing else owns.
            (pid, unsafe { OwnedHandle::from_raw_handle(handle.0) })
        })
        .collect();

    job.send_kill(None).into_result().expect("terminate the job");
    let verdict = job.wait_drained(None).expect("wait for the job to drain");

    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
    for (pid, handle) in &held {
        // SAFETY: `handle` is open for the call.
        let waited = unsafe { WaitForSingleObject(HANDLE(handle.as_raw_handle()), 0) };
        assert_eq!(
            waited, WAIT_OBJECT_0,
            "pid {pid} is a member the drain answered before it was signalled"
        );
    }
    for member in &mut members {
        member.wait().expect("reap a member");
    }
}

/// A kill the OS refuses names no member to wait for: its `Err` is returned, where a wait over members
/// it did not kill would hang. A handle without `JOB_OBJECT_TERMINATE` lists the live member and is
/// refused the kill. The wait is made to end the member where it blocks, so a mutant fails by assertion.
///
/// Mutant: the members are named whether or not the kill landed.
#[skuld::test]
fn a_job_kill_the_os_refuses_waits_for_no_member() {
    use std::cell::Cell;
    use std::rc::Rc;

    use windows::Win32::System::SystemServices::JOB_OBJECT_QUERY;

    use crate::containment::Contains as _;

    let (mut child, job) = spawn_job_member();
    let refused = job.duplicate_with_access_for_test(JOB_OBJECT_QUERY);

    let (sent, wait) = refused.kill(None).split();
    assert!(
        sent.into_result().is_err(),
        "a handle without JOB_OBJECT_TERMINATE is refused the kill"
    );
    let job = Rc::new(job);
    let blocked = Rc::new(Cell::new(false));
    let _blocking = crate::wait::block_probe::on_blocking({
        let (job, blocked) = (job.clone(), blocked.clone());
        move || {
            blocked.set(true);
            job.hard_kill().expect("end the member");
        }
    });
    wait.wait().expect("a kill that failed waits for nothing");

    assert!(!blocked.get(), "the wait blocked on a member the kill did not reach");
    job.hard_kill().expect("end the member");
    _ = child.wait();
}

/// The members are listed before `TerminateJobObject`, not after it: a member that has left the job's
/// list by the time the kill runs is still named. The member is ended and reaped right before the kill,
/// so the job's list is empty when the kill runs, whatever order the kernel signals a process in.
///
/// Mutant: the list is read after the kill.
#[skuld::test]
fn a_job_lists_its_members_before_it_terminates_them() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::containment::Contains as _;

    let (child, job) = spawn_job_member();
    let id = crate::identity::ProcessId::of(child.id())
        .found()
        .expect("the member's identity");
    let child = Rc::new(RefCell::new(child));
    let _ending = super::fault::set_before_job_kill({
        let child = child.clone();
        move || {
            let mut child = child.borrow_mut();
            child.kill().expect("end the member");
            child.wait().expect("reap the member");
        }
    });

    let (sent, wait) = job.kill(None).split();

    sent.into_result().expect("the job's kill");
    assert_eq!(
        wait.members_for_test(),
        [id],
        "the member was named before the kill ended it"
    );
}

/// A kill that waits for the members reads the job's list once before it, and one that only sends
/// reads none: the list is work for the wait alone.
///
/// Mutant: `send_kill` lists the members first.
#[skuld::test]
fn only_a_job_kill_that_waits_reads_the_members_list() {
    use crate::containment::Contains as _;

    let (mut child, job) = spawn_job_member();
    {
        let _forced = super::fault::force_job_pid_list(Vec::new());
        _ = job.kill(None).split();
        assert_eq!(
            super::fault::job_pid_list_queries(),
            1,
            "a kill that waits lists the job once, before it terminates it"
        );
    }
    let (mut child2, job2) = spawn_job_member();
    let _forced = super::fault::force_job_pid_list(Vec::new());
    job2.send_kill(None).into_result().expect("the job's kill");
    assert_eq!(
        super::fault::job_pid_list_queries(),
        0,
        "a kill that only sends reads no list"
    );
    _ = (child.wait(), child2.wait());
}

/// `query_job_pid_list` on a freshly created, unpopulated job reports no members — the fast
/// path `wait_drained_raw` relies on to return `AllMembersExited` without ever opening a
/// process handle.
#[skuld::test]
fn query_job_pid_list_is_empty_for_an_unpopulated_job() {
    use super::JobHandle;
    let job = JobHandle::create_empty_for_test();
    let pids = super::query_job_pid_list(job.raw).expect("query pid list");
    assert!(pids.is_empty(), "an empty job must report no members: {pids:?}");
}

/// `wait_drained_raw`'s empty-job fast path: no member was ever assigned, so the very first
/// re-enumeration already reports `AllMembersExited`, with no wait and no deadline needed.
#[skuld::test]
fn wait_drained_raw_reports_drained_for_an_empty_job() {
    use super::JobHandle;
    let job = JobHandle::create_empty_for_test();
    let verdict = super::wait_drained_raw(&job, None).expect("wait_drained_raw");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
}

/// A listing whose pids are none a live member does not end the drain: a member may have joined after
/// it, so the wait lists the job again, and only an empty fresh listing is a drain. The job is empty,
/// so the second listing says drained; the query count is what tells it from a verdict taken off the
/// first.
fn assert_drained_only_by_a_fresh_listing(listed: Vec<u32>) {
    let job = super::JobHandle::create_empty_for_test();
    let forced = super::fault::force_job_pid_list(listed);
    let verdict = super::wait_drained_raw(&job, None).expect("wait_drained_raw");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
    assert_eq!(
        super::fault::job_pid_list_queries(),
        2,
        "the wait ended on a listing of pids that are no live member, without listing again"
    );
    drop(forced);
}

/// A listed pid that names no process (`OpenProcess` answers `ERROR_INVALID_PARAMETER`) is no live
/// member. Windows ignores a pid's low two bits on lookup, so pids 1-3 resolve to 0, which
/// `OpenProcess` refuses.
///
/// Mutant: a round whose listed pids are all gone answers `AllMembersExited`.
#[skuld::test]
fn wait_drained_raw_lists_again_after_a_listing_of_pids_that_are_gone() {
    assert_drained_only_by_a_fresh_listing(vec![1]);
}

/// A listed pid that opens but is not in the job (its number was reused) is no longer a member.
/// This test's own process is that bystander.
#[skuld::test]
fn wait_drained_raw_lists_again_after_a_listing_of_pids_that_are_not_members() {
    assert_drained_only_by_a_fresh_listing(vec![std::process::id()]);
}

/// A round that starts past the deadline lists; a listing that names only pids that are no live member
/// (a deleted pid shows for one listing) is followed by exactly one more listing, which is final. Here
/// the job is empty, so that listing is empty and the tree drained just before the deadline.
///
/// Mutant: a stale-only round past the deadline answers `MembersRemain` off its one listing.
#[skuld::test]
fn wait_drained_raw_with_an_elapsed_deadline_answers_drained_when_the_one_more_listing_is_empty() {
    let job = super::JobHandle::create_empty_for_test();
    let forced = super::fault::force_job_pid_list(vec![1]);
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero).expect("wait_drained_raw");

    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
    assert_eq!(super::fault::job_pid_list_queries(), 2, "the listing, and one more");
    drop(forced);
}

/// The one more listing is final: a non-empty one answers `MembersRemain` with no open, no poll and no
/// further round. The real job holds a live member for it.
///
/// Mutant: a non-empty final listing is answered `AllMembersExited`.
#[skuld::test]
fn wait_drained_raw_with_an_elapsed_deadline_answers_members_remain_when_the_one_more_listing_is_not_empty() {
    let (child, job) = spawn_job_member();
    let forced = super::fault::force_job_pid_list(vec![1]);
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero).expect("wait_drained_raw");

    assert_eq!(verdict, crate::containment::TreeDrain::MembersRemain);
    assert_eq!(super::fault::job_pid_list_queries(), 2, "the listing, and one more");
    drop(forced);
    job.hard_kill().expect("end the member");
    let_member_exit(child);
}

/// Live members that the zero-ms poll finds unsignalled answer `MembersRemain` off the round's own
/// listing: one query, no final listing. The member blocks on its stdin, which this test holds open.
///
/// Mutant: that branch takes the final listing, which is a second query.
#[skuld::test]
fn wait_drained_raw_with_an_elapsed_deadline_answers_members_remain_off_its_own_listing_for_live_members() {
    let (child, job) = spawn_job_member();
    let forced = super::fault::force_job_pid_lists([]);
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero).expect("wait_drained_raw");

    assert_eq!(verdict, crate::containment::TreeDrain::MembersRemain);
    assert_eq!(super::fault::job_pid_list_queries(), 1, "the round's own listing only");
    drop(forced);
    job.hard_kill().expect("end the member");
    let_member_exit(child);
}

/// The final listing is the last: when it too names only stale pids, the answer is `MembersRemain` and
/// nothing lists a third time. A third listing here would be the real, empty job.
///
/// Mutant: the one more listing is another round, which lists again.
#[skuld::test]
fn wait_drained_raw_with_an_elapsed_deadline_lists_no_third_time() {
    let job = super::JobHandle::create_empty_for_test();
    let forced = super::fault::force_job_pid_lists([vec![1], vec![1]]);
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero).expect("wait_drained_raw");

    assert_eq!(verdict, crate::containment::TreeDrain::MembersRemain);
    assert_eq!(super::fault::job_pid_list_queries(), 2, "the listing, and one more");
    drop(forced);
}

/// A listed member whose handle the zero-ms poll finds signalled (it has exited, and its process object
/// is still held, so it still opens as a member) is stale evidence too: exactly one more listing
/// answers, here the real job, empty.
///
/// Mutant: a signalled poll at an elapsed deadline answers `MembersRemain` off the listing.
#[skuld::test]
fn wait_drained_raw_with_an_elapsed_deadline_lists_once_more_after_a_signalled_poll() {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};

    let (mut child, job) = spawn_job_member();
    drop(child.stdin.take());
    child.wait().expect("the member exits");
    // The member's own child (`more`) is a member too: the job is empty only once it has gone.
    assert_eq!(
        super::wait_drained_raw(&job, None).expect("the job drains"),
        crate::containment::TreeDrain::AllMembersExited
    );
    // SAFETY: a standard Win32 call; the handle is closed below.
    let opened = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            child.id(),
        )
    };
    let held = super::member_to_watch(opened, job.raw)
        .expect("the exited member opens")
        .expect("the exited member is still a member of its job while its process object is held");
    // SAFETY: opened above.
    _ = unsafe { windows::Win32::Foundation::CloseHandle(held) };
    let forced = super::fault::force_job_pid_list(vec![child.id()]);
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero).expect("wait_drained_raw");

    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
    assert_eq!(super::fault::job_pid_list_queries(), 2, "the listing, and one more");
    drop(forced);
}

/// An empty listing answers `AllMembersExited` whatever the deadline.
///
/// Mutant: a round past the deadline answers `MembersRemain` before it reads the listing.
#[skuld::test]
fn wait_drained_raw_with_an_elapsed_deadline_answers_drained_for_an_empty_listing() {
    let job = super::JobHandle::create_empty_for_test();
    let forced = super::fault::force_job_pid_list(Vec::new());
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero).expect("wait_drained_raw");

    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
    assert_eq!(super::fault::job_pid_list_queries(), 1, "exactly one listing");
    drop(forced);
}

/// An empty first listing is no answer: the drain looks for the job's members in a system snapshot. The
/// member is alive, in the job, when the listing (forced) comes back empty; at an elapsed deadline
/// the drain polls it and answers `MembersRemain`.
///
/// Mutant: an empty first listing answers `AllMembersExited` off the list alone.
#[skuld::test]
fn wait_drained_raw_does_not_answer_an_empty_first_listing_while_a_member_runs() {
    let (child, job) = spawn_job_member();
    let forced = super::fault::force_job_pid_list(Vec::new());
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero);

    drop(forced);
    job.hard_kill().expect("end the member");
    let_member_exit(child);
    assert_eq!(
        verdict.expect("wait_drained_raw"),
        crate::containment::TreeDrain::MembersRemain,
        "the drain was answered off an empty listing while a member's process object was unsignalled"
    );
}

/// A member the wait never opened is waited for too: with more live members than one wait set holds
/// (`MAXIMUM_WAIT_OBJECTS - 1`), the last is left unopened, and the listing after the rest exit is
/// empty (forced) while it runs.
///
/// Mutant: the drain confirms only the members it opened.
#[skuld::test]
fn wait_drained_raw_waits_for_a_member_it_never_opened_past_the_wait_set() {
    use crate::test_child::spawn_job_with_members;

    let (mut members, job) = spawn_job_with_members(super::MAXIMUM_WAIT_OBJECTS);
    let unopened = members.pop().expect("a last member");
    let mut listed: Vec<u32> = members.iter().map(std::process::Child::id).collect();
    listed.push(unopened.id());
    // Reaped, but each handle stays open, so each pid still opens as a signalled member.
    for member in &mut members {
        drop(member.stdin.take());
        member.wait().expect("wait for a member to exit");
    }
    let forced = super::fault::force_job_pid_lists([listed, Vec::new()]);
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero);

    drop(forced);
    job.hard_kill().expect("end the member");
    let_member_exit(unopened);
    assert_eq!(
        verdict.expect("wait_drained_raw"),
        crate::containment::TreeDrain::MembersRemain,
        "the drain was answered while a member it never opened was unsignalled"
    );
}

/// A system snapshot that cannot be taken is the drain's failure, with its cause: an empty listing
/// of a job that has had a process is never answered `AllMembersExited` without it.
#[skuld::test]
fn wait_drained_raw_fails_when_the_snapshot_for_an_empty_listing_cannot_be_taken() {
    let (child, job) = spawn_job_member();
    let _snapshot = crate::containment::enumerate::backend_fault::force_snapshot_failure();
    let forced = super::fault::force_job_pid_list(Vec::new());

    let verdict = super::wait_drained_raw(&job, None);

    drop(forced);
    job.hard_kill().expect("end the member");
    let_member_exit(child);
    let error = verdict.expect_err("an empty listing with no snapshot is not a drain");
    assert!(
        matches!(&error, crate::error::Error::Unassessable { source: Some(_), .. }),
        "{error:?}"
    );
}

/// A job that has never had a process has none to wait for: an empty listing answers
/// `AllMembersExited` with no snapshot (a forced failure of it is never met).
///
/// Mutant: the stored count starts at a value no count equals.
#[skuld::test]
fn an_empty_listing_of_a_job_that_never_had_a_process_takes_no_snapshot() {
    let job = super::JobHandle::create_empty_for_test();
    let _snapshot = crate::containment::enumerate::backend_fault::force_snapshot_failure();
    let forced = super::fault::force_job_pid_list(Vec::new());

    let verdict = super::wait_drained_raw(&job, None);

    drop(forced);
    assert_eq!(
        verdict.expect("no snapshot is needed"),
        crate::containment::TreeDrain::AllMembersExited
    );
}

/// A drain that confirmed every member leaves nothing to confirm while no process joins the job: the
/// next empty listing answers `AllMembersExited` with no snapshot (a forced failure of it is never met).
///
/// Mutant: the count of the confirmed drain is not stored, so every empty listing scans.
#[skuld::test]
fn a_second_empty_listing_with_no_process_since_takes_no_snapshot() {
    let (child, job) = spawn_job_member();
    let_member_exit(child);
    assert_eq!(
        job.wait_drained(None).expect("the job drains"),
        crate::containment::TreeDrain::AllMembersExited
    );
    let _snapshot = crate::containment::enumerate::backend_fault::force_snapshot_failure();

    let verdict = job.wait_drained(None);

    assert_eq!(
        verdict.expect("nothing joined, so nothing is scanned"),
        crate::containment::TreeDrain::AllMembersExited
    );
}

/// A process that joins the job after a confirmed drain is confirmed too: the count has risen, so the
/// next empty listing (forced) takes the snapshot, finds the new member running and, at an elapsed
/// deadline, answers `MembersRemain`. A job's kill can leave exactly that listing empty over an
/// unsignalled member.
///
/// Mutant: a confirmed drain's stored count is trusted whatever the job's count is now.
#[skuld::test]
fn a_member_assigned_after_a_confirmed_drain_is_confirmed_too() {
    use std::os::windows::io::AsRawHandle as _;

    let (child, job) = spawn_job_member();
    let_member_exit(child);
    assert_eq!(
        job.wait_drained(None).expect("the job drains"),
        crate::containment::TreeDrain::AllMembersExited
    );
    let second = crate::test_child::spawn_more_blocker();
    job.assign_for_test(second.as_raw_handle())
        .expect("assign a new member to the job");
    let forced = super::fault::force_job_pid_list(Vec::new());
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = job.wait_drained(zero);

    drop(forced);
    job.hard_kill().expect("end the member");
    let_member_exit(second);
    assert_eq!(
        verdict.expect("wait_drained"),
        crate::containment::TreeDrain::MembersRemain,
        "the drain stood for a member it never confirmed"
    );
}

/// A drain that left a member out as settled has not confirmed it: the count is not stored, and a later
/// drain scans, finds the member (still running) and answers `MembersRemain`.
///
/// Mutant: the count is stored although a settled member was left out of the walk.
#[skuld::test]
fn a_drain_that_left_a_settled_member_out_does_not_stand_for_it_later() {
    use crate::containment::tree_kill::Settled;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_drain_that_left_a_settled_member_out_does_not_stand_for_it_later),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    // A member the caller may not wait on, with no console host beside it: a later wait for it fails.
    let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let id = crate::identity::windows_identity_from_handle_result(member.handle(), member.pid())
        .expect("the restricted member's identity");
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");
    let forced = super::fault::force_job_pid_lists([Vec::new(), Vec::new()]);

    let first = job.wait_drained_past(None, &Settled::new(vec![id], Vec::new()));
    let second = job.wait_drained(None);

    drop(forced);
    assert_eq!(
        first.expect("the first wait"),
        crate::containment::TreeDrain::AllMembersExited,
        "the settled member is not waited for"
    );
    let error = second.expect_err("the second wait finds the member it may not wait on");
    assert!(
        matches!(&error, crate::error::Error::Unassessable { detail, .. } if detail.contains(&member.pid().to_string())),
        "the first drain's count stood for a member it left out: {error:?}"
    );
}

/// A snapshot pid whose membership cannot be established (here a forced `IsProcessInJob` failure on
/// the only member, which has no console host beside it) is not shown to be the job's: it is skipped,
/// as a pid that cannot be opened is, and the drain is not failed by it.
///
/// Mutant: the failure is the drain's error.
#[skuld::test]
fn a_snapshot_pid_whose_membership_cannot_be_established_is_skipped() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_snapshot_pid_whose_membership_cannot_be_established_is_skipped),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");
    let _failed =
        super::fault::force_next_for_thread(super::fault::Step::Membership, ERROR_ACCESS_DENIED.0, member.pid());
    let forced = super::fault::force_job_pid_list(Vec::new());

    let verdict = super::wait_drained_raw(&job, None);

    drop(forced);
    assert_eq!(
        verdict.expect("a pid whose membership is unknown is skipped, not an error"),
        crate::containment::TreeDrain::AllMembersExited
    );
}

/// A pid the job's own list names whose membership cannot be established is a member whose exit cannot
/// be observed, and stays an error: it is returned with its pid, for the kill's wait to report.
///
/// Mutant: the listing skips it as the snapshot does.
#[skuld::test]
fn a_listed_pid_whose_membership_cannot_be_established_is_unobserved_with_its_pid() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    let (child, job) = spawn_job_member();
    let pid = child.id();
    let failed = super::fault::force_next_for_thread(super::fault::Step::Membership, ERROR_ACCESS_DENIED.0, pid);

    let (members, unobserved) = job.list_members(None);

    drop(failed);
    job.hard_kill().expect("end the member");
    let_member_exit(child);
    assert!(members.iter().all(|id| id.pid() != pid), "{members:?}");
    assert_eq!(
        unobserved.iter().filter(|unnamed| unnamed.pid == Some(pid)).count(),
        1,
        "{unobserved:?}"
    );
}

/// A snapshot member whose start time cannot be read (a forced failure) is an error naming its pid:
/// it is a member, and its exit cannot be observed.
///
/// Mutant: the member is skipped.
#[skuld::test]
fn a_snapshot_member_whose_identity_cannot_be_read_is_an_error() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_snapshot_member_whose_identity_cannot_be_read_is_an_error),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let pid = member.pid();
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");
    let _failed = super::fault::force_next_for_thread(super::fault::Step::Identity, ERROR_ACCESS_DENIED.0, pid);
    let forced = super::fault::force_job_pid_list(Vec::new());

    let verdict = super::wait_drained_raw(&job, None);

    drop(forced);
    let error = verdict.expect_err("a member whose identity cannot be read is not a drain");
    assert!(
        matches!(&error, crate::error::Error::Unassessable { detail, source: Some(_) }
            if detail.contains(&pid.to_string())),
        "{error:?}"
    );
}

/// A member the listing could not name by identity is reported once by a kill's wait: the edge's
/// confirmation finds the same member in the snapshot, its identity unreadable there too (a forced
/// failure), and does not report it again.
///
/// Mutant: the edge is waited for with no memory of the pids the listing could not name, so the
/// confirmation names the same pid a second time.
#[skuld::test]
fn a_kill_wait_reports_a_member_whose_identity_cannot_be_read_once() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    use crate::containment::dispatch::TreeKillOutcome;
    use crate::containment::drain_edge::DrainEdge;
    use crate::containment::tree_kill::Unnamed;
    use crate::containment::TreeKill;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_kill_wait_reports_a_member_whose_identity_cannot_be_read_once),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let pid = member.pid();
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");
    let unnamed = Unnamed::member(
        pid,
        crate::error::Error::Unassessable {
            detail: "its start time could not be read".to_owned(),
            source: None,
        },
    );
    let _failed = super::fault::force_next_for_thread(super::fault::Step::Identity, ERROR_ACCESS_DENIED.0, pid);
    let forced = super::fault::force_job_pid_list(Vec::new());
    let (_, wait) = TreeKill::listed(
        TreeKillOutcome::Ran(Ok(())),
        Vec::new(),
        vec![unnamed],
        DrainEdge::Job(&job),
    )
    .split();

    let verdict = wait.wait();

    drop(forced);
    let error = verdict.expect_err("a member whose exit cannot be observed is not a drain");
    let report = crate::error::Report(&error).to_string();
    assert_eq!(
        report.matches(&format!("pid {pid}")).count(),
        1,
        "the member is named once: {report}"
    );
}

/// A snapshot member whose start time cannot be read is the drain's error whatever the deadline: one
/// still-running member the confirmation would wait for at a deadline does not hide it. A member that
/// runs (A) is in the job beside one that cannot be identified (B, a forced failure); the wait is
/// bounded by an elapsed deadline, so a walk that waits for A first answers `MembersRemain`.
///
/// Mutant: the walk reports B's error only once it reaches it, after waiting for A.
#[skuld::test]
fn a_member_whose_identity_cannot_be_read_is_reported_though_another_still_runs_at_the_deadline() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(
            a_member_whose_identity_cannot_be_read_is_reported_though_another_still_runs_at_the_deadline
        ),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use std::os::windows::io::AsRawHandle as _;

    let job = super::JobHandle::create_empty_for_test();
    // A is spawned first, so the snapshot most likely names it first (the order the mutant needs); B
    // is assigned first, as the OS lets a process of the fixture's own job into a new job only first.
    let running = crate::test_child::spawn_more_blocker();
    let unreadable = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let pid = unreadable.pid();
    job.assign_for_test(unreadable.handle().0)
        .expect("assign the unreadable member to the job");
    job.assign_for_test(running.as_raw_handle())
        .expect("assign the running member to the job");
    let _failed = super::fault::force_next_for_thread(super::fault::Step::Identity, ERROR_ACCESS_DENIED.0, pid);
    let forced = super::fault::force_job_pid_list(Vec::new());
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero);

    drop(forced);
    job.hard_kill().expect("end the members");
    let_member_exit(running);
    let error = verdict.expect_err("a member whose identity cannot be read is not a drain, nor remaining");
    assert!(
        matches!(&error, crate::error::Error::Unassessable { detail, .. } if detail.contains(&pid.to_string())),
        "{error:?}"
    );
}

/// A member the kill's wait already reported by its identity (it refuses the wait's open) is reported
/// once, though the confirmation finds it in the snapshot with its start time unreadable (a forced
/// failure): the entry with no identity matches the member by its pid.
///
/// Mutant: `Settled::covers` matches an entry with no identity only against the pids the listing could
/// not name, so the member is named a second time.
#[skuld::test]
fn a_kill_wait_reports_a_member_it_waited_for_once_when_the_snapshot_cannot_read_its_identity() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    use crate::containment::dispatch::TreeKillOutcome;
    use crate::containment::drain_edge::DrainEdge;
    use crate::containment::TreeKill;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(
            a_kill_wait_reports_a_member_it_waited_for_once_when_the_snapshot_cannot_read_its_identity
        ),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let pid = member.pid();
    let id = crate::identity::windows_identity_from_handle_result(member.handle(), pid)
        .expect("the restricted member's identity");
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");
    let _failed = super::fault::force_next_for_thread(super::fault::Step::Identity, ERROR_ACCESS_DENIED.0, pid);
    let forced = super::fault::force_job_pid_list(Vec::new());
    let (_, wait) = TreeKill::listed(TreeKillOutcome::Ran(Ok(())), vec![id], Vec::new(), DrainEdge::Job(&job)).split();

    let verdict = wait.wait();

    drop(forced);
    let error = verdict.expect_err("a member whose exit cannot be observed is not a drain");
    let report = crate::error::Report(&error).to_string();
    assert_eq!(
        report.matches(&format!("pid {pid}")).count(),
        1,
        "the member is named once: {report}"
    );
}

/// A member the caller may open for its membership but not wait on (an elevated member under a
/// non-elevated caller) is a member whose exit cannot be observed: the drain says so, naming it,
/// with the OS error as the cause, and never answers `AllMembersExited` while it runs. The member's
/// DACL grants `PROCESS_QUERY_LIMITED_INFORMATION` and nothing else.
///
/// Mutant: membership is decided with the access the wait needs, so a member the wait is refused
/// for is not one.
#[skuld::test]
fn wait_drained_raw_names_a_member_it_may_not_wait_on_when_the_listing_is_empty() {
    use std::error::Error as _;
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(
            wait_drained_raw_names_a_member_it_may_not_wait_on_when_the_listing_is_empty
        ),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    // Without a console, so the job's only member is the restricted one: a console host the member
    // brought along would be another member, running, and which the drain reaches first would
    // decide the answer.
    let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");
    let forced = super::fault::force_job_pid_list(Vec::new());

    let verdict = super::wait_drained_raw(&job, None);

    drop(forced);
    let error = verdict.expect_err("a member whose exit cannot be observed is not a drain");
    assert!(
        matches!(&error, crate::error::Error::Unassessable { detail, source: Some(_) }
            if detail.contains(&member.pid().to_string())),
        "{error:?}"
    );
    assert_eq!(
        crate::error::first_os_code(error.source().expect("the OS error is the cause")),
        Some(ERROR_ACCESS_DENIED.0 as i32),
        "{error:?}"
    );
}

/// [`wait_drained_raw_names_a_member_it_may_not_wait_on_when_the_listing_is_empty`] for a member the
/// job still LISTS: the round's open for its wait is refused, and the answer names its pid with the OS
/// error as the cause, as the confirmation's does.
///
/// Mutant: the round that is refused the only listed member drops its pid from the error.
#[skuld::test]
fn wait_drained_raw_names_a_member_it_may_not_wait_on_while_the_job_lists_it() {
    use std::error::Error as _;
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(wait_drained_raw_names_a_member_it_may_not_wait_on_while_the_job_lists_it),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");

    let verdict = super::wait_drained_raw(&job, None);

    let error = verdict.expect_err("a member whose exit cannot be observed is not a drain");
    assert!(
        matches!(&error, crate::error::Error::Unassessable { detail, source: Some(_) }
            if detail.contains(&member.pid().to_string())),
        "{error:?}"
    );
    assert_eq!(
        crate::error::first_os_code(error.source().expect("the OS error is the cause")),
        Some(ERROR_ACCESS_DENIED.0 as i32),
        "{error:?}"
    );
}

/// A kill's wait names a member it may not wait on once: the edge's confirmation of the empty listing
/// does not report a member the wait for the members already did.
///
/// Mutant: the edge is waited for with no memory of the members the kill's wait settled, so the
/// confirmation names the same pid a second time.
#[skuld::test]
fn a_kill_wait_names_a_member_it_may_not_wait_on_once() {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    use crate::containment::dispatch::TreeKillOutcome;
    use crate::containment::drain_edge::DrainEdge;
    use crate::containment::TreeKill;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_kill_wait_names_a_member_it_may_not_wait_on_once),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let member = crate::identity::windows_fixture::spawn_query_only_without_console(&done);
    let id = crate::identity::windows_identity_from_handle_result(member.handle(), member.pid())
        .expect("the restricted member's identity");
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");
    let forced = super::fault::force_job_pid_list(Vec::new());
    let (_, wait) = TreeKill::listed(TreeKillOutcome::Ran(Ok(())), vec![id], Vec::new(), DrainEdge::Job(&job)).split();

    let verdict = wait.wait();

    drop(forced);
    let error = verdict.expect_err("a member whose exit cannot be observed is not a drain");
    let report = crate::error::Report(&error).to_string();
    assert_eq!(
        report.matches(&format!("pid {}", member.pid())).count(),
        1,
        "the member is named once: {report}"
    );
    assert!(
        report.contains("was killed, but its exit cannot be observed"),
        "the kill's wait names it: {report}"
    );
    assert_eq!(
        crate::error::first_os_code(&error),
        Some(ERROR_ACCESS_DENIED.0 as i32),
        "{report}"
    );
}

/// A root whose wait failed (it refuses the wait's open) is reported once, though it is still in the
/// job's snapshot: the edge's confirmation does not name it again.
///
/// Mutant: a failed root wait leaves the root's identity out of what the kill's wait settled.
#[skuld::test]
fn a_kill_wait_reports_a_root_whose_wait_failed_once() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_kill_wait_reports_a_root_whose_wait_failed_once),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    assert_the_failed_root_is_the_one_error(&done, false);
}

/// [`a_kill_wait_reports_a_root_whose_wait_failed_once`] for a root whose start time the snapshot cannot
/// read (a forced failure): it is settled by its pid.
///
/// Mutant: a failed root wait leaves the root's pid out of what the kill's wait reported.
#[skuld::test]
fn a_kill_wait_reports_a_root_whose_wait_failed_once_when_the_snapshot_cannot_read_its_identity() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(
            a_kill_wait_reports_a_root_whose_wait_failed_once_when_the_snapshot_cannot_read_its_identity
        ),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    assert_the_failed_root_is_the_one_error(&done, true);
}

fn assert_the_failed_root_is_the_one_error(done: &crate::test_own_process::Completion, unreadable: bool) {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    use crate::containment::dispatch::TreeKillOutcome;
    use crate::containment::drain_edge::DrainEdge;
    use crate::containment::TreeKill;
    use crate::error::Error;

    let member = crate::identity::windows_fixture::spawn_query_only_without_console(done);
    let id = crate::identity::windows_identity_from_handle_result(member.handle(), member.pid())
        .expect("the restricted member's identity");
    let root = crate::os_process::windows::WindowsProcess::open(id)
        .expect("open the restricted member")
        .expect("a live process opens with QUERY alone");
    let job = super::JobHandle::create_empty_for_test();
    job.assign_for_test(member.handle().0)
        .expect("assign the restricted member to the job");
    let _failed = unreadable.then(|| {
        super::fault::force_next_for_thread(super::fault::Step::Identity, ERROR_ACCESS_DENIED.0, member.pid())
    });
    let forced = super::fault::force_job_pid_list(Vec::new());
    let (_, wait) = TreeKill::listed(
        TreeKillOutcome::Ran(Ok(())),
        Vec::new(),
        Vec::new(),
        DrainEdge::Job(&job),
    )
    .split();

    let verdict = wait.with_root(&root, member.pid(), true).wait();

    drop(forced);
    let error = verdict.expect_err("a root whose exit cannot be observed is not a drain");
    assert!(
        matches!(&error, Error::Unassessable { detail, source: Some(source) }
            if detail.starts_with("the root was killed") && !matches!(&**source, Error::Several(_))),
        "the root is the one error: {error:?}"
    );
}

/// An empty listing is the drain only once the members the snapshot names are signalled: the list
/// drops a member before its process object signals. The second member is alive, in the job, when
/// the second listing (forced) comes back empty; the wait must block on it, and the hook ends it
/// when the wait arms, so the drain is answered only after its exit.
///
/// Mutant: an empty listing answers `AllMembersExited` without waiting for the snapshot's members.
#[skuld::test]
fn wait_drained_raw_waits_for_the_members_the_snapshot_names_when_the_listing_empties() {
    use std::cell::Cell;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    let (mut first, mut second, job) = spawn_job_with_two_members();
    let stdin = second.stdin.take().expect("piped stdin");
    first.kill().expect("end the first member");
    first.wait().expect("reap the first member");
    let forced = super::fault::force_job_pid_lists([vec![first.id(), second.id()], Vec::new()]);
    crate::wait::wait_ms_probe::take();
    let released = Rc::new(Cell::new(false));
    crate::wait::wait_ms_probe::on_second_arm({
        let released = released.clone();
        move || {
            released.set(true);
            drop(stdin); // EOF: the second member exits
        }
    });

    let deadline = Instant::now() + Duration::from_secs(3600);
    let verdict = super::wait_drained_raw(&job, Some(deadline));

    crate::wait::wait_ms_probe::take();
    drop(forced);
    let ended = released.get();
    // The member ends either way: on a failure the hook never ran.
    let_member_exit(second);
    assert!(
        ended,
        "the drain was answered by the empty listing while a member's process object was unsignalled"
    );
    assert_eq!(
        verdict.expect("wait_drained_raw"),
        crate::containment::TreeDrain::AllMembersExited
    );
}

/// A member that left the listing in an earlier round is still waited for when a later listing is
/// empty. Lists: both members, then the signalled first one alone (the second left the list while
/// unsignalled), then none. The second member stays alive, so the bounded wait ends in
/// `MembersRemain` at its deadline rather than answering the drain off the empty listing.
///
/// Mutant: an empty listing is answered off the earlier rounds' handles, not the snapshot.
#[skuld::test]
fn wait_drained_raw_keeps_waiting_for_a_member_that_left_the_listing_in_an_earlier_round() {
    use std::time::Duration;

    let (mut first, second, job) = spawn_job_with_two_members();
    first.kill().expect("end the first member");
    first.wait().expect("reap the first member");
    let forced = super::fault::force_job_pid_lists([vec![first.id(), second.id()], vec![first.id()], Vec::new()]);
    let deadline = crate::wait::deadline_from(Duration::from_millis(50));

    let verdict = super::wait_drained_raw(&job, deadline);

    drop(forced);
    let_member_exit(second);
    assert_eq!(
        verdict.expect("wait_drained_raw"),
        crate::containment::TreeDrain::MembersRemain,
        "the drain was answered while a member's process object was unsignalled"
    );
}

/// A round past the deadline whose final listing is empty polls the members the snapshot names, and
/// answers `MembersRemain` for one that is still running.
///
/// Mutant: the final empty listing answers `AllMembersExited` without looking at the snapshot.
#[skuld::test]
fn wait_drained_raw_with_an_elapsed_deadline_polls_the_members_its_empty_final_listing_leaves() {
    let (mut first, second, job) = spawn_job_with_two_members();
    first.kill().expect("end the first member");
    first.wait().expect("reap the first member");
    let forced = super::fault::force_job_pid_lists([vec![first.id(), second.id()], Vec::new()]);
    let zero = crate::wait::deadline_from(std::time::Duration::ZERO);

    let verdict = super::wait_drained_raw(&job, zero);

    assert_eq!(super::fault::job_pid_list_queries(), 2, "the listing, and one more");
    drop(forced);
    let_member_exit(second);
    assert_eq!(
        verdict.expect("wait_drained_raw"),
        crate::containment::TreeDrain::MembersRemain,
        "the drain was answered while a member's process object was unsignalled"
    );
}

/// A real, still-running job member reports `MembersRemain` at an already-elapsed deadline —
/// not a race: the child is blocked reading its own piped stdin, which this test still holds
/// open at the point of the check, so the member's liveness there is a fact this test itself
/// holds, not a guess about timing. Also exercises `query_job_pid_list`'s non-empty branch (the
/// pid must be visible in the job before `wait_drained_raw` can find it to wait on at all), and
/// — once the child is let go and reaped — the live re-enumeration that turns a real exit into
/// `AllMembersExited`, synchronized on `Child::wait()` rather than on any elapsed time.
#[skuld::test]
fn wait_drained_raw_tracks_a_real_member_through_exit() {
    use std::os::windows::io::AsRawHandle;

    // `cmd /C more`: a binary present on every Windows host, which blocks reading its stdin
    // until EOF, then exits. No new external dependency — this is the OS shell.
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "more"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn cmd /C more");
    let raw = child.as_raw_handle();

    let job = super::assign_to_kill_on_close_job(raw).expect("assign to job");

    let pids = super::query_job_pid_list(job.raw).expect("query pid list");
    assert_eq!(
        pids,
        vec![child.id()],
        "the job must report exactly the member just assigned"
    );

    // An already-elapsed deadline: `crate::wait::remaining` reads it as Duration::ZERO without
    // blocking at all, so this assertion is instantaneous — the point under test is that a
    // non-empty live member set reports MembersRemain rather than a guessed drain verdict.
    let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let verdict = super::wait_drained_raw(&job, Some(past)).expect("wait_drained_raw");
    assert_eq!(verdict, crate::containment::TreeDrain::MembersRemain);

    // Let the child exit on its own terms (EOF on stdin), then confirm the job reports drained
    // once it genuinely has. `Child::wait()` only returns once the OS reports the process gone
    // — a real synchronization point, not a timing guess.
    drop(child.stdin.take());
    child.wait().expect("wait for cmd /C more to exit");

    let verdict = super::wait_drained_raw(&job, None).expect("wait_drained_raw");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
}

// Deadline contract for `wait_drained_raw`: never report `MembersRemain` before the real
// deadline. Seams are documented in `crate::wait`.

/// A never-draining job armed with a sub-millisecond remainder rounds up to 1ms, reports
/// `MembersRemain` only at the deadline, and derives its argument from the site's own deadline.
///
/// Mutant: truncate in `win32_timeout_ms` -> `ms` is 0. Mutant: add slack -> `ms` is above 1.
/// Mutant: ignore the site's deadline -> `requested` is not 5ms.
#[skuld::test]
fn wait_drained_raw_arms_the_ceiling_of_the_remaining_duration() {
    use std::time::{Duration, Instant};
    let (child, job) = spawn_job_member();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    let deadline = at + Duration::from_millis(5);
    let verdict = super::wait_drained_raw(&job, Some(deadline));
    let reached = Instant::now() >= deadline;
    let arms = crate::wait::wait_ms_probe::take();
    let_member_exit(child);
    assert_eq!(
        verdict.expect("a live never-exiting member must not report a wait failure"),
        crate::containment::TreeDrain::MembersRemain
    );
    assert!(reached, "the call returned before the real deadline");
    let first = arms.first().expect("at least one armed wait");
    assert_eq!(first.remaining, Duration::from_micros(500));
    assert_eq!(first.ms, 1);
    assert_eq!(
        first.requested,
        Duration::from_millis(5),
        "the site must pass the time left to its own deadline (clock frozen at the deadline's origin)"
    );
}

/// An early, unclamped `WAIT_TIMEOUT` hours before the deadline is not trusted: the site
/// re-arms and reports the real drain.
///
/// Mutant: return `MembersRemain` on the first `WAIT_TIMEOUT` -> one arm, wrong verdict.
#[skuld::test]
fn wait_drained_raw_never_reports_members_remain_before_the_deadline() {
    use std::time::{Duration, Instant};
    let (mut child, job) = spawn_job_member();
    let stdin = child.stdin.take().expect("piped stdin");
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    crate::wait::wait_ms_probe::on_second_arm(move || drop(stdin)); // EOF -> member exits for real
    let deadline = Instant::now() + Duration::from_secs(3600);
    let verdict = super::wait_drained_raw(&job, Some(deadline));
    let arms = crate::wait::wait_ms_probe::take();
    child.wait().expect("reap the member after it exits");
    assert_eq!(
        verdict.expect("a genuinely-drained job must not report a wait failure"),
        crate::containment::TreeDrain::AllMembersExited
    );
    assert!(arms.len() >= 2, "expected a re-arm, got {} arm(s)", arms.len());
}

/// A wait clamped below the deadline re-arms, recomputing `remaining` each round.
///
/// Mutant: return `MembersRemain` on the first `WAIT_TIMEOUT` -> one arm, wrong verdict.
/// Mutant: hoist `remaining` above the loop -> `remaining` does not shrink.
#[skuld::test]
fn wait_drained_raw_re_arms_past_a_clamped_timeout() {
    use std::time::{Duration, Instant};
    let (mut child, job) = spawn_job_member();
    let stdin = child.stdin.take().expect("piped stdin");
    crate::wait::wait_ms_probe::take();
    let _clamp = crate::wait::wait_clamp_seam::set(5);
    crate::wait::wait_ms_probe::on_second_arm(move || drop(stdin));
    let deadline = Instant::now() + Duration::from_secs(3600);
    let verdict = super::wait_drained_raw(&job, Some(deadline));
    let arms = crate::wait::wait_ms_probe::take();
    child.wait().expect("reap the member after it exits");
    assert_eq!(
        verdict.expect("a genuinely-drained job must not report a wait failure"),
        crate::containment::TreeDrain::AllMembersExited
    );
    crate::wait::wait_ms_probe::assert_rearmed_with_fresh_remaining(&arms, 5);
}

/// Live coverage of the `Ok(true)` arm against a real console. `Ok(false)` needs the DETACHED
/// helper in the integration suite (a different process); `Err` is not provokable live, hence
/// the fault seam exercised below. This test does NOT guard the integration test against
/// vacuity — that binary carries its own `console=0` / `console=1` assertions, measured inside
/// the helper itself.
#[skuld::test]
fn caller_has_console_is_true_under_cargo_test() {
    assert!(
        matches!(super::caller_has_console(), Ok(true)),
        "the test runner is expected to run with a console attached"
    );
}

/// The `Err` arm's production, via the fault seam — a live `GetConsoleProcessList` cannot be
/// made to fail. This exercises the fault-injection scaffolding, not a real API failure; the
/// consumption side is covered by `invalid_handle_with_a_failed_probe_stays_io`.
#[skuld::test]
fn console_probe_error_surfaces() {
    super::fault::set_force_console_probe_error(true);
    assert!(super::caller_has_console().is_err());
    assert!(!super::fault::armed(), "the seam must be consumed by one call");
    // The very next call is a real probe again.
    assert!(matches!(super::caller_has_console(), Ok(true)));
}

/// `ERROR_INVALID_HANDLE`, the bare Win32 code every `io::Error` cosca returns carries.
const ERROR_INVALID_HANDLE: i32 = 6;
/// `ERROR_ACCESS_DENIED` — a different failure, which must NOT be classified as a missing console.
const ERROR_ACCESS_DENIED: i32 = 5;

fn io_err(code: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(code)
}

#[skuld::test]
fn invalid_handle_with_no_console_is_typed_no_console() {
    let e = super::classify_ctrl_event_failure(4242, io_err(ERROR_INVALID_HANDLE), Ok(false));
    let crate::error::Error::NoConsole { detail } = e else {
        panic!("expected NoConsole, got {e:?}");
    };
    assert!(detail.contains("4242"), "the detail must name the group: {detail}");
    assert!(
        detail.contains("kill_tree()"),
        "the detail must name the way out: {detail}"
    );
}

#[skuld::test]
fn invalid_handle_with_a_console_attached_stays_io() {
    // The probe contradicts the code: never claim a cause we just measured to be false.
    let e = super::classify_ctrl_event_failure(1, io_err(ERROR_INVALID_HANDLE), Ok(true));
    assert!(matches!(e, crate::error::Error::Io(_)), "got {e:?}");
}

/// The error `GenerateConsoleCtrlEvent` returns when the caller has no console: what the `windows`
/// crate builds from the thread's last error.
fn no_console_failure() -> windows::core::Error {
    // SAFETY: setting the calling thread's last error has no preconditions.
    unsafe {
        windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::ERROR_INVALID_HANDLE);
    }
    windows::core::Error::from_thread()
}

/// `terminate` classifies the OS's own failure: `ERROR_INVALID_HANDLE` from the call, with the
/// probe confirming no console, is `NoConsole`. This is the check that the converted error matches
/// the classifier's code.
///
/// Mutant: `terminate_with` converts with `.into()`, so the code is `0x80070006`, the classifier
/// does not recognise it, and the result is `Io`.
#[skuld::test]
fn terminate_classifies_a_real_no_console_failure() {
    let e = super::terminate_with(4242, || Err(no_console_failure()), || Ok(false)).expect_err("the send failed");
    assert!(matches!(e, crate::error::Error::NoConsole { .. }), "got {e:?}");
}

#[skuld::test]
fn invalid_handle_with_a_failed_probe_stays_io() {
    let probe = Err(std::io::Error::from_raw_os_error(87)); // ERROR_INVALID_PARAMETER
    let e = super::classify_ctrl_event_failure(1, io_err(ERROR_INVALID_HANDLE), probe);
    assert!(matches!(e, crate::error::Error::Io(_)), "got {e:?}");
}

#[skuld::test]
fn a_different_failure_code_stays_io_whatever_the_probe_says() {
    for console in [Ok(true), Ok(false)] {
        let e = super::classify_ctrl_event_failure(1, io_err(ERROR_ACCESS_DENIED), console);
        assert!(matches!(e, crate::error::Error::Io(_)), "got {e:?}");
    }
    let e = super::classify_ctrl_event_failure(1, io_err(ERROR_ACCESS_DENIED), Err(io_err(87)));
    assert!(matches!(e, crate::error::Error::Io(_)), "got {e:?}");
}

// The mechanism the creation-flag word settles, one test per row. Nine inputs, three distinct
// outcomes: no constant implementation passes, and the last three rows pin that
// `OtherConsoleGroup` is a statement about a route to a group that EXISTS, not a synonym for
// "detached" — with no group flag there is nothing to address, whatever the console situation.
mod mechanism_from_flags_tests {
    use crate::containment::windows::{group_flags, mechanism_from_flags, root_flags};
    use crate::graceful::GracefulMechanism;
    use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CREATE_NO_WINDOW, DETACHED_PROCESS};

    #[skuld::test]
    fn mechanism_from_flags_reports_none_for_no_flags() {
        assert_eq!(mechanism_from_flags(0), GracefulMechanism::None);
    }

    #[skuld::test]
    fn mechanism_from_flags_reports_console_group_for_group_flags() {
        assert_eq!(mechanism_from_flags(group_flags()), GracefulMechanism::ConsoleGroup);
    }

    #[skuld::test]
    fn mechanism_from_flags_reports_console_group_for_root_flags() {
        assert_eq!(mechanism_from_flags(root_flags()), GracefulMechanism::ConsoleGroup);
    }

    #[skuld::test]
    fn mechanism_from_flags_reports_other_console_group_for_group_plus_detached() {
        assert_eq!(
            mechanism_from_flags(group_flags() | DETACHED_PROCESS.0),
            GracefulMechanism::OtherConsoleGroup
        );
    }

    #[skuld::test]
    fn mechanism_from_flags_reports_other_console_group_for_group_plus_new_console() {
        assert_eq!(
            mechanism_from_flags(group_flags() | CREATE_NEW_CONSOLE.0),
            GracefulMechanism::OtherConsoleGroup
        );
    }

    #[skuld::test]
    fn mechanism_from_flags_reports_other_console_group_for_group_plus_no_window() {
        assert_eq!(
            mechanism_from_flags(group_flags() | CREATE_NO_WINDOW.0),
            GracefulMechanism::OtherConsoleGroup
        );
    }

    #[skuld::test]
    fn mechanism_from_flags_reports_none_for_detached_without_a_group() {
        assert_eq!(mechanism_from_flags(DETACHED_PROCESS.0), GracefulMechanism::None);
    }

    #[skuld::test]
    fn mechanism_from_flags_reports_none_for_a_new_console_without_a_group() {
        assert_eq!(mechanism_from_flags(CREATE_NEW_CONSOLE.0), GracefulMechanism::None);
    }

    #[skuld::test]
    fn mechanism_from_flags_reports_none_for_no_window_without_a_group() {
        assert_eq!(mechanism_from_flags(CREATE_NO_WINDOW.0), GracefulMechanism::None);
    }
}

// ===== job breakaway probe =====

/// The `Unknown` arm exists so cosca never asserts a cause it could not measure. Neither Win32
/// call in the probe can be made to fail on a live system, so the seam is the only route to that
/// arm's production — and without the seam the probe reports a real verdict, which is what makes
/// this assertion about the arm rather than about the constant.
#[skuld::test]
fn probe_reports_unknown_when_the_query_fails() {
    use crate::containment::windows::{fault, probe_job_breakaway, JobBreakaway};
    assert_ne!(
        probe_job_breakaway(),
        JobBreakaway::Unknown,
        "unarmed, the probe must reach a real verdict"
    );
    fault::set_force_job_probe_error(true);
    assert_eq!(probe_job_breakaway(), JobBreakaway::Unknown);
    assert_ne!(
        probe_job_breakaway(),
        JobBreakaway::Unknown,
        "take semantics: the fault applies to exactly one call"
    );
}

/// The env var that tells [`fixture_reports_job_breakaway_probe`] it was re-exec'd deliberately
/// by [`probe_agrees_with_an_independent_is_process_in_job_measurement`], rather than picked up
/// by an ordinary, unfiltered suite run.
const JOB_BREAKAWAY_PROBE_FIXTURE_MARKER: &str = "COSCA_FIXTURE_JOB_BREAKAWAY_PROBE";

/// A RELATIONSHIP, never an absolute: whether CI runs test processes inside a job object is not
/// ours to control. It fails if the probe's first branch is inverted, which is the bug that would
/// make every ambient job read as "no job" and silently disable the typed containment error.
///
/// The measurement itself runs in [`fixture_reports_job_breakaway_probe`], a freshly spawned
/// re-exec of this binary — never in this (top-level) test process. Under nextest, this process
/// is spawned and only ASSIGNED to its job object afterward: nextest's own job-assignment call
/// trails the spawn rather than preceding or blocking on it. Two reads taken directly in this
/// process, moments apart, could straddle that assignment and disagree with each other even
/// though no real job is actually racing. A freshly spawned child inherits its parent's job
/// membership atomically at `CreateProcess`, and nothing assigns it to a job afterward, so both
/// reads taken INSIDE it always agree with each other, whichever way the ambient membership
/// happens to fall.
#[skuld::test]
fn probe_agrees_with_an_independent_is_process_in_job_measurement() {
    let exe = std::env::current_exe().expect("current_exe");
    let fixture = crate::test_child::fixture_path!(fixture_reports_job_breakaway_probe);
    let child = crate::test_spawn::spawn(
        crate::test_reexec::with_json_events(
            crate::test_reexec::command(&exe).args(crate::test_reexec::fixture_args(fixture)),
        )
        .env(JOB_BREAKAWAY_PROBE_FIXTURE_MARKER, "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped()),
    )
    .expect("spawn the job-breakaway probe fixture");
    let output = child.wait_with_output().expect("wait for the fixture child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if let Err(why) = crate::test_reexec::suite_passed_exactly_one(&output) {
        panic!(
            "job-breakaway probe fixture did not run and pass exactly one test: {why}\n--- stdout ---\n{stdout}\n\
             --- stderr ---\n{stderr}"
        );
    }
}

/// The child half of [`probe_agrees_with_an_independent_is_process_in_job_measurement`]: a no-op
/// when picked up by an ordinary, unfiltered suite run ([`JOB_BREAKAWAY_PROBE_FIXTURE_MARKER`] is
/// unset there). Re-executed via `current_exe() --exact` with that var set, it performs the real
/// measurement — see the driver's own doc for why it must run here, in a freshly spawned process,
/// rather than in the driver itself.
#[skuld::test]
fn fixture_reports_job_breakaway_probe() {
    if std::env::var_os(JOB_BREAKAWAY_PROBE_FIXTURE_MARKER).is_none() {
        return; // picked up by an ordinary suite run — deliberately inert
    }
    use crate::containment::windows::{probe_job_breakaway, JobBreakaway};
    use windows::Win32::System::JobObjects::IsProcessInJob;
    use windows::Win32::System::Threading::GetCurrentProcess;

    let mut in_job = windows::core::BOOL(0);
    // SAFETY: standard Win32; `in_job` is a valid out-param and `None` asks "in ANY job".
    unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut in_job) }.expect("IsProcessInJob");

    let verdict = probe_job_breakaway();
    if in_job.as_bool() {
        assert_ne!(
            verdict,
            JobBreakaway::NotInJob,
            "this process IS in a job, so the probe must not report otherwise"
        );
    } else {
        assert_eq!(
            verdict,
            JobBreakaway::NotInJob,
            "this process is in no job, so the probe must say so"
        );
    }
}

// ===== initial-thread resume ownership =====

/// A suspended process this test made itself, holding its main thread. It sits in a
/// kill-on-close job, so the OS kills it however the test process exits; `Drop` kills it sooner.
struct SuspendedHelper {
    process: windows::Win32::Foundation::HANDLE,
    thread: windows::Win32::Foundation::HANDLE,
    tid: u32,
    pid: u32,
    _job: super::JobHandle,
}

impl SuspendedHelper {
    fn new() -> Self {
        use windows::core::PWSTR;
        use windows::Win32::System::Threading::{
            CreateProcessW, CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
        };
        let mut cmdline: Vec<u16> = "cmd /C more".encode_utf16().chain(std::iter::once(0)).collect();
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `cmdline` is a NUL-terminated writable UTF-16 buffer that outlives the call.
        unsafe {
            CreateProcessW(
                None,
                Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                None,
                None,
                &si,
                &mut pi,
            )
        }
        .expect("CreateProcessW for the suspended helper");
        let job = super::assign_to_kill_on_close_job(pi.hProcess.0).expect("assign the helper to a job");
        Self {
            process: pi.hProcess,
            thread: pi.hThread,
            tid: pi.dwThreadId,
            pid: pi.dwProcessId,
            _job: job,
        }
    }
}

impl Drop for SuspendedHelper {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::TerminateProcess;
        // SAFETY: both handles are live and owned by this helper.
        unsafe {
            _ = TerminateProcess(self.process, 1);
            _ = CloseHandle(self.thread);
            _ = CloseHandle(self.process);
        }
    }
}

/// Spawn a contained blocker. Whatever is injected or forced on this thread applies to it.
fn spawn_contained_blocker() -> Result<crate::Child, crate::error::Error> {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    cmd.contain();
    cmd.spawn()
}

/// Spawn with an extra snapshot entry for `tid`, owned by `owner` (`None`: the child).
/// Returns the spawn result and what the walk did with the entry.
fn spawn_with_injected_tid(
    tid: u32,
    owner: Option<u32>,
) -> (
    Result<crate::Child, crate::error::Error>,
    Option<Option<crate::containment::windows::Visit>>,
) {
    let injected = crate::containment::windows::fault::inject_snapshot_tid(tid, owner);
    let spawned = spawn_contained_blocker();
    let visit = crate::containment::windows::fault::take_injected_visit();
    drop(injected);
    (spawned, visit)
}

fn finish_child(spawned: Result<crate::Child, crate::error::Error>) {
    let mut child = spawned.expect("a stale snapshot entry must not fail the spawn");
    assert_eq!(
        child.containment(),
        crate::Containment::JobObject,
        "the walk under test only runs for a Job Object spawn"
    );
    drop(child.stdin().expect("piped stdin"));
    child.wait().expect("wait for the contained child");
}

/// A thread id the snapshot lists under the child (owner = the child's pid) but that belongs to
/// another process (a reused id) must not be resumed, and must not fail the spawn. The helper's
/// main thread has suspend count 1; suspending it again returns the previous count, so 1 proves
/// nothing resumed it and 0 proves something did.
#[skuld::test]
fn windows_resume_initial_threads_never_resumes_a_foreign_thread() {
    use crate::containment::windows::Visit;
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    let helper = SuspendedHelper::new();
    let (spawned, visit) = spawn_with_injected_tid(helper.tid, None);
    assert!(
        spawned.is_ok(),
        "a snapshot entry for another process's thread must not fail the spawn: {:?}",
        spawned.as_ref().err()
    );
    assert_eq!(
        visit,
        Some(Some(Visit::Foreign { owner: helper.pid })),
        "the injected entry must be walked and identified as the helper's"
    );

    // SAFETY: `helper.thread` is a live thread handle with suspend rights.
    let previous = unsafe { SuspendThread(helper.thread) };
    assert_eq!(
        previous, 1,
        "the helper's thread is another process's: the spawn must not have resumed it"
    );
    // SAFETY: as above; restore the count this test added.
    unsafe { ResumeThread(helper.thread) };

    finish_child(spawned);
}

/// The owner filter drops a snapshot entry listed under another pid before any thread is opened.
#[skuld::test]
fn windows_resume_initial_threads_drops_an_entry_owned_by_another_pid() {
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    let helper = SuspendedHelper::new();
    let (spawned, visit) = spawn_with_injected_tid(helper.tid, Some(helper.pid));
    assert_eq!(visit, Some(None), "an entry owned by another pid must be filtered out");
    // SAFETY: `helper.thread` is a live thread handle with suspend rights.
    let previous = unsafe { SuspendThread(helper.thread) };
    assert_eq!(previous, 1, "a filtered entry must not be touched");
    // SAFETY: as above.
    unsafe { ResumeThread(helper.thread) };
    finish_child(spawned);
}

/// A listed thread that exited and whose id was not reused makes `OpenThread` fail with
/// `ERROR_INVALID_PARAMETER`, and must not fail the spawn. The kernel masks an id's low two bits
/// before the lookup, so id 1 resolves to CID 0, which is never allocated to any thread or
/// process: the lookup always fails, whatever ids are live or reused.
#[skuld::test]
fn windows_resume_initial_threads_skips_a_thread_id_that_no_longer_exists() {
    use crate::containment::windows::Visit;

    let (spawned, visit) = spawn_with_injected_tid(1, None);
    assert!(
        spawned.is_ok(),
        "a snapshot entry for a nonexistent thread must not fail the spawn: {:?}",
        spawned.as_ref().err()
    );
    assert_eq!(
        visit,
        Some(Some(Visit::Gone)),
        "the entry must be walked and found gone"
    );
    finish_child(spawned);
}

/// `ERROR_ACCESS_DENIED` on the query-only open marks the id as someone else's: the child's own
/// threads are openable by its creator. Forced onto the child's first thread, that leaves nothing
/// resumed, and the spawn fails with the stale-walk error rather than an open failure.
#[skuld::test]
fn windows_resume_initial_threads_treats_a_denied_query_open_as_stale() {
    use crate::containment::windows::fault::{force_next, Step};
    const ERROR_ACCESS_DENIED: u32 = 5;

    let _forced = force_next(Step::QueryOpen, ERROR_ACCESS_DENIED);
    let spawned = spawn_contained_blocker();
    assert!(spawned.is_err(), "no thread was resumed, so the spawn must fail");
    let text = format!("{:?}", spawned.err());
    assert!(
        text.contains("was stale") && text.contains("access denied"),
        "a denied query open must be reported as a stale skip: {text}"
    );
}

/// Spawn with `step` forced to fail on the child's first thread; the spawn must fail with an
/// error naming `call`, the thread and the pid.
fn assert_forced_failure_fails_the_spawn(step: crate::containment::windows::fault::Step, code: u32, call: &str) {
    let _forced = crate::containment::windows::fault::force_next(step, code);
    let spawned = spawn_contained_blocker();
    assert!(
        spawned.is_err(),
        "a failure on the child's own thread must fail the spawn"
    );
    let text = format!("{:?}", spawned.err());
    assert!(
        text.contains(&format!("{call} failed for thread")) && text.contains("of pid"),
        "the error must name the call, thread and pid ({call}): {text}"
    );
    assert!(!text.contains("was stale"), "a failure is not a stale skip: {text}");
}

#[skuld::test]
fn windows_resume_initial_threads_fails_the_spawn_when_the_query_open_fails() {
    use crate::containment::windows::fault::Step;
    const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
    assert_forced_failure_fails_the_spawn(Step::QueryOpen, ERROR_NOT_ENOUGH_MEMORY, "OpenThread(query)");
}

/// A denied suspend/resume open of a thread that IS the child's is a failure, not a skip.
#[skuld::test]
fn windows_resume_initial_threads_fails_the_spawn_when_the_resume_open_is_denied() {
    use crate::containment::windows::fault::Step;
    const ERROR_ACCESS_DENIED: u32 = 5;
    assert_forced_failure_fails_the_spawn(Step::ResumeOpen, ERROR_ACCESS_DENIED, "OpenThread(suspend/resume)");
}

#[skuld::test]
fn windows_resume_initial_threads_fails_the_spawn_when_the_owner_is_unreadable() {
    use crate::containment::windows::fault::Step;
    const ERROR_INVALID_HANDLE: u32 = 6;
    assert_forced_failure_fails_the_spawn(Step::Owner, ERROR_INVALID_HANDLE, "GetProcessIdOfThread");
}

#[skuld::test]
fn windows_resume_initial_threads_fails_the_spawn_when_resume_thread_fails() {
    use crate::containment::windows::fault::Step;
    const ERROR_INVALID_HANDLE: u32 = 6;
    assert_forced_failure_fails_the_spawn(Step::Resume, ERROR_INVALID_HANDLE, "ResumeThread");
}

/// The walk keeps the FIRST failure: it is the root cause, and later ones only follow from it.
#[skuld::test]
fn walk_verdict_returns_the_first_failure() {
    use super::{walk_verdict, Walk};
    let mut walk = Walk::default();
    walk.fail("ResumeThread", 1, 9, "first cause");
    walk.fail("ResumeThread", 2, 9, "second cause");
    let text = walk_verdict(9, walk).expect_err("a failure").to_string();
    assert!(text.contains("thread 1") && text.contains("first cause"), "{text}");
    assert!(
        !text.contains("second cause"),
        "the later failure replaced the first: {text}"
    );
}

/// A failed Win32 call on a thread reaches the caller with its plain Win32 code and the kind it
/// classifies to, and the message still names the call, the thread and the pid.
///
/// Mutant: `fail_win32` builds `io::Error::other(msg)`, so the code is lost and the kind is `Other`.
#[skuld::test]
fn fail_win32_keeps_the_win32_code_and_kind() {
    use super::{walk_verdict, Walk};
    use windows::core::{Error, HRESULT};
    let mut walk = Walk::default();
    let cause = Error::from_hresult(HRESULT::from_win32(ERROR_ACCESS_DENIED as u32));
    walk.fail_win32("ResumeThread", 1, 9, cause);
    let err = walk_verdict(9, walk).expect_err("a failure");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err:?}");
    assert_eq!(err.raw_os_error(), None, "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), Some(ERROR_ACCESS_DENIED), "{err:?}");
    assert_eq!(err.to_string(), "ResumeThread failed for thread 1 of pid 9");
}

/// A tie in creation times is cosca's finding, not a failed call: no OS code.
#[skuld::test]
fn fail_unidentified_has_no_os_code() {
    use super::{walk_verdict, Walk};
    let mut walk = Walk::default();
    walk.fail_unidentified(7, 12, 34);
    let err = walk_verdict(7, walk).expect_err("a failure");
    assert_eq!(err.raw_os_error(), None, "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), None, "{err:?}");
}

/// When every listed thread was stale the walk fails, and the error names the last skip.
#[skuld::test]
fn walk_verdict_with_only_skips_names_the_last_skip() {
    use super::{walk_verdict, Walk};
    let mut walk = Walk::default();
    walk.skip("thread 7 no longer exists".to_owned());
    let text = walk_verdict(4321, walk).expect_err("nothing was resumed").to_string();
    assert!(
        text.contains("4321") && text.contains("thread 7 no longer exists"),
        "{text}"
    );
    let text = walk_verdict(4321, Walk::default())
        .expect_err("nothing listed")
        .to_string();
    assert!(text.contains("listed no threads"), "{text}");
}

/// The tie error is one single-spaced sentence naming the pid and both threads.
#[skuld::test]
fn fail_unidentified_reports_the_whole_sentence() {
    use super::{walk_verdict, Walk};
    let mut walk = Walk::default();
    walk.fail_unidentified(7, 12, 34);
    let text = walk_verdict(7, walk).expect_err("a failure").to_string();
    assert_eq!(
        text,
        "the initial thread of pid 7 cannot be identified: threads 12 and 34 have the same creation time"
    );
}

/// Every thread the snapshot listed for the child reads back as gone: the identification finds no
/// initial thread, and the walk's error says the listed threads were stale, not that none were listed.
/// An odd id is never a thread id (they are multiples of 4), so each of these is gone.
#[skuld::test]
fn initial_thread_id_records_a_skip_for_each_stale_thread() {
    use super::{initial_thread_id, walk_verdict, Walk};
    let mut walk = Walk::default();
    let found = initial_thread_id(7, &[0xFFFF_FFFF, 0xFFFF_FFFD], &mut walk);
    assert_eq!(
        found, None,
        "no listed thread is readable, so none is the initial thread"
    );
    let text = walk_verdict(7, walk).expect_err("nothing was resumed").to_string();
    assert!(
        text.contains("every thread the snapshot listed for pid 7 was stale")
            && text.contains("thread 4294967293")
            && !text.contains("listed no threads"),
        "the error must say the listed threads were stale: {text}"
    );
}

#[skuld::test]
fn walk_verdict_accepts_a_walk_that_resumed_a_thread() {
    use super::{walk_verdict, Walk};
    let mut walk = Walk {
        resumed: 1,
        ..Walk::default()
    };
    walk.skip("thread 7 no longer exists".to_owned());
    walk_verdict(4321, walk).expect("a resumed thread with stale siblings is a success");
}

/// `GetProcessId` answers 0 for a handle that is not a process.
#[skuld::test]
fn process_pid_of_rejects_a_handle_that_names_no_process() {
    let result = super::process_pid_of(windows::Win32::Foundation::HANDLE::default());
    assert!(result.is_err(), "a null handle names no process: {result:?}");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("GetProcessId"),
        "error must name the call: {err}"
    );
}

/// `GetProcessId` failing reaches the caller with its Win32 code and the kind that code classifies
/// to, and the message names the call: a null handle is `ERROR_INVALID_HANDLE`.
///
/// Mutant: `process_pid_of` builds `io::Error::other(format!(..))`, losing the code and the kind.
#[skuld::test]
fn process_pid_of_failure_carries_the_win32_code() {
    let err = super::process_pid_of(windows::Win32::Foundation::HANDLE::default()).expect_err("a null handle");
    assert_eq!(err.raw_os_error(), None, "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), Some(ERROR_INVALID_HANDLE), "{err:?}");
    assert_eq!(
        err.kind(),
        std::io::Error::from_raw_os_error(ERROR_INVALID_HANDLE).kind(),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "GetProcessId failed on the child's handle");
}

/// A handle that names no process breaks the caller's contract. Debug builds assert it.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "live process handle")]
fn resume_initial_threads_asserts_its_handle_contract_in_debug() {
    _ = super::resume_initial_threads(std::ptr::null_mut(), super::SuspendCount::Any);
}

/// Release builds return the error instead. Runs in the release lane.
#[cfg(not(debug_assertions))]
#[skuld::test]
fn resume_initial_threads_reports_a_broken_handle_contract_in_release() {
    let err = super::resume_initial_threads(std::ptr::null_mut(), super::SuspendCount::Any)
        .expect_err("a null handle names no process");
    assert!(err.to_string().contains("GetProcessId"), "{err}");
}

// ===== frozen release =====

/// Kill and reap a std child these tests left suspended or running.
fn dispose(mut child: std::process::Child) {
    child.kill().expect("kill the test child");
    child.wait().expect("reap the test child");
}

/// `resume_initial_threads` brings a frozen child's initial thread from suspend count 1 to 0: it runs.
#[skuld::test]
fn resume_initial_threads_leaves_no_thread_suspended() {
    let mut child = crate::test_frozen::spawn_suspended_blocker();
    let thread = crate::test_frozen::InitialThread::of(child.id());
    assert_eq!(thread.suspend_count(), 1, "the child is created suspended");

    super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect("resume a frozen child");

    assert_eq!(thread.suspend_count(), 0, "the resumed child's initial thread must run");
    drop(child.stdin.take());
    child.wait().expect("the resumed blocker exits on stdin EOF");
}

/// Something suspended the initial thread a second time during the window (a debugger, an
/// EDR agent): one resume leaves it suspended, and `Ok` there would hand out a frozen process.
#[skuld::test]
fn resume_initial_threads_fails_when_the_initial_thread_was_suspended_twice() {
    let child = crate::test_frozen::spawn_suspended_blocker();
    let thread = crate::test_frozen::InitialThread::of(child.id());
    thread.suspend_once();

    let err = super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect_err("the thread is still suspended");

    let text = err.to_string();
    assert!(
        text.contains("previous suspend count was 2"),
        "the error must name the count it found: {text}"
    );
    assert_eq!(
        thread.suspend_count(),
        1,
        "the walk resumed once; the foreign suspend is still held, and the failure says so"
    );
    dispose(child);
}

/// Something already ran the child (its count was 0): "ran no instruction" no longer holds, so a
/// frozen child's resume must not report a clean success.
#[skuld::test]
fn resume_initial_threads_fails_when_the_initial_thread_was_already_running() {
    let child = crate::test_frozen::spawn_suspended_blocker();
    let thread = crate::test_frozen::InitialThread::of(child.id());
    assert_eq!(thread.release_one(), 1);

    let err = super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect_err("the child already ran");

    let text = err.to_string();
    assert!(
        text.contains("previous suspend count was 0"),
        "the error must name the count it found: {text}"
    );
    dispose(child);
}

/// Another party (an EDR agent, a debugger) started a thread in the frozen child, and it runs: the
/// child is still as its creator left it, because the INITIAL thread is suspended exactly once.
#[skuld::test]
fn resume_initial_threads_accepts_a_running_thread_someone_else_started() {
    let mut child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    let _injected = crate::test_frozen::inject_running_thread_into_std_child(&child);

    super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect("a running second thread must not fail the release of a child whose initial thread is frozen");

    assert_eq!(initial.suspend_count(), 0, "the initial thread must run");
    drop(child.stdin.take());
    child.wait().expect("the resumed blocker exits on stdin EOF");
}

/// A thread another party holds suspended is theirs: the frozen release resumes the initial thread,
/// the only one its creator suspended, and leaves the other at the count it had.
#[skuld::test]
fn resume_initial_threads_leaves_a_thread_someone_else_suspended_suspended() {
    let mut child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    let held = crate::test_frozen::inject_suspended_thread_into_std_child(&child);

    super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect("the initial thread is frozen exactly once");

    assert_eq!(initial.suspend_count(), 0, "the initial thread must run");
    assert_eq!(
        held.suspend_count(),
        1,
        "the other party's suspension must still be held after the release"
    );
    drop(child.stdin.take());
    child.wait().expect("the resumed blocker exits on stdin EOF");
}

/// The release's resume walk visits only the initial thread: another thread of the child is read
/// for its creation time, but the walk's own `open_query` (`Step::QueryOpen`) is never made for it.
/// The failure is armed for that thread alone, and the walk must leave it unconsumed.
#[skuld::test]
fn resume_initial_threads_visits_only_the_initial_thread() {
    use crate::containment::windows::fault::{force_next_for_thread, forced_is_armed, Step};
    const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

    let mut child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    let other = crate::test_frozen::inject_running_thread_into_std_child(&child);
    let _forced = force_next_for_thread(Step::QueryOpen, ERROR_NOT_ENOUGH_MEMORY, other.tid());

    super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect("the resume walk's open_query must not be made for a thread that is not the initial one");

    assert!(forced_is_armed(), "the walk opened the other thread");
    assert_eq!(initial.suspend_count(), 0, "the initial thread must run");
    drop(child.stdin.take());
    child.wait().expect("the resumed blocker exits on stdin EOF");
}

/// A child thread whose creation time cannot be read might be the earlier one, so the initial thread
/// is not identifiable: the release fails, and resumes nothing.
#[skuld::test]
fn resume_initial_threads_resumes_nothing_when_a_childs_creation_time_cannot_be_read() {
    use crate::containment::windows::fault::{force_next_for_thread, Step};
    const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

    let child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    let other = crate::test_frozen::inject_running_thread_into_std_child(&child);
    let _forced = force_next_for_thread(Step::CreationTime, ERROR_NOT_ENOUGH_MEMORY, other.tid());

    let err = super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect_err("the initial thread cannot be identified");

    let text = err.to_string();
    assert!(
        text.contains("GetThreadTimes failed") && text.contains(&format!("thread {} of pid", other.tid())),
        "the error must name the call and the unreadable thread: {text}"
    );
    assert_eq!(
        initial.suspend_count(),
        1,
        "nothing may be resumed when the initial thread is unknown"
    );
    dispose(child);
}

/// Two threads created at the same clock reading: which came first is unknowable (thread ids carry
/// no order), so the release fails and resumes nothing rather than guessing.
#[skuld::test]
fn resume_initial_threads_resumes_nothing_when_the_earliest_creation_times_are_equal() {
    let child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    let other = crate::test_frozen::inject_running_thread_into_std_child(&child);
    let _equal = crate::containment::windows::fault::equal_creation_times();

    let err = super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect_err("the initial thread cannot be identified");

    // The listing order of the two threads is the snapshot's, so either order is the sentence.
    let (a, b) = (initial.tid(), other.tid());
    let sentence = |first: u32, second: u32| {
        format!(
            "the initial thread of pid {} cannot be identified: threads {first} and {second} have the same creation time",
            child.id()
        )
    };
    let text = err.to_string();
    assert!(
        text == sentence(a, b) || text == sentence(b, a),
        "the error must say why the initial thread is unknown, in single-spaced words: {text}"
    );
    assert_eq!(
        initial.suspend_count(),
        1,
        "nothing may be resumed when the initial thread is unknown"
    );
    dispose(child);
}

/// `earliest_created`: the earliest time wins wherever it is listed; a tie for the earliest is a
/// tie, whichever ids hold it; a tie among later times is irrelevant.
#[skuld::test]
fn earliest_created_answers_the_unique_earliest_and_reports_a_tie_for_it() {
    use super::Earliest;

    assert_eq!(super::earliest_created([]), Earliest::NoThread);
    assert_eq!(super::earliest_created([(7, 1)]), Earliest::Unique(1));
    assert_eq!(super::earliest_created([(9, 1), (7, 2), (8, 3)]), Earliest::Unique(2));
    assert_eq!(super::earliest_created([(7, 5), (7, 2), (8, 3)]), Earliest::Tie(5, 2));
    assert_eq!(super::earliest_created([(8, 5), (8, 2), (7, 3)]), Earliest::Unique(3));
}

/// The ordinary spawn's walk is unchanged: `Any` resumes every thread of the child, as `contain()`
/// always has.
#[skuld::test]
fn resume_initial_threads_with_any_count_resumes_every_thread() {
    let mut child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    let second = crate::test_frozen::inject_suspended_thread_into_std_child(&child);

    super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::Any)
        .expect("resume every thread");

    assert_eq!(initial.suspend_count(), 0, "the initial thread must run");
    assert_eq!(second.suspend_count(), 0, "`Any` resumes the second thread too");
    drop(child.stdin.take());
    child.wait().expect("the resumed blocker exits on stdin EOF");
}

/// The initial thread ran while a second thread exists: still a failure, and it names the initial
/// thread, not the other one.
#[skuld::test]
fn resume_initial_threads_names_the_initial_thread_when_it_was_already_running() {
    let child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    assert_eq!(initial.release_one(), 1);
    let _injected = crate::test_frozen::inject_running_thread_into_std_child(&child);

    let err = super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect_err("the initial thread already ran");

    let text = err.to_string();
    assert!(
        text.contains(&format!("thread {} of pid", initial.tid())) && text.contains("previous suspend count was 0"),
        "the error must name the initial thread and its count: {text}"
    );
    dispose(child);
}

/// The initial thread was suspended twice while a second thread exists: still a failure naming the
/// initial thread.
#[skuld::test]
fn resume_initial_threads_names_the_initial_thread_when_it_was_suspended_twice() {
    let child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    initial.suspend_once();
    let _injected = crate::test_frozen::inject_running_thread_into_std_child(&child);

    let err = super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::ExactlyOne)
        .expect_err("the initial thread is still suspended");

    let text = err.to_string();
    assert!(
        text.contains(&format!("thread {} of pid", initial.tid())) && text.contains("previous suspend count was 2"),
        "the error must name the initial thread and its count: {text}"
    );
    dispose(child);
}

/// The initial thread is the earliest created, wherever the snapshot lists it: a list that puts the
/// later thread first must not make that one the initial.
#[skuld::test]
fn initial_thread_id_picks_the_earliest_created_thread_whatever_the_list_order() {
    let child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());
    let injected = crate::test_frozen::inject_running_thread_into_std_child(&child);

    for tids in [[initial.tid(), injected.tid()], [injected.tid(), initial.tid()]] {
        let mut walk = super::Walk::default();
        let picked = super::initial_thread_id(child.id(), &tids, &mut walk);
        assert_eq!(picked, Some(initial.tid()), "list {tids:?}");
        assert!(walk.last_err.is_none(), "{:?}", walk.last_err);
    }
    dispose(child);
}

/// A listed thread that is another process's, or gone, is nobody's initial thread, even when it is
/// older than the child's own.
#[skuld::test]
fn initial_thread_id_ignores_a_thread_that_is_not_the_childs() {
    let older = crate::test_frozen::spawn_suspended_blocker();
    let older_thread = crate::test_frozen::InitialThread::of(older.id());
    let child = crate::test_frozen::spawn_suspended_blocker();
    let initial = crate::test_frozen::InitialThread::of(child.id());

    // Thread id 1 resolves to CID 0, never allocated: the lookup always fails.
    let mut walk = super::Walk::default();
    let picked = super::initial_thread_id(child.id(), &[older_thread.tid(), 1, initial.tid()], &mut walk);

    assert_eq!(picked, Some(initial.tid()));
    assert!(
        walk.last_err.is_none(),
        "a foreign or vanished thread is a skip: {:?}",
        walk.last_err
    );
    dispose(older);
    dispose(child);
}

/// The ordinary spawn's resume does not ask that the child was suspended exactly once: a thread
/// something else already ran (a debugger's break-in thread, an EDR agent's) must not fail a
/// `contain()` spawn that has always accepted it.
#[skuld::test]
fn resume_initial_threads_with_any_count_accepts_a_thread_that_was_already_running() {
    let child = crate::test_frozen::spawn_suspended_blocker();
    let thread = crate::test_frozen::InitialThread::of(child.id());
    assert_eq!(thread.release_one(), 1);

    super::resume_initial_threads(crate::test_frozen::raw(&child), super::SuspendCount::Any)
        .expect("the ordinary resume accepts a running thread");

    dispose(child);
}

/// The ordinary `contain()` attach, end to end: the same tolerance as above, through `attach_job`.
#[skuld::test]
fn death_watch_attach_job_succeeds_when_the_initial_thread_was_already_running() {
    let mut child = crate::test_frozen::spawn_suspended_releasable();
    let thread = crate::test_frozen::InitialThread::of(child.id());
    assert_eq!(thread.release_one(), 1);

    let job = super::attach_job(crate::test_frozen::raw(&child))
        .expect("an ordinary attach must not fail on a running thread")
        .expect("the job was assigned");

    // KILL_ON_JOB_CLOSE ends the child. `wait` closes its stdin, so a close that killed nothing
    // lets it run to its end.
    drop(job);
    crate::test_frozen::assert_not_released("the child", child.wait().expect("reap the child"));
}

/// A frozen child whose initial thread cannot be resumed fails the attach with that failure as the
/// cause. The job's kill after it, which fails too, is the attach's cleanup: the cause is not
/// changed by it, and it is not in the cause's text.
///
/// Mutants: the kill's failure is only logged; it replaces the resume's as the cause; it is among
/// the cause's `source`s; it is not logged at warn, naming the job and that the tree may still run.
#[skuld::test]
fn attach_job_whose_resume_and_job_kill_both_fail_returns_the_kill_as_cleanup() {
    use super::fault::{force_next, set_before_job_kill, Step};
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_INVALID_HANDLE: u32 = 6;

    crate::log_capture::install();
    let mark = crate::log_capture::mark();

    let child = crate::test_frozen::spawn_suspended_blocker();
    // One failure is forced at a time: the kill's is armed once the resume's is spent.
    let kill_failure = std::rc::Rc::new(std::cell::RefCell::new(None));
    let _resume = force_next(Step::Resume, ERROR_ACCESS_DENIED);
    let _arms_the_kill = set_before_job_kill({
        let kill_failure = std::rc::Rc::clone(&kill_failure);
        move || *kill_failure.borrow_mut() = Some(force_next(Step::JobKill, ERROR_INVALID_HANDLE))
    });

    let failure = super::attach_job(crate::test_frozen::raw(&child)).expect_err("the resume failed");

    assert!(
        matches!(failure.cause, crate::error::Error::Containment { .. }),
        "{failure:?}"
    );
    assert_eq!(
        crate::error::first_os_code(&failure.cause),
        Some(ERROR_ACCESS_DENIED as i32),
        "the resume's failure is the cause: {failure:?}"
    );
    let cleanup = failure.cleanup.expect("the job kill's failure is the cleanup");
    assert_eq!(cleanup.iter().len(), 1, "{cleanup:?}");
    assert_eq!(
        crate::error::first_os_code(&**cleanup.first()),
        Some(ERROR_INVALID_HANDLE as i32),
        "{cleanup:?}"
    );
    let warns = crate::log_capture::warns_since(mark, "job kill after a failed resume also failed");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("the tree may still be running") && warns[0].contains("terminating the job"),
        "{warns:?}"
    );
    assert!(
        crate::error::said(&**cleanup.first()).starts_with(&crate::error::io_said("terminating the job: ")),
        "the cleanup member names its step: {cleanup:?}"
    );
    drop(kill_failure);
    dispose(child);
}

/// A spawn whose attach fails in its resume, and whose job kill after it fails too, returns the
/// resume as the cause and the kill in the `cleanup` of the error that says the program may have
/// started, beside the child's fate.
///
/// Mutant: the spawn drops the attach's cleanup when it tears the child down.
#[skuld::test]
fn a_spawn_whose_attach_fails_returns_the_job_kill_in_its_cleanup() {
    use super::fault::{force_next, set_before_job_kill, Step};
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_INVALID_HANDLE: u32 = 6;

    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.contain();
    let kill_failure = std::rc::Rc::new(std::cell::RefCell::new(None));
    let _resume = force_next(Step::Resume, ERROR_ACCESS_DENIED);
    let _arms_the_kill = set_before_job_kill({
        let kill_failure = std::rc::Rc::clone(&kill_failure);
        move || *kill_failure.borrow_mut() = Some(force_next(Step::JobKill, ERROR_INVALID_HANDLE))
    });

    let error = cmd.spawn().expect_err("the resume failed");

    let crate::error::Error::MayHaveStarted {
        source, cleanup, fate, ..
    } = &error
    else {
        panic!("expected MayHaveStarted, got {error:?}");
    };
    assert_eq!(*fate, crate::error::ChildFate::Reaped, "{error:?}");
    assert!(
        matches!(**source, crate::error::Error::Containment { .. }),
        "{source:?}"
    );
    assert_eq!(
        crate::error::first_os_code(&**source),
        Some(ERROR_ACCESS_DENIED as i32),
        "{source:?}"
    );
    let cleanup = cleanup.as_ref().expect("the job kill's failure is the cleanup");
    assert_eq!(cleanup.iter().len(), 1, "{cleanup:?}");
    assert_eq!(
        crate::error::first_os_code(&**cleanup.first()),
        Some(ERROR_INVALID_HANDLE as i32),
        "{cleanup:?}"
    );
    drop(kill_failure);
}

/// `assign_held` assigns the job and does not resume: the thread stays frozen.
#[skuld::test]
fn death_watch_assign_held_assigns_the_job_without_resuming() {
    let mut child = crate::test_frozen::spawn_suspended_releasable();
    let thread = crate::test_frozen::InitialThread::of(child.id());

    let job = super::assign_held(crate::test_frozen::raw(&child)).expect("assign the held child");

    assert_eq!(thread.suspend_count(), 1, "assign_held must not resume");
    assert_ne!(
        crate::test_frozen::limit_flags(&job).0
            & windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0,
        0
    );
    drop(job); // KILL_ON_JOB_CLOSE ends the child
    crate::test_frozen::release(&mut child, &thread);
    crate::test_frozen::assert_not_released("the frozen child", child.wait().expect("reap the frozen child"));
}

// Win32 codes of job failures =====
//
// Each site converts a `windows::core::Error` to an `io::Error`. A bare `.into()` keeps the
// HRESULT (`0x8007xxxx`) where std reports the Win32 code. An event handle is a real handle that
// is not a job, so each job call on it fails with `ERROR_INVALID_HANDLE`: no Job Object is made.

fn event_handle() -> windows::Win32::Foundation::HANDLE {
    // SAFETY: creating an unnamed event has no preconditions.
    unsafe { windows::Win32::System::Threading::CreateEventW(None, true, false, None) }.expect("create an event handle")
}

/// `TerminateJobObject` failing reaches the caller with its Win32 code.
///
/// Mutant: `hard_kill` converts with `.into()`, so the code is `0x80070006`.
#[skuld::test]
fn hard_kill_failure_carries_the_win32_code() {
    let h = super::JobHandle::new(event_handle());
    let err = h.hard_kill().expect_err("an event is not a job");
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE), "{err:?}");
}

/// A tree kill whose `TerminateJobObject` fails is an `Error::Containment` over the Win32 error: a
/// kill that can have peers returns a variant with a `source`, and the code stays down the chain.
///
/// Mutant: the failed kill is a bare `Error::Io`.
#[skuld::test]
fn a_failed_job_kill_is_a_containment_over_the_win32_error() {
    use crate::containment::Contains as _;
    let h = super::JobHandle::new(event_handle());
    let left = h.send_kill(None).into_result().expect_err("an event is not a job");
    let [error] = &left.members[..] else {
        panic!("{left:?}");
    };
    assert!(matches!(error, crate::error::Error::Containment { .. }), "{error:?}");
    assert_eq!(
        crate::error::first_os_code(error),
        Some(ERROR_INVALID_HANDLE),
        "{error:?}"
    );
}

/// A `CreateJobObjectW` failure carries the plain Win32 code. The call cannot be made to fail, so
/// the failure is injected at `owned_job`.
///
/// Mutant: `owned_job` converts with `.into()`, so the code is `0x80070008`.
#[skuld::test]
fn owned_job_failure_carries_the_win32_code() {
    use windows::core::HRESULT;
    use windows::Win32::Foundation::ERROR_NOT_ENOUGH_MEMORY;
    let failed = windows::core::Error::from_hresult(HRESULT::from_win32(ERROR_NOT_ENOUGH_MEMORY.0));
    let err = super::owned_job(Err(failed)).expect_err("the creation failed");
    assert_eq!(err.raw_os_error(), Some(ERROR_NOT_ENOUGH_MEMORY.0 as i32), "{err:?}");
}

/// `SetInformationJobObject` failing carries the plain Win32 code.
///
/// Mutant: `set_kill_on_close_or_close` converts with `.into()`, so the code is `0x80070006`.
#[skuld::test]
fn set_kill_on_close_failure_carries_the_win32_code() {
    let err = super::set_kill_on_close_or_close(event_handle()).expect_err("an event is not a job");
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE), "{err:?}");
}

/// `AssignProcessToJobObject` failing carries the plain Win32 code.
///
/// Mutant: `assign_or_close` converts with `.into()`, so the code is `0x80070006`.
#[skuld::test]
fn assign_failure_carries_the_win32_code() {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle and has no preconditions.
    let me = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let err = super::assign_or_close(event_handle(), me).expect_err("an event is not a job");
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE), "{err:?}");
}

/// A member check that fails (`IsProcessInJob` on a handle that is not a job) is reported with the
/// plain Win32 code, not dropped.
///
/// Mutant: the `IsProcessInJob` arm of `member_to_watch` converts with `.into()`, so the code is
/// `0x80070006`.
#[skuld::test]
fn member_check_failure_carries_the_win32_code() {
    use windows::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    // SAFETY: opening this process has no preconditions; `member_to_watch` closes the handle.
    let opened = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            GetCurrentProcessId(),
        )
    };
    let err = super::member_to_watch(opened, event_handle()).expect_err("an event is not a job");
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE), "{err:?}");
}

/// An `OpenProcess` refusal is reported with the plain Win32 code, while `ERROR_INVALID_PARAMETER`
/// (the process already exited) is not a failure.
///
/// Mutant: the generic `Err(e)` arm of `member_to_watch` converts with `.into()`, so the code is
/// `0x80070005`.
#[skuld::test]
fn denied_open_carries_the_win32_code() {
    use windows::core::HRESULT;
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED as DENIED, ERROR_INVALID_PARAMETER, HANDLE};
    let refused = |code| Err(windows::core::Error::from_hresult(HRESULT::from_win32(code)));
    let err = super::member_to_watch(refused(DENIED.0), HANDLE::default()).expect_err("denied");
    assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED), "{err:?}");
    let gone = super::member_to_watch(refused(ERROR_INVALID_PARAMETER.0), HANDLE::default());
    assert!(matches!(gone, Ok(None)), "an exited pid is not a failure: {gone:?}");
}

/// `Thread32First` failing on a handle that is not a snapshot carries the plain Win32 code.
///
/// Mutant: `thread_entries_closing` converts with `.into()`, so the code is `0x80070006`.
#[skuld::test]
fn thread_walk_failure_carries_the_win32_code() {
    let err = super::thread_entries_closing(event_handle()).expect_err("an event is not a snapshot");
    let code = err.raw_os_error();
    assert_eq!(code, Some(ERROR_INVALID_HANDLE), "ERROR_INVALID_HANDLE expected");
}

/// A `CreateToolhelp32Snapshot` failure carries the plain Win32 code. The call cannot be made to
/// fail, so the failure is injected at `thread_snapshot`.
///
/// Mutant: `thread_snapshot` converts with `.into()`, so the code is `0x80070008`.
#[skuld::test]
fn thread_snapshot_failure_carries_the_win32_code() {
    use windows::core::HRESULT;
    use windows::Win32::Foundation::ERROR_NOT_ENOUGH_MEMORY;
    let failed = windows::core::Error::from_hresult(HRESULT::from_win32(ERROR_NOT_ENOUGH_MEMORY.0));
    let err = super::thread_snapshot(Err(failed)).expect_err("the snapshot failed");
    assert_eq!(err.raw_os_error(), Some(ERROR_NOT_ENOUGH_MEMORY.0 as i32), "{err:?}");
}

/// A `disarm` the OS refuses is returned, with the plain Win32 code, and the flag stays set.
///
/// Mutants: `disarm` logs the failure and returns `Ok`; it converts with `.into()`, so the code is
/// `0x80070005`.
#[skuld::test]
fn a_refused_disarm_is_returned_with_the_win32_code() {
    use super::JobHandle;
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    let job = JobHandle::create_without_set_access_for_test();

    let err = job
        .disarm()
        .expect_err("the OS refuses SetInformationJobObject on this handle");

    assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{err:?}");
}

/// A `disarm` on a handle that allows it is `Ok`.
#[skuld::test]
fn disarm_of_an_empty_job_is_ok() {
    super::JobHandle::create_empty_for_test()
        .disarm()
        .expect("a job made by the crate can be disarmed");
}

/// A `disarm` after `hard_kill` clears `KILL_ON_JOB_CLOSE`: the flag the real create path sets.
///
/// Mutant: `disarm` does nothing.
#[skuld::test]
fn disarm_after_hard_kill_clears_the_flag() {
    let (child, job) = spawn_job_member();
    assert!(
        super::job_kills_on_close(&job),
        "the create path sets KILL_ON_JOB_CLOSE"
    );
    job.hard_kill().expect("hard_kill on a live job");
    job.disarm().expect("disarm after hard_kill");
    assert_eq!(crate::test_frozen::limit_flags(&job).0, 0);
    let_member_exit(child);
}
