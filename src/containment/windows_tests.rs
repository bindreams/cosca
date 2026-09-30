//! Unit tests for Windows Job Object containment helpers.
//! Substantive runtime coverage is in the integration tests (tests/spawn_io.rs).

#[test]
fn job_handle_debug_does_not_panic() {
    // Verify the Debug impl compiles and runs cleanly for a consumed (raw == null) handle.
    // `port` is never a legal null, so there is no struct-literal shortcut to that state: go
    // through the real constructor (`create_empty_for_test`) and a real consuming path
    // (`hard_kill`, which both nulls `raw` and closes the underlying job handle — unlike a bare
    // `take`, it doesn't leak the real handle this constructor opened) instead of hand-building
    // a `JobHandle`.
    use super::JobHandle;
    let h = JobHandle::create_empty_for_test();
    h.hard_kill().expect("hard_kill on a live job");
    let s = format!("{h:?}");
    assert!(s.contains("JobHandle"), "debug output: {s}");
}

/// A `wait_drained` call against an already-consumed job handle must report `Unassessable`,
/// never a guessed `AllMembersExited` — the handle is gone, so nothing here re-checked whether
/// every member actually finished exiting (`TerminateJobObject`/`CloseHandle` are not
/// documented as synchronous with member process teardown).
#[test]
fn wait_drained_on_a_consumed_handle_is_unassessable() {
    use super::JobHandle;
    let h = JobHandle::create_empty_for_test();
    h.hard_kill().expect("hard_kill on a live job");
    let err = h
        .wait_drained(Some(None), None)
        .expect_err("a consumed job handle must not report a live drain verdict");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("expected Unassessable, got {err:?}");
    };
    assert!(
        source.is_none(),
        "nothing was asked of the OS on this path — no source is expected"
    );
}

/// `query_job_pid_list` on a freshly created, unpopulated job reports no members — the fast
/// path `wait_drained_raw` relies on to return `AllMembersExited` without ever opening a
/// process handle.
#[test]
fn query_job_pid_list_is_empty_for_an_unpopulated_job() {
    use super::JobHandle;
    let job = JobHandle::create_empty_for_test();
    let job_handle = job.as_handle().expect("freshly created job handle must be live");
    let pids = super::query_job_pid_list(job_handle).expect("query pid list");
    assert!(pids.is_empty(), "an empty job must report no members: {pids:?}");
}

/// `wait_drained_raw`'s empty-job fast path: no member was ever assigned, so the very first
/// re-enumeration already reports `AllMembersExited`, with no wait and no deadline needed.
#[test]
fn wait_drained_raw_reports_drained_for_an_empty_job() {
    use super::JobHandle;
    let job = JobHandle::create_empty_for_test();
    let job_handle = job.as_handle().expect("freshly created job handle must be live");
    let verdict = super::wait_drained_raw(job_handle, Some(None), None).expect("wait_drained_raw");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
}

/// A real, still-running job member reports `MembersRemain` at an already-elapsed deadline —
/// not a race: the child is blocked reading its own piped stdin, which this test still holds
/// open at the point of the check, so the member's liveness there is a fact this test itself
/// holds, not a guess about timing. Also exercises `query_job_pid_list`'s non-empty branch (the
/// pid must be visible in the job before `wait_drained_raw` can find it to wait on at all), and
/// — once the child is let go and reaped — the live re-enumeration that turns a real exit into
/// `AllMembersExited`, synchronized on `Child::wait()` rather than on any elapsed time.
#[test]
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
    let job_handle = job.as_handle().expect("freshly created job handle must be live");

    let pids = super::query_job_pid_list(job_handle).expect("query pid list");
    assert_eq!(
        pids,
        vec![child.id()],
        "the job must report exactly the member just assigned"
    );

    // An already-elapsed deadline: `crate::wait::remaining` reads it as Duration::ZERO without
    // blocking at all, so this assertion is instantaneous — the point under test is that a
    // non-empty live member set reports MembersRemain rather than a guessed drain verdict.
    let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let verdict = super::wait_drained_raw(job_handle, Some(Some(past)), None).expect("wait_drained_raw");
    assert_eq!(verdict, crate::containment::TreeDrain::MembersRemain);

    // Let the child exit on its own terms (EOF on stdin), then confirm the job reports drained
    // once it genuinely has. `Child::wait()` only returns once the OS reports the process gone
    // — a real synchronization point, not a timing guess.
    drop(child.stdin.take());
    child.wait().expect("wait for cmd /C more to exit");

    let verdict = super::wait_drained_raw(job_handle, Some(None), None).expect("wait_drained_raw");
    assert_eq!(verdict, crate::containment::TreeDrain::AllMembersExited);
}

// Deadline contract for `wait_drained_raw`: never report `MembersRemain` before the real
// deadline. Seams are documented in `crate::wait`.

/// A live job with one still-running member: `cmd /C more`, blocked reading its own piped
/// stdin until EOF. Mirrors `wait_drained_raw_tracks_a_real_member_through_exit` above.
fn spawn_job_member() -> (std::process::Child, super::JobHandle) {
    use std::os::windows::io::AsRawHandle;
    let child = crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "more"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn cmd /C more");
    let raw = child.as_raw_handle();
    let job = super::assign_to_kill_on_close_job(raw).expect("assign to job");
    (child, job)
}

fn let_member_exit(mut child: std::process::Child) {
    drop(child.stdin.take());
    child.wait().expect("wait for cmd /C more to exit");
}

/// A never-draining job armed with a sub-millisecond remainder rounds up to 1ms, reports
/// `MembersRemain` only at the deadline, and derives its argument from the site's own deadline.
///
/// Mutant: truncate in `win32_timeout_ms` -> `ms` is 0. Mutant: add slack -> `ms` is above 1.
/// Mutant: ignore the site's deadline -> `requested` is not 5ms.
#[test]
fn wait_drained_raw_arms_the_ceiling_of_the_remaining_duration() {
    use std::time::{Duration, Instant};
    let (child, job) = spawn_job_member();
    let job_handle = job.as_handle().expect("freshly created job handle must be live");
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    let deadline = at + Duration::from_millis(5);
    let verdict = super::wait_drained_raw(job_handle, Some(Some(deadline)), None);
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
#[test]
fn wait_drained_raw_never_reports_members_remain_before_the_deadline() {
    use std::time::{Duration, Instant};
    let (mut child, job) = spawn_job_member();
    let stdin = child.stdin.take().expect("piped stdin");
    let job_handle = job.as_handle().expect("freshly created job handle must be live");
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    crate::wait::wait_ms_probe::on_second_arm(move || drop(stdin)); // EOF -> member exits for real
    let deadline = Instant::now() + Duration::from_secs(3600);
    let verdict = super::wait_drained_raw(job_handle, Some(Some(deadline)), None);
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
#[test]
fn wait_drained_raw_re_arms_past_a_clamped_timeout() {
    use std::time::{Duration, Instant};
    let (mut child, job) = spawn_job_member();
    let stdin = child.stdin.take().expect("piped stdin");
    let job_handle = job.as_handle().expect("freshly created job handle must be live");
    crate::wait::wait_ms_probe::take();
    let _clamp = crate::wait::wait_clamp_seam::set(5);
    crate::wait::wait_ms_probe::on_second_arm(move || drop(stdin));
    let deadline = Instant::now() + Duration::from_secs(3600);
    let verdict = super::wait_drained_raw(job_handle, Some(Some(deadline)), None);
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
#[test]
fn caller_has_console_is_true_under_cargo_test() {
    assert!(
        matches!(super::caller_has_console(), Ok(true)),
        "the test runner is expected to run with a console attached"
    );
}

/// The `Err` arm's production, via the fault seam — a live `GetConsoleProcessList` cannot be
/// made to fail. This exercises the fault-injection scaffolding, not a real API failure; the
/// consumption side is covered by `invalid_handle_with_a_failed_probe_stays_io`.
#[test]
fn console_probe_error_surfaces() {
    super::fault::set_force_console_probe_error(true);
    assert!(super::caller_has_console().is_err());
    assert!(!super::fault::armed(), "the seam must be consumed by one call");
    // The very next call is a real probe again.
    assert!(matches!(super::caller_has_console(), Ok(true)));
}

/// `HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)`. Derived from the documented Win32 macro
/// (`0x8007_0000 | (x & 0xFFFF)` for positive `x`, with `ERROR_INVALID_HANDLE` == 6), not from
/// this crate's own output.
const E_INVALID_HANDLE: i32 = 0x8007_0006u32 as i32;
/// `HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)` — a different failure, which must NOT be
/// classified as a missing console.
const E_ACCESS_DENIED: i32 = 0x8007_0005u32 as i32;

fn io_err(hresult: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(hresult)
}

#[test]
fn invalid_handle_with_no_console_is_typed_no_console() {
    let e = super::classify_ctrl_event_failure(4242, io_err(E_INVALID_HANDLE), Ok(false));
    let crate::error::Error::NoConsole { detail } = e else {
        panic!("expected NoConsole, got {e:?}");
    };
    assert!(detail.contains("4242"), "the detail must name the group: {detail}");
    assert!(
        detail.contains("kill_tree()"),
        "the detail must name the way out: {detail}"
    );
}

#[test]
fn invalid_handle_with_a_console_attached_stays_io() {
    // The probe contradicts the code: never claim a cause we just measured to be false.
    let e = super::classify_ctrl_event_failure(1, io_err(E_INVALID_HANDLE), Ok(true));
    assert!(matches!(e, crate::error::Error::Io(_)), "got {e:?}");
}

#[test]
fn invalid_handle_with_a_failed_probe_stays_io() {
    let probe = Err(std::io::Error::from_raw_os_error(87)); // ERROR_INVALID_PARAMETER
    let e = super::classify_ctrl_event_failure(1, io_err(E_INVALID_HANDLE), probe);
    assert!(matches!(e, crate::error::Error::Io(_)), "got {e:?}");
}

#[test]
fn a_different_failure_code_stays_io_whatever_the_probe_says() {
    for console in [Ok(true), Ok(false)] {
        let e = super::classify_ctrl_event_failure(1, io_err(E_ACCESS_DENIED), console);
        assert!(matches!(e, crate::error::Error::Io(_)), "got {e:?}");
    }
    let e = super::classify_ctrl_event_failure(1, io_err(E_ACCESS_DENIED), Err(io_err(87)));
    assert!(matches!(e, crate::error::Error::Io(_)), "got {e:?}");
}

#[test]
fn the_no_console_signature_matches_the_real_win32_mapping() {
    // Pins the HRESULT the live path will see against the constant above, so a windows-rs
    // change to the io::Error conversion cannot silently un-classify the error.
    use windows::Win32::Foundation::ERROR_INVALID_HANDLE;
    let hr = windows::core::HRESULT::from_win32(ERROR_INVALID_HANDLE.0);
    assert_eq!(hr.0, E_INVALID_HANDLE);
    assert_eq!(
        std::io::Error::from(windows::core::Error::from_hresult(hr)).raw_os_error(),
        Some(E_INVALID_HANDLE)
    );
}

// The mechanism the creation-flag word settles, one test per row. Nine inputs, three distinct
// outcomes: no constant implementation passes, and the last three rows pin that
// `OtherConsoleGroup` is a statement about a route to a group that EXISTS, not a synonym for
// "detached" — with no group flag there is nothing to address, whatever the console situation.
mod mechanism_from_flags_tests {
    use crate::containment::windows::{group_flags, mechanism_from_flags, root_flags};
    use crate::graceful::GracefulMechanism;
    use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CREATE_NO_WINDOW, DETACHED_PROCESS};

    #[test]
    fn mechanism_from_flags_reports_none_for_no_flags() {
        assert_eq!(mechanism_from_flags(0), GracefulMechanism::None);
    }

    #[test]
    fn mechanism_from_flags_reports_console_group_for_group_flags() {
        assert_eq!(mechanism_from_flags(group_flags()), GracefulMechanism::ConsoleGroup);
    }

    #[test]
    fn mechanism_from_flags_reports_console_group_for_root_flags() {
        assert_eq!(mechanism_from_flags(root_flags()), GracefulMechanism::ConsoleGroup);
    }

    #[test]
    fn mechanism_from_flags_reports_other_console_group_for_group_plus_detached() {
        assert_eq!(
            mechanism_from_flags(group_flags() | DETACHED_PROCESS.0),
            GracefulMechanism::OtherConsoleGroup
        );
    }

    #[test]
    fn mechanism_from_flags_reports_other_console_group_for_group_plus_new_console() {
        assert_eq!(
            mechanism_from_flags(group_flags() | CREATE_NEW_CONSOLE.0),
            GracefulMechanism::OtherConsoleGroup
        );
    }

    #[test]
    fn mechanism_from_flags_reports_other_console_group_for_group_plus_no_window() {
        assert_eq!(
            mechanism_from_flags(group_flags() | CREATE_NO_WINDOW.0),
            GracefulMechanism::OtherConsoleGroup
        );
    }

    #[test]
    fn mechanism_from_flags_reports_none_for_detached_without_a_group() {
        assert_eq!(mechanism_from_flags(DETACHED_PROCESS.0), GracefulMechanism::None);
    }

    #[test]
    fn mechanism_from_flags_reports_none_for_a_new_console_without_a_group() {
        assert_eq!(mechanism_from_flags(CREATE_NEW_CONSOLE.0), GracefulMechanism::None);
    }

    #[test]
    fn mechanism_from_flags_reports_none_for_no_window_without_a_group() {
        assert_eq!(mechanism_from_flags(CREATE_NO_WINDOW.0), GracefulMechanism::None);
    }
}

// ===== job breakaway probe =====

/// The `Unknown` arm exists so cosca never asserts a cause it could not measure. Neither Win32
/// call in the probe can be made to fail on a live system, so the seam is the only route to that
/// arm's production — and without the seam the probe reports a real verdict, which is what makes
/// this assertion about the arm rather than about the constant.
#[test]
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
#[test]
fn probe_agrees_with_an_independent_is_process_in_job_measurement() {
    let exe = std::env::current_exe().expect("current_exe");
    let fixture = crate::test_child::fixture_path!(fixture_reports_job_breakaway_probe);
    let child = crate::test_spawn::spawn(
        std::process::Command::new(&exe)
            .args(["--test-threads=1", "--exact", fixture])
            .env(JOB_BREAKAWAY_PROBE_FIXTURE_MARKER, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped()),
    )
    .expect("spawn the job-breakaway probe fixture");
    let output = child.wait_with_output().expect("wait for the fixture child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "job-breakaway probe fixture failed (status {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status,
    );
    assert!(
        stdout.contains("running 1 test") && stdout.contains("test result: ok. 1 passed;"),
        "fixture exited 0 but its libtest banner shows something other than exactly one test run \
         and passed — most likely the `--exact` filter matched ZERO tests, which libtest also \
         exits 0 for:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// The child half of [`probe_agrees_with_an_independent_is_process_in_job_measurement`]: a no-op
/// when picked up by an ordinary, unfiltered suite run ([`JOB_BREAKAWAY_PROBE_FIXTURE_MARKER`] is
/// unset there). Re-executed via `current_exe() --exact` with that var set, it performs the real
/// measurement — see the driver's own doc for why it must run here, in a freshly spawned process,
/// rather than in the driver itself.
#[test]
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

/// A suspended process this test made itself, holding its main thread; killed on drop.
struct SuspendedHelper {
    process: windows::Win32::Foundation::HANDLE,
    thread: windows::Win32::Foundation::HANDLE,
    tid: u32,
    pid: u32,
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
        Self {
            process: pi.hProcess,
            thread: pi.hThread,
            tid: pi.dwThreadId,
            pid: pi.dwProcessId,
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

/// Spawn a contained blocker with `tid` injected into the snapshot walk as an entry of the
/// child. Returns the spawn result and what the walk did with the entry.
fn spawn_with_injected_tid(
    tid: u32,
) -> (
    Result<crate::Child, crate::error::Error>,
    Option<Option<crate::containment::windows::Visit>>,
) {
    let injected = crate::containment::windows::fault::inject_snapshot_tid(tid);
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    cmd.contain();
    let spawned = cmd.spawn();
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
/// nothing resumed it and 0 proves something did. The recorded visit proves the entry was walked
/// and identified as the helper's, rather than never reached.
#[test]
fn windows_resume_initial_threads_never_resumes_a_foreign_thread() {
    use crate::containment::windows::Visit;
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    let helper = SuspendedHelper::new();
    let (spawned, visit) = spawn_with_injected_tid(helper.tid);
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

/// A listed thread that exited and whose id was not reused makes `OpenThread` fail with
/// `ERROR_INVALID_PARAMETER`. That is as stale as a reused id and must not fail the spawn. Id 1
/// is not a multiple of 4, so no thread ever has it: the outcome cannot depend on id reuse.
#[test]
fn windows_resume_initial_threads_skips_a_thread_id_that_no_longer_exists() {
    use crate::containment::windows::Visit;

    let (spawned, visit) = spawn_with_injected_tid(1);
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

/// `GetProcessId` answers 0 for a handle that is not a process; that must be an error naming the
/// call, not a walk that matches the System Idle process.
#[test]
fn process_pid_of_rejects_a_handle_that_names_no_process() {
    let result = super::process_pid_of(windows::Win32::Foundation::HANDLE::default());
    assert!(result.is_err(), "a null handle names no process: {result:?}");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("GetProcessId"),
        "error must name the call: {err}"
    );
}

/// When every listed thread was stale the spawn fails, and the error says why.
#[test]
fn none_resumed_error_names_the_last_skip_reason() {
    let err = super::none_resumed_error(4321, Some("thread 8 no longer exists"));
    let text = err.to_string();
    assert!(
        text.contains("4321") && text.contains("thread 8 no longer exists"),
        "{text}"
    );
    let text = super::none_resumed_error(4321, None).to_string();
    assert!(text.contains("listed no threads"), "{text}");
}
