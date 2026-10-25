//! Unit tests for Windows Job Object containment helpers.
//! Substantive runtime coverage is in the integration tests (tests/spawn_io.rs).

#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
fn query_job_pid_list_is_empty_for_an_unpopulated_job() {
    use super::JobHandle;
    let job = JobHandle::create_empty_for_test();
    let job_handle = job.as_handle().expect("freshly created job handle must be live");
    let pids = super::query_job_pid_list(job_handle).expect("query pid list");
    assert!(pids.is_empty(), "an empty job must report no members: {pids:?}");
}

/// `wait_drained_raw`'s empty-job fast path: no member was ever assigned, so the very first
/// re-enumeration already reports `AllMembersExited`, with no wait and no deadline needed.
#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
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

/// A Win32 failure inside the containment layer reaches the caller as its plain Win32 code, so
/// `kind()` and `raw_os_error()` classify it. A null handle is a real `ERROR_INVALID_HANDLE`.
///
/// Mutant: `duplicate_job` converts with the `windows` crate's own `io::Error` conversion, which
/// keeps the HRESULT (`0x80070006`).
#[skuld::test]
fn duplicate_job_failure_carries_the_win32_code() {
    let err = super::duplicate_job(windows::Win32::Foundation::HANDLE::default())
        .expect_err("duplicating a null handle must fail");
    let crate::error::Error::Io(err) = err else {
        panic!("expected Error::Io, got {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE), "{err:?}");
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
    let mut cmd = crate::Command::new();
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

/// The OS code of an `io_context` error, read from its source.
fn source_os_code(e: &std::io::Error) -> Option<i32> {
    std::error::Error::source(e.get_ref()?)
        .and_then(|s| s.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
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
    assert_eq!(source_os_code(&err), Some(ERROR_ACCESS_DENIED), "{err:?}");
    assert!(
        err.to_string()
            .starts_with("ResumeThread failed for thread 1 of pid 9: "),
        "{err}"
    );
}

/// A tie in creation times is cosca's finding, not a failed call: no OS code.
#[skuld::test]
fn fail_unidentified_has_no_os_code() {
    use super::{walk_verdict, Walk};
    let mut walk = Walk::default();
    walk.fail_unidentified(7, 12, 34);
    let err = walk_verdict(7, walk).expect_err("a failure");
    assert_eq!(err.raw_os_error(), None, "{err:?}");
    assert_eq!(source_os_code(&err), None, "{err:?}");
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
    assert_eq!(source_os_code(&err), Some(ERROR_INVALID_HANDLE), "{err:?}");
    assert_eq!(
        err.kind(),
        std::io::Error::from_raw_os_error(ERROR_INVALID_HANDLE).kind(),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with("GetProcessId failed on the child's handle: "),
        "{err}"
    );
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
    let mut child = crate::test_frozen::spawn_suspended_blocker();
    let thread = crate::test_frozen::InitialThread::of(child.id());
    assert_eq!(thread.release_one(), 1);

    let job = super::attach_job(crate::test_frozen::raw(&child))
        .expect("an ordinary attach must not fail on a running thread")
        .expect("the job was assigned");

    drop(job); // KILL_ON_JOB_CLOSE ends the child
    child.wait().expect("the job's close killed the child");
}

/// `assign_held` assigns the job and does not resume: the thread stays frozen.
#[skuld::test]
fn death_watch_assign_held_assigns_the_job_without_resuming() {
    let child = crate::test_frozen::spawn_suspended_blocker();
    let thread = crate::test_frozen::InitialThread::of(child.id());

    let job = super::assign_held(crate::test_frozen::raw(&child)).expect("assign the held child");

    assert_eq!(thread.suspend_count(), 1, "assign_held must not resume");
    assert_ne!(
        crate::test_frozen::limit_flags(&job).0
            & windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0,
        0
    );
    drop(job); // KILL_ON_JOB_CLOSE ends the child
    let mut child = child;
    child.wait().expect("the job's close killed the frozen child");
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

/// `Thread32First` failing on a handle that is not a snapshot carries the plain Win32 code, and the
/// handle is closed.
///
/// Mutant: `thread_entries_closing` converts with `.into()`, so the code is an HRESULT
/// (`0x8007xxxx`).
#[skuld::test]
fn thread_walk_failure_carries_the_win32_code() {
    let err = super::thread_entries_closing(event_handle()).expect_err("an event is not a snapshot");
    let code = err.raw_os_error();
    assert!(
        matches!(code, Some(c) if c != 0 && c < 0x1_0000),
        "expected a plain Win32 code, got {code:?}"
    );
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
