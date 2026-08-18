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
    h.hard_kill();
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
    h.hard_kill();
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
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "more"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
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

/// Live coverage of the `Ok(true)` arm against a real console. `Ok(false)` needs the DETACHED
/// helper in the integration suite (a different process); `Err` is not provokable live, hence
/// the fault seam exercised below. This test does NOT guard the integration test against
/// vacuity — that binary carries its own `console=0` / `console=1` assertions, measured inside
/// the helper itself.
#[test]
fn caller_has_console_is_true_under_cargo_test() {
    assert!(
        matches!(super::caller_has_console(), Ok(true)),
        "cargo test is expected to run with a console attached"
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
