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
