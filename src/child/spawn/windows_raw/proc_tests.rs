use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

use windows::Win32::System::Threading::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};

use super::{create_process, win32_io_error, RawChild};

fn spawn_long_lived_runas() -> RawChild {
    // A real, NON-elevated child wrapped with the runas flag. `ping -n 5 127.0.0.1` runs
    // ~4s — long-lived enough that kill/teardown must actually terminate it.
    let mut cmdline: Vec<u16> = "ping -n 5 127.0.0.1\0".encode_utf16().collect();
    // A zeroed STARTUPINFOEXW (null lpAttributeList is fine); `create_process` fills cb.
    // `EXTENDED_STARTUPINFO_PRESENT` satisfies create_process's contract (it sizes the
    // struct as extended, so CreateProcessW must be told to treat it as such).
    let mut si = STARTUPINFOEXW::default();
    let (proc, pid) =
        create_process(None, &mut cmdline, &mut si, None, &None, EXTENDED_STARTUPINFO_PRESENT.0).expect("spawn");
    RawChild::new_runas(proc, pid)
}

/// A real, non-elevated, long-lived (~4s) child — long enough to outlast every deadline the
/// `wait_deadline` tests below use (<=200ms), with no stdin pipe to manage.
fn spawn_long_lived() -> RawChild {
    let mut cmdline: Vec<u16> = "ping -n 5 127.0.0.1\0".encode_utf16().collect();
    let mut si = STARTUPINFOEXW::default();
    let (proc, pid) =
        create_process(None, &mut cmdline, &mut si, None, &None, EXTENDED_STARTUPINFO_PRESENT.0).expect("spawn");
    RawChild::new(proc, pid)
}

#[test]
fn runas_kill_of_a_killable_child_returns_and_reaps() {
    let child = spawn_long_lived_runas();
    child
        .kill()
        .expect("kill of our own (non-elevated) runas-flagged child must succeed");
    // kill() returned (no hang). `TerminateProcess` is asynchronous — it initiates termination
    // and returns before the process object signals — so confirm the real exit via a blocking
    // wait on that event (never a racing try_wait poll, never a timer).
    let status = child.wait().expect("wait after kill");
    assert!(!status.success(), "a TerminateProcess(1) exit is non-zero: {status:?}");
}

#[test]
fn runas_teardown_on_drop_returns_promptly() {
    let child = spawn_long_lived_runas();
    child.teardown_on_drop(); // must not hang even though the runas arm is taken
    assert!(
        child.try_wait().expect("try_wait").is_some(),
        "teardown must reap a killable runas child"
    );
}

/// A Win32 failure wrapped as `HRESULT_FROM_WIN32` comes back as its Win32 code, as std's own
/// spawn reports it, so `kind()` classifies it. Any other HRESULT is kept whole.
#[test]
fn win32_io_error_unwraps_a_win32_hresult() {
    use windows::core::{Error, HRESULT};
    let dir = win32_io_error(Error::from_hresult(HRESULT(0x8007_010Bu32 as i32)));
    assert_eq!(dir.raw_os_error(), Some(267));
    assert_eq!(dir.kind(), std::io::ErrorKind::NotADirectory);
    let e_fail = win32_io_error(Error::from_hresult(HRESULT(0x8000_4005u32 as i32)));
    assert_eq!(e_fail.raw_os_error(), Some(0x8000_4005u32 as i32));
}

/// `CreateProcessW` refusing a working directory surfaces `ERROR_DIRECTORY`, not its HRESULT.
#[test]
fn a_refused_cwd_is_reported_as_its_win32_code() {
    let base = tempfile::tempdir().unwrap();
    let missing: Vec<u16> = base
        .path()
        .join("missing")
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let mut cmdline: Vec<u16> = "cmd /c exit 0\0".encode_utf16().collect();
    let mut si = STARTUPINFOEXW::default();
    let err = create_process(
        None,
        &mut cmdline,
        &mut si,
        None,
        &Some(missing),
        EXTENDED_STARTUPINFO_PRESENT.0,
    )
    .expect_err("a missing cwd must be refused");
    let crate::error::Error::Io(err) = err else {
        panic!("expected Error::Io, got {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(267), "{err:?}");
    assert_eq!(err.kind(), std::io::ErrorKind::NotADirectory, "{err:?}");
}

// Deadline-contract tests for `RawChild::wait_deadline` (site 4 of the
// "deadline-windows-never-early" bug this PR fixes; see docs/principles.md #13 — PR #233, not
// yet merged): never report "still running" before the caller's real deadline. Same seams and
// rationale as `src/wait/windows_tests.rs`'s module doc (`wait_ms_probe`, `wait_clamp_seam`,
// `remaining_override_seam`) — this site shares `crate::wait::win32_timeout_ms` with the other
// three.

fn expected_ms_unclamped(remaining: Duration) -> u32 {
    u32::try_from(remaining.as_nanos().div_ceil(1_000_000)).expect("well under u32::MAX for these tests' durations")
}

/// Ceiling, not truncation, and no added slack, for `wait_deadline`'s own `ms` computation:
/// the FIRST armed wait must use EXACTLY `ceil_millis` of a seam-forced sub-millisecond
/// `remaining` — deterministic, not dependent on landing on a sub-millisecond remainder by
/// real OS-clock chance (which real Windows wait-timer coarseness can otherwise mask).
///
/// Mutant: this site's pre-fix expression, `u32::try_from(remaining.as_millis()).unwrap_or(...)`
/// -> fails: 500µs would truncate (via `as_millis()`'s own flooring) to `0`, not ceil to `1`.
#[test]
fn wait_deadline_arms_the_ceiling_of_the_remaining_duration() {
    let child = spawn_long_lived();
    crate::wait::wait_ms_probe::take();
    crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = child.wait_deadline(deadline);
    let probed = crate::wait::wait_ms_probe::take();
    crate::wait::remaining_override_seam::take(); // defensive: consume any unused override
    let status = result.expect("a live long-lived child must not report a wait failure");
    assert!(status.is_none(), "a long-lived child must not be reported as exited this soon");
    let &(first_ms, first_remaining) = probed.first().expect("expected at least one recorded (ms, remaining) pair");
    assert_eq!(first_remaining, Duration::from_micros(500));
    assert_eq!(
        first_ms, 1,
        "500µs must ceil to 1ms exactly (not truncate to 0, not slack up to >1); got ms={first_ms}"
    );
    child.kill().expect("cleanup: kill the long-lived fixture");
    let _ = child.wait();
}

/// Never-early: once `wait_deadline` reports `None` ("still running") against a deadline, the
/// real clock must already be at or past that deadline. An end-to-end regression check for the
/// ORIGINAL bug as a whole (see `src/wait/windows_tests.rs`'s module doc for why this does not
/// pin a mutant distinct from the ceiling and re-arm tests here).
#[test]
fn wait_deadline_never_reports_still_running_before_the_deadline() {
    let child = spawn_long_lived();
    let deadline = Instant::now() + Duration::from_millis(5);
    let status = child
        .wait_deadline(deadline)
        .expect("a live long-lived child must not report a wait failure");
    assert!(status.is_none(), "a long-lived child must not be reported as exited this soon");
    assert!(
        Instant::now() >= deadline,
        "reported still-running strictly before the deadline actually passed"
    );
    child.kill().expect("cleanup: kill the long-lived fixture");
    let _ = child.wait();
}

/// The recheck loop's job: a wait capped below the real deadline (in production, the
/// `INFINITE - 1` / ~49.7-day clamp) must not be trusted as proof the deadline passed — the
/// loop must `continue` (re-arm, recomputing `remaining` FRESH every iteration), not return
/// `None` early. `wait_clamp_seam` substitutes a tiny clamp for the real one so this is
/// provable in milliseconds, not days.
///
/// Mutant: replace the deadline-recheck-and-`continue` on `WAIT_TIMEOUT` with an unconditional
/// `return Ok(None)` -> fails deterministically: `wait_deadline` would report "still running"
/// after only the clamped interval (a few ms), long before the real (200ms) deadline, AND only
/// one `(ms, remaining)` pair would be recorded.
/// Mutant: hoist the loop's `remaining` computation so it is not recomputed fresh each
/// iteration -> fails the strictly-decreasing-`remaining` assertion below.
#[test]
fn wait_deadline_re_arms_past_a_clamped_timeout() {
    let child = spawn_long_lived();
    crate::wait::wait_ms_probe::take();
    crate::wait::wait_clamp_seam::set(Some(5));
    let deadline = Instant::now() + Duration::from_millis(200);
    let result = child.wait_deadline(deadline);
    crate::wait::wait_clamp_seam::set(None);
    let probed = crate::wait::wait_ms_probe::take();
    let status = result.expect("a live long-lived child must not report a wait failure");
    assert!(status.is_none(), "a long-lived child must not be reported as exited this soon");
    assert!(
        Instant::now() >= deadline,
        "a clamped wait must re-arm and keep waiting, not report still-running at the clamp"
    );
    assert!(
        probed.len() >= 2,
        "a 5ms-clamped wait against a 200ms deadline must re-arm (>=2 recorded arms), got {}",
        probed.len()
    );
    for (ms, remaining) in &probed {
        assert_eq!(
            *ms,
            expected_ms_unclamped(*remaining).min(5),
            "every armed ms must equal exactly min(ceil_millis(remaining), clamp)"
        );
    }
    for pair in probed.windows(2) {
        assert!(
            pair[1].1 < pair[0].1,
            "remaining must strictly decrease across re-arms (recomputed fresh every \
             iteration, not hoisted and reused): {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
    child.kill().expect("cleanup: kill the long-lived fixture");
    let _ = child.wait();
}
