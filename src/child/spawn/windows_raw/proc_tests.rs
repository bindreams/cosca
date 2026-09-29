use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

use windows::Win32::System::Threading::{CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};

use super::{create_process, win32_io_error, RawChild};

/// Kills and reaps the wrapped `RawChild` when dropped — including during a panicking unwind —
/// so a deadline-contract test fixture never leaks a live process if an assertion fails
/// partway through. `RawChild::kill`/`wait` are both idempotent (an already-exited/-killed
/// child is success), so this is safe even if a test also kills it explicitly on its own
/// happy path.
struct KillOnDrop(RawChild);

impl std::ops::Deref for KillOnDrop {
    type Target = RawChild;
    fn deref(&self) -> &RawChild {
        &self.0
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A `CREATE_SUSPENDED` process: its one thread never runs, so it never exits on its own — a
/// fixture with no lifetime to race, unlike a real `ping` (whose ~4s run is a bet: a slow CI
/// host could let a deadline-contract test observe it exit mid-test, or a failed assertion
/// could skip a plain `kill()` cleanup and leak it running). Held in `KillOnDrop` so a panic
/// mid-test still kills and reaps it.
fn spawn_suspended() -> KillOnDrop {
    let mut cmdline: Vec<u16> = "cmd /C exit 0\0".encode_utf16().collect(); // never actually runs
    let mut si = STARTUPINFOEXW::default();
    let (proc, pid) = create_process(
        None,
        &mut cmdline,
        &mut si,
        None,
        &None,
        EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_SUSPENDED.0,
    )
    .expect("spawn suspended");
    KillOnDrop(RawChild::new(proc, pid))
}

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
// "deadline-windows-never-early" bug this PR fixes; see docs/principles.md #13): never report "still running" before the caller's real deadline. Same seams and
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
    let child = spawn_suspended();
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = child.wait_deadline(deadline);
    let probed = crate::wait::wait_ms_probe::take();
    let status = result.expect("a live suspended child must not report a wait failure");
    assert!(
        status.is_none(),
        "a suspended child must not be reported as exited this soon"
    );
    let &(first_ms, first_remaining) = probed
        .first()
        .expect("expected at least one recorded (ms, remaining) pair");
    assert_eq!(first_remaining, Duration::from_micros(500));
    assert_eq!(
        first_ms, 1,
        "500µs must ceil to 1ms exactly (not truncate to 0, not slack up to >1); got ms={first_ms}"
    );
    // `child` (`KillOnDrop`) kills and reaps the suspended process when it drops here.
}

/// Never-early: a `WAIT_TIMEOUT` must NEVER be trusted as proof the real deadline passed,
/// whether or not this round's wait happened to be clamped. Per Microsoft's Wait Functions and
/// Time-out Intervals, "the wait may time out in less than the specified length of time" even
/// for an UN-clamped, correctly-ceiled interval — so a recheck conditioned on "was this arm
/// clamped" is exactly as wrong as no recheck at all. `remaining_override_seam` simulates that
/// directly: the FIRST arm is forced to a tiny, UN-clamped 500µs against a real deadline that is
/// HOURS away. `on_second_arm` fires the instant the loop re-arms a second time, terminating the
/// suspended fixture for real; the wait must resolve via that genuine exit event, never an early
/// "still running" verdict.
///
/// Mutant: trust an un-clamped `WAIT_TIMEOUT` outright (no recheck at all, or a recheck
/// conditioned on "was this arm clamped") -> fails: returns after the first (forced,
/// un-clamped) arm, `probed.len() == 1`, and the result wrongly claims "still running" even
/// though the real deadline is hours off.
#[test]
fn wait_deadline_never_reports_still_running_before_the_deadline() {
    let child = spawn_suspended();
    let raw_handle = child.handle(); // Copy; stays valid — `child` isn't dropped until below
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    crate::wait::wait_ms_probe::on_second_arm(move || {
        // SAFETY: `child`'s `OwnedHandle` is still alive at this point — it is not dropped
        // until after `wait_deadline` returns below, which is strictly after this hook runs.
        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(raw_handle, 1);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(3600); // hours off: nowhere near expiry
    let result = child.wait_deadline(deadline);
    let probed = crate::wait::wait_ms_probe::take();
    let status = result.expect("a genuinely-terminated child must not report a wait failure");
    assert!(
        status.is_some(),
        "must report exited once genuinely killed, not falsely conclude still-running from an \
         early, un-clamped WAIT_TIMEOUT"
    );
    assert!(
        probed.len() >= 2,
        "must re-arm past the first (forced-early, un-clamped) WAIT_TIMEOUT rather than \
         trusting it outright, got {} arm(s)",
        probed.len()
    );
}

/// The recheck loop's job under a REAL clamp (distinct from the un-clamped early-timeout path
/// the test above exercises): a wait capped below the real deadline (in production, the
/// `INFINITE - 1` / ~49.7-day clamp) must not be trusted as proof the deadline passed — the
/// loop must `continue` (re-arm, recomputing `remaining` FRESH every iteration), not return
/// `None` early. `wait_clamp_seam` substitutes a tiny 5ms clamp for the real one against a real
/// deadline that is hours away, so EVERY round is genuinely clamped. `on_second_arm` ends the
/// wait deterministically via a real exit event — not a race against how much real time a fixed
/// window (e.g. a 200ms real deadline) leaves for setup plus however many re-arms complete in
/// it (this is also why the fixture is a `CREATE_SUSPENDED` process, not a real `ping -n 5`
/// with its own ~4s lifetime to race).
///
/// Mutant: replace the deadline-recheck-and-`continue` on `WAIT_TIMEOUT` with an unconditional
/// `return Ok(None)` -> fails deterministically: `probed.len() == 1`, and the result wrongly
/// claims "still running" (the hook, gated on a second arm, never fires).
/// Mutant: hoist the loop's `remaining` computation so it is not recomputed fresh each
/// iteration -> fails the strictly-decreasing-`remaining` assertion below.
#[test]
fn wait_deadline_re_arms_past_a_clamped_timeout() {
    let child = spawn_suspended();
    let raw_handle = child.handle();
    crate::wait::wait_ms_probe::take();
    let _clamp = crate::wait::wait_clamp_seam::set(5);
    crate::wait::wait_ms_probe::on_second_arm(move || {
        // SAFETY: see `wait_deadline_never_reports_still_running_before_the_deadline` above.
        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(raw_handle, 1);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(3600); // hours off: always clamped
    let result = child.wait_deadline(deadline);
    let probed = crate::wait::wait_ms_probe::take();
    let status = result.expect("a genuinely-terminated child must not report a wait failure");
    assert!(
        status.is_some(),
        "must report exited once genuinely killed, not falsely conclude still-running at the \
         clamp"
    );
    assert!(
        probed.len() >= 2,
        "a 5ms-clamped wait must re-arm (>=2 recorded arms) before the real exit event, got {}",
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
}
