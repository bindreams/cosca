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
        _ = self.0.kill();
        _ = self.0.wait();
    }
}

/// A `CREATE_SUSPENDED` process: its thread never runs, so it never exits on its own. Held in
/// `KillOnDrop` so a panic mid-test still kills and reaps it.
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

// Deadline contract for `RawChild::wait_deadline`: never report "still running" before the real
// deadline. Seams are documented in `crate::wait`.

/// A suspended child armed with a sub-millisecond remainder rounds up to 1ms, reports `None`
/// only at the deadline, and derives its argument from the caller's deadline.
///
/// Mutant: truncate in `win32_timeout_ms` -> `ms` is 0. Mutant: add slack -> `ms` is above 1.
/// Mutant: ignore the caller's deadline -> `requested` is not 5ms.
#[test]
fn wait_deadline_arms_the_ceiling_of_the_remaining_duration() {
    let child = spawn_suspended();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    let deadline = at + Duration::from_millis(5);
    let result = child.wait_deadline(deadline);
    let reached = Instant::now() >= deadline;
    let arms = crate::wait::wait_ms_probe::take();
    let status = result.expect("a live suspended child must not report a wait failure");
    assert!(status.is_none(), "a suspended child never exits");
    assert!(reached, "the call returned before the real deadline");
    let first = arms.first().expect("at least one armed wait");
    assert_eq!(first.remaining, Duration::from_micros(500));
    assert_eq!(first.ms, 1);
    assert_eq!(
        first.requested,
        Duration::from_millis(5),
        "the site must pass the time left to the caller's deadline (clock frozen at its origin)"
    );
}

/// An early, unclamped `WAIT_TIMEOUT` hours before the deadline is not trusted: the site
/// re-arms and reports the real exit.
///
/// Mutant: return `None` on the first `WAIT_TIMEOUT` -> one arm, wrongly reports running.
#[test]
fn wait_deadline_never_reports_still_running_before_the_deadline() {
    let child = spawn_suspended();
    let raw_handle = child.handle(); // Copy; valid until `child` drops after the call
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    crate::wait::wait_ms_probe::on_second_arm(move || {
        // SAFETY: `child` outlives `wait_deadline`, which returns after this hook runs.
        unsafe {
            _ = windows::Win32::System::Threading::TerminateProcess(raw_handle, 1);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(3600);
    let result = child.wait_deadline(deadline);
    let arms = crate::wait::wait_ms_probe::take();
    let status = result.expect("a genuinely-terminated child must not report a wait failure");
    assert!(status.is_some(), "an early WAIT_TIMEOUT was trusted");
    assert!(arms.len() >= 2, "expected a re-arm, got {} arm(s)", arms.len());
}

/// A wait clamped below the deadline re-arms, recomputing `remaining` each round.
///
/// Mutant: return `None` on the first `WAIT_TIMEOUT` -> one arm, wrongly reports running.
/// Mutant: hoist `remaining` above the loop -> `remaining` does not shrink.
#[test]
fn wait_deadline_re_arms_past_a_clamped_timeout() {
    let child = spawn_suspended();
    let raw_handle = child.handle();
    crate::wait::wait_ms_probe::take();
    let _clamp = crate::wait::wait_clamp_seam::set(5);
    crate::wait::wait_ms_probe::on_second_arm(move || {
        // SAFETY: see `wait_deadline_never_reports_still_running_before_the_deadline`.
        unsafe {
            _ = windows::Win32::System::Threading::TerminateProcess(raw_handle, 1);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(3600);
    let result = child.wait_deadline(deadline);
    let arms = crate::wait::wait_ms_probe::take();
    let status = result.expect("a genuinely-terminated child must not report a wait failure");
    assert!(status.is_some(), "a clamped WAIT_TIMEOUT was trusted");
    crate::wait::wait_ms_probe::assert_rearmed_with_fresh_remaining(&arms, 5);
}
