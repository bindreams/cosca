use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, STARTUPINFOEXW,
};

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
    spawn_suspended_as(RawChild::new)
}

/// [`spawn_suspended`] as a non-elevated runas child, so `RawChild`'s runas arms run.
fn spawn_suspended_runas() -> KillOnDrop {
    spawn_suspended_as(RawChild::new_runas)
}

fn spawn_suspended_as(wrap: fn(std::os::windows::io::OwnedHandle, u32) -> RawChild) -> KillOnDrop {
    let mut cmdline: Vec<u16> = "cmd /C exit 0\0".encode_utf16().collect();
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
    KillOnDrop(wrap(proc, pid))
}

/// A runas `RawChild` over a second handle to `owner`'s process that lacks `PROCESS_TERMINATE`,
/// so its `TerminateProcess` is denied. `owner` stays the only handle that can end it.
fn runas_without_terminate_right(owner: &KillOnDrop) -> RawChild {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    // SAFETY: plain OpenProcess on the live pid `owner` pins.
    let h = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            owner.id(),
        )
    }
    .expect("open without PROCESS_TERMINATE");
    // SAFETY: `h` is a fresh owned handle from OpenProcess.
    RawChild::new_runas(unsafe { OwnedHandle::from_raw_handle(h.0) }, owner.id())
}

/// End `handle` with exit code 0, which only a process no earlier `TerminateProcess` has claimed
/// takes: a real kill (exit 1) has already marked the thread terminated, so a later
/// `TerminateProcess` cannot change the exit code. That later call returns success or
/// `ERROR_ACCESS_DENIED` depending on timing; any other error is a test bug.
fn end_with_code_zero(handle: HANDLE) {
    // SAFETY: the caller's live process handle.
    match unsafe { TerminateProcess(handle, 0) } {
        Ok(()) => {}
        Err(e) if e.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {}
        Err(e) => panic!("TerminateProcess(handle, 0) failed: {e:?}"),
    }
}

/// Arm the wait observer to end `owner`'s child with exit code 0 before every blocking reap.
fn end_on_wait(owner: &KillOnDrop) -> super::fault::Observer {
    let handle = owner.handle();
    super::fault::observe_waits(move || end_with_code_zero(handle))
}

/// Mutants: `is_reaped` answers `false`; `is_reaped` answers `true`.
#[test]
fn raw_is_reaped_after_exit() {
    let child = spawn_suspended();
    assert!(!child.is_reaped(), "a suspended child has not exited");
    child.kill().expect("kill");
    child.wait().expect("wait");
    assert!(child.is_reaped());
}

/// Mutants: `TerminateProcess` in `kill` a no-op reporting `Ok` or `ERROR_ACCESS_DENIED`.
#[test]
fn runas_kill_of_a_killable_child_returns_and_reaps() {
    let child = spawn_suspended_runas();
    // Keeps a no-op `kill` from hanging its denied-arm wait; see `end_with_code_zero`.
    let _observer = end_on_wait(&child);
    child
        .kill()
        .expect("kill of our own (non-elevated) runas-flagged child must succeed");
    // Keeps a no-op `kill` that reported `Ok` from hanging the wait below.
    end_with_code_zero(child.handle());
    // `TerminateProcess` is asynchronous — it initiates termination and returns before the
    // process object signals — so confirm the real exit via a blocking wait on that event
    // (never a racing try_wait poll, never a timer).
    let status = child.wait().expect("wait after kill");
    assert_eq!(status.code(), Some(1), "a TerminateProcess(1) exit is 1: {status:?}");
}

/// Mutants: `TerminateProcess` in `teardown_on_drop` a no-op reporting `Ok` or
/// `ERROR_ACCESS_DENIED`; the wait after an accepted terminate dropped.
#[test]
fn runas_teardown_on_drop_returns_promptly() {
    let child = spawn_suspended_runas();
    // Keeps a no-op terminate from hanging teardown's wait; see `end_with_code_zero`.
    let observer = end_on_wait(&child);
    child.teardown_on_drop();
    assert_eq!(observer.waits(), 1, "teardown must block on the exit it started");
    let status = child.wait().expect("wait after teardown");
    assert_eq!(
        status.code(),
        Some(1),
        "teardown must end it with TerminateProcess(1): {status:?}"
    );
}

/// The runas `ERROR_ACCESS_DENIED` arm with a child we CAN terminate (`can_terminate` is true):
/// the denial means exit is underway, so teardown reaps.
///
/// Mutant: drop `&& !self.can_terminate()`, so a terminable runas child is left running.
#[test]
fn runas_teardown_on_drop_reaps_when_terminate_is_denied_but_permitted() {
    let owner = spawn_suspended();
    let denied = runas_without_terminate_right(&owner);
    let observer = end_on_wait(&owner);
    denied.teardown_on_drop();
    assert_eq!(observer.waits(), 1, "a terminable runas child's denial must be reaped");
    let status = denied.wait().expect("wait after teardown");
    assert_eq!(
        status.code(),
        Some(0),
        "only the observer's terminate ended it: {status:?}"
    );
}

/// As above, for `kill`.
///
/// Mutant: drop `&& !self.can_terminate()` in `kill`, so it returns `ERROR_ACCESS_DENIED`.
#[test]
fn runas_kill_reaps_when_terminate_is_denied_but_permitted() {
    let owner = spawn_suspended();
    let denied = runas_without_terminate_right(&owner);
    let observer = end_on_wait(&owner);
    denied
        .kill()
        .expect("a denial on a terminable runas child means exit is underway");
    assert_eq!(observer.waits(), 1, "kill must reap that exit");
}

/// The runas `ERROR_ACCESS_DENIED` arm with a child we cannot terminate: never block.
///
/// Mutant: reap in the `runas && !can_terminate()` arm of `teardown_on_drop`.
#[test]
fn runas_teardown_on_drop_never_blocks_on_an_unterminable_child() {
    let owner = spawn_suspended();
    let denied = runas_without_terminate_right(&owner);
    let observer = end_on_wait(&owner);
    observer.force_unterminable();
    denied.teardown_on_drop();
    assert_eq!(observer.waits(), 0, "teardown blocked on a child it cannot terminate");
    assert!(
        denied.try_wait().expect("try_wait").is_none(),
        "nothing ended the child"
    );
}

/// As above, for `kill`: surfaces the denial.
///
/// Mutant: reap in the `runas && !can_terminate()` arm of `kill`.
#[test]
fn runas_kill_of_an_unterminable_child_surfaces_the_denial_without_blocking() {
    let owner = spawn_suspended();
    let denied = runas_without_terminate_right(&owner);
    let observer = end_on_wait(&owner);
    observer.force_unterminable();
    let err = denied
        .kill()
        .expect_err("an unterminable runas child must not report success");
    assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{err:?}");
    assert_eq!(observer.waits(), 0, "kill blocked on a child it cannot terminate");
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
