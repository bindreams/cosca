use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, STARTUPINFOEXW,
};

use super::{create_process, RawChild};

/// Ends and reaps the wrapped `RawChild` when dropped, including during a panicking unwind. It calls
/// `TerminateProcess` directly, not `RawChild::kill`: some tests are about `kill`, and a no-op
/// `kill` would leave the `wait` unbounded. Running after an explicit kill is harmless.
struct KillOnDrop(RawChild);

impl std::ops::Deref for KillOnDrop {
    type Target = RawChild;
    fn deref(&self) -> &RawChild {
        &self.0
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        // SAFETY: the wrapped child's live process handle.
        _ = unsafe { TerminateProcess(self.0.handle(), 1) };
        _ = self.0.wait();
    }
}

/// A `CREATE_SUSPENDED` process: its thread never runs, so it never exits on its own. Held in
/// `KillOnDrop` so a panic mid-test still kills and reaps it.
fn spawn_suspended() -> KillOnDrop {
    KillOnDrop(suspended_raw())
}

fn suspended_raw() -> RawChild {
    let (proc, pid) = suspended_handle();
    RawChild::new(proc, pid)
}

/// The owned handle and pid of a `CREATE_SUSPENDED` process, with every right.
fn suspended_handle() -> (std::os::windows::io::OwnedHandle, u32) {
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
    (proc, pid)
}

/// A handle to `owner`'s process that lacks `PROCESS_TERMINATE`, so its `TerminateProcess` is
/// denied. `owner` stays the only handle that can end it.
fn handle_without_terminate_right(owner: &KillOnDrop) -> std::os::windows::io::OwnedHandle {
    use std::os::windows::io::FromRawHandle;
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
    unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(h.0) }
}

/// A `RawChild` over [`handle_without_terminate_right`].
fn without_terminate_right(owner: &KillOnDrop) -> RawChild {
    RawChild::new(handle_without_terminate_right(owner), owner.id())
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

/// Block on the child's exit without going through `RawChild`, so nothing of the handle's own is
/// recorded. The wait is on a real external event.
fn wait_for_exit_unrecorded(handle: HANDLE) {
    // SAFETY: the caller's live process handle.
    let r = unsafe { WaitForSingleObject(handle, INFINITE) };
    assert_eq!(r, WAIT_OBJECT_0);
}

/// An exited child nobody waited on is not reaped; its own `wait` is the reap.
///
/// Mutants: `is_reaped` polls the process handle (fails the first assertion); `wait` never records
/// (fails the last).
#[skuld::test]
fn raw_is_reaped_only_once_its_own_wait_returns() {
    let child = spawn_suspended();
    assert!(!child.is_reaped());
    child.kill().expect("kill");
    // Keeps a no-op `kill` from hanging the wait below, which this test does not exercise.
    end_with_code_zero(child.handle());
    wait_for_exit_unrecorded(child.handle());
    assert!(!child.is_reaped(), "an exit nobody waited on is not a recorded reap");
    child.wait().expect("wait");
    assert!(child.is_reaped());
}

/// [`raw_is_reaped_only_once_its_own_wait_returns`], through the `ProcHandle::Raw` arm.
///
/// Mutants: the arm polls the handle; the arm answers `false`.
#[skuld::test]
fn proc_handle_raw_is_reaped_only_once_its_own_wait_returns() {
    use crate::child::proc_handle::ProcHandle;
    let handle = ProcHandle::Raw(suspended_raw());
    assert!(!handle.is_reaped());
    handle.kill().expect("kill");
    let raw = match &handle {
        ProcHandle::Raw(r) => r.handle(),
        ProcHandle::Std(_) => unreachable!(),
    };
    // Keeps a no-op `kill` from hanging the wait below, which this test does not exercise.
    end_with_code_zero(raw);
    wait_for_exit_unrecorded(raw);
    assert!(!handle.is_reaped(), "an exit nobody waited on is not a recorded reap");
    handle.wait().expect("wait");
    assert!(handle.is_reaped());
}

/// Mutants: `TerminateProcess` in `kill` a no-op reporting `Ok` or `ERROR_ACCESS_DENIED`.
#[skuld::test]
fn kill_of_a_killable_child_returns_and_reaps() {
    let child = spawn_suspended();
    // Keeps a no-op `kill` from hanging its denied-arm wait; see `end_with_code_zero`.
    let _observer = end_on_wait(&child);
    child.kill().expect("kill of our own child must succeed");
    // Keeps a no-op `kill` that reported `Ok` from hanging the wait below.
    end_with_code_zero(child.handle());
    // `TerminateProcess` is asynchronous — it initiates termination and returns before the
    // process object signals — so confirm the real exit via a blocking wait on that event
    // (never a racing try_wait poll, never a timer).
    let status = child.wait().expect("wait after kill");
    assert_eq!(status.code(), Some(1), "a TerminateProcess(1) exit is 1: {status:?}");
}

/// The identity the spawn would have read for `child`.
fn identity_of(child: &RawChild) -> crate::identity::ProcessId {
    crate::identity::ProcessId::of(child.id()).found().expect("identity")
}

/// A failed spawn's teardown whose `TerminateProcess` is refused because the process has exited (the
/// handle lacks `PROCESS_TERMINATE`, so only its signalled state shows it) leaves the only wait to
/// `wait_warning`: the kill itself does not block, so the wait is warned about once. Every exit wait
/// the teardown performs is counted.
///
/// Mutants: the teardown's `kill` reaps on the denial, a blocking wait before `wait_warning`; the
/// teardown waits directly once more before `wait_warning`.
#[cfg(feature = "tokio")]
#[skuld::test]
fn raw_spawn_teardown_with_a_denied_terminate_waits_only_inside_wait_warning() {
    use crate::error::ChildFate;

    let owner = spawn_suspended();
    let id = identity_of(&owner);
    let denied = handle_without_terminate_right(&owner);
    // Ends the process, so the wait after the denied kill returns at once.
    end_with_code_zero(owner.handle());
    owner.wait().expect("wait for the owner's child");

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let observer = super::fault::observe_waits(|| {});
    crate::child::spawn::fault::set_late_exit();
    let fate = super::super::raw_spawn_teardown(denied, owner.id(), Some(id), Some(Duration::from_secs(1)));

    assert_eq!(
        observer.waits(),
        1,
        "the kill must not wait: the one wait is the warned one"
    );
    let warns = crate::log_capture::records_since_on_current_thread(mark, "still waiting");
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert_eq!(fate, ChildFate::Reaped);
}

/// A failed spawn's teardown whose kill was refused as a termination under way (the refusal is
/// forced, so the process stays alive) and whose wait then fails cannot say the kill was delivered:
/// the fate is `Unknown`.
///
/// Mutant: the teardown answers `Killed` for any failed wait, whether or not the kill was delivered.
#[skuld::test]
fn raw_spawn_teardown_with_a_denied_terminate_and_a_failed_wait_is_unknown() {
    use crate::error::ChildFate;
    use std::os::windows::io::BorrowedHandle;

    let owner = spawn_suspended();
    // SAFETY: `owner` holds its process handle open for the whole test.
    let proc = unsafe { BorrowedHandle::borrow_raw(owner.handle().0) }
        .try_clone_to_owned()
        .expect("duplicate the process handle");
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let observer = super::fault::observe_waits(|| {});
    observer.fail_next_wait();
    let fate = super::super::raw_spawn_teardown(proc, owner.id(), None, None);
    assert_eq!(fate, ChildFate::Unknown);
    assert_eq!(observer.waits(), 1, "the teardown made the wait that failed");
}

/// A failed spawn's teardown whose `TerminateProcess` fails outright (here on an event handle, which
/// answers `ERROR_INVALID_HANDLE`) asked nothing to exit: it logs and answers `Running { id }`
/// without waiting. The event is signaled and the wait forced to fail, so a teardown that waits
/// anyway returns at once and fails the assertions.
///
/// Mutant: the failed-kill arm falls through to the wait.
#[skuld::test]
fn raw_spawn_teardown_with_a_failed_terminate_is_running_and_does_not_wait() {
    use crate::error::ChildFate;
    use std::os::windows::io::FromRawHandle;
    use windows::Win32::System::Threading::CreateEventW;

    let owner = spawn_suspended();
    let id = identity_of(&owner);
    // SAFETY: a fresh unnamed manual-reset event, signaled; the returned handle is ours alone.
    let event = unsafe { CreateEventW(None, true, true, None) }.expect("create an event");
    // SAFETY: `event` is a fresh owned handle from CreateEventW.
    let event = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(event.0) };
    let observer = super::fault::observe_waits(|| {});
    observer.fail_next_wait();
    let fate = super::super::raw_spawn_teardown(event, owner.id(), Some(id), None);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert_eq!(observer.waits(), 0, "a kill that failed must not be followed by a wait");
}

/// As above with the kill delivered: the process was ended, so the fate is `Killed`.
///
/// Mutant: the teardown answers `Unknown` for any failed wait.
#[skuld::test]
fn raw_spawn_teardown_with_a_delivered_terminate_and_a_failed_wait_is_killed() {
    use crate::error::ChildFate;

    let (proc, pid) = suspended_handle();
    let observer = super::fault::observe_waits(|| {});
    observer.fail_next_wait();
    let fate = super::super::raw_spawn_teardown(proc, pid, None, None);
    assert_eq!(fate, ChildFate::Killed);
}

/// Mutants: `TerminateProcess` in `teardown_on_drop` a no-op reporting `Ok` or
/// `ERROR_ACCESS_DENIED`; the wait after an accepted terminate dropped.
#[skuld::test]
fn teardown_on_drop_returns_promptly() {
    let child = spawn_suspended();
    // Keeps a no-op terminate from hanging teardown's wait; see `end_with_code_zero`.
    let observer = end_on_wait(&child);
    child.teardown_on_drop(identity_of(&child));
    assert_eq!(observer.waits(), 1, "teardown must block on the exit it started");
    let status = child.wait().expect("wait after teardown");
    assert_eq!(
        status.code(),
        Some(1),
        "teardown must end it with TerminateProcess(1): {status:?}"
    );
}

/// A handle without `PROCESS_TERMINATE` to a live child (a higher-integrity runas child): teardown
/// never blocks.
///
/// What it could not do comes back for the caller's one warn, and it logs nothing itself.
///
/// Mutants: reap in the `Failed` arm of `teardown_on_drop`; the arm logs its own warn instead of
/// returning it; a refusal on a handle without the right reads as the exit.
#[skuld::test]
fn teardown_on_drop_never_blocks_on_a_handle_without_terminate() {
    crate::log_capture::install();
    let owner = spawn_suspended();
    let denied = without_terminate_right(&owner);
    let observer = end_on_wait(&owner);
    let mark = crate::log_capture::mark();
    let torn = denied.teardown_on_drop(identity_of(&denied));
    assert!(
        torn.left
            .as_deref()
            .is_some_and(|text| text.contains("higher integrity")),
        "{torn:?}"
    );
    assert!(
        crate::log_capture::records_since_on_current_thread(mark, "")
            .iter()
            .all(|(level, _)| *level > log::Level::Warn),
        "the warn is the caller's"
    );
    assert_eq!(observer.waits(), 0, "teardown blocked on a child it cannot terminate");
    assert!(
        denied.try_wait().expect("try_wait").is_none(),
        "nothing ended the child"
    );
}

/// As above, for `kill`: surfaces the denial.
///
/// Mutants: reap in the `Failed` arm of `kill`; a refusal on a handle without the right reads as
/// the exit.
#[skuld::test]
fn kill_of_a_handle_without_terminate_surfaces_the_denial_without_blocking() {
    let owner = spawn_suspended();
    let denied = without_terminate_right(&owner);
    let observer = end_on_wait(&owner);
    let err = denied
        .kill()
        .expect_err("a handle without PROCESS_TERMINATE must not report success");
    assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{err:?}");
    assert_eq!(observer.waits(), 0, "kill blocked on a child it cannot terminate");
}

/// A handle without `PROCESS_TERMINATE` to a child that has exited: its signalled state is the
/// exit, so `kill` reaps it and succeeds.
///
/// Mutant: `kill` reads the refusal by the handle's rights alone, so a dead child is
/// `ERROR_ACCESS_DENIED`.
#[skuld::test]
fn kill_of_a_handle_without_terminate_to_an_exited_child_reaps_and_succeeds() {
    let owner = spawn_suspended();
    let child = without_terminate_right(&owner);
    let observer = super::fault::observe_waits(|| {});
    end_with_code_zero(owner.handle());
    wait_for_exit_unrecorded(child.handle());
    child.kill().expect("a signalled process is the exit, not a denial");
    assert_eq!(observer.waits(), 1, "kill must reap the exit it found");
    assert!(child.is_reaped());
}

/// As above, for `teardown_on_drop`: the child is `Reaped` and nothing is left running.
///
/// Mutant: `teardown_on_drop` reads the refusal by the handle's rights alone, so it leaves a dead
/// child as `Running` with a "higher integrity" warning.
#[skuld::test]
fn teardown_of_a_handle_without_terminate_to_an_exited_child_reaps_it() {
    use crate::error::ChildFate;
    let owner = spawn_suspended();
    let child = without_terminate_right(&owner);
    let observer = super::fault::observe_waits(|| {});
    end_with_code_zero(owner.handle());
    wait_for_exit_unrecorded(child.handle());
    let torn = child.teardown_on_drop(identity_of(&child));
    assert_eq!(torn.fate, ChildFate::Reaped, "{torn:?}");
    assert!(torn.left.is_none(), "{torn:?}");
    assert_eq!(observer.waits(), 1);
}

/// A child whose exit is under way but not signalled yet, on a handle that holds
/// `PROCESS_TERMINATE`: `kill` reaps it and succeeds. The seam refuses a child that stays alive;
/// the wait observer ends it.
///
/// Mutant: a refusal is the exit only for a signalled process, so `kill` is `ERROR_ACCESS_DENIED`.
#[skuld::test]
fn kill_of_an_exiting_unsignalled_child_reaps_and_succeeds() {
    let child = spawn_suspended();
    let observer = end_on_wait(&child);
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    child
        .kill()
        .expect("a refusal on a handle holding the right is the exit");
    assert_eq!(observer.waits(), 1, "kill must reap the exit it found");
}

/// As above, for `teardown_on_drop`.
///
/// Mutant: a refusal is the exit only for a signalled process, so the child is left `Running`.
#[skuld::test]
fn teardown_of_an_exiting_unsignalled_child_reaps_it() {
    use crate::error::ChildFate;
    let child = spawn_suspended();
    let observer = end_on_wait(&child);
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let torn = child.teardown_on_drop(identity_of(&child));
    assert_eq!(torn.fate, ChildFate::Reaped, "{torn:?}");
    assert!(torn.left.is_none(), "{torn:?}");
    assert_eq!(observer.waits(), 1);
}

/// A failed `GetExitCodeProcess` reports the plain Win32 code. A null handle is a real
/// `ERROR_INVALID_HANDLE`.
///
/// Mutant: `exit_status` propagates the `windows::core::Error` with `?`, whose `io::Error`
/// conversion keeps the HRESULT.
#[skuld::test]
fn a_failed_exit_status_read_is_reported_as_its_win32_code() {
    let err = super::exit_status(HANDLE::default()).expect_err("a null handle has no exit status");
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{err:?}");
}

/// `CreateProcessW` refusing a working directory surfaces `ERROR_DIRECTORY`, not its HRESULT.
#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
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

/// A failed wait after a delivered kill is `Killed`; after a refused kill nothing was delivered, so
/// the child's fate is not known. A collected status is `Reaped` either way.
///
/// Mutants: the refused kill's failed wait says `Killed`; a failed wait says `Reaped`.
#[skuld::test]
fn a_failed_wait_after_a_refused_kill_is_unknown_not_killed() {
    use crate::error::ChildFate;
    use std::os::windows::process::ExitStatusExt as _;
    let failed = || Err(std::io::Error::other("forced wait failure 3a7c"));
    let exited = || Ok(std::process::ExitStatus::from_raw(1));
    assert_eq!(super::fate_after_reap(true, failed()), ChildFate::Killed);
    assert_eq!(super::fate_after_reap(false, failed()), ChildFate::Unknown);
    assert_eq!(super::fate_after_reap(true, exited()), ChildFate::Reaped);
    assert_eq!(super::fate_after_reap(false, exited()), ChildFate::Reaped);
}

/// `kill` on a handle `TerminateProcess` rejects with something other than a denial is `Err` with
/// the plain Win32 code. An event handle is a real handle that is not a process, so the call fails
/// with `ERROR_INVALID_HANDLE`.
///
/// Mutant: the generic `Err(e)` arm of `kill` converts with `.into()`, so the code is `0x80070006`.
#[skuld::test]
fn kill_of_a_handle_that_is_not_a_process_carries_the_win32_code() {
    use std::os::windows::io::{FromRawHandle as _, OwnedHandle};
    // SAFETY: creating an unnamed event has no preconditions.
    let event = unsafe { windows::Win32::System::Threading::CreateEventW(None, true, false, None) }
        .expect("create an event handle");
    // SAFETY: `event` is a fresh handle that nothing else owns.
    let owned = unsafe { OwnedHandle::from_raw_handle(event.0) };
    let child = RawChild::new(owned, 0);
    let err = child.kill().expect_err("an event cannot be terminated");
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{err:?}");
}
