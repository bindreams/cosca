//! Deadline contract of `wait_until`, and the Win32 codes of the handle primitives' failures. Seams
//! are documented in `crate::wait`.

use std::time::Duration;

use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_NOT_ENOUGH_MEMORY, HANDLE};
use windows::Win32::System::Threading::CreateEventW;

use crate::identity::ProcessId;
use crate::wait::test_clock::FrozenClockGuard;

/// `wait_until` with its frozen-clock advance dropped fails at the second round.
///
/// Mutant: drop the `advance_by_elapsed_if_frozen` call in `rearm_until` -> same panic, without
/// the seam. Mutant: drop `rearm_until`'s `check.round()` -> the second round fails the test with
/// a different message, instead of the loop spinning forever.
#[skuld::test]
#[should_panic(expected = "no progress")]
fn wait_until_panics_when_its_advance_is_dropped() {
    use windows::Win32::Foundation::WAIT_TIMEOUT;

    let (_clock, at) = FrozenClockGuard::install();
    let _skip = crate::wait::test_clock::SkipAdvanceGuard::install();
    let deadline = Some(Some(at + Duration::from_secs(3600)));
    let mut waits = 0;
    crate::wait::wait_until(deadline, |_ms| {
        waits += 1;
        assert!(waits < 2, "the check let a second round run");
        WAIT_TIMEOUT
    });
}

// Win32 codes of failures =====
//
// Each site converts a `windows::core::Error` to an `io::Error`. A bare `.into()` keeps the
// HRESULT (`0x8007xxxx`) where std reports the Win32 code, so each test drives the failing call
// and asserts the code.

/// An event handle: a real handle that is not a process, so `GetProcessTimes` and
/// `TerminateProcess` on it fail with `ERROR_INVALID_HANDLE`. The callee under test closes it.
fn event_handle() -> HANDLE {
    // SAFETY: creating an unnamed event has no preconditions.
    unsafe { CreateEventW(None, true, false, None) }.expect("create an event handle")
}

/// An identity that cannot be read from the held handle is `Unassessable` with the plain Win32
/// code, for `open_verified` and `open_verified_for_kill`, which share `holds_process`.
///
/// Mutant: `holds_process` converts with `.into()`, so the source's code is `0x80070006`.
#[skuld::test]
fn holds_process_of_an_unreadable_handle_carries_the_win32_code() {
    let err = super::holds_process(event_handle(), ProcessId::current()).expect_err("an event has no creation time");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("expected Unassessable, got {err:?}");
    };
    let io = source.expect("the OS error is preserved");
    assert_eq!(io.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{io:?}");
}

/// A `CreateEventW` failure is `Io` with the plain Win32 code. The call cannot be made to fail, so
/// the failure is injected at `owned_event`.
///
/// Mutant: `owned_event` converts with `.into()`, so the code is `0x80070008`.
#[skuld::test]
fn owned_event_failure_carries_the_win32_code() {
    let failed = windows::core::Error::from_hresult(HRESULT::from_win32(ERROR_NOT_ENOUGH_MEMORY.0));
    let err = super::owned_event(Err(failed)).expect_err("the creation failed");
    let crate::error::Error::Io(io) = err else {
        panic!("expected Io, got {err:?}");
    };
    assert_eq!(io.raw_os_error(), Some(ERROR_NOT_ENOUGH_MEMORY.0 as i32), "{io:?}");
}

/// `open_verified` on a live process we may not open is `Unassessable` with the plain Win32 code.
/// Needs the DACL fixture, which creates a Job Object: CI only.
///
/// Mutant: the `Opened::Denied` arm of `open_verified` converts with `.into()`, so the code is
/// `0x80070005`.
#[skuld::test]
fn open_verified_of_an_access_denied_live_process_carries_the_win32_code() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(open_verified_of_an_access_denied_live_process_carries_the_win32_code),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let io = denied_open_source(&done, |id| crate::wait::backend::open_verified(id).map(|_| ()));
    assert_eq!(io.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{io:?}");
}

/// The `Unassessable` source of a refused open of the unkillable fixture, which `call` runs `id`
/// through. Needs the DACL fixture, which creates a Job Object: CI only.
fn denied_open_source(
    done: &crate::test_own_process::Completion,
    call: impl FnOnce(ProcessId) -> Result<(), crate::error::Error>,
) -> std::io::Error {
    let child = crate::identity::windows_fixture::spawn_unkillable(done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let err = call(id).expect_err("an unopenable live process is not 'gone'");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("expected Unassessable, got {err:?}");
    };
    source.expect("the OS error is preserved")
}
