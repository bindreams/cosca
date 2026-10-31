//! The Win32 code of the cancel event's creation failure.

use windows::core::HRESULT;
use windows::Win32::Foundation::ERROR_NOT_ENOUGH_MEMORY;

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
