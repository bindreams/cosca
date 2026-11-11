use std::os::windows::io::BorrowedHandle;

use windows::Win32::Foundation::ERROR_INVALID_HANDLE;

use super::OwnedJobDup;

/// A Win32 failure inside the containment layer reaches the caller as its plain Win32 code, so
/// `kind()` and `raw_os_error()` classify it. A null handle is a real `ERROR_INVALID_HANDLE`.
///
/// Mutant: `OwnedJobDup::new` converts with the `windows` crate's own `io::Error` conversion, which
/// keeps the HRESULT (`0x80070006`).
#[skuld::test]
fn duplicate_failure_carries_the_win32_code() {
    // SAFETY: the value is only handed to `DuplicateHandle`, which refuses it; this test needs a
    // handle the OS refuses.
    let null = unsafe { BorrowedHandle::borrow_raw(std::ptr::null_mut()) };
    let Err(err) = OwnedJobDup::new(null) else {
        panic!("duplicating a null handle must fail");
    };
    let crate::error::Error::Io(err) = err else {
        panic!("expected Error::Io, got {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{err:?}");
}
