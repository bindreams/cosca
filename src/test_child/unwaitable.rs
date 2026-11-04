//! A Windows handle on which every `WaitForSingleObject` fails.

use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// A handle to this process opened without `SYNCHRONIZE`, so a wait on it fails with
/// `ERROR_ACCESS_DENIED`. Unlike a closed handle's value, it stays this test's until dropped: no
/// other thread can be handed the same value.
pub(crate) fn unwaitable_handle() -> OwnedHandle {
    // SAFETY: opening this process has no preconditions.
    let opened = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, GetCurrentProcessId()) }
        .expect("open this process without SYNCHRONIZE");
    // SAFETY: `opened` is a fresh owned handle from `OpenProcess`.
    unsafe { OwnedHandle::from_raw_handle(opened.0) }
}
