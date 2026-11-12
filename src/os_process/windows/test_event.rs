//! An unnamed event, the stand-in for a waitable handle in the tests of the Windows waits.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateEventW, SetEvent};

use crate::error::{win32_io_error, Error};

/// An unnamed manual-reset event, initially unsignaled. Signal with [`signal_test_event`];
/// `OwnedHandle` closes it.
pub(crate) fn new_test_event() -> Result<OwnedHandle, Error> {
    // SAFETY: creating an unnamed event has no preconditions.
    let h = unsafe { CreateEventW(None, true, false, None) }.map_err(|e| Error::Io(win32_io_error(e)))?;
    // SAFETY: `h` is a freshly created, owned event handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0 as _) })
}

/// Signal `event`, which stays signalled.
pub(crate) fn signal_test_event(event: &OwnedHandle) {
    // SAFETY: `event` is a live event handle (the OwnedHandle keeps it open).
    unsafe { SetEvent(HANDLE(event.as_raw_handle())) }.expect("SetEvent on an owned event handle");
}
