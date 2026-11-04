//! Windows `exit_only`: a process handle. There is no reap; a signalled handle's exit code is
//! final.

use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::WaitForSingleObject;

use super::{Reap, Target};
use crate::os_process::child::{ExitRecord, PeekOutcome};

fn handle<'a>(target: &Target<'a>) -> BorrowedHandle<'a> {
    match target {
        Target::Handle(h) => *h,
    }
}

/// `GetExitCodeProcess` on a signalled handle. The code is the status even when it is 259
/// (`STILL_ACTIVE`): a child may exit with that code, and nothing re-reads it as "running".
pub(crate) fn exit_status(h: BorrowedHandle<'_>) -> io::Result<std::process::ExitStatus> {
    crate::child::spawn::windows_raw::exit_status(HANDLE(h.as_raw_handle()))
}

pub(super) fn peek(target: &Target<'_>) -> io::Result<PeekOutcome> {
    let h = handle(target);
    // SAFETY: `h` is a live process handle borrowed for the call; a zero timeout polls.
    let r = unsafe { WaitForSingleObject(HANDLE(h.as_raw_handle()), 0) };
    if r == WAIT_OBJECT_0 {
        Ok(PeekOutcome::Exit(ExitRecord::Status(exit_status(h)?)))
    } else if r == WAIT_TIMEOUT {
        Ok(PeekOutcome::Running)
    } else {
        let e = io::Error::last_os_error();
        // A wait on our own process handle, which carries `SYNCHRONIZE`, does not fail: a failure
        // is a closed or invalid handle, our bug.
        debug_assert!(
            false,
            "WaitForSingleObject on our own process handle returned {r:?}: {e}"
        );
        Err(e)
    }
}

pub(super) fn try_reap(target: &Target<'_>) -> io::Result<Reap> {
    match peek(target)? {
        PeekOutcome::Exit(record) => Ok(Reap::Reaped(record)),
        PeekOutcome::Running => Ok(Reap::Running),
        PeekOutcome::Foreign(f) => Ok(Reap::Foreign(f)),
    }
}
