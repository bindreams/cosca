//! Windows `exit_only`: a process handle. There is no reap; a signalled handle's exit code is
//! final.

use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::WaitForSingleObject;

use super::{Peek, Reap, Reaped, Target};

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

pub(super) fn peek(target: &Target<'_>) -> io::Result<Peek> {
    let h = handle(target);
    // SAFETY: `h` is a live process handle borrowed for the call; a zero timeout polls.
    let r = unsafe { WaitForSingleObject(HANDLE(h.as_raw_handle()), 0) };
    if r == WAIT_OBJECT_0 {
        Ok(Peek::Exit(Reaped::Status(exit_status(h)?)))
    } else if r == WAIT_TIMEOUT {
        Ok(Peek::Running)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn try_reap(target: &Target<'_>) -> io::Result<Reap> {
    match peek(target)? {
        Peek::Exit(reaped) => {
            #[cfg(test)]
            if let Some(forced) = super::seams::take_forced_reap() {
                return match forced {
                    super::seams::ForcedReap::None => Ok(Reap::Running),
                    super::seams::ForcedReap::Errno(e) => Err(io::Error::from_raw_os_error(e)),
                };
            }
            Ok(Reap::Reaped(reaped))
        }
        Peek::Running => Ok(Reap::Running),
        Peek::Foreign(f) => Ok(Reap::Foreign(f)),
    }
}
