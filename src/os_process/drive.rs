//! The synchronous wait loop over an [`OsProcess`].

use std::time::{Duration, Instant};

use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
use crate::wait::remaining;

/// Block until `p` has exited or `timeout` has passed, and say which. `Ok(true)` = exited;
/// `Ok(false)` = still running after the deadline's final look. `None` = until exit;
/// `Some(ZERO)` = one look, no blocking call; a `Duration` too large for the clock is unbounded.
/// Non-reaping. Every blocking call is armed from the time remaining, read right before it.
pub(crate) fn exited_by(p: &mut dyn OsProcess, timeout: Option<Duration>) -> Result<bool, Error> {
    #[cfg(feature = "tokio")]
    crate::bounded::assert_may_block("waiting for a process to exit");
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    // Absolute up front, so no wake extends the total wait.
    let deadline = timeout.and_then(crate::wait::deadline_from);
    loop {
        // Read before the look: a look made at or after the deadline is the final one.
        let final_look = remaining(deadline) == Some(Duration::ZERO);
        match p.exited()? {
            Exit::Exited => return Ok(true),
            Exit::Running(_) if final_look => return Ok(false),
            Exit::Running(wait_for) => {
                if remaining(deadline) != Some(Duration::ZERO) {
                    block(&wait_for, deadline)?;
                }
            }
        }
    }
}

/// Block on `wait_for` until it wakes or `deadline` passes. The caller looks again either way.
fn block(wait_for: &WaitFor<'_>, deadline: Option<Option<Instant>>) -> Result<(), Error> {
    match wait_for {
        #[cfg(target_os = "linux")]
        WaitFor::Readable(pidfd) => {
            crate::wait::poll_pidfd_exit(*pidfd, deadline).map_err(Error::Io)?;
        }
        #[cfg(target_os = "macos")]
        WaitFor::Kqueue(watch) => {
            #[cfg(test)]
            crate::wait::block_probe::record(remaining(deadline));
            watch.block(deadline)?;
        }
        #[cfg(windows)]
        WaitFor::Signalled(process) => {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows::Win32::System::Threading::WaitForSingleObject;

            let handle = HANDLE(process.as_raw_handle());
            let waited = crate::wait::wait_until(deadline, |ms| {
                #[cfg(test)]
                crate::wait::block_probe::record((ms != u32::MAX).then(|| Duration::from_millis(ms.into())));
                // SAFETY: `handle` is borrowed from `wait_for`, which outlives the call.
                unsafe { WaitForSingleObject(handle, ms) }
            });
            if waited != WAIT_OBJECT_0 && waited != WAIT_TIMEOUT {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod drive_tests;
