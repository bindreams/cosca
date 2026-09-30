//! A test that traces its own child, outside the helper's contract: the helper is a separate
//! process that is never the tracee's parent, and this is the parent attaching itself.

use std::time::Duration;

use super::sys::{self, Stop};

/// Why [`attach_settled`] did not return a settled stop.
#[derive(Debug)]
pub(crate) enum AttachError {
    /// A request failed with this errno.
    Errno(i32),
    /// The tracee exited before it stopped, so no stop is coming: the `waitid` `si_code`
    /// (`CLD_EXITED` 1, `CLD_KILLED` 2, `CLD_DUMPED` 3) and `si_status`.
    Exited { code: i32, status: i32 },
}

/// Attach this process to its own child `pid` and return once the stop has settled, so the caller
/// can act on it ([`sys::stop`] says why the settling matters). Unlike [`start`](super::start)'s
/// helper, the caller is the tracee's parent and the tracer.
///
/// The stop does wake a waiting parent (`psignal(pp, SIGCHLD)` and `wakeup(pp)`, xnu-12377.121.6
/// `kern_sig.c:2777-2779`), but before the stopping thread parks in `assert_wait` (`:2784`), and
/// nothing signals the park. So this re-checks under a capped backoff: a deterministic
/// condition, not a bet on time. It ends when the stop settles or the tracee is gone; an exited
/// tracee never stops, so without that exit this would spin.
pub(crate) fn attach_settled(pid: u32) -> Result<(), AttachError> {
    sys::attach(pid).map_err(AttachError::Errno)?;
    settle(|| sys::stop(pid), || sys::peek(pid, libc::WEXITED | libc::WNOHANG))
}

/// The stop's signal if `pid`'s stop has settled, without consuming it.
pub(crate) fn settled_stop(pid: u32) -> Result<Option<i32>, i32> {
    Ok(match sys::stop(pid)? {
        Stop::Stopped(signal) => Some(signal),
        Stop::Running | Stop::Settling => None,
    })
}

/// [`attach_settled`]'s loop over its two reads: the `stop` peek, and the `exited` peek that
/// runs only while no settled stop is seen.
fn settle(
    mut stop: impl FnMut() -> Result<Stop, i32>,
    mut exited: impl FnMut() -> Result<libc::siginfo_t, i32>,
) -> Result<(), AttachError> {
    let mut backoff = Duration::from_millis(1);
    loop {
        match stop().map_err(AttachError::Errno)? {
            Stop::Stopped(_) => return Ok(()),
            Stop::Running | Stop::Settling => {
                // macOS reports a stop to a `WEXITED` wait too, so `si_code` says which it is.
                let exited = exited().map_err(AttachError::Errno)?;
                if exited.si_pid != 0
                    && matches!(exited.si_code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
                {
                    return Err(AttachError::Exited {
                        code: exited.si_code,
                        status: exited.si_status,
                    });
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_millis(50));
            }
        }
    }
}

#[cfg(test)]
#[path = "attach_tests.rs"]
mod attach_tests;
