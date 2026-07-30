//! Non-reaping, race-free death-watch and hard-kill for a `ProcessId`. `block_until_exit`
//! blocks the calling thread in ONE kernel syscall until exit or timeout (no sleep-poll).
//! NEVER reaps: the target's real parent collects the zombie.

use std::time::{Duration, Instant};

use crate::error::Error;
use crate::identity::ProcessId;

#[cfg_attr(target_os = "linux", path = "wait/linux.rs")]
#[cfg_attr(target_os = "macos", path = "wait/macos.rs")]
#[cfg_attr(windows, path = "wait/windows.rs")]
pub(crate) mod backend;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("cosca::wait is implemented only for Linux, macOS, and Windows");

/// Force the NEXT grace-watch on THIS thread to fail (consumed by `block_until_exit`,
/// `Child::wait_timeout`, and `tokio::wait::{grace_wait, wait_exit}`), so the watch-error
/// escalation ordering is testable. Same take-semantics contract as the treewalk fault seam.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    thread_local! {
        static FORCE_WATCH_ERROR: Cell<bool> = const { Cell::new(false) };
    }
    pub(crate) fn set_force_watch_error(on: bool) {
        FORCE_WATCH_ERROR.with(|f| f.set(on));
    }
    pub(crate) fn take_force_watch_error() -> bool {
        FORCE_WATCH_ERROR.with(|f| f.replace(false))
    }
    pub(crate) fn armed() -> bool {
        FORCE_WATCH_ERROR.with(|f| f.get())
    }
    pub(crate) fn forced_watch_error() -> crate::error::Error {
        crate::error::Error::Io(std::io::Error::other("forced grace-watch failure (test seam)"))
    }
}

/// Block until the process with identity `id` exits. `Ok(true)` = exited; `Ok(false)`
/// = the timeout elapsed while it was still alive; `Err` = a wait failure (incl.
/// `Unsupported` on Linux kernels < 5.3). `None` = block until exit; `Some(ZERO)` =
/// poll once; an overflowing `Duration` saturates to unbounded. Non-reaping.
///
/// Cross-privilege divergence: when the caller lacks rights to wait on a *live* foreign
/// process, macOS surfaces the permission failure as `Err` whereas Windows cannot open the
/// handle and reports `Ok(true)` (matching [`ProcessId::is_alive`]'s open-failure convention).
pub(crate) fn block_until_exit(id: ProcessId, timeout: Option<Duration>) -> Result<bool, Error> {
    #[cfg(test)]
    if fault::take_force_watch_error() {
        return Err(fault::forced_watch_error());
    }
    // Convert to an absolute deadline up front so EINTR retries don't extend the total wait.
    let deadline = timeout.map(|d| Instant::now().checked_add(d));
    backend::block_until_exit(id, deadline)
}

/// Hard-kill the process with identity `id` (`SIGKILL` / `TerminateProcess`),
/// identity-verified. Already-dead ⇒ `Ok`; a real failure (no rights / `EPERM`) ⇒ `Err`.
pub(crate) fn kill(id: ProcessId) -> Result<(), Error> {
    backend::kill(id)
}

/// Send the graceful termination signal (`SIGTERM`) to the process with identity `id`,
/// identity-verified. Signal-only — does not wait or reap. Already-dead ⇒ `Ok`; a real
/// failure (no rights / `EPERM`) ⇒ `Err`. Windows has no per-process graceful signal ⇒
/// `Unsupported`.
pub(crate) fn terminate(id: ProcessId) -> Result<(), Error> {
    backend::terminate(id)
}

/// Remaining time until `deadline` (`None` = unbounded; `Some(None)` = a duration
/// that overflowed `Instant` ⇒ unbounded). Saturates to ZERO once past. Shared by the
/// backends to recompute the per-syscall timeout after an `EINTR` retry.
pub(crate) fn remaining(deadline: Option<Option<Instant>>) -> Option<Duration> {
    match deadline {
        None | Some(None) => None,
        Some(Some(at)) => Some(at.saturating_duration_since(Instant::now())),
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
