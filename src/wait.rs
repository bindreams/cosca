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
///
/// This is one mechanism, not the crate's whole graceful surface: on Windows a child that
/// leads its own console process group is addressed through that group instead.
/// [`crate::graceful::signal`], reached via [`Child::terminate`](crate::Child::terminate), is
/// the mechanism-aware entry point that picks between them.
pub(crate) fn terminate(id: ProcessId) -> Result<(), Error> {
    backend::terminate(id)
}

/// A mock clock offset for deadline arithmetic, test-only. `remaining` adds this on top of the
/// real `Instant::now()` so a test can push the deadline check from "still open" to "elapsed"
/// deterministically, with no real sleep — e.g. to prove a loop stops taking new rounds once a
/// deadline has passed, without waiting out a real deadline to observe it.
///
/// Thread-local, not global: the test harness runs each test on its own OS thread by default,
/// so the offset starts at `Duration::ZERO` for every test with nothing to reset. A test that
/// needs to advance the clock from WITHIN a call already in progress (rather than before
/// making it) does so through a `#[cfg(test)]` hook invoked on the same thread mid-call — see
/// `wait::macos::test_hooks::set_round_hook`.
#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    thread_local! {
        static OFFSET: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    }

    /// The mock "now": real `Instant::now()` plus this thread's accumulated offset.
    pub(crate) fn now() -> Instant {
        Instant::now() + OFFSET.with(Cell::get)
    }

    /// Advance this thread's offset by `by`, moving the mock "now" further into the future.
    /// Exercised only by macOS's `marker_eof_tests` today (the only current caller across the
    /// crate's platforms), so this is genuinely dead code everywhere else — same pattern as
    /// `containment::cgroup::parse`'s Linux-only helpers.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn advance(by: Duration) {
        OFFSET.with(|o| o.set(o.get() + by));
    }
}

#[cfg(not(test))]
fn now() -> Instant {
    Instant::now()
}

#[cfg(test)]
fn now() -> Instant {
    test_clock::now()
}

/// Remaining time until `deadline` (`None` = unbounded; `Some(None)` = a duration
/// that overflowed `Instant` ⇒ unbounded). Saturates to ZERO once past. Shared by the
/// backends to recompute the per-syscall timeout after an `EINTR` retry.
///
/// Reads the clock through [`now`], which in test builds is the real clock plus a per-thread
/// mock offset (see [`test_clock`]); in non-test builds `now` is `Instant::now()` with zero
/// indirection, so this function's behavior outside tests is unchanged.
pub(crate) fn remaining(deadline: Option<Option<Instant>>) -> Option<Duration> {
    match deadline {
        None | Some(None) => None,
        Some(Some(at)) => Some(at.saturating_duration_since(now())),
    }
}

/// Convert a relative `duration` into the crate's `deadline` convention
/// (`Option<Option<Instant>>`, the inverse of [`remaining`]): `Instant::now() + duration`,
/// saturating to unbounded (`Some(None)`, read by `remaining` the same as outer `None`) on
/// overflow rather than panicking. Shared by every `_timeout`/`grace`-style call that starts
/// a fresh relative wait from "now".
pub(crate) fn deadline_from(duration: Duration) -> Option<Option<Instant>> {
    Some(Instant::now().checked_add(duration))
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
