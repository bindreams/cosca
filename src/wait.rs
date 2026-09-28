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
    let deadline = timeout.map(|d| now().checked_add(d));
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

/// A mock clock, test-only: once frozen, `remaining` reads this instant instead of the real
/// `Instant::now()`, so a test can drive deadline arithmetic to a deterministic value with no
/// real sleep. Thread-local; `FrozenClockGuard` resets it on `Drop`, including during
/// unwinding.
#[cfg(test)]
// `advance`, `FrozenClockGuard` and friends are exercised only by macOS's `marker_eof_tests`
// today (the only current caller across the crate's platforms) — genuinely dead code
// everywhere else, same pattern as `containment::cgroup::parse`'s Linux-only helpers. `now`
// itself stays used everywhere via `remaining`, so this is a no-op for it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) mod test_clock {
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    thread_local! {
        static FROZEN: Cell<Option<Instant>> = const { Cell::new(None) };
    }

    /// Freeze this thread's mock clock at the real "now", and return that instant. Until
    /// [`reset`] (or the end of a [`FrozenClockGuard`]'s scope), [`now`] returns exactly this
    /// value — not real elapsed time — so a test's own setup latency can never change what a
    /// deadline computed from it means.
    fn freeze_now() -> Instant {
        // Nesting is not supported: the INNER guard's `Drop` would unfreeze the clock out from
        // under the OUTER guard, which is still alive and still expects it frozen.
        debug_assert!(
            FROZEN.with(Cell::get).is_none(),
            "test_clock::freeze_now called while already frozen — nesting FrozenClockGuard is \
             not supported"
        );
        let at = Instant::now();
        FROZEN.with(|f| f.set(Some(at)));
        at
    }

    /// Advance the frozen instant by `by`. Panics if the clock isn't frozen — silently doing
    /// nothing (advancing an unfrozen clock that's about to be overridden by real time anyway)
    /// would hide a test bug rather than fail it loudly.
    pub(crate) fn advance(by: Duration) {
        FROZEN.with(|f| {
            let cur = f.get().expect("test_clock::advance called before the clock was frozen");
            f.set(Some(cur + by));
        });
    }

    /// Advance the frozen instant by `real_elapsed` — a no-op if the clock isn't frozen (an
    /// unfrozen clock already tracks real time on its own). Called automatically by
    /// `block_on_kqueue` around every completed round's real, blocking `kevent` call, so a
    /// frozen clock a test forgot to (or a bug failed to) advance explicitly can never make a
    /// GENUINELY elapsed real wait invisible to `remaining`: even with no test hook ever calling
    /// [`advance`], `now` eventually catches up to whatever real time was actually spent
    /// blocked in the kernel, turning what would otherwise be an unbounded spin under a
    /// never-advancing mock clock into, at worst, a wait bounded by the real timeouts genuinely
    /// requested — never a true infinite loop.
    pub(crate) fn advance_by_elapsed_if_frozen(real_elapsed: Duration) {
        FROZEN.with(|f| {
            if let Some(cur) = f.get() {
                f.set(Some(cur + real_elapsed));
            }
        });
    }

    /// The mock "now": the frozen instant if [`FrozenClockGuard::install`] is active on this
    /// thread, else real `Instant::now()` (this module's unfrozen default, matching production
    /// behavior exactly).
    pub(crate) fn now() -> Instant {
        FROZEN.with(|f| f.get()).unwrap_or_else(Instant::now)
    }

    fn reset() {
        FROZEN.with(|f| f.set(None));
    }

    /// RAII installer for the frozen clock: freezes on construction, resets to unfrozen on
    /// `Drop` — including during unwinding, so a test that panics mid-assertion never leaks a
    /// frozen clock into whatever runs on this thread next.
    #[must_use]
    pub(crate) struct FrozenClockGuard {
        _private: (),
    }

    impl FrozenClockGuard {
        /// Freeze the clock and return the guard plus the frozen instant.
        pub(crate) fn install() -> (Self, Instant) {
            let at = freeze_now();
            (Self { _private: () }, at)
        }
    }

    impl Drop for FrozenClockGuard {
        fn drop(&mut self) {
            reset();
        }
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
/// Reads the clock via [`now`], which honours [`test_clock`] in test builds.
pub(crate) fn remaining(deadline: Option<Option<Instant>>) -> Option<Duration> {
    match deadline {
        None | Some(None) => None,
        Some(Some(at)) => Some(at.saturating_duration_since(now())),
    }
}

/// Convert a relative `duration` into the crate's `deadline` convention
/// (`Option<Option<Instant>>`, the inverse of [`remaining`]): [`now`]`() + duration`, saturating
/// to unbounded (`Some(None)`, read by `remaining` the same as outer `None`) on overflow rather
/// than panicking. Shared by every `_timeout`/`grace`-style call that starts a fresh relative
/// wait from "now".
pub(crate) fn deadline_from(duration: Duration) -> Option<Option<Instant>> {
    Some(now().checked_add(duration))
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
