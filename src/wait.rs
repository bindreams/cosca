//! Non-reaping, race-free death-watch and hard-kill for a `ProcessId`. `block_until_exit`
//! blocks the calling thread until exit or timeout, never a sleep-poll: one kernel syscall on
//! Linux/macOS; on Windows, one or more `WaitForSingleObject`/`WaitForMultipleObjects` calls in
//! a row, only ever re-armed against the caller's own real deadline (see `wait_until`).
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
    /// unfrozen clock already tracks real time on its own). Called after every real, blocking
    /// wait keyed to a real `Instant` deadline — macOS's `block_on_kqueue` (`kevent`), the Linux
    /// cgroup drain loop (`CgroupLeaf::wait_drained`), and Windows' `wait_until` — so a frozen
    /// clock never hides a genuinely elapsed wait from `remaining`, and a re-arm loop under it
    /// cannot spin forever.
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
/// than panicking. Also saturates when the result lands within a millisecond of `Instant`'s own
/// ceiling: tokio's timer wheel rounds a deadline up by just under that much (unchecked) when
/// arming `sleep_until`/`timeout_at`, so a `Block` carrying an instant this close to the ceiling
/// would panic there instead of waiting. Shared by every `_timeout`/`grace`-style call that
/// starts a fresh relative wait from "now".
pub(crate) fn deadline_from(duration: Duration) -> Option<Option<Instant>> {
    Some(
        now()
            .checked_add(duration)
            .filter(|at| at.checked_add(Duration::from_millis(1)).is_some()),
    )
}

/// The largest `Instant` reachable from `start`, found purely through `checked_add`'s own
/// overflow signal — no assumption about where a platform's `Instant` ceiling actually is.
/// Shared by tests (here and in `tokio::wait_tests`) that need an instant genuinely close to
/// that ceiling, not a platform-specific guess.
#[cfg(test)]
pub(crate) fn instant_near_ceiling(start: Instant) -> Instant {
    let mut at = start;
    let mut step = Duration::from_secs(1 << 62);
    loop {
        while let Some(next) = at.checked_add(step) {
            at = next;
        }
        if step <= Duration::from_nanos(1) {
            return at;
        }
        step /= 2;
    }
}

/// `d` rounded UP to whole milliseconds. `Duration::as_millis()` floors, so a sub-millisecond
/// remainder would arm a non-blocking `0` poll instead of a wait. Pure and portable; call
/// [`win32_timeout_ms`], which adds the clamp every call site needs.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
fn ceil_millis(d: Duration) -> u128 {
    d.as_nanos().div_ceil(1_000_000)
}

/// Win32 `INFINITE` (`u32::MAX`); local because this module is portable.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
const WIN32_INFINITE: u32 = u32::MAX;

/// The millisecond timeout ONE Win32 wait call (`WaitForSingleObject`/`WaitForMultipleObjects`)
/// should be armed with for a REMAINING duration: `None` -> [`WIN32_INFINITE`]; `Some(d)` -> `d`
/// ceiled to whole milliseconds ([`ceil_millis`]) and clamped to `WIN32_INFINITE - 1` (~49.7
/// days), so a finite deadline never collides with the "no timeout" sentinel.
///
/// This is not a retry loop, and a `WAIT_TIMEOUT` from a wait armed with it is never proof the
/// deadline passed. Per Microsoft's [Wait Functions and Time-out Intervals], "If the time-out
/// interval is less than the resolution of the system clock, the wait may time out in less than
/// the specified length of time", so even an unclamped, ceiled wait can return early; the clamp
/// is a second, independent way for a wait to undershoot. Every site therefore rechecks the real
/// deadline after each `WAIT_TIMEOUT` and re-arms, which `wait_until` does for all of them.
///
/// [Wait Functions and Time-out Intervals]: https://learn.microsoft.com/en-us/windows/win32/sync/wait-functions
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
pub(crate) fn win32_timeout_ms(remaining: Option<Duration>) -> u32 {
    match remaining {
        None => WIN32_INFINITE,
        Some(requested) => {
            #[cfg(test)]
            let d = remaining_override_seam::take().unwrap_or(requested);
            #[cfg(not(test))]
            let d = requested;
            let ms = ceil_millis(d).min(win32_wait_clamp() as u128) as u32;
            debug_assert!(
                ms != WIN32_INFINITE,
                "a finite remaining duration must never clamp up to the Win32 INFINITE sentinel"
            );
            #[cfg(test)]
            wait_ms_probe::record(ms, d, requested);
            ms
        }
    }
}

/// Run `wait` (one Win32 wait, armed with the `ms` it is given) until it returns something other
/// than `WAIT_TIMEOUT`, or the real `deadline` has passed (`WAIT_TIMEOUT` then). A `WAIT_TIMEOUT`
/// is never trusted: the remaining time is recomputed from `deadline` each round and the wait
/// re-armed (see [`win32_timeout_ms`]). `None`/`Some(None)` is unbounded.
///
/// Reads only the clock after `wait` returns, so `GetLastError` still holds `wait`'s error.
#[cfg(windows)]
pub(crate) fn wait_until(
    deadline: Option<Option<Instant>>,
    mut wait: impl FnMut(u32) -> windows::Win32::Foundation::WAIT_EVENT,
) -> windows::Win32::Foundation::WAIT_EVENT {
    use windows::Win32::Foundation::WAIT_TIMEOUT;
    loop {
        #[cfg(test)]
        let call_start = Instant::now();
        let waited = wait(win32_timeout_ms(remaining(deadline)));
        #[cfg(test)]
        test_clock::advance_by_elapsed_if_frozen(call_start.elapsed());
        if waited != WAIT_TIMEOUT || remaining(deadline) == Some(Duration::ZERO) {
            return waited;
        }
    }
}

/// The clamp [`win32_timeout_ms`] applies to a finite `remaining` (production:
/// `WIN32_INFINITE - 1`); [`wait_clamp_seam`] lowers it so tests reach the re-arm path quickly.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
fn win32_wait_clamp() -> u32 {
    #[cfg(test)]
    if let Some(v) = wait_clamp_seam::get() {
        return v;
    }
    WIN32_INFINITE - 1
}

// Test seams =====
// For the Windows wait sites: thread-local, each guard restores the production default on drop,
// including mid-panic.

/// Overrides the clamp [`win32_timeout_ms`] applies. Portable, so pure unit tests can use it.
#[cfg(test)]
pub(crate) mod wait_clamp_seam {
    use std::cell::Cell;
    thread_local! {
        static OVERRIDE_MS: Cell<Option<u32>> = const { Cell::new(None) };
    }
    #[must_use]
    pub(crate) fn set(ms: u32) -> Guard {
        OVERRIDE_MS.with(|c| c.set(Some(ms)));
        Guard(())
    }
    pub(crate) fn get() -> Option<u32> {
        OVERRIDE_MS.with(|c| c.get())
    }
    pub(crate) struct Guard(());
    impl Drop for Guard {
        fn drop(&mut self) {
            OVERRIDE_MS.with(|c| c.set(None));
        }
    }
}

/// Forces the NEXT [`win32_timeout_ms`] call with a `Some` remaining to use a chosen duration,
/// so a ceiling-versus-truncation divergence shows in the recorded `ms` alone instead of
/// depending on landing on a sub-millisecond remainder by chance. Consumed once; the guard
/// clears an unconsumed override on drop.
#[cfg(test)]
pub(crate) mod remaining_override_seam {
    use std::cell::Cell;
    use std::time::Duration;
    thread_local! {
        static OVERRIDE: Cell<Option<Duration>> = const { Cell::new(None) };
    }
    #[must_use]
    pub(crate) fn set(d: Duration) -> Guard {
        OVERRIDE.with(|c| c.set(Some(d)));
        Guard(())
    }
    pub(crate) fn take() -> Option<Duration> {
        OVERRIDE.with(|c| c.take())
    }
    pub(crate) struct Guard(());
    impl Drop for Guard {
        fn drop(&mut self) {
            OVERRIDE.with(|c| c.set(None));
        }
    }
}

/// Records every wait a site arms via [`win32_timeout_ms`]: the `ms` chosen, the `remaining` it
/// was computed from (after any [`remaining_override_seam`] substitution), and the `requested`
/// remaining the site itself passed in. Tests assert `ms == expected_ms(remaining, clamp)`
/// exactly, that `remaining` strictly shrinks across re-arms (recomputed each round, not
/// hoisted), and that `requested` derives from the site's real deadline.
#[cfg(test)]
pub(crate) mod wait_ms_probe {
    use std::cell::RefCell;
    use std::time::Duration;

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Arm {
        pub(crate) ms: u32,
        pub(crate) remaining: Duration,
        pub(crate) requested: Duration,
    }

    thread_local! {
        static RECORDED: RefCell<Vec<Arm>> = const { RefCell::new(Vec::new()) };
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    pub(crate) fn record(ms: u32, remaining: Duration, requested: Duration) {
        let count = RECORDED.with(|r| {
            let mut r = r.borrow_mut();
            r.push(Arm {
                ms,
                remaining,
                requested,
            });
            r.len()
        });
        // Runs on the waiting thread before the second real wait starts.
        if count == 2 {
            if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
                hook();
            }
        }
    }

    /// Run `hook` when the SECOND arm is recorded: ends a wait through a real event exactly when
    /// the site has re-armed past its first `WAIT_TIMEOUT`.
    // Only Windows tests register a hook.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn on_second_arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    /// Drain everything recorded on this thread, and drop any unconsumed hook.
    // Only Windows tests read the probe back.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn take() -> Vec<Arm> {
        HOOK.with(|h| *h.borrow_mut() = None);
        RECORDED.with(|r| r.take())
    }

    /// Assert a clamped wait re-armed (at least two arms), that each armed exactly
    /// `expected_ms(remaining, clamp)`, and that `remaining` shrank strictly across arms.
    // Only Windows tests call it.
    #[cfg_attr(not(windows), allow(dead_code))]
    #[track_caller]
    pub(crate) fn assert_rearmed_with_fresh_remaining(arms: &[Arm], clamp: u32) {
        assert!(arms.len() >= 2, "expected a re-arm, got {} arm(s)", arms.len());
        for arm in arms {
            assert_eq!(arm.ms, expected_ms(arm.remaining, clamp), "{arm:?}");
        }
        for pair in arms.windows(2) {
            assert!(
                pair[1].remaining < pair[0].remaining,
                "remaining must be recomputed each round: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    /// The `ms` a site must arm for `remaining` under `clamp`: `ceil(remaining)` in whole
    /// milliseconds, capped at `clamp`. Independent of `ceil_millis`.
    // Only Windows tests call it.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn expected_ms(remaining: Duration, clamp: u32) -> u32 {
        let ceil = remaining.as_nanos().div_ceil(1_000_000);
        u32::try_from(ceil.min(u128::from(clamp))).expect("capped at a u32 clamp")
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
