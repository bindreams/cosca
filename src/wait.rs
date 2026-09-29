//! Non-reaping, race-free death-watch and hard-kill for a `ProcessId`. `block_until_exit`
//! blocks the calling thread until exit or timeout, never a sleep-poll: one kernel syscall on
//! Linux/macOS; on Windows, one or more `WaitForSingleObject`/`WaitForMultipleObjects` calls in
//! a row, only ever re-armed against the caller's own real deadline (see [`win32_timeout_ms`]'s
//! doc) — no busy-spin, no sleep in between.
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
    /// unfrozen clock already tracks real time on its own). Called automatically around every
    /// completed round of a real, blocking wait keyed to a real `Instant` deadline — macOS's
    /// `block_on_kqueue` after each `kevent` call, and the Linux cgroup drain loop's bounded arm
    /// (`CgroupLeaf::wait_drained`) after each `wait_deadline` call — so a frozen clock a test
    /// forgot to (or a bug failed to) advance explicitly can never make a GENUINELY elapsed real
    /// wait invisible to `remaining`: even with no test hook ever calling [`advance`], `now`
    /// eventually catches up to whatever real time was actually spent blocked in the kernel,
    /// turning what would otherwise be an unbounded spin under a never-advancing mock clock
    /// into, at worst, a wait bounded by the real timeouts genuinely requested — never a true
    /// infinite loop.
    ///
    /// Genuinely dead code on Windows, which has neither caller.
    #[cfg_attr(windows, allow(dead_code))]
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

/// `d` rounded UP to whole milliseconds, not truncated. `Duration::as_millis()` floors, which
/// for a sub-millisecond remainder (e.g. 500µs) yields `0` — a Win32 wait armed with that `0`
/// is a non-blocking poll rather than a genuine wait, a needless, entirely self-inflicted extra
/// margin of earliness on top of whatever the OS itself may already introduce.
///
/// Ceiling does NOT, by itself, make a single wait call never-early. Per Microsoft's [Wait
/// Functions and Time-out Intervals]: "If the time-out interval is less than the resolution of
/// the system clock, the wait may time out in less than the specified length of time" — even a
/// correctly-ceiled, un-clamped wait can still return early on real hardware. What actually
/// guarantees cosca's never-early deadline contract is the unconditional recheck-and-re-arm
/// loop at every call site (see [`win32_timeout_ms`]'s doc), which never trusts ANY
/// `WAIT_TIMEOUT` without checking the real deadline. `Duration::ZERO` ceils to `0`, which is
/// correct: a zero-remaining deadline is a poll, not a wait.
///
/// [Wait Functions and Time-out Intervals]: https://learn.microsoft.com/en-us/windows/win32/sync/wait-functions
///
/// Pure and portable (no OS dependency) so it is unit-testable on every host, including this
/// one. Not `pub(crate)`-visible on its own outside this module — call [`win32_timeout_ms`],
/// which wraps it with the clamp every real call site needs.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
fn ceil_millis(d: Duration) -> u128 {
    let nanos = d.as_nanos();
    let ms = nanos.div_ceil(1_000_000);
    debug_assert!(ms * 1_000_000 >= nanos, "ceil_millis must round UP, never down");
    ms
}

/// The Win32 `WaitForSingleObject`/`WaitForMultipleObjects` "no timeout" sentinel value
/// (`INFINITE` = `u32::MAX`). Defined locally rather than imported from the `windows` crate,
/// which is a Windows-only dependency unavailable to this portable module — so
/// [`win32_timeout_ms`]'s "never returns this for a finite `remaining`" contract has one
/// value, shared by every Windows wait site, to check itself against.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
const WIN32_INFINITE: u32 = u32::MAX;

/// Convert a REMAINING duration into the millisecond timeout a SINGLE Win32 wait call
/// (`WaitForSingleObject`/`WaitForMultipleObjects`) should be armed with. `None` (unbounded)
/// -> [`WIN32_INFINITE`]. `Some(d)` -> `d` ceiled to whole milliseconds (see [`ceil_millis`] —
/// never truncated) and clamped to `WIN32_INFINITE - 1` (~49.7 days: `WIN32_INFINITE` itself
/// is the "no timeout" sentinel, so a finite deadline must never be allowed to collide with
/// it — not even where an UN-clamped `d`'s own ms value happens to equal `u32::MAX` exactly;
/// `u32::try_from(remaining.as_millis()).unwrap_or(INFINITE - 1)`, an earlier shape of this
/// conversion at one call site, missed exactly that case, since `try_from` SUCCEEDS for
/// `u32::MAX`).
///
/// This converts ONE call's timeout — it is not itself a retry loop. EVERY call site with a
/// genuine deadline (`Some`) must retry on `WAIT_TIMEOUT` UNCONDITIONALLY, not only when this
/// call happened to be clamped: per Microsoft's [Wait Functions and Time-out Intervals], "If
/// the time-out interval is less than the resolution of the system clock, the wait may time
/// out in less than the specified length of time" — an UN-clamped, correctly-ceiled wait can
/// still return `WAIT_TIMEOUT` before its own requested interval has genuinely elapsed. The
/// clamp (`WIN32_INFINITE - 1`, ~49.7 days) is a SECOND, independent reason a single call's
/// timeout can undershoot the real deadline — for a much larger gap — but it is not the only
/// one, and a recheck that only fires "if this arm was clamped" is exactly as wrong as no
/// recheck at all. Every call site must therefore recompute its `remaining` FRESH (via
/// [`remaining`], from the real deadline) before EVERY call — never reuse a value computed
/// before an earlier iteration — and never trust ANY `WAIT_TIMEOUT` as proof the real deadline
/// passed without rechecking `remaining` against it, until it genuinely has. See the loop shape
/// at every call site: `wait/windows.rs::block_until_exit`, `block_until_exit_or_cancel`,
/// `containment/windows.rs::wait_drained_raw`, and
/// `child/spawn/windows_raw/proc.rs::RawChild::wait_deadline`.
///
/// [Wait Functions and Time-out Intervals]: https://learn.microsoft.com/en-us/windows/win32/sync/wait-functions
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
pub(crate) fn win32_timeout_ms(remaining: Option<Duration>) -> u32 {
    match remaining {
        None => WIN32_INFINITE,
        Some(d) => {
            // Test-only, single-use override: lets a test force a specific (e.g.
            // sub-millisecond) `d` for exactly the NEXT call, so the ceiling-vs-truncation
            // divergence is provable from the recorded `ms` alone — deterministically, not by
            // racing real OS-clock/scheduler jitter to land on a sub-millisecond remainder
            // (which real Windows wait-timer coarseness can otherwise mask; see
            // `wait_ms_probe`/`remaining_override_seam` callers).
            #[cfg(test)]
            let d = remaining_override_seam::take().unwrap_or(d);
            let clamp = win32_wait_clamp();
            let ms = ceil_millis(d).min(clamp as u128) as u32;
            debug_assert!(
                ms != WIN32_INFINITE,
                "a finite remaining duration must never clamp up to the Win32 INFINITE sentinel"
            );
            #[cfg(test)]
            wait_ms_probe::record(ms, d);
            ms
        }
    }
}

/// The clamp [`win32_timeout_ms`] applies to a finite `remaining` (production:
/// `WIN32_INFINITE - 1`, ~49.7 days). A test can override it via [`wait_clamp_seam`] to
/// exercise the "clamped wait elapsed before the real deadline, re-arm" path
/// deterministically, without an actual 49.7-day wait.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
fn win32_wait_clamp() -> u32 {
    #[cfg(test)]
    if let Some(v) = wait_clamp_seam::get() {
        return v;
    }
    WIN32_INFINITE - 1
}

/// Test-only seam: lets a test override the clamp [`win32_timeout_ms`] applies (production
/// default: `WIN32_INFINITE - 1`, ~49.7 days) so the "clamped wait elapsed before the real
/// deadline, re-arm" path is exercised deterministically — without actually waiting 49.7 days
/// for a real clamp to fire. Portable (no OS dependency): usable from a pure unit test of
/// [`win32_timeout_ms`] on any host, not just from the Windows-only call sites.
#[cfg(test)]
pub(crate) mod wait_clamp_seam {
    use std::cell::Cell;
    thread_local! {
        static OVERRIDE_MS: Cell<Option<u32>> = const { Cell::new(None) };
    }
    /// Override the clamp for the current thread until the returned guard drops — RAII, not a
    /// hand-paired `set`/`set(None)`, so a test that panics before an explicit restore (e.g. a
    /// failed assertion) still leaves the production default in place for whatever test runs
    /// next on this thread.
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

/// Test-only seam: forces the NEXT call to [`win32_timeout_ms`] (with a `Some` `remaining`) to
/// use this exact duration instead of the value its caller computed — consumed once. Landing
/// on a sub-millisecond remainder naturally (real deadline minus real elapsed setup time) is
/// likely but not deterministic, and real Windows wait-timer coarseness can mask a
/// ceiling-vs-truncation divergence measured only by wall-clock elapsed time (this is exactly
/// how a prior, unfixed version of `*_arms_the_ceiling_of_the_remaining_duration` for
/// `block_until_exit_or_cancel` passed against genuinely truncating code — see this PR's
/// description). This seam makes the divergence provable from the recorded `ms` alone.
#[cfg(test)]
pub(crate) mod remaining_override_seam {
    use std::cell::Cell;
    use std::time::Duration;
    thread_local! {
        static OVERRIDE: Cell<Option<Duration>> = const { Cell::new(None) };
    }
    /// Force the next [`win32_timeout_ms`] call to use `d` instead of its real argument, until
    /// consumed (by that call) or the returned guard drops, whichever comes first. RAII: the
    /// guard clears any UNCONSUMED override on drop — including mid-panic during a failed
    /// assertion — so a test can never leak a stale forced value onto a later test sharing this
    /// thread, without a hand-written defensive `take()` at every call site.
    #[must_use]
    pub(crate) fn set(d: Duration) -> Guard {
        OVERRIDE.with(|c| c.set(Some(d)));
        Guard(())
    }
    /// Consume and return the forced value, if one is still armed.
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

/// Test-only seam: records, for every Win32 wait a call site arms via [`win32_timeout_ms`],
/// the millisecond count it chose alongside the EXACT `remaining` duration it was computed
/// from (after any [`remaining_override_seam`] substitution) — so a test can assert the exact
/// relationship `ms == min(ceil_millis(remaining), clamp)`, not merely a looser
/// `ms >= remaining` bound, and — across a clamped-and-re-armed wait's several calls — that
/// each round's recorded `remaining` is strictly less than the previous round's (proving
/// `remaining` was recomputed fresh each time, not hoisted out of the retry loop and reused
/// stale).
#[cfg(test)]
pub(crate) mod wait_ms_probe {
    use std::cell::RefCell;
    use std::time::Duration;
    thread_local! {
        static RECORDED: RefCell<Vec<(u32, Duration)>> = const { RefCell::new(Vec::new()) };
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub(crate) fn record(ms: u32, remaining: Duration) {
        let count = RECORDED.with(|r| {
            let mut r = r.borrow_mut();
            r.push((ms, remaining));
            r.len()
        });
        // Fires synchronously, on this thread, strictly BEFORE the caller's second real Win32
        // wait call executes (this function returns to `win32_timeout_ms`, which returns to the
        // call site, which only THEN calls `WaitForSingleObject`/`WaitForMultipleObjects`) — so
        // a hook that ends a fixture's life (closing stdin, killing it, signalling cancel) is
        // guaranteed to have taken effect, or be in flight, before that second wait blocks.
        if count == 2 {
            if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
                hook();
            }
        }
    }
    /// Register a one-shot hook that runs the instant the SECOND `(ms, remaining)` pair is
    /// recorded. Lets a test end a wait deterministically via a real event exactly when the
    /// loop has genuinely re-armed past a first, deliberately early/clamped `WAIT_TIMEOUT` —
    /// rather than racing a fixed real-clock window for "enough" re-arms to happen in time.
    // Only the Windows-only test files register a hook (see `take`'s comment above).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn on_second_arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    /// Drain and return everything recorded on the current thread since the last `take()`,
    /// clearing any unconsumed hook too (defensive — every test that arms one is expected to
    /// reach a second arm and consume it, but a differently-behaving mutant must not leak a
    /// hook onto a later test sharing this thread).
    // Only the Windows-only test files read the probe back; a non-Windows test build compiles
    // `record` (called unconditionally under `#[cfg(test)]` inside `win32_timeout_ms`, exercised
    // by this module's own portable tests) but never calls `take()`.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn take() -> Vec<(u32, Duration)> {
        HOOK.with(|h| *h.borrow_mut() = None);
        RECORDED.with(|r| r.take())
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
