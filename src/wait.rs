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

/// Remaining time until `deadline` (`None` = unbounded; `Some(None)` = a duration
/// that overflowed `Instant` ⇒ unbounded). Saturates to ZERO once past. Shared by the
/// backends to recompute the per-syscall timeout after an `EINTR` retry.
pub(crate) fn remaining(deadline: Option<Option<Instant>>) -> Option<Duration> {
    match deadline {
        None | Some(None) => None,
        Some(Some(at)) => Some(at.saturating_duration_since(Instant::now())),
    }
}

/// Convert a relative `duration` into the crate's `deadline` convention
/// (`Option<Option<Instant>>`, the inverse of [`remaining`]): `Instant::now() + duration`,
/// saturating to unbounded (`Some(None)`, read by `remaining` the same as outer `None`) on
/// overflow rather than panicking. Also saturates when the result lands within a millisecond of
/// `Instant`'s own ceiling: tokio's timer wheel rounds a deadline up by just under that much
/// (unchecked) when arming `sleep_until`/`timeout_at`, so a `Block` carrying an instant this
/// close to the ceiling would panic there instead of waiting. Shared by every `_timeout`/
/// `grace`-style call that starts a fresh relative wait from "now".
pub(crate) fn deadline_from(duration: Duration) -> Option<Option<Instant>> {
    Some(
        Instant::now()
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
/// polls immediately and can report "timed out" up to a full millisecond before the caller's
/// real deadline, violating cosca's never-early deadline contract. `Duration::ZERO` ceils to
/// `0`, which is correct: a zero-remaining deadline is a poll, not a wait.
///
/// Pure and portable (no OS dependency) so it is unit-testable on every host, including this
/// one — the Windows wait sites are the only current callers, but the math itself is not
/// Windows-specific.
#[cfg_attr(not(any(test, windows)), allow(dead_code))] // only wired into the Windows wait sites
pub(crate) fn ceil_millis(d: Duration) -> u128 {
    let nanos = d.as_nanos();
    let ms = nanos.div_ceil(1_000_000);
    debug_assert!(ms * 1_000_000 >= nanos, "ceil_millis must round UP, never down");
    ms
}

/// Test-only seam: lets a test override the clamp the Windows wait sites apply to a computed
/// millisecond timeout (production default: `INFINITE - 1`, ~49.7 days) so the "clamped wait
/// elapsed before the real deadline, re-arm" path is exercised deterministically — without
/// actually waiting 49.7 days for a real clamp to fire.
#[cfg(all(test, windows))]
pub(crate) mod wait_clamp_seam {
    use std::cell::Cell;
    thread_local! {
        static OVERRIDE_MS: Cell<Option<u32>> = const { Cell::new(None) };
    }
    /// Override the clamp for the current thread. `None` restores the production default.
    pub(crate) fn set(ms: Option<u32>) {
        OVERRIDE_MS.with(|c| c.set(ms));
    }
    pub(crate) fn get() -> Option<u32> {
        OVERRIDE_MS.with(|c| c.get())
    }
}

/// Test-only seam: records, for every Win32 wait a call site arms, the millisecond count it
/// chose alongside the exact `remaining` duration it was computed from — so a test can assert
/// the ceiling relationship (`armed_ms >= remaining`) structurally, without depending on
/// wall-clock timing around the call (which real OS/syscall jitter makes unreliable to assert
/// on directly).
#[cfg(all(test, windows))]
pub(crate) mod wait_ms_probe {
    use std::cell::RefCell;
    use std::time::Duration;
    thread_local! {
        static RECORDED: RefCell<Vec<(u32, Duration)>> = const { RefCell::new(Vec::new()) };
    }
    pub(crate) fn record(ms: u32, remaining: Duration) {
        RECORDED.with(|r| r.borrow_mut().push((ms, remaining)));
    }
    /// Drain and return everything recorded on the current thread since the last `take()`.
    pub(crate) fn take() -> Vec<(u32, Duration)> {
        RECORDED.with(|r| r.take())
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
