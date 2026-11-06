//! The time, deadline and blocking-wait helpers the wait drivers share, and macOS child reaping
//! (`macos`). The by-identity wait and signals are [`crate::os_process`]. NEVER reaps: the target's
//! real parent collects the zombie.

use std::time::{Duration, Instant};

pub(crate) mod exit_only;

pub(crate) mod teardown_warn;

#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("cosca::wait is implemented only for Linux, macOS, and Windows");

/// Force the NEXT grace-watch on THIS thread to fail (consumed by the entry of each driver,
/// [`crate::os_process::drive`] and `tokio::drive`, and by `Child::wait_timeout`),
/// so the watch-error escalation ordering is testable. Same take-semantics contract as the treewalk fault seam.
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
        /// Bumped by every [`advance_by_elapsed_if_frozen`] call, zero elapsed included.
        static ADVANCES: Cell<u64> = const { Cell::new(0) };
        static SKIP_ADVANCE: Cell<bool> = const { Cell::new(false) };
        static ZERO_ELAPSED: Cell<bool> = const { Cell::new(false) };
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

    /// Advance the frozen instant by `real_elapsed` (a no-op if the clock isn't frozen). Called
    /// after every real, blocking wait keyed to a real `Instant` deadline, so a frozen clock never
    /// hides a genuinely elapsed wait from `remaining` and a re-arm loop under it cannot spin
    /// forever.
    pub(crate) fn advance_by_elapsed_if_frozen(real_elapsed: Duration) {
        if SKIP_ADVANCE.with(Cell::get) {
            return;
        }
        ADVANCES.with(|a| a.set(a.get() + 1));
        let real_elapsed = if ZERO_ELAPSED.with(Cell::get) {
            Duration::ZERO
        } else {
            real_elapsed
        };
        FROZEN.with(|f| {
            if let Some(cur) = f.get() {
                f.set(Some(cur + real_elapsed));
            }
        });
    }

    pub(crate) fn is_frozen() -> bool {
        FROZEN.with(|f| f.get()).is_some()
    }

    /// Makes [`advance_by_elapsed_if_frozen`] do nothing until dropped: the "advance dropped"
    /// mutant, for tests that prove a loop's [`RoundCheck`] fires.
    #[must_use]
    pub(crate) struct SkipAdvanceGuard(());

    impl SkipAdvanceGuard {
        pub(crate) fn install() -> Self {
            SKIP_ADVANCE.with(|s| s.set(true));
            Self(())
        }
    }

    impl Drop for SkipAdvanceGuard {
        fn drop(&mut self) {
            SKIP_ADVANCE.with(|s| s.set(false));
        }
    }

    /// Pins every round's measured elapsed to zero until dropped: the frozen clock stays where it
    /// is (so no deadline is ever reached) while [`advance_by_elapsed_if_frozen`] is still called,
    /// which is what a real round that took no clock ticks looks like.
    #[must_use]
    pub(crate) struct ZeroElapsedGuard(());

    impl ZeroElapsedGuard {
        pub(crate) fn install() -> Self {
            ZERO_ELAPSED.with(|z| z.set(true));
            Self(())
        }
    }

    impl Drop for ZeroElapsedGuard {
        fn drop(&mut self) {
            ZERO_ELAPSED.with(|z| z.set(false));
        }
    }

    /// The exit code of a process that found a [`RoundCheck`] violation while panicking. Neither
    /// `0` nor libtest's `101`, so a caller can tell it from a pass and from an ordinary failure.
    pub(crate) const VIOLATION_EXIT_CODE: i32 = 113;
    const _: () = assert!(VIOLATION_EXIT_CODE != 0 && VIOLATION_EXIT_CODE != 101);

    /// Ends the process at once with `code`: no unwinding, no atexit handlers, and no `SIGABRT`,
    /// whose crash report and core file a deliberate failure has no use for.
    fn exit_now(code: i32) -> ! {
        #[cfg(unix)]
        // SAFETY: `_exit` takes no pointers and does not return.
        unsafe {
            libc::_exit(code)
        }
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
            // SAFETY: the pseudo-handle of the current process is always valid.
            unsafe { TerminateProcess(GetCurrentProcess(), code as u32) }.ok();
            // Only reached if the call failed: a process that must not go on still may not hang.
            std::process::abort()
        }
    }

    /// Per-invocation no-progress check for a re-arm loop under a frozen clock. Create one at wait
    /// entry and call [`round`](Self::round) once at the top of every round: two consecutive
    /// rounds with no [`advance_by_elapsed_if_frozen`] call between them mean the loop dropped its
    /// advance and would spin forever.
    ///
    /// While the thread is panicking (a Drop path) a second panic would abort the process without
    /// a word, so the violation is written to stderr, and the
    /// process exits at once with [`VIOLATION_EXIT_CODE`]: loud, and never a spin.
    pub(crate) struct RoundCheck {
        site: &'static str,
        last: Option<u64>,
    }

    impl RoundCheck {
        pub(crate) fn new(site: &'static str) -> Self {
            Self { site, last: None }
        }

        pub(crate) fn round(&mut self) {
            let generation = ADVANCES.with(Cell::get);
            let stalled = self.last == Some(generation) && is_frozen();
            self.last = Some(generation);
            if !stalled {
                return;
            }
            let message = format!(
                "{}: a round followed a round with no `advance_by_elapsed_if_frozen` call under a \
                 frozen clock: no progress (the loop dropped its advance)",
                self.site
            );
            if std::thread::panicking() {
                use std::io::Write as _;
                // A failed write changes nothing: the exit below is the failure.
                writeln!(std::io::stderr(), "{message}").ok();
                exit_now(VIOLATION_EXIT_CODE);
            }
            panic!("{message}");
        }
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

        /// Freeze the clock `lag` BEHIND the real now, so real time is already ahead of it: a
        /// wait that mixes the two clocks sees a real deadline that has passed while the frozen
        /// one has not.
        pub(crate) fn install_lagging(lag: Duration) -> (Self, Instant) {
            let at = Instant::now()
                .checked_sub(lag)
                .expect("the platform's monotonic clock has run for less than the requested lag");
            FROZEN.with(|f| {
                debug_assert!(f.get().is_none(), "nesting FrozenClockGuard is not supported");
                f.set(Some(at));
            });
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
pub(crate) fn now() -> Instant {
    Instant::now()
}

#[cfg(test)]
pub(crate) fn now() -> Instant {
    test_clock::now()
}

/// Remaining time until `deadline` (`None` = unbounded). Saturates to ZERO once past. Shared by
/// the backends to recompute the per-syscall timeout after an `EINTR` retry.
///
/// Reads the clock via [`now`], which honours [`test_clock`] in test builds.
pub(crate) fn remaining(deadline: Option<Instant>) -> Option<Duration> {
    remaining_at(deadline, now())
}

/// [`remaining`] against an explicit `now`, for waits that run on another clock (tokio's).
pub(crate) fn remaining_at(deadline: Option<Instant>, now: Instant) -> Option<Duration> {
    let remaining = deadline.map(|at| at.saturating_duration_since(now));
    #[cfg(test)]
    read_probe::record(read_probe::Event::Read { deadline, remaining });
    remaining
}

/// Test-only, thread-local log of every [`remaining_at`] read on the installing thread: the
/// deadline it was made against and its result, in order, with the [`mark`]s a call site drops
/// between them. A test proves which deadline a wait was armed from, and that no read precedes
/// a step, from the log. A [`crate::relayed_probe`], so it follows a wait onto a
/// `spawn_blocking` thread.
#[cfg(test)]
pub(crate) mod read_probe {
    use crate::relayed_probe::{self, Probe};
    use std::sync::mpsc::Sender;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Event {
        Read {
            deadline: Option<Instant>,
            remaining: Option<Duration>,
        },
        Mark(&'static str),
    }

    pub(crate) struct Log;
    impl Probe for Log {
        type Event = Event;
    }

    pub(crate) type Guard = relayed_probe::Guard<Log>;

    // Windows `tokio` tests are the only non-portable-test consumers.
    #[cfg_attr(
        not(all(windows, feature = "tokio")),
        allow(dead_code, reason = "Windows tokio tests are the only non-portable-test consumers")
    )]
    pub(crate) fn install(tx: Sender<Event>) -> Guard {
        relayed_probe::install(tx)
    }

    pub(crate) fn current() -> Option<Sender<Event>> {
        relayed_probe::current::<Log>()
    }

    pub(super) fn record(event: Event) {
        relayed_probe::notify::<Log>(event);
    }

    /// Drop a named marker into this thread's log, if one is installed.
    #[cfg_attr(not(windows), allow(dead_code, reason = "only Windows call sites drop markers"))]
    pub(crate) fn mark(name: &'static str) {
        record(Event::Mark(name));
    }
}

/// How far short of `Instant`'s ceiling a deadline must stay for tokio to arm it. tokio's timer
/// wheel rounds deadlines UP by up to `999_999` ns with an unchecked `Instant + Duration`, which
/// panics past the ceiling. 1 ms sits above that so we need not track tokio's constant. An instant
/// inside it is unbounded: see [`deadline_at`].
pub(crate) const TOKIO_TIMER_ROUNDING_MARGIN: Duration = Duration::from_millis(1);

/// Whether `at` leaves [`TOKIO_TIMER_ROUNDING_MARGIN`] before `Instant`'s ceiling, i.e. tokio can
/// arm it without panicking.
pub(crate) fn clears_tokio_timer_margin(at: Instant) -> bool {
    at.checked_add(TOKIO_TIMER_ROUNDING_MARGIN).is_some()
}

/// The pure core of [`deadline_from`]: `now + duration`, or `None` (unbounded) when that
/// overflows `Instant` or lands inside [`TOKIO_TIMER_ROUNDING_MARGIN`] of its ceiling. An
/// overflowing wait is unbounded everywhere in this crate, never a fixed far-future deadline,
/// which would answer EARLY.
pub(crate) fn deadline_at(now: Instant, duration: Duration) -> Option<Instant> {
    now.checked_add(duration).filter(|at| clears_tokio_timer_margin(*at))
}

/// Convert a relative `duration` into a deadline, the inverse of [`remaining`]: [`now`]`() +
/// duration`, per [`deadline_at`]: `None` (unbounded) rather than a panic on overflow, including
/// inside [`TOKIO_TIMER_ROUNDING_MARGIN`] of the ceiling. Shared by every `_timeout`/`grace`-style
/// call that starts a fresh relative wait from "now".
pub(crate) fn deadline_from(duration: Duration) -> Option<Instant> {
    deadline_at(now(), duration)
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
#[cfg_attr(
    not(any(test, windows)),
    allow(
        dead_code,
        reason = "called only by win32_timeout_ms and tests; win32_timeout_ms is itself dead off-windows"
    )
)]
fn ceil_millis(d: Duration) -> u128 {
    d.as_nanos().div_ceil(1_000_000)
}

/// Win32 `INFINITE` (`u32::MAX`); local because this module is portable.
#[cfg_attr(
    not(any(test, windows)),
    allow(
        dead_code,
        reason = "used only by win32_timeout_ms and tests; win32_timeout_ms is itself dead off-windows"
    )
)]
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
#[cfg_attr(
    not(any(test, windows)),
    allow(dead_code, reason = "only the Windows backend and portable tests call it")
)]
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

/// Run `round` until it yields `Some` or the real `deadline` has passed (`None` then). A `None`
/// from a round is never trusted before the deadline: the remaining time is recomputed from
/// `deadline` (on the test clock, see [`test_clock`]) immediately before every round, which must
/// arm its blocking call with it, and the loop goes round again. At least one round runs, so a
/// deadline already past still polls once. `None` is unbounded. A round's `Err` ends
/// the loop.
///
/// Owns the frozen-clock advance: a round must not advance it itself. Under a frozen clock a
/// round that follows one with no advance panics ([`test_clock::RoundCheck`]).
#[cfg_attr(
    not(any(test, target_os = "linux", windows)),
    allow(
        dead_code,
        reason = "called only by the Windows `wait_until` and the Linux holder's poll; macOS blocks on kqueue"
    )
)]
pub(crate) fn rearm_until<T, E>(
    deadline: Option<Instant>,
    mut round: impl FnMut(Option<Duration>) -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    #[cfg(test)]
    let mut check = test_clock::RoundCheck::new("rearm_until");
    loop {
        #[cfg(test)]
        check.round();
        let remaining_now = remaining(deadline);
        #[cfg(test)]
        let round_start = Instant::now();
        let out = round(remaining_now)?;
        #[cfg(test)]
        test_clock::advance_by_elapsed_if_frozen(round_start.elapsed());
        if out.is_some() || remaining(deadline) == Some(Duration::ZERO) {
            return Ok(out);
        }
    }
}

/// Whether any of `fds` has an event now, without blocking; the events found are in `fds`. A failed
/// poll is an error, never `false`.
#[cfg(unix)]
pub(crate) fn any_ready_now(fds: &mut [rustix::event::PollFd<'_>]) -> Result<bool, rustix::io::Errno> {
    let zero = rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 };
    loop {
        match rustix::event::poll(fds, Some(&zero)) {
            Ok(ready) => return Ok(ready > 0),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Blocks until `fds` has an event, retrying `EINTR`.
#[cfg(unix)]
pub(crate) fn poll_ready(fds: &mut [rustix::event::PollFd<'_>]) -> Result<(), rustix::io::Errno> {
    loop {
        match rustix::event::poll(fds, None) {
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Run `wait` (one Win32 wait, armed with the `ms` it is given) until it returns something other
/// than `WAIT_TIMEOUT`, or the real `deadline` has passed (`WAIT_TIMEOUT` then), via
/// [`rearm_until`]; see [`win32_timeout_ms`] for why a `WAIT_TIMEOUT` is never trusted.
///
/// The clock is read only after `wait` returns, so `GetLastError` still holds `wait`'s error.
#[cfg(windows)]
pub(crate) fn wait_until(
    deadline: Option<Instant>,
    mut wait: impl FnMut(u32) -> windows::Win32::Foundation::WAIT_EVENT,
) -> windows::Win32::Foundation::WAIT_EVENT {
    use windows::Win32::Foundation::WAIT_TIMEOUT;
    let waited = rearm_until(deadline, |remaining| {
        let waited = wait(win32_timeout_ms(remaining));
        Ok::<_, std::convert::Infallible>((waited != WAIT_TIMEOUT).then_some(waited))
    });
    match waited {
        Ok(Some(event)) => event,
        Ok(None) => WAIT_TIMEOUT,
        Err(never) => match never {},
    }
}

/// Waits until the exit of `pidfd`'s process is visible to this process, or until `until`, and
/// says which came first. Anything it cannot read (a failed peek, a foreign reap) answers `true`,
/// for the caller's unbounded wait to decide. Reaps nothing.
///
/// A readable pidfd whose zombie a foreign tracer still holds shows no exit to a peek. The kernel
/// wakes the pidfd again when the tracer lets go, but `poll(2)` on an already readable pidfd
/// returns at once and cannot wait for that wake, so the peek is repeated with a capped backoff
/// until `until`. A failed poll of the pidfd is logged and treated the same way: the peeks decide,
/// and a child still running at `until` answers `false`.
#[cfg(target_os = "linux")]
#[cfg_attr(
    not(any(test, feature = "tokio")),
    allow(dead_code, reason = "only an async spawn's teardown looks at a killed child's exit")
)]
pub(crate) fn pidfd_exit_visible_by(pidfd: std::os::fd::BorrowedFd<'_>, until: Instant) -> bool {
    use crate::os_process::drive::{run, RunOutcome};

    match run(&mut PidfdExit::new(pidfd), Some(until)) {
        Ok(RunOutcome::Done(())) => true,
        Ok(RunOutcome::DeadlinePassed) => false,
        Err(e) => {
            log::debug!("a look at a killed child's exit failed ({e}); the wait that follows decides");
            debug_assert!(false, "a pidfd look does not fail: {e}");
            true
        }
    }
}

/// A child's pidfd, as a [`Waitable`](crate::os_process::drive::Waitable): done once a peek shows
/// the exit.
#[cfg(target_os = "linux")]
#[cfg_attr(
    not(any(test, feature = "tokio")),
    allow(dead_code, reason = "only an async spawn's teardown looks at a killed child's exit")
)]
struct PidfdExit<'a> {
    pidfd: std::os::fd::BorrowedFd<'a>,
    /// A poll of `pidfd` has failed: the look no longer asks for a block.
    poll_failed: bool,
}

#[cfg(target_os = "linux")]
#[cfg_attr(
    not(any(test, feature = "tokio")),
    allow(dead_code, reason = "only an async spawn's teardown looks at a killed child's exit")
)]
impl<'a> PidfdExit<'a> {
    fn new(pidfd: std::os::fd::BorrowedFd<'a>) -> Self {
        Self {
            pidfd,
            poll_failed: false,
        }
    }

    /// Log a failed poll; the peeks decide from then on.
    fn note_poll_failed(&mut self, e: &dyn std::fmt::Display) {
        self.poll_failed = true;
        log::debug!("a look at a killed child's exit could not poll its pidfd ({e}); it peeks instead");
    }
}

#[cfg(target_os = "linux")]
impl crate::os_process::drive::Waitable for PidfdExit<'_> {
    type Output = ();

    fn look(&mut self) -> Result<crate::os_process::drive::Step<'_, ()>, crate::error::Error> {
        use crate::os_process::child::PeekOutcome;
        use crate::os_process::drive::Step;
        use crate::os_process::WaitFor;
        use crate::wait::exit_only::{self, Target};

        match exit_only::peek(&Target::PidFd(self.pidfd)) {
            Ok(PeekOutcome::Running) => {}
            Ok(PeekOutcome::Exit(_) | PeekOutcome::Foreign(_)) => return Ok(Step::Done(())),
            Err(e) => {
                log::debug!(
                    "a look at a killed child's exit could not peek at it ({e}); the wait that follows decides"
                );
                return Ok(Step::Done(()));
            }
        }
        if self.poll_failed {
            return Ok(Step::Recheck);
        }
        match crate::os_process::poll::is_readable(self.pidfd) {
            Ok(false) => Ok(Step::Wait(WaitFor::Readable(self.pidfd))),
            Ok(true) => Ok(Step::Recheck),
            Err(e) => {
                self.note_poll_failed(&e);
                Ok(Step::Recheck)
            }
        }
    }

    fn block_failed(&mut self, e: crate::error::Error) -> Result<(), crate::error::Error> {
        self.note_poll_failed(&e);
        Ok(())
    }
}

/// The longest a single timed block may be armed for: `0xFFFF_FFFE` ms. std's Windows
/// `Condvar::wait_timeout` turns anything above `u32::MAX` ms into `INFINITE` (`dur2timeout`),
/// and `u32::MAX` ms is `INFINITE` itself, so an unclamped huge remaining would block forever.
/// Applied to every timed `Condvar::wait_timeout` and `WaitForSingleObject`; the caller loops
/// until its deadline.
pub(crate) const MAX_BLOCK: Duration = Duration::from_millis(0xFFFF_FFFE);

/// `remaining`, clamped to [`MAX_BLOCK`]. After every wake, `now() >= deadline` decides expiry,
/// never the primitive's own "timed out".
pub(crate) fn clamp_block(remaining: Duration) -> Duration {
    remaining.min(MAX_BLOCK)
}

/// The clamp [`win32_timeout_ms`] applies to a finite `remaining` (production:
/// `WIN32_INFINITE - 1`); [`wait_clamp_seam`] lowers it so tests reach the re-arm path quickly.
#[cfg_attr(
    not(any(test, windows)),
    allow(
        dead_code,
        reason = "called only by win32_timeout_ms and tests; win32_timeout_ms is itself dead off-windows"
    )
)]
fn win32_wait_clamp() -> u32 {
    #[cfg(test)]
    if let Some(v) = wait_clamp_seam::get() {
        return v;
    }
    WIN32_INFINITE - 1
}

/// Test-only, thread-local record of the timeout each block or recheck pause was armed with on this
/// thread (`None` = unbounded): a `poll` round, a Win32 wait, a [`crate::os_process::drive`] pause,
/// or an `OwnedChild`'s `Condvar` block.
/// A test proves a deadline wait armed nothing longer than the time remaining, and blocked at all,
/// from the log.
#[cfg(test)]
pub(crate) mod block_probe {
    #[cfg(target_os = "macos")]
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::time::Duration;

    /// A hook that runs before each blocking round, with the round's index.
    #[cfg(target_os = "macos")]
    type RoundHook = Box<dyn FnMut(u32)>;

    /// A one-shot hook slot ([`on_blocking`]'s, [`on_pause`]'s or [`on_condvar_block`]'s). The hook
    /// gets the timeout the block or pause was armed with (`None`: none).
    type Slot = RefCell<Option<Box<dyn FnOnce(Option<Duration>)>>>;

    thread_local! {
        static ARMED: RefCell<Vec<Option<Duration>>> = const { RefCell::new(Vec::new()) };
        static ON_BLOCKING: Slot = const { RefCell::new(None) };
        static ON_PAUSE: Slot = const { RefCell::new(None) };
        static ON_CONDVAR_BLOCK: Slot = const { RefCell::new(None) };
        #[cfg(target_os = "macos")]
        static ROUND: Cell<u32> = const { Cell::new(0) };
        #[cfg(target_os = "macos")]
        static ON_ROUND: RefCell<Option<RoundHook>> = const { RefCell::new(None) };
        /// Which arming owns `ON_ROUND`: every arm and every disarm moves it on.
        #[cfg(target_os = "macos")]
        static ROUND_OWNER: Cell<u64> = const { Cell::new(0) };
    }

    fn record(armed: Option<Duration>) {
        ARMED.with(|a| a.borrow_mut().push(armed));
    }

    /// [`record`], for a thread about to make a blocking OS call on a descriptor or handle (`poll`,
    /// `WaitForSingleObject`), and run the hook [`on_blocking`] armed.
    pub(crate) fn record_blocking(armed: Option<Duration>) {
        record(armed);
        fire(&ON_BLOCKING, armed);
        #[cfg(target_os = "macos")]
        fire_round();
    }

    /// Record a recheck pause of `d` and run the armed [`on_pause`] hook. Unlike a block, it fires
    /// no round.
    pub(crate) fn record_pause(d: Duration) {
        record(Some(d));
        fire(&ON_PAUSE, Some(d));
    }

    /// Record a `Condvar` block `armed` for (`None`: no timeout) and run the armed
    /// [`on_condvar_block`] hook, under the lock. Unlike a block on a descriptor, it fires no round.
    pub(crate) fn record_condvar_block(armed: Option<Duration>) {
        record(armed);
        fire(&ON_CONDVAR_BLOCK, armed);
    }

    /// Run the hook armed in `slot` with `armed`, taken out first, so the hook may arm the slot
    /// again.
    fn fire(slot: &'static std::thread::LocalKey<Slot>, armed: Option<Duration>) {
        if let Some(hook) = slot.with(|h| h.borrow_mut().take()) {
            hook(armed);
        }
    }

    #[cfg(target_os = "macos")]
    fn fire_round() {
        let round = ROUND.with(|r| r.replace(r.get() + 1));
        // Out of its slot for the call, so the hook may itself arm or drop rounds; it goes back
        // only if neither happened.
        if let Some(mut hook) = ON_ROUND.with(|h| h.borrow_mut().take()) {
            let owner = ROUND_OWNER.with(Cell::get);
            hook(round);
            if ROUND_OWNER.with(Cell::get) == owner {
                ON_ROUND.with(|h| *h.borrow_mut() = Some(hook));
            }
        }
    }

    /// Disarms an [`on_every_round`] hook on drop.
    #[cfg(target_os = "macos")]
    #[must_use = "dropping this immediately disarms the hook; bind it for the probe's duration"]
    pub(crate) struct Rounds(u64);

    #[cfg(target_os = "macos")]
    impl Drop for Rounds {
        /// Disarms only the arming this guard came from: a guard that a later arm replaced does
        /// nothing.
        fn drop(&mut self) {
            if ROUND_OWNER.with(Cell::get) == self.0 {
                ON_ROUND.with(|h| *h.borrow_mut() = None);
                ROUND_OWNER.with(|o| o.set(self.0 + 1));
            }
        }
    }

    /// Run `hook` with the round's index on this thread just before every blocking `poll`, counted
    /// from 0 at this call: the wait's own look has just returned what to block on, and every lock
    /// is released.
    #[cfg(target_os = "macos")]
    pub(crate) fn on_every_round(hook: impl FnMut(u32) + 'static) -> Rounds {
        ROUND.with(|r| r.set(0));
        let owner = ROUND_OWNER.with(|o| o.replace(o.get() + 1)) + 1;
        ON_ROUND.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        Rounds(owner)
    }

    /// Run `hook` on this thread just before blocking round `round` (see [`on_every_round`]).
    #[cfg(target_os = "macos")]
    pub(crate) fn on_round(round: u32, hook: impl FnOnce() + 'static) -> Rounds {
        let mut hook = Some(hook);
        on_every_round(move |at| {
            if at == round {
                hook.take().expect("a round comes once")();
            }
        })
    }

    /// Disarms an unfired [`on_blocking`], [`on_pause`] or [`on_condvar_block`] hook on drop.
    #[must_use = "dropping this immediately disarms the hook; bind it for the probe's duration"]
    pub(crate) struct Armed(&'static std::thread::LocalKey<Slot>);

    impl Drop for Armed {
        fn drop(&mut self) {
            self.0.with(|h| *h.borrow_mut() = None);
        }
    }

    /// Run `hook` on this thread just before its next blocking `poll` or `WaitForSingleObject`: the
    /// thread has released every lock it took for the wait it is about to make.
    pub(crate) fn on_blocking(hook: impl FnOnce() + 'static) -> Armed {
        ON_BLOCKING.with(|h| *h.borrow_mut() = Some(Box::new(move |_| hook())));
        Armed(&ON_BLOCKING)
    }

    /// Run `hook` on this thread just before its next recheck pause sleeps. A hook that takes the
    /// `Waitable`'s lock proves the `Step::Recheck` contract (the lock is released before the
    /// pause); the hook firing alone does not.
    pub(crate) fn on_pause(hook: impl FnOnce() + 'static) -> Armed {
        ON_PAUSE.with(|h| *h.borrow_mut() = Some(Box::new(move |_| hook())));
        Armed(&ON_PAUSE)
    }

    /// Run `hook`, under the `OwnedChild`'s lock, just before this thread's next block on that
    /// handle's `Condvar` (no other `Condvar` fires it).
    /// A test's hook sends on a channel it then `recv()`s, so it knows the waiter is inside the
    /// `Condvar` before it releases anything: the wait releases the lock atomically, so the release
    /// cannot overtake it.
    pub(crate) fn on_condvar_block(hook: impl FnOnce() + 'static) -> Armed {
        on_condvar_block_with(move |_| hook())
    }

    /// [`on_condvar_block`], with the time the block is about to be armed for: `None` is a block
    /// with no timeout.
    pub(crate) fn on_condvar_block_with(hook: impl FnOnce(Option<Duration>) + 'static) -> Armed {
        ON_CONDVAR_BLOCK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        Armed(&ON_CONDVAR_BLOCK)
    }

    /// Every timeout armed on this thread since the last call, in order.
    pub(crate) fn take() -> Vec<Option<Duration>> {
        ARMED.with(|a| std::mem::take(&mut *a.borrow_mut()))
    }
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
    #[cfg_attr(not(windows), allow(dead_code, reason = "only Windows tests register a hook"))]
    pub(crate) fn on_second_arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    /// Drain everything recorded on this thread, and drop any unconsumed hook.
    // Only Windows tests read the probe back.
    #[cfg_attr(not(windows), allow(dead_code, reason = "only Windows tests read the probe back"))]
    pub(crate) fn take() -> Vec<Arm> {
        HOOK.with(|h| *h.borrow_mut() = None);
        RECORDED.with(|r| r.take())
    }

    /// Assert a clamped wait re-armed (at least two arms), that each armed exactly
    /// `expected_ms(remaining, clamp)`, and that `remaining` shrank strictly across arms.
    // Only Windows tests call it.
    #[cfg_attr(not(windows), allow(dead_code, reason = "only Windows tests call it"))]
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
    #[cfg_attr(not(windows), allow(dead_code, reason = "only Windows tests call it"))]
    pub(crate) fn expected_ms(remaining: Duration, clamp: u32) -> u32 {
        let ceil = remaining.as_nanos().div_ceil(1_000_000);
        u32::try_from(ceil.min(u128::from(clamp))).expect("capped at a u32 clamp")
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
