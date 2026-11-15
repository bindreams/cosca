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
/// [`crate::os_process::drive`] and `tokio::drive`, and by the cores of `Child::graceful_shutdown` and
/// `Child::graceful_shutdown_tree`, in `child::graceful::shutdown`),
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
    rustix::io::retry_on_intr(|| rustix::event::poll(fds, Some(&zero))).map(|ready| ready > 0)
}

/// Blocks until `fds` has an event, retrying `EINTR`.
#[cfg(unix)]
pub(crate) fn poll_ready(fds: &mut [rustix::event::PollFd<'_>]) -> Result<(), rustix::io::Errno> {
    rustix::io::retry_on_intr(|| rustix::event::poll(fds, None)).map(|_| ())
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
/// a cgroup drain's listener, or an `OwnedChild`'s `Condvar` block.
/// A test proves a deadline wait armed nothing longer than the time remaining, and blocked at all,
/// from the log.
///
/// A block calls [`blocking`] just before it blocks, naming what it blocks on; [`on_each_block`]
/// hands a test that, so the test can look at what the wait is about to wait for.
#[cfg(test)]
pub(crate) mod block_probe {
    use std::cell::{Cell, RefCell};
    use std::marker::PhantomData;
    use std::time::Duration;

    #[cfg(unix)]
    use std::os::fd::BorrowedFd;

    /// The hook [`on_each_block`] arms.
    type Hook = Box<dyn FnMut(&Block<'_>)>;

    /// `hook` is out of the slot while it runs, so it may itself arm or drop a hook, or block.
    struct Armament {
        id: u64,
        /// The rounds of a wait this hook has seen ([`Block::is_round`]).
        blocks: u32,
        hook: Option<Hook>,
    }

    thread_local! {
        static ARMED: RefCell<Vec<Option<Duration>>> = const { RefCell::new(Vec::new()) };
        /// The hooks armed on this thread, in the order they were armed.
        static ON_BLOCK: RefCell<Vec<Armament>> = const { RefCell::new(Vec::new()) };
        static NEXT_ID: Cell<u64> = const { Cell::new(0) };
        static ON_PAUSE: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    }

    /// What one wait waits on.
    #[allow(
        dead_code,
        reason = "`Fd` is read only by `Block::ready`, which only macOS tests call; `Drain` and `DrainAwait` are built on Linux only"
    )]
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum WaitObject<'a> {
        /// A descriptor `poll` is about to wait on: a pidfd, a kqueue, a pipe.
        #[cfg(unix)]
        Fd(BorrowedFd<'a>),
        /// A `WaitForSingleObject` or `WaitForMultipleObjects` call: the block names its kind only.
        #[cfg(windows)]
        Handles,
        /// Keeps `'a` used on Windows, where there is no `Fd`. Never built.
        #[cfg(windows)]
        Unbuilt(std::convert::Infallible, std::marker::PhantomData<&'a ()>),
        /// A thread blocking on a cgroup leaf's drain, on the pump's broadcast or on the leaf's own
        /// watch: the drain is in the leaf, so there is nothing to look at.
        Drain,
        /// A task awaiting a cgroup leaf's drain: nothing blocks, and there is nothing to look at.
        DrainAwait,
        /// Another waiter's reap: nothing to look at.
        Condvar,
    }

    /// One block, as the hook of [`on_each_block`] sees it.
    #[derive(Debug)]
    pub(crate) struct Block<'a> {
        /// `Some(1)` for the first block of a wait this hook sees. `None` at a block that is no
        /// round of a thread's wait: a `Condvar` block (another waiter's reap) and a
        /// [`WaitObject::DrainAwait`] (a task's await blocks no thread).
        #[cfg_attr(not(target_os = "macos"), allow(dead_code, reason = "only macOS tests read it"))]
        pub(crate) n: Option<u32>,
        /// What the call is armed for; `None` is unbounded.
        pub(crate) armed: Option<Duration>,
        pub(crate) on: WaitObject<'a>,
    }

    impl Block<'_> {
        /// Whether this is a round of a thread's wait: not another waiter's `Condvar` block, and not
        /// a task's [`WaitObject::DrainAwait`].
        pub(crate) fn is_round(&self) -> bool {
            self.n.is_some()
        }

        /// Whether the awaited event is already there (a zero-timeout `poll`); `None` when the block
        /// lends no descriptor.
        #[cfg_attr(not(target_os = "macos"), allow(dead_code, reason = "only macOS tests call it"))]
        pub(crate) fn ready(&self) -> Option<bool> {
            match &self.on {
                #[cfg(unix)]
                WaitObject::Fd(fd) => Some(
                    crate::os_process::poll::look_readable(*fd)
                        .expect("a zero-timeout look at the awaited descriptor: a broken one is no event"),
                ),
                _ => None,
            }
        }
    }

    fn record(armed: Option<Duration>) {
        ARMED.with(|a| a.borrow_mut().push(armed));
    }

    /// The one call a block site makes, just before the blocking call: records what the block is
    /// armed for (`None`: no timeout) and runs the hooks [`on_each_block`] armed. Every lock the
    /// wait took is released, except a `Condvar` block's: it holds the child's lock. A
    /// [`WaitObject::DrainAwait`] blocks no thread: the hooks run at it, but it is not recorded
    /// for [`take`] and is not counted as a block by any hook.
    pub(crate) fn blocking(armed: Option<Duration>, on: WaitObject<'_>) {
        if !matches!(on, WaitObject::DrainAwait) {
            record(armed);
        }
        let is_round = !matches!(on, WaitObject::Condvar | WaitObject::DrainAwait);
        // The hooks armed now, in arming order: one armed by a hook first sees the next block, and
        // one a hook disarmed does not run.
        let ids: Vec<u64> = ON_BLOCK.with(|hooks| hooks.borrow().iter().map(|a| a.id).collect());
        for id in ids {
            let taken = ON_BLOCK.with(|hooks| {
                let mut hooks = hooks.borrow_mut();
                let armament = hooks.iter_mut().find(|a| a.id == id)?;
                let hook = armament.hook.take()?;
                let n = is_round.then(|| {
                    armament.blocks += 1;
                    armament.blocks
                });
                Some((n, hook))
            });
            let Some((n, hook)) = taken else { continue };
            let mut running = Running { id, hook: Some(hook) };
            if let Some(hook) = running.hook.as_mut() {
                hook(&Block { n, armed, on });
            }
        }
    }

    /// A hook while it runs, out of its slot. Dropping it, also when the hook panicked, puts it
    /// back, so a hook that panicked once still runs at the next block.
    struct Running {
        id: u64,
        hook: Option<Hook>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let hook = self.hook.take();
            // Unless its guard dropped while it ran: then it drops here, outside the borrow, since
            // it may hold another guard.
            let unplaced = ON_BLOCK.with(|hooks| match hooks.borrow_mut().iter_mut().find(|a| a.id == self.id) {
                Some(armament) => {
                    armament.hook = hook;
                    None
                }
                None => hook,
            });
            drop(unplaced);
        }
    }

    /// Record a recheck pause of `d` and run the armed [`on_pause`] hook. Unlike a block, it is no
    /// [`Block`]: a backoff sleep waits on no object.
    pub(crate) fn record_pause(d: Duration) {
        record(Some(d));
        crate::oneshot_hook::fire(&ON_PAUSE);
    }

    /// Disarms the hook of [`on_each_block`], [`on_blocking`], [`on_condvar_block`] or [`on_pause`] on
    /// drop, and only that one. Not `Send`: the hooks are this thread's.
    #[must_use = "dropping this immediately disarms the hook; bind it for the probe's duration"]
    pub(crate) struct Armed(Disarm, PhantomData<*const ()>);

    enum Disarm {
        Pause {
            _hook: crate::oneshot_hook::Armed,
        },
        /// The [`Armament`] with this id.
        Block(u64),
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            if let Disarm::Block(id) = self.0 {
                // The armament drops after the borrow ends: its hook may hold another guard.
                let removed = ON_BLOCK.with(|hooks| {
                    let mut hooks = hooks.borrow_mut();
                    let at = hooks.iter().position(|a| a.id == id)?;
                    Some(hooks.remove(at))
                });
                drop(removed);
            }
        }
    }

    /// Run `hook` on this thread at every [`blocking`] call until the guard drops, numbering the
    /// blocks of a wait ([`Block::n`]) from 1 at this call. Any number of hooks may be armed at
    /// once: each runs at every block, in the order they were armed, and counts the blocks it sees
    /// from its own arming. One armed by a running hook is kept, and first sees the next block. A
    /// block made while a hook runs is not one that hook sees.
    ///
    /// A hook run at a `Condvar` block holds the child's lock: it must not take it.
    pub(crate) fn on_each_block(hook: impl FnMut(&Block<'_>) + 'static) -> Armed {
        let id = NEXT_ID.with(|next| next.replace(next.get() + 1));
        ON_BLOCK.with(|hooks| {
            hooks.borrow_mut().push(Armament {
                id,
                blocks: 0,
                hook: Some(Box::new(hook)),
            })
        });
        Armed(Disarm::Block(id), PhantomData)
    }

    /// Run `hook` once, at the next block of this thread that `keep` accepts.
    fn once_at(keep: fn(&Block<'_>) -> bool, hook: impl FnOnce(&Block<'_>) + 'static) -> Armed {
        let mut hook = Some(hook);
        on_each_block(move |block| {
            if keep(block) {
                if let Some(hook) = hook.take() {
                    hook(block);
                }
            }
        })
    }

    /// Run `hook` once, at this thread's next round of a wait ([`Block::is_round`]): the thread has
    /// released every lock it took for the wait it is about to make. A `Condvar` block and a task's
    /// await ([`WaitObject::DrainAwait`]) are no round here.
    pub(crate) fn on_blocking(hook: impl FnOnce() + 'static) -> Armed {
        once_at(|block| block.is_round(), move |_| hook())
    }

    /// Run `hook` on this thread just before its next recheck pause sleeps. A hook that takes the
    /// `Waitable`'s lock proves the `Step::Recheck` contract (the lock is released before the
    /// pause); the hook firing alone does not.
    pub(crate) fn on_pause(hook: impl FnOnce() + 'static) -> Armed {
        let _hook = crate::oneshot_hook::arm(&ON_PAUSE, hook);
        Armed(Disarm::Pause { _hook }, PhantomData)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn is_drain_wait(block: &Block<'_>) -> bool {
        matches!(block.on, WaitObject::Drain | WaitObject::DrainAwait)
    }

    /// Run `hook` once, at the next wait of this thread for a cgroup leaf's drain: a block on it
    /// ([`WaitObject::Drain`]) or a task's await of it ([`WaitObject::DrainAwait`]). A user that
    /// must tell the two apart filters on the kind itself, through [`on_each_block`].
    #[cfg(target_os = "linux")]
    pub(crate) fn on_drain_block(hook: impl FnOnce() + 'static) -> Armed {
        once_at(is_drain_wait, move |_| hook())
    }

    /// Run `act` at every wait of this thread for a cgroup leaf's drain ([`on_drain_block`]'s two
    /// kinds), until the guard drops.
    #[cfg(target_os = "linux")]
    pub(crate) fn on_each_drain_block(mut act: impl FnMut() + 'static) -> Armed {
        on_each_block(move |block| {
            if is_drain_wait(block) {
                act();
            }
        })
    }

    /// Run `hook`, under the `OwnedChild`'s lock, just before this thread's next block on that
    /// handle's `Condvar`. The wait releases the lock atomically, so a hook that signals the test
    /// proves the waiter is inside the `Condvar` before anything else can take the lock.
    pub(crate) fn on_condvar_block(hook: impl FnOnce() + 'static) -> Armed {
        on_condvar_block_with(move |_| hook())
    }

    /// [`on_condvar_block`], with the armed timeout (`None`: no timeout).
    pub(crate) fn on_condvar_block_with(hook: impl FnOnce(Option<Duration>) + 'static) -> Armed {
        once_at(
            |block| matches!(block.on, WaitObject::Condvar),
            move |block| hook(block.armed),
        )
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
