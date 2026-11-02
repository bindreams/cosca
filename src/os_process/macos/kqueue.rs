//! macOS kqueue primitives for [`crate::os_process`]: the [`Kqueue`] type, the `NOTE_EXIT` arms
//! (notify, never reap) and the blocking `kevent` loop. Signals go through the audit token, in
//! `os_process::macos`.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue as NixKqueue};

use crate::error::Error;

/// The longest timeout ONE `kevent` call is armed with: `i32::MAX` seconds (~68 years). XNU's
/// `kevent` rejects a `tv_sec` above `INT32_MAX` with `EINVAL` even when an event is pending.
/// The wait loop re-arms from the real deadline, so the cap never shortens the wait (principle 13).
const KEVENT_MAX_SECS: u64 = i32::MAX as u64;

/// The cap in force: [`KEVENT_MAX_SECS`], or a lower one a test installed.
fn kevent_cap() -> Duration {
    #[cfg(test)]
    if let Some(lowered) = test_hooks::clamp_override() {
        return lowered;
    }
    Duration::from_secs(KEVENT_MAX_SECS)
}

/// Contract of every timespec handed to `kevent`, computed or forced.
fn assert_kevent_timespec(ts: &libc::timespec) {
    debug_assert!(
        ts.tv_sec >= 0 && ts.tv_sec as u64 <= KEVENT_MAX_SECS,
        "kevent tv_sec {} exceeds XNU's INT32_MAX limit",
        ts.tv_sec
    );
}

/// The `kevent` timeout for a remaining time: `d` capped at [`kevent_cap`]. The single conversion
/// for every blocking `kevent` in the crate, the test tracer's included.
pub(crate) fn kevent_timeout(d: Duration) -> libc::timespec {
    let d = d.min(kevent_cap());
    let ts = libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    };
    assert_kevent_timespec(&ts);
    ts
}

/// What a `kevent` that returned 0 while the deadline still has time left means.
#[derive(Debug, PartialEq, Eq)]
enum ZeroReturn {
    /// The timeout was the full cap, so the deadline was further off: the intended re-arm.
    Rearm,
    /// A shorter (or no) timeout came back empty with time left: an early wake.
    Anomaly,
}

fn classify_zero_return(armed: Option<Duration>) -> ZeroReturn {
    if armed == Some(kevent_cap()) {
        ZeroReturn::Rearm
    } else {
        ZeroReturn::Anomaly
    }
}

fn placeholder() -> KEvent {
    KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0)
}

/// `NOTE_REAP` (xnu `sys/event.h`): a process was reaped. Spelled here because libc dropped it in
/// 0.2.190.
pub(crate) const NOTE_REAP: u32 = 0x1000_0000;

/// Events read per `kevent` call by [`Kqueue::poll`], which calls again while a read fills them.
const POLL_BATCH: usize = 32;

/// A kqueue: a set of subscriptions, each reporting what happened to it since it was last read.
///
/// One per waiter: events go to whichever reader takes them, and a registration is keyed by
/// (kqueue, ident, filter), so two waiters sharing one queue replace each other's registrations.
#[derive(Debug)]
pub(crate) struct Kqueue(NixKqueue);

/// What one subscription watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subscription {
    /// Process `pid`'s exit; and, if asked, signals delivered to it and its reap by anyone.
    Process { pid: u32, signals: bool, reap: bool },
    /// `fd`, a pipe, socket or kqueue, reaching `low_water` buffered bytes, or its other end closing.
    Readable { fd: RawFd, low_water: usize },
    /// Signal `signo` delivered to this process.
    Signal(libc::c_int),
}

/// What happened to one subscription since it was last read, merged: the kernel keeps one event
/// per subscription, so flags raised since the last read arrive together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    Process {
        pid: u32,
        exited: bool,
        signalled: bool,
        reaped: bool,
    },
    Readable {
        fd: RawFd,
        bytes: usize,
        closed: bool,
    },
    Signal {
        signo: libc::c_int,
        count: usize,
    },
    /// An `EV_ERROR` event: the kernel refused the registration (`ident`, `filter`).
    Error {
        ident: usize,
        filter: libc::c_short,
        errno: Errno,
    },
}

impl Subscription {
    /// The kernel change that applies `flags` to this subscription.
    fn change(self, flags: EvFlags) -> KEvent {
        match self {
            Subscription::Process { pid, signals, reap } => {
                let mut fflags = FilterFlag::NOTE_EXIT;
                if signals {
                    fflags |= FilterFlag::NOTE_SIGNAL;
                }
                if reap {
                    fflags |= FilterFlag::from_bits_retain(NOTE_REAP);
                }
                KEvent::new(pid as usize, EventFilter::EVFILT_PROC, flags, fflags, 0, 0)
            }
            Subscription::Readable { fd, low_water } => KEvent::new(
                fd as usize,
                EventFilter::EVFILT_READ,
                flags,
                FilterFlag::NOTE_LOWAT,
                // A threshold above `isize::MAX` is never reached either way.
                isize::try_from(low_water).unwrap_or(isize::MAX),
                0,
            ),
            Subscription::Signal(signo) => KEvent::new(
                signo as usize,
                EventFilter::EVFILT_SIGNAL,
                flags,
                FilterFlag::empty(),
                0,
                0,
            ),
        }
    }
}

impl Event {
    /// The event a kernel `KEvent` reports; an `EV_ERROR` event, whose `data` is the errno, is
    /// [`Event::Error`]. `None` for a filter [`Event`] does not name: a `Kqueue` holds only
    /// subscriptions it can report, so that breaks a contract (debug-asserted, warned in release).
    pub(crate) fn from_kevent(ev: &KEvent) -> Option<Event> {
        let flags = ev.flags();
        if flags.contains(EvFlags::EV_ERROR) {
            return Some(Event::Error {
                ident: ev.ident(),
                // 0 is no filter: a filter unknown to nix has no value to report.
                filter: ev.filter().map_or(0, |f| f as libc::c_short),
                errno: Errno::from_raw(ev.data() as i32),
            });
        }
        let fflags = ev.fflags();
        match ev.filter() {
            Ok(EventFilter::EVFILT_PROC) => Some(Event::Process {
                pid: ev.ident() as u32,
                exited: fflags.contains(FilterFlag::NOTE_EXIT),
                signalled: fflags.contains(FilterFlag::NOTE_SIGNAL),
                reaped: fflags.bits() & NOTE_REAP != 0,
            }),
            Ok(EventFilter::EVFILT_READ) => Some(Event::Readable {
                fd: ev.ident() as RawFd,
                bytes: count(ev),
                closed: flags.contains(EvFlags::EV_EOF),
            }),
            Ok(EventFilter::EVFILT_SIGNAL) => Some(Event::Signal {
                signo: ev.ident() as libc::c_int,
                count: count(ev),
            }),
            other => {
                log::warn!("kqueue: an event of filter {other:?} that no subscription asked for; dropped");
                debug_assert!(false, "an event of filter {other:?} that no subscription asked for");
                None
            }
        }
    }
}

/// The count an `EVFILT_READ` or `EVFILT_SIGNAL` event carries in `data` (bytes buffered, signals
/// delivered). Never negative; a negative one is an ABI surprise, warned about and clamped to 0.
fn count(ev: &KEvent) -> usize {
    if ev.data() < 0 {
        log::warn!(
            "kqueue: {:?} reported a negative data field ({}); clamped to 0",
            ev.filter(),
            ev.data()
        );
    }
    debug_assert!(
        ev.data() >= 0,
        "a read or signal event's data is a count and never negative, got {}",
        ev.data()
    );
    usize::try_from(ev.data()).unwrap_or(0)
}

/// The error a receipt's `data` names.
fn receipt_error(errno: i64) -> Error {
    Error::Io(std::io::Error::from_raw_os_error(errno as i32))
}

impl Kqueue {
    pub(crate) fn new() -> Result<Self, Error> {
        NixKqueue::new().map(Kqueue).map_err(|e| Error::Io(e.into()))
    }

    /// Applies one `EV_RECEIPT` change; a receipt whose `data` is an errno is that error.
    fn apply(&self, change: KEvent) -> Result<(), Error> {
        // EV_RECEIPT makes the change synchronous: kevent returns exactly one receipt event
        // whose `data` is the result.
        let mut receipt = [placeholder()];
        let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let n = self
            .0
            .kevent(&[change], &mut receipt, Some(zero))
            .map_err(|e| Error::Io(e.into()))?;
        if n != 1 {
            return Err(Error::Io(std::io::Error::other(
                "kqueue EV_RECEIPT returned no receipt event",
            )));
        }
        match receipt[0].data() {
            0 => Ok(()),
            errno => Err(receipt_error(errno as i64)),
        }
    }

    /// Registers `s`, replacing the registration of the same (kqueue, ident, filter) if there is
    /// one. Every subscription is `EV_CLEAR`: it reports what changed since it was last read. A
    /// dead pid fails with `ESRCH`, like any refused registration.
    pub(crate) fn subscribe(&self, s: Subscription) -> Result<(), Error> {
        self.apply(s.change(EvFlags::EV_ADD | EvFlags::EV_RECEIPT | EvFlags::EV_CLEAR))
    }

    /// Removes `s`'s registration. One the kernel already removed (a delivered exit) fails with
    /// `ENOENT`.
    pub(crate) fn unsubscribe(&self, s: Subscription) -> Result<(), Error> {
        self.apply(s.change(EvFlags::EV_DELETE | EvFlags::EV_RECEIPT))
    }

    /// Takes every pending event, in order, without blocking; empty if nothing is pending. An
    /// `EV_ERROR` event is an [`Event::Error`] among the rest: the call fails only when `kevent`
    /// does.
    pub(crate) fn poll(&self) -> Result<Vec<Event>, Error> {
        let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let mut batch = [placeholder(); POLL_BATCH];
        let mut events = Vec::new();
        loop {
            let n = match self.0.kevent(&[], &mut batch, Some(zero)) {
                Ok(n) => n,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(Error::Io(e.into())),
            };
            for ev in &batch[..n] {
                events.extend(Event::from_kevent(ev));
            }
            // A read that comes back short has taken everything pending.
            if n < POLL_BATCH {
                return Ok(events);
            }
        }
    }

    /// The underlying nix queue, for the blocking `kevent` loops and `await_reapable`'s own loop,
    /// which read it directly.
    pub(crate) fn native(&self) -> &NixKqueue {
        &self.0
    }
}

impl AsFd for Kqueue {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for Kqueue {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_fd().as_raw_fd()
    }
}

/// Create a kqueue and arm an `EVFILT_PROC | NOTE_EXIT` filter for `id`, re-verifying
/// identity. `Ok(None)` => already gone (treat as exited). The kqueue's fd polls readable
/// once the exit event is pending. Test-only: the production exit watch is
/// `os_process::macos::ExitWatch`, which the tests that need a bare kqueue do not reach.
#[cfg(test)]
pub(crate) fn arm_proc_exit(id: crate::identity::ProcessId) -> Result<Option<Kqueue>, Error> {
    let kq = Kqueue::new()?;
    let exit = Subscription::Process {
        pid: id.pid(),
        signals: false,
        reap: false,
    };
    match kq.subscribe(exit) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(None), // pid already gone
        Err(e) => return Err(e),
    }
    // An unassessable identity is NOT gone and must not be reported as an exit.
    match id.exists() {
        crate::identity::Existence::Present => Ok(Some(kq)),
        crate::identity::Existence::Gone => Ok(None), // recycled before the filter armed
        crate::identity::Existence::Unknown => {
            log::warn!(
                "wait: pid {} identity could not be confirmed; its exit cannot be observed",
                id.pid()
            );
            Err(Error::Unassessable {
                detail: format!(
                    "pid {} identity could not be confirmed; its exit cannot be observed",
                    id.pid()
                ),
                source: None,
            })
        }
    }
}

/// Block on an armed kqueue until `interpret` concludes, or until `deadline`, checking
/// `remaining(deadline)` fresh before every real `kevent` call and again once an event actually
/// arrives (never inferring elapsed-ness from `kevent` returning 0, nor trusting the value
/// sampled before a call that may have blocked long enough to cross the deadline itself) —
/// `interpret` and the final `on_timeout` return both see this freshly-checked flag, so neither
/// does deadline-funded work (like draining bytes) once there is no deadline left to fund it
/// (principle 13). A round already in flight when the deadline passes is not interrupted; only
/// the NEXT round is refused. `Ok(0)` alone is never trusted as proof the deadline passed
/// either — a mutant (or bug) could desync the requested timeout from `remaining`, so it is
/// re-checked before concluding, and retried as spurious otherwise. Shared by every blocking
/// kqueue wait this crate arms — `EVFILT_PROC` here, `EVFILT_READ` in `containment::marker_eof`.
pub(crate) fn block_on_kqueue<T: Copy>(
    kq: &Kqueue,
    deadline: Option<Instant>,
    on_timeout: T,
    mut interpret: impl FnMut(&KEvent, bool) -> Result<Option<T>, Error>,
) -> Result<T, Error> {
    let mut events = [placeholder()];
    #[cfg(test)]
    let mut round: u32 = 0;
    #[cfg(test)]
    let mut check = crate::wait::test_clock::RoundCheck::new("block_on_kqueue");
    loop {
        #[cfg(test)]
        check.round();
        #[cfg(test)]
        test_hooks::fire_round_hook(round, kq.native());
        #[cfg(test)]
        let call_start = Instant::now();

        // `EINTR` retries here, inside the SAME round, without re-firing the hook or advancing
        // `round` — round and kevent_calls() must stay one notion.
        let (already_elapsed, timeout, outcome) = loop {
            let remaining = crate::wait::remaining(deadline);
            let already_elapsed = remaining == Some(Duration::ZERO);
            // nix Kqueue::kevent takes Option<libc::timespec> (None = block forever).
            #[allow(unused_mut, reason = "mutated only under #[cfg(test)] below")]
            let mut timeout = remaining.map(kevent_timeout);
            #[cfg(test)]
            if let Some(forced) = test_hooks::take_timeout_override() {
                let forced = libc::timespec {
                    tv_sec: forced.as_secs() as libc::time_t,
                    tv_nsec: forced.subsec_nanos() as libc::c_long,
                };
                assert_kevent_timespec(&forced);
                timeout = Some(forced);
            }
            match kq.0.kevent(&[], &mut events, timeout) {
                Err(nix::errno::Errno::EINTR) => continue,
                outcome => break (already_elapsed, timeout, outcome),
            }
        };
        // Bounds what would otherwise be an unbounded spin under a mock clock a test forgot to
        // advance: see `test_clock::advance_by_elapsed_if_frozen`'s own doc. A no-op outside
        // tests and whenever the clock isn't frozen.
        #[cfg(test)]
        crate::wait::test_clock::advance_by_elapsed_if_frozen(call_start.elapsed());
        #[cfg(test)]
        test_hooks::record_kevent_call(as_duration(timeout));
        // Captured before incrementing: this round's own index, not the next round's.
        #[cfg(test)]
        let this_round = round;
        #[cfg(test)]
        {
            round += 1;
        }

        match outcome {
            Ok(0) => {
                if crate::wait::remaining(deadline) == Some(Duration::ZERO) {
                    return Ok(on_timeout);
                }
                match classify_zero_return(as_duration(timeout)) {
                    ZeroReturn::Rearm => log::debug!("wait: kevent reached its timeout cap with time left; re-arming"),
                    ZeroReturn::Anomaly => log::warn!(
                        "wait: kevent returned 0 after a timeout below the cap ({:?}) with time left; re-arming",
                        as_duration(timeout)
                    ),
                }
                continue; // retry from the freshly recomputed remaining time
            }
            Ok(_) => {
                #[cfg(test)]
                test_hooks::record_event_data(events[0].data());
                #[cfg(test)]
                test_hooks::fire_post_event_hook(this_round);
                let elapsed = already_elapsed || crate::wait::remaining(deadline) == Some(Duration::ZERO);
                if let Some(verdict) = interpret(&events[0], elapsed)? {
                    return Ok(verdict);
                }
                if elapsed {
                    return Ok(on_timeout);
                }
            }
            Err(nix::errno::Errno::EINTR) => {
                debug_assert!(false, "EINTR must be retried in the inner loop above, never reach here");
                continue;
            }
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
}

/// The requested `kevent` timeout as a `Duration`.
fn as_duration(timeout: Option<libc::timespec>) -> Option<Duration> {
    timeout.map(|ts| {
        debug_assert!(
            ts.tv_sec >= 0 && ts.tv_nsec >= 0,
            "a kevent timeout must never be negative"
        );
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    })
}

#[cfg(test)]
pub(crate) mod test_hooks;

#[cfg(test)]
#[path = "kqueue_tests.rs"]
mod kqueue_tests;
