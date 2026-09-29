//! The macOS wait for a child's exit, by number: a kqueue holding `EVFILT_PROC` (`NOTE_EXIT |
//! NOTE_REAP`) and `EVFILT_SIGNAL` (`SIGCHLD`), plus a peek. It never reaps: the caller reaps
//! afterwards through the handle it holds, and for a zombie that returns at once.
//!
//! - A peek that finds an exit record is [`Waited::Reapable`]. A still-running child blocks on
//!   the kqueue; a spurious wake, such as a sibling's `SIGCHLD`, only re-peeks.
//! - `NOTE_REAP` on the wait's own knote is [`Waited::Gone`]: only a real reap fires it (the
//!   tracer's hand-back re-sends `NOTE_EXIT` and returns before `proc_knote(child, NOTE_REAP)`,
//!   `kern_exit.c:2721-2773` against `:2787`), and every caller reaps only after this returns,
//!   so a `NOTE_REAP` during the wait means something else reaped the child. It never peeks
//!   again by a pid that may since name another child. An `ECHILD` from a peek is `Gone` too.
//! - Once `NOTE_EXIT` has come, or the registration's receipt says `ESRCH` (the child is already
//!   past `P_REF_DEAD`), it re-peeks with a backoff until the peek finds the zombie: XNU is
//!   finishing the exit on its own, and the backoff re-checks that real condition. 1 ms doubling
//!   to at most 50 ms, no iteration cap; elapsed time decides nothing.
//! - `EV_CLEAR` on the `EVFILT_PROC` knote: with `NOTE_REAP` requested `NOTE_EXIT` is not
//!   one-shot and the knote's `fflags` are never cleared, so without it the knote re-activates
//!   and every backoff `kevent` returns at once (`kern_event.c:1222-1224`, `:993-995`,
//!   `:4442-4445`, `:1314`): a CPU spin between exit and `SZOMB`.
//! - Under `SIG_IGN` or `SA_NOCLDWAIT`, XNU reaps the child itself and sends no `SIGCHLD`
//!   (`kern_exit.c:2577-2601`). The wait registers `EVFILT_PROC` itself, so a caller whose own
//!   registration got `ESRCH` still has a `NOTE_EXIT` to wait for.
//! - `deadline` is the caller's bound: never early, and never late by the wait's own choice.
//!   Every blocking `kevent`, the backoff's included, is timed to the time remaining. When that
//!   runs out, one final peek decides: a zombie found is `Reapable`, else `DeadlinePassed`.
//!   `None` is unbounded.

use std::io;
use std::time::{Duration, Instant};

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use super::add_with_receipt;
use crate::wait::exit_only::{self, Foreign, Peek, Target};

/// The wait's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waited {
    /// The child is a zombie, and reapable.
    Reapable,
    /// The deadline passed with the child still running, after one final peek.
    DeadlinePassed,
    /// Something else reaped the child.
    Gone,
}

/// Slots in one `kevent` batch.
const BATCH: usize = 8;

const BACKOFF_START: Duration = Duration::from_millis(1);
const BACKOFF_CAP: Duration = Duration::from_millis(50);

fn blank() -> KEvent {
    KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0)
}

// `NOTE_REAP` is `#[deprecated]` in libc, but it is the only spelling of the flag.
#[allow(deprecated, reason = "libc marks NOTE_REAP deprecated; there is no other spelling")]
const NOTE_REAP: u32 = libc::NOTE_REAP;

/// Register `EVFILT_SIGNAL` for `SIGCHLD` and `EVFILT_PROC` for `pid`. `Ok(true)` when the
/// `EVFILT_PROC` receipt says `ESRCH` (the child is already past `P_REF_DEAD`).
fn register(kq: &Kqueue, pid: u32) -> io::Result<bool> {
    let signal = KEvent::new(
        libc::SIGCHLD as usize,
        EventFilter::EVFILT_SIGNAL,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT | EvFlags::EV_CLEAR,
        FilterFlag::empty(),
        0,
        0,
    );
    let added = add_with_receipt(kq, signal).map_err(into_io)?;
    if added != 0 {
        return Err(io::Error::from_raw_os_error(added as i32));
    }
    #[cfg(test)]
    if super::test_hooks::take_forced_esrch_registration() {
        return Ok(true);
    }
    let proc_exit = KEvent::new(
        pid as usize,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT | EvFlags::EV_CLEAR,
        FilterFlag::NOTE_EXIT | FilterFlag::from_bits_retain(NOTE_REAP),
        0,
        0,
    );
    match add_with_receipt(kq, proc_exit).map_err(into_io)? {
        0 => Ok(false),
        e if e == libc::ESRCH as i64 => Ok(true),
        e => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

fn into_io(e: crate::error::Error) -> io::Error {
    match e {
        crate::error::Error::Io(e) => e,
        other => io::Error::other(other),
    }
}

/// One non-consuming look, by number and with no start check.
fn peek(pid: u32) -> io::Result<Peek> {
    exit_only::peek(&Target::pid(pid, None))
}

/// The peek's verdict as a wait verdict, or `None` when the child is still running.
fn settle(peeked: Peek) -> Option<Waited> {
    match peeked {
        Peek::Exit(_) => Some(Waited::Reapable),
        Peek::Running => None,
        Peek::Foreign(Foreign::Gone | Foreign::Other) => Some(Waited::Gone),
    }
}

/// Read every event already pending without blocking, until a round returns fewer events than
/// the buffer holds; `true` if any is `NOTE_REAP`.
fn drain_for_reap(kq: &Kqueue, events: &mut [KEvent; BATCH]) -> io::Result<bool> {
    loop {
        let n = kevent_round(kq, events, Some(Duration::ZERO))?;
        if scan(&events[..n]).0 {
            return Ok(true);
        }
        if n < BATCH {
            return Ok(false);
        }
    }
}

/// `(saw NOTE_REAP, saw NOTE_EXIT)` in `events`.
fn scan(events: &[KEvent]) -> (bool, bool) {
    let (mut reap, mut exit) = (false, false);
    for event in events {
        #[cfg(test)]
        super::test_hooks::record_event(event.filter().map_or(0, |f| f as i16), event.fflags().bits());
        if event.filter() == Ok(EventFilter::EVFILT_PROC) {
            reap |= event.fflags().bits() & NOTE_REAP != 0;
            exit |= event.fflags().contains(FilterFlag::NOTE_EXIT);
        }
    }
    (reap, exit)
}

/// One `kevent` call with `timeout`, `EINTR` retried inside the same round.
fn kevent_round(kq: &Kqueue, events: &mut [KEvent; BATCH], timeout: Option<Duration>) -> io::Result<usize> {
    #[cfg(test)]
    let started = Instant::now();
    let n = loop {
        match kq.kevent(&[], events, timeout.map(timespec)) {
            Ok(n) => break n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    #[cfg(test)]
    {
        crate::wait::test_clock::advance_by_elapsed_if_frozen(started.elapsed());
        super::test_hooks::record_await_kevent(timeout);
    }
    Ok(n)
}

fn timespec(d: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: d.as_secs().min(i64::MAX as u64) as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    }
}

/// Wait until `pid`'s exit is reapable, on `kq`; see the module docs.
pub(crate) fn await_reapable_on(kq: &Kqueue, pid: u32, deadline: Option<Instant>) -> io::Result<Waited> {
    let deadline = deadline.map(Some);
    let mut backoff = register(kq, pid)?;
    let mut interval = BACKOFF_START;
    let mut events = [blank(); BATCH];
    #[cfg(test)]
    let mut round: u32 = 0;
    #[cfg(test)]
    let mut check = crate::wait::test_clock::RoundCheck::new("await_reapable_on");
    let mut repeek = false;
    loop {
        #[cfg(test)]
        check.round();
        if repeek {
            #[cfg(test)]
            {
                super::test_hooks::fire_before_repeek();
                if backoff {
                    super::test_hooks::fire_esrch_repeek();
                }
            }
        }
        repeek = true;
        // A `NOTE_REAP` anywhere before a peek means something else reaped the child: never
        // peek again by a pid that may since name another child.
        if drain_for_reap(kq, &mut events)? {
            return Ok(Waited::Gone);
        }
        if let Some(verdict) = settle(peek(pid)?) {
            return Ok(verdict);
        }
        if expired(deadline) {
            return final_peek(pid);
        }
        // Block: on the kqueue alone until `NOTE_EXIT`, then per backoff interval.
        #[cfg(test)]
        super::test_hooks::fire_kevent_round(round);
        #[cfg(test)]
        {
            round += 1;
        }
        let timeout = match (backoff, crate::wait::remaining(deadline)) {
            (true, Some(left)) => Some(interval.min(left)),
            (true, None) => Some(interval),
            (false, left) => left,
        };
        // A deadline wait never arms an unbounded `kevent`.
        debug_assert!(
            deadline.is_none() || timeout.is_some(),
            "a deadline wait armed an unbounded kevent"
        );
        let n = kevent_round(kq, &mut events, timeout)?;
        let (reaped, exited) = scan(&events[..n]);
        if reaped {
            return Ok(Waited::Gone);
        }
        if exited {
            backoff = true;
        } else if backoff && n == 0 {
            interval = (interval * 2).min(BACKOFF_CAP);
        }
        if expired(deadline) {
            // No new round: the drain, then the one final peek.
            if drain_for_reap(kq, &mut events)? {
                return Ok(Waited::Gone);
            }
            return final_peek(pid);
        }
    }
}

fn expired(deadline: Option<Option<Instant>>) -> bool {
    crate::wait::remaining(deadline) == Some(Duration::ZERO)
}

/// The one non-blocking look at expiry.
fn final_peek(pid: u32) -> io::Result<Waited> {
    #[cfg(test)]
    exit_only::seams::step(exit_only::seams::HolderStep::FinalPeek);
    Ok(settle(peek(pid)?).unwrap_or(Waited::DeadlinePassed))
}

/// [`await_reapable_on`] on a kqueue of its own.
pub(crate) fn await_reapable(pid: u32, deadline: Option<Instant>) -> io::Result<Waited> {
    let kq = Kqueue::new().map_err(io::Error::from)?;
    await_reapable_on(&kq, pid, deadline)
}
