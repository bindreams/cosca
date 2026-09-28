//! macOS death-watch + kill via kqueue `EVFILT_PROC` + `NOTE_EXIT` (notifies, never
//! reaps) and identity-verified `kill(2)` (no pidfd on Darwin, so a residual pid-reuse
//! window between re-verify and signal is irreducible — documented at the call site).

use std::time::{Duration, Instant};

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use crate::error::Error;
use crate::identity::ProcessId;

fn placeholder() -> KEvent {
    KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0)
}

/// Apply one change to an EXISTING kqueue with `EV_RECEIPT` (synchronous, receipt-checked)
/// and return the add result: 0 = armed, otherwise an errno. The single definition of the
/// receipt dance, shared by every filter this crate arms via `EV_ADD | EV_RECEIPT` — no
/// hand-rolled twin to drift.
pub(crate) fn add_with_receipt(kq: &Kqueue, change: KEvent) -> Result<i64, Error> {
    // EV_RECEIPT makes EV_ADD synchronous: kevent returns exactly one receipt event
    // whose `data` is the add result (0 = armed, an errno otherwise).
    let mut receipt = [placeholder()];
    let n = kq
        .kevent(&[change], &mut receipt, None)
        .map_err(|e| Error::Io(e.into()))?;
    if n != 1 {
        return Err(Error::Io(std::io::Error::other(
            "kqueue EV_RECEIPT returned no receipt event",
        )));
    }
    Ok(receipt[0].data() as i64)
}

/// Arm an `EVFILT_PROC | NOTE_EXIT` filter for `pid` on an EXISTING kqueue. `Ok(None)` => the
/// pid is already gone.
pub(crate) fn arm_note_exit_on(kq: &Kqueue, pid: u32) -> Result<Option<()>, Error> {
    let change = KEvent::new(
        pid as usize,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    );
    let add_result = add_with_receipt(kq, change)?;
    if add_result == libc::ESRCH as i64 {
        return Ok(None); // pid already gone
    }
    if add_result != 0 {
        return Err(Error::Io(std::io::Error::from_raw_os_error(add_result as i32)));
    }
    Ok(Some(()))
}

/// Create a kqueue and arm an `EVFILT_PROC | NOTE_EXIT` filter for `id`, re-verifying
/// identity. `Ok(None)` => already gone (treat as exited). The kqueue's fd polls readable
/// once the exit event is pending — consumed by the sync blocking wait below and by the
/// async reactor watch (`tokio::wait`).
pub(crate) fn arm_proc_exit(id: ProcessId) -> Result<Option<Kqueue>, Error> {
    let kq = Kqueue::new().map_err(|e| Error::Io(e.into()))?;
    if arm_note_exit_on(&kq, id.pid())?.is_none() {
        return Ok(None); // pid already gone
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

/// Drain one pending event from an armed kqueue without blocking. `Ok(Some(()))` = the exit
/// event was observed; `Ok(None)` = nothing pending (spurious readiness — re-wait); `Err` =
/// EV_ERROR (any, mirroring the blocking wait) or a kevent failure.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))] // non-test consumer is tokio::wait's watch loop
pub(crate) fn drain_proc_exit(kq: &Kqueue) -> Result<Option<()>, Error> {
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut events = [placeholder()];
    loop {
        match kq.kevent(&[], &mut events, Some(zero)) {
            Ok(0) => return Ok(None), // nothing pending
            Ok(_) => {
                if events[0].flags().contains(EvFlags::EV_ERROR) {
                    return Err(Error::Io(std::io::Error::from_raw_os_error(events[0].data() as i32)));
                }
                return Ok(Some(())); // NOTE_EXIT
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
}

pub(crate) fn block_until_exit(id: ProcessId, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
    let Some(kq) = arm_proc_exit(id)? else {
        return Ok(true);
    };
    block_on_kqueue(&kq, deadline, false, |event| {
        if event.flags().contains(EvFlags::EV_ERROR) {
            return Err(Error::Io(std::io::Error::from_raw_os_error(event.data() as i32)));
        }
        Ok(Some(true)) // NOTE_EXIT
    })
}

/// Block on an armed kqueue until `interpret` concludes, or until `deadline`. `interpret` maps
/// ONE pending `KEvent` to `Ok(Some(verdict))` (conclusive — stop) or `Ok(None)` (nothing
/// conclusive yet, e.g. bytes drained below a filter's own terminal condition — keep waiting).
/// `on_timeout` is the verdict for a genuine timeout.
///
/// The deadline is checked explicitly at the top of every round, not inferred from `kevent`
/// returning 0: a continuously-ready descriptor (e.g. a sustained pipe writer) keeps `kevent`
/// returning real events even with an already-expired timeout, so relying on "0 events, timed
/// out" alone would let the wait overrun the deadline by an unbounded number of rounds.
/// Checking `remaining(deadline)` before each `kevent` call bounds the overrun to at most one
/// in-flight round: once a round starts with the deadline already elapsed, an inconclusive
/// event in THAT round returns `on_timeout` immediately rather than looping back.
///
/// Shared by every blocking kqueue wait this crate arms — `EVFILT_PROC` here, `EVFILT_READ` in
/// `containment::marker_eof` — so a hazard found against one filter (an already-past deadline
/// against a sticky, already-satisfied event) is fixed once, not rediscovered per filter.
pub(crate) fn block_on_kqueue<T: Copy>(
    kq: &Kqueue,
    deadline: Option<Option<Instant>>,
    on_timeout: T,
    mut interpret: impl FnMut(&KEvent) -> Result<Option<T>, Error>,
) -> Result<T, Error> {
    let mut events = [placeholder()];
    #[cfg(test)]
    let mut round: u32 = 0;
    loop {
        // Fires before this round's `remaining(deadline)` is computed, so a hook that advances
        // the mock clock (`crate::wait::test_clock`) changes what THIS round sees, not just a
        // later one. Nothing but that computation and the `kevent` call itself follows before
        // the next hook firing, so this is also "right before the real, blocking kevent call"
        // for a hook that only cares about that.
        #[cfg(test)]
        test_hooks::fire_round_hook(round);

        let remaining = crate::wait::remaining(deadline);
        let already_elapsed = remaining == Some(Duration::ZERO);
        // nix Kqueue::kevent takes Option<libc::timespec> (None = block forever).
        let timeout = remaining.map(|d| libc::timespec {
            tv_sec: d.as_secs().min(i64::MAX as u64) as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });
        // Recorded from `timeout` itself (the literal argument about to reach `kevent`), not
        // from `remaining` — so a mutant that decouples the two (e.g. always passing `None`
        // regardless of what `remaining` computed) shows up in the recording too.
        #[cfg(test)]
        test_hooks::record_kevent_call(
            timeout.map(|ts| Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.max(0) as u32)),
        );
        match kq.kevent(&[], &mut events, timeout) {
            Ok(0) => return Ok(on_timeout), // genuinely timed out, no events
            Ok(_) => {
                if let Some(verdict) = interpret(&events[0])? {
                    return Ok(verdict);
                }
                if already_elapsed {
                    return Ok(on_timeout);
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
        #[cfg(test)]
        {
            round += 1;
        }
    }
}

/// Test-only structural seams for `block_on_kqueue`: a per-round hook and counters that let a
/// test prove "checks the deadline every round, blocks for real, never spins" without timing
/// anything. Thread-local — the test harness runs each test on its own OS thread, so state
/// starts fresh with nothing to reset. A hook set on one thread only ever fires for
/// `block_on_kqueue` calls made on THAT thread — a test that needs to act partway through a
/// call in progress (e.g. killing the process being waited on, right before the next real
/// `kevent`) installs the hook and reads the counters back from the SAME thread that makes the
/// call, never by peeking at another thread's thread-local directly (see
/// `marker_eof_tests`'s unbounded sustained-writer test, which kills the writer from inside
/// its own round hook for exactly this reason — no second thread, no cross-thread race).
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::{Cell, RefCell};
    use std::time::Duration;

    type RoundHook = Box<dyn FnMut(u32)>;

    thread_local! {
        static ROUND_HOOK: RefCell<Option<RoundHook>> = const { RefCell::new(None) };
        static KEVENT_CALLS: Cell<u32> = const { Cell::new(0) };
        static REQUESTED_TIMEOUTS: RefCell<Vec<Option<Duration>>> = const { RefCell::new(Vec::new()) };
    }

    /// Install a closure `block_on_kqueue` invokes once at the top of every loop iteration on
    /// THIS thread, with the 0-based round index.
    pub(crate) fn set_round_hook(hook: impl FnMut(u32) + 'static) {
        ROUND_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn fire_round_hook(round: u32) {
        ROUND_HOOK.with(|h| {
            if let Some(hook) = h.borrow_mut().as_mut() {
                hook(round);
            }
        });
    }

    /// Count of real `kq.kevent(...)` calls `block_on_kqueue` has issued on THIS thread.
    pub(crate) fn kevent_calls() -> u32 {
        KEVENT_CALLS.with(Cell::get)
    }

    /// The ACTUAL timeout argument passed to each real `kevent` call so far, in round order
    /// (recorded from the literal argument at the call site, not from `remaining(deadline)`
    /// upstream of it) — proof the requested timeout is both a live recomputation every round
    /// AND the value that really reached the syscall, not a duration cached once before the
    /// loop or one that diverges from what was actually requested.
    pub(crate) fn requested_timeouts() -> Vec<Option<Duration>> {
        REQUESTED_TIMEOUTS.with(|v| v.borrow().clone())
    }

    pub(crate) fn record_kevent_call(requested: Option<Duration>) {
        KEVENT_CALLS.with(|c| c.set(c.get() + 1));
        REQUESTED_TIMEOUTS.with(|v| v.borrow_mut().push(requested));
    }
}

pub(crate) fn kill(id: ProcessId) -> Result<(), Error> {
    use nix::sys::signal::{kill as nix_kill, Signal};
    use nix::unistd::Pid;
    // Re-verify identity immediately before signaling. The window between this check
    // and kill(2) is irreducible on macOS (no pidfd); a recycled pid in that window is
    // a documented best-effort limitation, mirroring treewalk::kill_by_identity.
    match ProcessId::of(id.pid()) {
        crate::identity::Resolved::Found(live) if live == id => {}
        // gone (or recycled) => already-dead is success
        crate::identity::Resolved::Found(_) | crate::identity::Resolved::Gone => return Ok(()),
        crate::identity::Resolved::Unknown => {
            log::warn!(
                "wait: pid {} identity could not be confirmed - no signal was sent",
                id.pid()
            );
            return Err(Error::Unassessable {
                detail: format!("pid {} identity could not be confirmed; no signal was sent", id.pid()),
                source: None,
            });
        }
    }
    // `nix::unistd::Pid::from_raw` is infallible and accepts 0, and `kill(0, sig)` signals
    // the CALLER-S ENTIRE PROCESS GROUP. `kernel_task` is pid 0 and macOS RESOLVES it, so the
    // re-verify above does not rule the value out, and a `debug_assert` would vanish in
    // release. Use the same total guard the `sig 0` probe uses.
    let Some(target) = crate::identity::probe::signal_target(id.pid()) else {
        // A discard site: the Result can carry this, so it must not read as a silent success.
        log::warn!(
            "wait: pid {} is not a single-process signal target - not signaled",
            id.pid()
        );
        return Err(Error::Unassessable {
            detail: format!("pid {} is not a signalable single-process target", id.pid()),
            source: None,
        });
    };
    match nix_kill(Pid::from_raw(target), Signal::SIGKILL) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()), // exited between re-verify and kill
        Err(e) => Err(Error::Io(e.into())),      // EPERM etc. surfaced, not swallowed
    }
}

pub(crate) fn terminate(id: ProcessId) -> Result<(), Error> {
    use nix::sys::signal::{kill as nix_kill, Signal};
    use nix::unistd::Pid;
    // Re-verify identity immediately before signaling.
    match ProcessId::of(id.pid()) {
        crate::identity::Resolved::Found(live) if live == id => {}
        // gone (or recycled) => already-dead is success
        crate::identity::Resolved::Found(_) | crate::identity::Resolved::Gone => return Ok(()),
        crate::identity::Resolved::Unknown => {
            log::warn!(
                "wait: pid {} identity could not be confirmed - no signal was sent",
                id.pid()
            );
            return Err(Error::Unassessable {
                detail: format!("pid {} identity could not be confirmed; no signal was sent", id.pid()),
                source: None,
            });
        }
    }
    // `nix::unistd::Pid::from_raw` is infallible and accepts 0, and `kill(0, sig)` signals
    // the CALLER-S ENTIRE PROCESS GROUP. `kernel_task` is pid 0 and macOS RESOLVES it, so the
    // re-verify above does not rule the value out, and a `debug_assert` would vanish in
    // release. Use the same total guard the `sig 0` probe uses.
    let Some(target) = crate::identity::probe::signal_target(id.pid()) else {
        // A discard site: the Result can carry this, so it must not read as a silent success.
        log::warn!(
            "wait: pid {} is not a single-process signal target - not signaled",
            id.pid()
        );
        return Err(Error::Unassessable {
            detail: format!("pid {} is not a signalable single-process target", id.pid()),
            source: None,
        });
    };
    match nix_kill(Pid::from_raw(target), Signal::SIGTERM) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => Err(Error::Io(e.into())),
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
