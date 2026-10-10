//! macOS death-watch + kill via kqueue `EVFILT_PROC` + `NOTE_EXIT` (notifies, never
//! reaps) and identity-verified `kill(2)` (no pidfd on Darwin, so a residual pid-reuse
//! window between re-verify and signal is irreducible — documented at the call site).

use std::time::{Duration, Instant};

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use crate::error::Error;
use crate::identity::ProcessId;

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
    debug_assert!(
        d.is_zero() || ts.tv_sec > 0 || ts.tv_nsec > 0,
        "a remaining time of {d:?} became a zero kevent timeout: a poll, which spins until the clock catches up"
    );
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
/// [`arm_proc_exit`] for a pid whose unique id was read earlier, `unique`: the watch is armed on the
/// pid, then the id is read again, so a stranger that took the pid is never watched, whatever
/// happened before the arming. `Ok(None)`: the pid is gone, or no longer (or not provably) has that
/// id; there is nothing of the child's to watch, and the caller's own check says what that means.
#[cfg_attr(
    not(feature = "tokio"),
    allow(dead_code, reason = "the only consumer is tokio::wait's watch")
)]
pub(crate) fn arm_proc_exit_for(pid: u32, unique: u64) -> Result<Option<Kqueue>, Error> {
    use crate::identity::{uniq_info, ReadPurpose, UniqRead};
    let kq = Kqueue::new().map_err(|e| Error::Io(e.into()))?;
    if arm_note_exit_on(&kq, pid)?.is_none() {
        return Ok(None);
    }
    match uniq_info(pid, ReadPurpose::Arm) {
        UniqRead::Found(info) if info.unique_id == unique => Ok(Some(kq)),
        UniqRead::Found(_) | UniqRead::Gone | UniqRead::Refused(_) => Ok(None),
    }
}

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
#[cfg_attr(
    not(feature = "tokio"),
    allow(dead_code, reason = "non-test consumer is tokio::wait's watch loop")
)]
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
    block_on_kqueue(&kq, deadline, false, |event, _already_elapsed| {
        if event.flags().contains(EvFlags::EV_ERROR) {
            return Err(Error::Io(std::io::Error::from_raw_os_error(event.data() as i32)));
        }
        Ok(Some(true)) // NOTE_EXIT
    })
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
    deadline: Option<Option<Instant>>,
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
        test_hooks::fire_round_hook(round, kq);
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
            match kq.kevent(&[], &mut events, timeout) {
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
#[path = "macos/test_hooks.rs"]
pub(crate) mod test_hooks;

#[path = "macos/await_reapable.rs"]
mod await_reapable;
#[cfg(test)]
pub(crate) use await_reapable::await_reapable_on;
pub(crate) use await_reapable::{await_reapable, Waited};

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
