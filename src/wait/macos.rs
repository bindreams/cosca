//! macOS death-watch + kill via kqueue `EVFILT_PROC` + `NOTE_EXIT` (notifies, never
//! reaps) and identity-verified `kill(2)` (no pidfd on Darwin, so a residual pid-reuse
//! window between re-verify and signal is irreducible — documented at the call site).

use std::time::Instant;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use crate::error::Error;
use crate::identity::ProcessId;

fn placeholder() -> KEvent {
    KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0)
}

/// Arm an `EVFILT_PROC | NOTE_EXIT` filter for `pid` on an EXISTING kqueue (`EV_RECEIPT`:
/// synchronous, receipt-checked). `Ok(None)` => the pid is already gone. The single
/// definition of the receipt dance — `arm_proc_exit` consumes it, and the decoy composition
/// test arms its second filter through it (no hand-rolled twin to drift).
pub(crate) fn arm_note_exit_on(kq: &Kqueue, pid: u32) -> Result<Option<()>, Error> {
    let change = KEvent::new(
        pid as usize,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    );
    // EV_RECEIPT makes EV_ADD synchronous: kevent returns exactly one receipt event
    // whose `data` is the add result (0 = armed, ESRCH = pid gone, other = errno).
    let mut receipt = [placeholder()];
    let n = kq
        .kevent(&[change], &mut receipt, None)
        .map_err(|e| Error::Io(e.into()))?;
    if n != 1 {
        return Err(Error::Io(std::io::Error::other(
            "kqueue EV_RECEIPT returned no receipt event",
        )));
    }
    let add_result = receipt[0].data() as i64;
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
    if !id.exists() {
        return Ok(None); // recycled before the filter armed
    }
    Ok(Some(kq))
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
    let mut events = [placeholder()];
    loop {
        // nix Kqueue::kevent takes Option<libc::timespec> (None = block forever).
        let timeout = crate::wait::remaining(deadline).map(|d| libc::timespec {
            tv_sec: d.as_secs().min(i64::MAX as u64) as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });
        match kq.kevent(&[], &mut events, timeout) {
            Ok(0) => return Ok(false), // timed out, still alive
            Ok(_) => {
                if events[0].flags().contains(EvFlags::EV_ERROR) {
                    return Err(Error::Io(std::io::Error::from_raw_os_error(events[0].data() as i32)));
                }
                return Ok(true); // NOTE_EXIT
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
}

pub(crate) fn kill(id: ProcessId) -> Result<(), Error> {
    use nix::sys::signal::{kill as nix_kill, Signal};
    use nix::unistd::Pid;
    // Re-verify identity immediately before signaling. The window between this check
    // and kill(2) is irreducible on macOS (no pidfd); a recycled pid in that window is
    // a documented best-effort limitation, mirroring treewalk::kill_by_identity.
    if ProcessId::of(id.pid()) != Some(id) {
        return Ok(()); // gone (or recycled) => already-dead is success
    }
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; signal target cast would truncate",
        id.pid()
    );
    match nix_kill(Pid::from_raw(id.pid() as i32), Signal::SIGKILL) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()), // exited between re-verify and kill
        Err(e) => Err(Error::Io(e.into())),      // EPERM etc. surfaced, not swallowed
    }
}

pub(crate) fn terminate(id: ProcessId) -> Result<(), Error> {
    use nix::sys::signal::{kill as nix_kill, Signal};
    use nix::unistd::Pid;
    // Re-verify identity immediately before signaling.
    if ProcessId::of(id.pid()) != Some(id) {
        return Ok(()); // gone (or recycled) => already-dead is success
    }
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; signal target cast would truncate",
        id.pid()
    );
    match nix_kill(Pid::from_raw(id.pid() as i32), Signal::SIGTERM) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => Err(Error::Io(e.into())),
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
