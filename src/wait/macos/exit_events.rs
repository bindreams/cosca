//! The kqueue registration a child's exit wait arms on macOS, and the non-blocking read of what it
//! got: `EVFILT_PROC` (`NOTE_EXIT | NOTE_REAP | NOTE_SIGNAL`) and `EVFILT_SIGNAL` (`SIGCHLD`). The
//! waits that block on it (`MacosChild`'s, the tokio child's) own their blocking and their
//! verdicts, through `drive`.
//!
//! - `NOTE_REAP` on the wait's own knote means something else reaped the child: only a real reap
//!   fires it (the tracer's hand-back re-sends `NOTE_EXIT` and returns before
//!   `proc_knote(child, NOTE_REAP)`, `kern_exit.c:2721-2773` against `:2787`), and every caller
//!   reaps only after its wait returns. A traced child's `NOTE_EXIT` reaches this process only at
//!   its tracer's hand-back; see [`TracerWatch`] for how the wait watches the tracer chain. A
//!   signal to the child or to a tracer only makes the wait look again.
//! - Every knote is `EV_CLEAR` (see `Kqueue::subscribe`): with `NOTE_REAP` requested `NOTE_EXIT` is
//!   not one-shot and the knote's `fflags` are never cleared, so without it the knote re-activates
//!   and every later `kevent` returns at once (`kern_event.c:1222-1224`, `:993-995`, `:4442-4445`,
//!   `:1314`): a CPU spin between exit and `SZOMB`.
//! - Under `SIG_IGN` or `SA_NOCLDWAIT`, XNU reaps the child itself and sends no `SIGCHLD`
//!   (`kern_exit.c:2577-2601`). The wait registers `EVFILT_PROC` itself, so a caller whose own
//!   registration got `ESRCH` still has a `NOTE_EXIT` to wait for.

use std::io;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

use super::TracerWatch;
use crate::identity::Kernel;
#[cfg(test)]
use crate::os_process::macos::kqueue::test_hooks;
use crate::os_process::macos::kqueue::{kevent_timeout, Event, Kqueue, Subscription};

/// Slots in one `kevent` batch.
const BATCH: usize = 8;

fn blank() -> KEvent {
    KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0)
}

/// What [`register_exit_events`] subscribes for `pid`: its exit, its signals and its reap.
pub(crate) fn reap_registration(pid: u32) -> Subscription {
    Subscription::Process {
        pid,
        signals: true,
        reap: true,
    }
}

/// Register on `kq` `EVFILT_SIGNAL` for `SIGCHLD` and `EVFILT_PROC` for `pid`. `Ok(true)` when the
/// `EVFILT_PROC` receipt says `ESRCH` (the child is already past `P_REF_DEAD`), so no `NOTE_EXIT`
/// or `NOTE_REAP` will come.
pub(crate) fn register_exit_events(kernel: &dyn Kernel, kq: &Kqueue, pid: u32) -> io::Result<bool> {
    kernel.subscribe(kq, Subscription::Signal(libc::SIGCHLD))?;
    match kernel.subscribe(kq, reap_registration(pid)) {
        Ok(()) => Ok(false),
        Err(e) if crate::error::first_os_code(&e) == Some(libc::ESRCH) => Ok(true),
        Err(e) => Err(e),
    }
}

/// `(saw NOTE_REAP, saw NOTE_EXIT)` of the child `pid` in `events`. A signal, to the child or to a
/// tracer, and a tracer's exit are neither: they only wake the wait to look again.
fn scan(events: &[KEvent], pid: u32, tracer: &mut TracerWatch) -> (bool, bool) {
    let (mut reap, mut exit) = (false, false);
    for raw in events {
        #[cfg(test)]
        test_hooks::record_event(raw.filter().map_or(0, |f| f as i16), raw.fflags().bits());
        let Some(event) = Event::from_kevent(raw) else {
            continue;
        };
        if tracer.fired(&event, pid) {
            continue;
        }
        if let Event::Process { exited, reaped, .. } = event {
            reap |= reaped;
            exit |= exited;
        }
    }
    (reap, exit)
}

/// One `kevent` call that does not block: what is pending on `kq`, up to the buffer.
fn poll_round(kq: &Kqueue, events: &mut [KEvent; BATCH]) -> io::Result<usize> {
    let timeout = Some(kevent_timeout(std::time::Duration::ZERO));
    loop {
        match kq.native().kevent(&[], events, timeout) {
            Ok(n) => return Ok(n),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Read every event pending on `kq` without blocking: whether one was the child `pid`'s
/// `NOTE_REAP`, and whether one was its `NOTE_EXIT`. The events of the tracers `tracer` watches are
/// neither.
pub(crate) fn drain_exit_events(kq: &Kqueue, pid: u32, tracer: &mut TracerWatch) -> io::Result<(bool, bool)> {
    let mut events = [blank(); BATCH];
    let (mut reaped, mut exited) = (false, false);
    loop {
        // A verdict from an earlier round stands over a later failure: nothing reports it again.
        let n = match poll_round(kq, &mut events) {
            Ok(n) => n,
            Err(e) if reaped || exited => {
                log::warn!(
                    "wait: reading pid {pid}'s kqueue failed after its exit was read: {report}",
                    report = crate::error::Report(&e)
                );
                return Ok((reaped, exited));
            }
            Err(e) => return Err(e),
        };
        let (reap, exit) = scan(&events[..n], pid, tracer);
        reaped |= reap;
        exited |= exit;
        if n < BATCH {
            return Ok((reaped, exited));
        }
    }
}
