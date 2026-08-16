//! The macOS fd-marker's EOF edge: the event that fires when the last holder of the marker's
//! write end exits.
//!
//! Every member of the tree inherits the write end (`fdmarker`); the supervisor keeps the read
//! end. The kernel closes descriptors on process exit unconditionally, so the edge needs no
//! cooperation from the tree, no bookkeeping from the supervisor, and — unlike ppid
//! enumeration — it covers members reparented to launchd.
//!
//! Two limits, both structural rather than incidental:
//!
//! - **Exited, not reaped.** A descriptor closes before the zombie is collected, so the edge
//!   says every member has *exited*; it says nothing about statuses. A caller wanting a
//!   status still waits on the root.
//! - **A member that `close()`s the descriptor leaves the set.** The edge is exactly as
//!   trustworthy as the marker's membership: it can fire while such a member still runs.
//!   That is the same trust model as the marker itself — naive-child containment.
//!
//! Every knote here is armed with `NOTE_LOWAT` and a high low-water mark. `EV_EOF` is always
//! the sole verdict, unconditional of buffered bytes — but the low-water mark itself is
//! clamped by the kernel to the pipe's actual buffer capacity (measured ~64 KiB on this host),
//! so it suppresses wakeups for ordinary writes (which is all the crate should ever produce —
//! nothing in the crate writes to the marker) without being an absolute guarantee against a
//! member that sustains output at or above that ceiling. That residual case degrades to a
//! bounded, deadline-respecting, CPU-proportional drain rather than a genuine kernel block —
//! documented and tested, not assumed away.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Instant;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use crate::error::Error;

#[cfg(test)]
#[path = "marker_eof_tests.rs"]
mod marker_eof_tests;

/// Whether every holder of the marker's write end has **exited**.
///
/// Exited is not reaped: descriptors close before the zombie is collected, so
/// `AllMembersExited` never implies a status is available. It also means every holder of the
/// *marker*, which a member that closed the descriptor has stopped being.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeDrain {
    /// Every marker holder has exited. Statuses have NOT been collected.
    AllMembersExited,
    /// At least one marker holder was still running at the deadline.
    MembersRemain,
}

/// The `NOTE_LOWAT` low-water mark every knote in this module is armed with. Clamped by the
/// kernel to the pipe's actual buffer capacity — see the module doc for what this does and
/// does not guarantee.
const LOW_WATER_MARK: isize = 1 << 20; // 1 MiB (requested; effectively min(this, pipe capacity))

/// Make the read end non-blocking (idempotent). Raw `libc::fcntl`, matching the crate's
/// existing style (`src/elevation/posix.rs`) rather than `nix::fcntl`. The read end belongs
/// solely to the supervisor, so the file-status flag is ours to set.
fn ensure_nonblocking(read_end: BorrowedFd<'_>) -> Result<(), Error> {
    let fd = read_end.as_raw_fd();
    // SAFETY: fcntl(F_GETFL/F_SETFL) on a live borrowed fd; no pointer args beyond the flags.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        if flags & libc::O_NONBLOCK != 0 {
            return Ok(());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Read and discard up to `n` bytes, tolerating short reads. Bounded by `n` — a count the
/// KERNEL just reported via the triggering kevent's own `data` field, never "keep reading
/// until it stops." Below the low-water clamp this branch never runs at all; at or above it,
/// this is what keeps a single round bounded — the OUTER loop (`block_until_drained`) is what
/// keeps the total wait bounded by the caller's deadline despite repeated rounds.
fn drain_pending(read_end: BorrowedFd<'_>, mut n: usize) -> Result<(), Error> {
    let mut buf = [0u8; 4096];
    while n > 0 {
        let want = n.min(buf.len());
        match nix::unistd::read(read_end, &mut buf[..want]) {
            Ok(0) => return Ok(()), // EOF raced ahead of us; nothing left to drain
            Ok(got) => n -= got,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EAGAIN) => return Ok(()), // a concurrent reader won the race
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
    Ok(())
}

/// Create a kqueue with `EVFILT_READ` armed on the marker read end, `NOTE_LOWAT`-gated (see
/// the module doc for what this does and does not guarantee) so ordinary writes never wake
/// it — only `EV_EOF` does.
///
/// One kqueue PER WAITER, deliberately: a knote is keyed on `(kqueue, fd, filter)`, so private
/// kqueues compose (two waiters both see the edge) where two registrations of the same
/// descriptor on one shared queue would take each other's place.
///
/// `unbounded_wait` says whether the caller intends to wait with no deadline: an `Unassessable`
/// write-end check combined with an unbounded wait is exactly the condition under which this
/// primitive could hang forever with no elevated runtime signal — see
/// `refuse_if_write_end_held`.
pub(crate) fn arm(read_end: BorrowedFd<'_>, unbounded_wait: bool) -> Result<Kqueue, Error> {
    ensure_nonblocking(read_end)?;
    refuse_if_write_end_held(read_end, unbounded_wait)?;
    let kq = Kqueue::new().map_err(|e| Error::Io(e.into()))?;
    let change = KEvent::new(
        read_end.as_raw_fd() as usize,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
        FilterFlag::NOTE_LOWAT,
        LOW_WATER_MARK,
        0,
    );
    let add_result = crate::wait::backend::add_with_receipt(&kq, change)?;
    if add_result != 0 {
        return Err(Error::Io(std::io::Error::from_raw_os_error(add_result as i32)));
    }
    Ok(kq)
}

/// Interpret ONE `EVFILT_READ` event on the marker read end — the single definition shared by
/// the one-shot drain (`drain_kqueue`) and the blocking wait's loop body
/// (`block_until_drained`), so there is no hand-rolled twin to drift.
///
/// `Ok(Some(AllMembersExited))` = `EV_EOF` was set — final, regardless of buffered bytes, so no
/// read happens in this branch. `Ok(None)` = readable without `EV_EOF`, which with
/// `NOTE_LOWAT` armed only happens once buffered bytes reach the clamp: `event.data()` is
/// exactly how many are queued, discarded in one bounded round via `drain_pending`. `Err` =
/// `EV_ERROR` or a `kevent`/read failure.
fn interpret_read_event(event: &KEvent, read_end: BorrowedFd<'_>) -> Result<Option<TreeDrain>, Error> {
    if event.flags().contains(EvFlags::EV_ERROR) {
        return Err(Error::Io(std::io::Error::from_raw_os_error(event.data() as i32)));
    }
    if event.flags().contains(EvFlags::EV_EOF) {
        return Ok(Some(TreeDrain::AllMembersExited));
    }
    // `data` is a byte count for a readable, non-EOF, non-error EVFILT_READ event — never
    // negative per the kqueue contract this module relies on everywhere else. `.max(0)` is a
    // release-build fallback only; a violation here is a kqueue/ABI surprise or a bug in this
    // module's own event handling, not an ordinary runtime condition, so it gets a loud
    // debug_assert rather than being silently absorbed into the routine "nothing to drain yet"
    // code path.
    debug_assert!(
        event.data() >= 0,
        "EVFILT_READ data must be non-negative per kernel contract, got {}",
        event.data()
    );
    drain_pending(read_end, event.data().max(0) as usize)?;
    Ok(None) // bytes discarded; holders remain (EV_EOF was clear)
}

/// Take one pending event from an armed kqueue without blocking. `Ok(Some(_))` = the drain was
/// observed; `Ok(None)` = nothing conclusive yet (nothing pending, or — only once the
/// low-water clamp is reached — a member's bytes, discarded) — re-wait; `Err` = see
/// `interpret_read_event`.
pub(crate) fn drain_kqueue(kq: &Kqueue, read_end: BorrowedFd<'_>) -> Result<Option<TreeDrain>, Error> {
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];
    loop {
        match kq.kevent(&[], &mut events, Some(zero)) {
            Ok(0) => return Ok(None), // nothing pending
            Ok(_) => return interpret_read_event(&events[0], read_end),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
}

/// One-shot drain check: exact, not heuristic — arms a private kqueue and reads its
/// zero-timeout verdict off `EV_EOF`, the same authoritative signal `block_until_drained`
/// uses. `Ok(None)` from `drain_kqueue` (nothing pending yet) means a write end is open with
/// nothing queued: `MembersRemain`, correctly, since `AllMembersExited` is only ever reported
/// when the kernel itself said `EV_EOF`.
///
/// No production caller exists yet — kept as crate-internal primitive surface for a future
/// consumer, exercised directly by the unit tests below. `#[allow(dead_code)]` reflects that
/// honestly instead of leaving the lib target to fail `cargo clippy --all-targets -D
/// warnings`, which sees no test-cfg code and would otherwise flag this as unused. A one-shot
/// check never blocks, so it never risks a caller-invisible hang: it always passes `false` for
/// `arm`'s `unbounded_wait`.
#[allow(dead_code)]
pub(crate) fn probe(read_end: BorrowedFd<'_>) -> Result<TreeDrain, Error> {
    let kq = arm(read_end, false)?;
    match drain_kqueue(&kq, read_end)? {
        Some(verdict) => Ok(verdict),
        None => Ok(TreeDrain::MembersRemain),
    }
}

/// Block until every marker holder has exited, or until `deadline`.
///
/// `deadline` follows the crate's watch convention: `None` = block indefinitely, `Some(None)`
/// = a duration that overflowed `Instant` (also indefinite), `Some(Some(at))` = an absolute
/// deadline; a deadline already in the past still performs exactly one non-blocking check
/// before concluding — the sticky, level-triggered `EV_EOF` a genuinely-already-drained tree
/// left pending must be observed, not assumed away by the elapsed deadline alone (there is a
/// dedicated test pinning this: an already-drained tree checked past a stale deadline still
/// reports `AllMembersExited`, not a verdict inferred from "no time is left"). Uses one kernel
/// syscall per wait round — no interval is chosen anywhere in this path.
///
/// **The deadline is checked explicitly at the top of every round, not inferred from `kevent`
/// returning 0.** A member sustaining writes past the `NOTE_LOWAT` clamp keeps the descriptor
/// continuously ready, and `kevent` returns as soon as ANY event is ready — including with a
/// zero/expired timeout — so it never actually returns "0 events, timed out" while the pipe
/// stays full; relying on that alone lets the wait overrun the deadline by an unbounded number
/// of rounds. Checking `remaining(deadline)` before each `kevent` call bounds the overrun to at
/// most one in-flight round's drain: once a round starts with the deadline already elapsed, a
/// non-EOF event in THAT round (bytes drained, holders remain) returns immediately rather than
/// looping back for another round — otherwise a sustained writer whose deadline has already
/// elapsed would spin forever, since "elapsed" never becomes "more elapsed."
pub(crate) fn block_until_drained(
    read_end: BorrowedFd<'_>,
    deadline: Option<Option<Instant>>,
) -> Result<TreeDrain, Error> {
    let unbounded_wait = crate::wait::remaining(deadline).is_none();
    let kq = arm(read_end, unbounded_wait)?;
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];
    loop {
        // Recompute from the absolute deadline so an EINTR retry cannot extend the total wait,
        // AND so a continuously-ready descriptor (a sustained writer) cannot make `kevent`
        // return real events forever without this loop ever noticing the deadline passed.
        let remaining = crate::wait::remaining(deadline);
        let already_elapsed = remaining == Some(std::time::Duration::ZERO);
        let timeout = remaining.map(|d| libc::timespec {
            tv_sec: d.as_secs().min(i64::MAX as u64) as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });
        match kq.kevent(&[], &mut events, timeout) {
            Ok(0) => return Ok(TreeDrain::MembersRemain), // genuinely timed out, no events
            Ok(_) => {
                if let Some(verdict) = interpret_read_event(&events[0], read_end)? {
                    return Ok(verdict);
                }
                // Bytes discarded (only past the low-water clamp), holders remain. A round that
                // started with the deadline already elapsed stops here rather than looping back:
                // see the doc comment above for why (a sustained writer past an elapsed deadline
                // must not spin).
                if already_elapsed {
                    return Ok(TreeDrain::MembersRemain);
                }
                // otherwise loop back, where the deadline is re-checked BEFORE the next kevent call
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
}

// Detecting a supervisor-retained write-end copy =====
//
// Reuses `fdmarker`'s own `PROC_PIDFDPIPEINFO` FFI surface (already `pub(crate)`) instead of
// declaring a second copy of the same struct layout.

use crate::containment::fdmarker::{fd_pipe_info, pipe_fds_of, FdPipeInfoQuery, PipeQuery};

/// Whether THIS process still holds a copy of the marker's write end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteEndCheck {
    /// No descriptor in this process refers to the marker's write end.
    Clear,
    /// The supervisor kept a copy — the edge can never fire.
    HeldByUs,
    /// The kernel would not describe our own descriptors, or `read_end` is not a pipe at all —
    /// the check is inconclusive.
    Unassessable,
}

/// Scan this process's own descriptors for a copy of the marker's write end.
///
/// Exact rather than heuristic: the read end's `pipe_peerhandle` IS the write end's
/// `pipe_handle`, so the comparison names one kernel object. Costs one `PROC_PIDLISTFDS` plus
/// one `proc_pidfdinfo` per pipe descriptor of this process, once per arm.
///
/// **Scope, stated honestly:** this catches a supervisor bug (its OWN retained copy) at the
/// instant of the scan. It is not a general liveness oracle for the write end: a foreign
/// process holding a copy is invisible to a self-scan by construction (mitigated instead by
/// the marker's parent-side descriptor not being inheritable), and a copy created in THIS
/// process after the scan (e.g. a `dup()` racing the caller) is a snapshot gap of the same
/// irreducible-window kind already documented at the `kill(2)` re-verify in
/// `src/wait/macos.rs` — checked-then-acted-on, not held under a lock.
pub(crate) fn write_end_check(read_end: BorrowedFd<'_>) -> WriteEndCheck {
    let me = std::process::id();
    let write_handle = match fd_pipe_info(me, read_end.as_raw_fd()) {
        FdPipeInfoQuery::Found(info) => info.pipe_peerhandle,
        FdPipeInfoQuery::Absent | FdPipeInfoQuery::Denied => return WriteEndCheck::Unassessable,
    };
    let fds = match pipe_fds_of(me) {
        PipeQuery::Found(fds) => fds,
        PipeQuery::Gone | PipeQuery::Denied => return WriteEndCheck::Unassessable,
    };
    let mut any_probe_failed = false;
    for fd in fds {
        if fd == read_end.as_raw_fd() {
            continue; // the read end itself
        }
        match fd_pipe_info(me, fd) {
            FdPipeInfoQuery::Found(info) if info.pipe_handle == write_handle => return WriteEndCheck::HeldByUs,
            FdPipeInfoQuery::Found(_) => {}
            // `pipe_fds_of` just reported this exact fd as a pipe (moments ago), so this is
            // the routine "vanished between the two calls" case, not a probe failure.
            FdPipeInfoQuery::Absent => {}
            // A per-fd probe can fail transiently (the fd closed between listing and query).
            // Folded into Unassessable rather than silently treated as "not a match": the ONE
            // probe that would have found the retained copy is exactly the one that can fail
            // this way, and "exact rather than heuristic" (above) must not quietly degrade to
            // "exact except when it isn't."
            FdPipeInfoQuery::Denied => any_probe_failed = true,
        }
    }
    if any_probe_failed {
        return WriteEndCheck::Unassessable;
    }
    WriteEndCheck::Clear
}

/// Refuse to watch an edge that provably cannot fire. `Unassessable` proceeds UNLESS the
/// caller intends to wait with no deadline: an inconclusive scan combined with a bounded wait
/// is capped by the caller's own deadline regardless, but combined with an UNBOUNDED wait it is
/// exactly the condition under which this primitive could hang forever with no elevated
/// runtime signal at all — so only that combination is refused.
fn refuse_if_write_end_held(read_end: BorrowedFd<'_>, unbounded_wait: bool) -> Result<(), Error> {
    match write_end_check(read_end) {
        WriteEndCheck::Clear => Ok(()),
        WriteEndCheck::Unassessable if !unbounded_wait => {
            log::debug!("marker EOF: could not confirm this process holds no copy of the marker write end");
            Ok(())
        }
        WriteEndCheck::Unassessable => {
            log::warn!(
                "marker EOF: could not confirm this process holds no copy of the marker write end, \
                 and the caller is waiting with no deadline - refusing rather than risking an \
                 unbounded hang"
            );
            Err(Error::Unassessable {
                detail: "could not confirm this process holds no copy of the containment marker's \
                         write end, and the wait has no deadline"
                    .into(),
                source: None,
            })
        }
        WriteEndCheck::HeldByUs => {
            // No debug_assert here: a deliberately-constructed HeldByUs condition must return
            // Err, not panic, so callers (including tests) can observe it.
            log::error!(
                "marker EOF: this process still holds a copy of the marker write end - the tree-drain \
                 edge can never fire. This is a cosca bug: the write end must be closed after spawn."
            );
            Err(Error::Containment {
                detail: "the supervisor still holds a copy of the containment marker's write end, so the \
                         tree-drain edge can never fire"
                    .into(),
            })
        }
    }
}
