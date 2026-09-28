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
//! Every knote here is armed with `NOTE_LOWAT`, a high low-water mark, and `EV_CLEAR` (arm once
//! per genuinely new edge, not once per `kevent` call while the condition merely holds).
//! `EV_EOF` is always the sole verdict, unconditional of buffered bytes — but the low-water
//! mark itself is clamped by the kernel to the pipe's actual buffer capacity (measured ~64 KiB
//! on this host), so it suppresses wakeups for ordinary writes (which is all the crate should
//! ever produce — nothing in the crate writes to the marker) without being an absolute
//! guarantee against a member that sustains output at or above that ceiling.
//!
//! That residual case is handled differently depending on whether the wait is bounded:
//!
//! - **Bounded** (a caller-supplied deadline): the excess is drained in bounded rounds, an
//!   accommodation for a misbehaving-but-eventually-cooperative writer, paid for by the
//!   caller's own deadline — CPU-proportional to the writer's throughput for the wait's
//!   duration, same as the drain itself. No round starts once the deadline has passed. The one
//!   non-blocking check at expiry looks for EOF only and drains nothing. The in-flight round
//!   may finish arbitrarily later (principle 13).
//! - **Unbounded** (no deadline at all): nothing is drained. The effective low-water clamp
//!   equals the pipe's full capacity, so the very edge that makes the knote ready is also the
//!   instant the writer's own `write()` call blocks in the kernel — the original design
//!   assumption this module's misuse contract already documents (see `fdmarker`'s module doc:
//!   a member that writes to its inherited marker descriptor "blocks once the kernel pipe
//!   buffer fills"). Not draining lets that self-limiting behavior stand: with `EV_CLEAR` set
//!   and no new bytes possible while the writer stays blocked, the wait genuinely blocks in the
//!   kernel — poll-free, not CPU-proportional — until the writer's descriptor closes (forcibly
//!   or otherwise) or, for the bounded callers layered on top of this primitive, a deadline is
//!   reached. An unbounded wait cannot honestly offer both zero CPU AND forward progress for a
//!   sustained writer at the same time (continuing to drain IS continuing to do work
//!   proportional to what the writer produces, for as long as the writer keeps producing it) —
//!   this module chooses zero CPU for the unbounded case, since that is also the case with no
//!   deadline to bound the alternative.
//!
//!   The verdict stays TRUE while that writer is blocked, which is why this is a cost and not a
//!   wrong answer: a member parked in `write()` is still alive and still holds a write end, so
//!   the tree really does still have a member and `MembersRemain` is what an honest observer
//!   reports. The blocked member is visible in the process table; the alternative trades that
//!   visibility for a supervisor quietly spending a third of a core (measured 23-37% against a
//!   writer sustaining ~1 GB/s) to carry a member that is already outside the marker's contract.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Instant;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use crate::containment::TreeDrain;
use crate::error::Error;

#[cfg(test)]
#[path = "marker_eof_tests.rs"]
mod marker_eof_tests;

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
/// until it stops." Below the low-water clamp this branch never runs at all; at or above it —
/// and only for a caller with an actual deadline, see `interpret_read_event` — this is what
/// keeps a single round bounded — the OUTER loop (`wait::backend::block_on_kqueue`, reached via
/// `block_until_drained`) is what keeps the total wait bounded by the caller's deadline despite
/// repeated rounds.
fn drain_pending(read_end: BorrowedFd<'_>, original_n: usize) -> Result<(), Error> {
    let mut n = original_n;
    let mut buf = [0u8; 4096];
    let result = loop {
        if n == 0 {
            break Ok(());
        }
        let want = n.min(buf.len());
        match nix::unistd::read(read_end, &mut buf[..want]) {
            Ok(0) => break Ok(()), // EOF raced ahead of us; nothing left to drain
            Ok(got) => n -= got,   // still nonzero next iteration if `got < want`
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EAGAIN) => break Ok(()), // a concurrent reader won the race
            Err(e) => break Err(Error::Io(e.into())),
        }
    };
    // Recorded regardless of outcome — even a partial drain (EOF/EAGAIN cut it short) really
    // did consume `original_n - n` bytes. Test-only; see `drain_test_hooks`'s own doc for why
    // this is a bytes-drained counter and not a wall-clock or call-count proxy.
    #[cfg(test)]
    drain_test_hooks::record_drained((original_n - n) as u64);
    result
}

/// Test-only, and confined to macOS builds only by virtue of this whole module being macOS-only
/// (`#[cfg(target_os = "macos")]` at the `containment::marker_eof` declaration in
/// `containment.rs`) — no separate `cfg_attr` needed, unlike `wait::test_clock`'s helpers, which
/// live in a cross-platform module.
#[cfg(test)]
pub(crate) mod drain_test_hooks {
    use std::cell::Cell;

    thread_local! {
        static DRAINED_BYTES: Cell<u64> = const { Cell::new(0) };
    }

    /// Cumulative bytes `drain_pending` has actually discarded on THIS thread so far —
    /// monotonically increasing, so a test proves "round N drained nothing" by comparing a
    /// BASELINE taken right before round N to the total taken right after the whole wait
    /// concludes, immune to a writer refilling the pipe in between and masking a
    /// FIONREAD-only comparison (a sustained writer can restore the byte COUNT a round wrongly
    /// drained, but it can never undo this counter having moved).
    pub(crate) fn drained_bytes() -> u64 {
        DRAINED_BYTES.with(Cell::get)
    }

    pub(crate) fn record_drained(n: u64) {
        DRAINED_BYTES.with(|c| c.set(c.get() + n));
    }
}

/// Create a kqueue with `EVFILT_READ` armed on the marker read end, `NOTE_LOWAT`-gated (see
/// the module doc for what this does and does not guarantee) so ordinary writes never wake
/// it — only `EV_EOF` does.
///
/// One kqueue PER WAITER, deliberately: a knote is keyed on `(kqueue, fd, filter)`, so private
/// kqueues compose (two waiters both see the edge) where two registrations of the same
/// descriptor on one shared queue would take each other's place.
///
/// `unbounded_wait` says whether the caller intends to wait with no deadline — see
/// `refuse_if_write_end_held` for why that matters.
pub(crate) fn arm(read_end: BorrowedFd<'_>, unbounded_wait: bool) -> Result<Kqueue, Error> {
    ensure_nonblocking(read_end)?;
    refuse_if_write_end_held(read_end, unbounded_wait)?;
    let kq = Kqueue::new().map_err(|e| Error::Io(e.into()))?;
    let change = KEvent::new(
        read_end.as_raw_fd() as usize,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT | EvFlags::EV_CLEAR,
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
/// `NOTE_LOWAT` armed only happens once buffered bytes reach the clamp — i.e. the pipe is at
/// capacity, so a writer that keeps writing is, at that exact instant, already blocked in its
/// own `write()`. `suppress_drain` decides what happens next:
///
/// - **`false`** (a bounded wait with deadline funding left): `event.data()` bytes are
///   discarded via `drain_pending`, in one round bounded by the count the kernel itself
///   reported — the crate's accommodation for a misbehaving-but-eventually-cooperative writer,
///   paid for by the caller's own deadline.
/// - **`true`**: nothing is read. Two DISTINCT callers ask for this, unified under one flag by
///   principle 13: an unbounded wait (no deadline exists to fund a drain), and a
///   bounded wait whose deadline has ALREADY elapsed for this round (no deadline is left to
///   fund one, even though one existed a moment ago) — once elapsed, the final check looks for
///   `EV_EOF` only and never drains. The armed knote carries `EV_CLEAR` (see `arm`), so with no
///   bytes drained there is no new edge to refire on until the writer's OWN blocked `write()`
///   unblocks (impossible while the pipe stays full) or the descriptor closes (`EV_EOF`,
///   unconditional of buffered bytes). The wait genuinely blocks in the kernel rather than
///   draining on the writer's behalf forever — see the module doc for why an indefinite wait
///   cannot honestly offer both zero CPU and forward progress for a sustained writer, and why
///   this crate chooses zero CPU plus the writer's own original self-limiting contract
///   (`fdmarker`'s module doc) for that case.
///
/// `Err` = `EV_ERROR` or a `kevent`/read failure.
fn interpret_read_event(
    event: &KEvent,
    read_end: BorrowedFd<'_>,
    suppress_drain: bool,
) -> Result<Option<TreeDrain>, Error> {
    if event.flags().contains(EvFlags::EV_ERROR) {
        return Err(Error::Io(std::io::Error::from_raw_os_error(event.data() as i32)));
    }
    if event.flags().contains(EvFlags::EV_EOF) {
        return Ok(Some(TreeDrain::AllMarkersClosed));
    }
    // `data` is a byte count for a readable, non-EOF, non-error EVFILT_READ event — never
    // negative per the kqueue contract this module relies on everywhere else. A violation here
    // is a kqueue/ABI surprise or a bug in this module's own event handling, not an ordinary
    // runtime condition: `debug_assert!` catches it loudly in debug builds, and `log::warn!`
    // leaves a trace in release ones too — clamping to `0` and returning the routine "nothing to
    // drain yet" verdict must not happen in total silence, unlike an ordinary empty drain.
    if event.data() < 0 {
        log::warn!(
            "marker EOF: EVFILT_READ reported a negative data field ({}) on a non-EOF event — a \
             kqueue ABI surprise or a bug in this module's own event handling",
            event.data()
        );
    }
    debug_assert!(
        event.data() >= 0,
        "EVFILT_READ data must be non-negative per kernel contract, got {}",
        event.data()
    );
    if !suppress_drain {
        drain_pending(read_end, event.data().max(0) as usize)?;
    }
    Ok(None) // holders remain (EV_EOF was clear)
}

/// Take one pending event from an armed kqueue without blocking. `Ok(Some(_))` = the drain was
/// observed; `Ok(None)` = nothing conclusive yet (nothing pending, or — only when `!suppress_drain`
/// and the low-water clamp is reached — a member's bytes, discarded) — re-wait; `Err` = see
/// `interpret_read_event`. `suppress_drain` is `interpret_read_event`'s own parameter of the
/// same name, passed straight through — it does NOT have to equal whatever `unbounded_wait`
/// the kqueue was armed with (`arm`'s own, separate parameter, which governs
/// `refuse_if_write_end_held`'s policy, not draining): `probe`'s caller arms bounded (an
/// `Unassessable` write-end scan should still proceed, capped by the caller's own deadline) but
/// always suppresses draining (a one-shot, zero-timeout check IS a check at expiry — see
/// `probe`'s own doc), the same "no round starts once the deadline has passed, the one
/// non-blocking check at expiry looks for `EV_EOF` only" rule `block_on_kqueue`/
/// `interpret_read_event` apply to a bounded wait's own final round (principle 13).
pub(crate) fn drain_kqueue(
    kq: &Kqueue,
    read_end: BorrowedFd<'_>,
    suppress_drain: bool,
) -> Result<Option<TreeDrain>, Error> {
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
            Ok(_) => return interpret_read_event(&events[0], read_end, suppress_drain),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
}

/// One-shot drain check: exact, not heuristic — arms a private kqueue and reads its
/// zero-timeout verdict off `EV_EOF`, the same signal `block_until_drained` uses (advisory, per
/// this module's `TreeDrain::AllMarkersClosed` — see that type's own doc). `Ok(None)` from
/// `drain_kqueue` (nothing pending yet) means a write end is open with nothing queued:
/// `MembersRemain`, correctly, since `AllMarkersClosed` is only ever reported when the kernel
/// itself said `EV_EOF`.
///
/// A zero-timeout check IS a check at expiry — the same one a bounded `block_until_drained`
/// wait performs on its own final round once the deadline has passed — so this never drains
/// (`drain_kqueue`'s `suppress_drain = true`): it looks for `EV_EOF` only (principle 13). It
/// still arms bounded (`false` for `arm`'s OWN, separate `unbounded_wait` parameter), so an
/// `Unassessable` write-end scan proceeds rather than refuses — the two parameters govern
/// different policies and do not have to agree; see `drain_kqueue`'s own doc.
///
/// Called from `wait_tree_deadline`'s zero-duration case (`crate::tokio::wait`) — a one-shot
/// check never blocks, so it never risks a caller-invisible hang there. That caller lives
/// behind the crate's `tokio` feature, so this (and its own callee `drain_kqueue`) really is
/// unreachable without it — `#[allow(dead_code)]` reflects that honestly for a `tokio`-disabled
/// build instead of leaving the lib target to fail `cargo clippy --all-targets -D warnings`
/// there.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn probe(read_end: BorrowedFd<'_>) -> Result<TreeDrain, Error> {
    let kq = arm(read_end, false)?;
    match drain_kqueue(&kq, read_end, true)? {
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
/// left pending must be observed, not assumed away by the elapsed deadline alone. Uses one
/// kernel syscall per wait round — no interval is chosen anywhere in this path.
///
/// The per-round deadline-checking and `kevent` mechanics live in `wait::backend::block_on_kqueue`
/// (shared with the proc-exit watch); this function supplies only the marker's own arm and
/// per-event interpretation (`interpret_read_event`).
///
/// A genuinely unbounded wait (`None`, or `Some(None)`) never drains bytes past the low-water
/// clamp on a sustained writer — see the module doc for why, and `interpret_read_event` for
/// where that decision is made. A bounded wait (`Some(Some(_))`, including one already past)
/// keeps draining as long as its deadline has funding left; once a round starts with the
/// deadline already elapsed, that round stops draining too (principle 13) — same
/// `suppress_drain` flag, just also true for that reason.
pub(crate) fn block_until_drained(
    read_end: BorrowedFd<'_>,
    deadline: Option<Option<Instant>>,
) -> Result<TreeDrain, Error> {
    let unbounded_wait = crate::wait::remaining(deadline).is_none();
    let kq = arm(read_end, unbounded_wait)?;
    crate::wait::backend::block_on_kqueue(&kq, deadline, TreeDrain::MembersRemain, |event, already_elapsed| {
        interpret_read_event(event, read_end, unbounded_wait || already_elapsed)
    })
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
/// is still bounded by the caller's own deadline (no new rounds after it), but combined with
/// an UNBOUNDED wait it is exactly the condition under which this primitive could hang forever
/// with no elevated runtime signal at all — so only that combination is refused.
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
