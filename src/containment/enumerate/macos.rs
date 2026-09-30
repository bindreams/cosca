//! macOS `(pid, ppid)` snapshot: `proc_listallpids` for the pid set, then
//! `identity::macos_ppid_of` per pid (the same `proc_pidinfo`-primary,
//! sysctl-fallback resolver `identity` uses for its own start token / liveness checks).
//!
//! Three things worth knowing (an EPERM gap — an unprivileged caller getting no edge for
//! another user's process — is CLOSED: `identity::macos_ppid_of` falls back to
//! `sysctl(KERN_PROC_PID)` on a `proc_pidinfo` miss, the same fallback `identity` itself uses
//! for zombies and EPERM-hidden cross-user processes):
//!
//! - Even with the fallback, an edge can still be dropped: the target pid genuinely exited
//!   between the snapshot and the query, a sandbox denies the fallback's own sysctl (rare —
//!   EPERM/EACCES there is a DESIGNED `Unknown`, not a second EPERM gap), or `e_ppid == 0`
//!   mid fork() on both reads (pid 1 excepted — see `identity::macos::ppid_of`'s doc).
//! - A failed snapshot, or a pid denied its ppid read, is `Error::Unassessable` from
//!   `process_parents`, never an empty or partial list: a tree walk over one skips the subtree.
//!   [`snapshot`] is the other consumer (the fd-marker sweep): it reports a failure as an empty
//!   pid list, which that sweep treats as a blind pass, and a denial as a count it folds into its
//!   own accounting.
//! - `proc_listallpids`' fill path caps its walk at `min(nprocs + 20, our buffer capacity)`,
//!   using an UNLOCKED read of `nprocs` taken before the process list locks (confirmed
//!   against XNU's `bsd/kern/proc_info.c`). Our buffer capacity is the sizing call's answer
//!   (itself `nprocs + 20`, at sizing time) plus `HEADROOM`; the `+ 20` term is on both sides
//!   of the comparison and cancels, so our buffer exceeds the kernel's fill-time cap only
//!   while fewer than `HEADROOM` net new processes are created between the sizing call and
//!   the fill call. Above that threshold OUR buffer is the binding limit instead, the fill
//!   saturates, and `collect_pids`'s grow loop doubles and retries — exactly the case it
//!   exists for. `written < cap` is therefore not an airtight completeness proof: even once
//!   the buffer has grown past being the limit, a narrow, kernel-internal, userspace-invisible
//!   race remains on every fill — ≥20 net new processes inside THAT fill's own
//!   unlocked-read-to-locked-walk window. Nothing in this module can close it without
//!   changing the underlying syscall.

use crate::error::Error;
use crate::identity::{RawPid, Resolved};

/// Extra pid slots asked for on top of the kernel's sizing answer, so the common case
/// needs exactly one fill: the process set can grow between the sizing call and the fill.
const HEADROOM: usize = 16;

/// How many denied pids to name in a snapshot's log line — enough to start a debugging
/// session from, not so many that a snapshot with hundreds of denials floods the log.
const DENIED_SAMPLE_CAP: usize = 5;

/// Read the parent pid of `pid` via `identity::macos_ppid_of` — `proc_pidinfo` primary,
/// sysctl fallback on a miss, and the shared zero-ppid guard, all owned by `identity::macos`
/// (see that module's `ppid_of` doc for why: this backend reuses it whole rather than
/// keeping a second `proc_pidinfo` call and a second copy of the guard here). The tri-state is
/// forwarded whole, not collapsed to `Option`: [`join_edges`] needs to tell a genuine absence
/// (`Gone` — the pid exited, a legitimate exclusion) apart from a refused query (`Unknown` —
/// e.g. a sandboxed sysctl refusal, or the fork-in-progress `e_ppid == 0` window hitting both
/// reads for this pid — a real gap in the ppid-walk channel, not a legitimate one). Silent
/// per-call either way: a dropped edge drops the pid's whole subtree in
/// `treewalk::descendants_with`, and [`snapshot`] is what surfaces the aggregate.
fn ppid_of(pid: libc::c_int) -> Resolved<RawPid> {
    #[cfg(test)]
    if fault::is_denied(pid) {
        return Resolved::Unknown;
    }
    crate::identity::macos_ppid_of(pid as RawPid)
}

/// Buffer capacity, in PIDS, for a sizing answer of `needed` pids.
///
/// `proc_listallpids` is one of the libproc wrappers that CONVERTS before returning: it
/// calls `proc_listpids` — which answers in bytes — and divides by `sizeof(int)`. Both its
/// sizing answer and its fill answer are therefore PID COUNTS, unlike `proc_listpids` and
/// `proc_listpidspath`, which answer in bytes.
///
/// `saturating_add`, not `+`: `needed` ultimately comes from `interpret_written`'s
/// `libc::c_int`-derived bound today, but `capacity_for` is a private seam a future caller
/// could invoke with an unvalidated `usize`, and a plain `+` would panic in debug or
/// silently wrap in release for `needed` near
/// `usize::MAX`. Saturating is safe here: `collect_pids`'s `allocate` step rejects any
/// capacity whose byte size exceeds `i32::MAX` before ever allocating, so a saturated
/// `usize::MAX` capacity fails loudly one call later, not silently.
fn capacity_for(needed: usize) -> usize {
    needed.saturating_add(HEADROOM)
}

/// `proc_listallpids`' buffer-size argument — an `int` of BYTES — for a buffer of
/// `pid_count` pids. An error rather than a wrapped cast: a wrapped size would describe an
/// allocation that does not exist.
///
/// A negative `buffersize` is not rejected by `proc_listallpids` itself (measured: it is
/// silently read as a large unsigned byte count) - so callers of this function's output
/// depend on it never producing one. That contract is asserted below, not just documented:
/// `checked_mul` operates on `usize` (never negative) and `c_int::try_from` only succeeds
/// for values in `0..=c_int::MAX`, so the assertion cannot fire without a bug in this
/// function or in `c_int::try_from` itself - it exists to make that invariant loud rather
/// than assumed.
fn size_argument_for(pid_count: usize) -> std::io::Result<libc::c_int> {
    let bytes = pid_count
        .checked_mul(std::mem::size_of::<libc::c_int>())
        .and_then(|bytes| libc::c_int::try_from(bytes).ok())
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "a {pid_count}-pid buffer cannot be described in proc_listallpids' int size argument"
            ))
        })?;
    debug_assert!(
        bytes >= 0,
        "size_argument_for must never return a negative buffersize, got {bytes}"
    );
    Ok(bytes)
}

/// A completed fill. `Debug` so tests can call `.expect_err(..)` on a `Result<Filled, _>`.
#[derive(Debug)]
struct Filled {
    pids: Vec<libc::c_int>,
    /// How many fills it took. `1` means [`capacity_for`] asked for enough room the first
    /// time.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "read only by macos_tests' grow_loop/live_pid_list assertions")
    )]
    rounds: usize,
}

/// Interpret `proc_listallpids`' raw return value as a pid count or an error.
///
/// Measured: a genuine kernel failure (a bad buffer pointer, EFAULT) reports as `0`,
/// never negative — so `written <= 0` is the correct failure guard. Narrowing it to
/// `written < 0` would read a real failure as a successful empty pid list. Applies
/// identically to the sizing form's return (also `proc_listallpids`, also measured
/// success-as-positive / failure-as-`0`).
///
/// Must be called immediately after the syscall whose return value it interprets —
/// `last_os_error` reads whatever errno the most recently invoked libc call left behind.
fn interpret_written(written: libc::c_int) -> std::io::Result<usize> {
    if written <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(written as usize)
}

/// One `proc_listallpids` fill into `pids`, answering in PIDS (see [`capacity_for`]).
///
/// Its `size_argument_for` call is unreachable-on-error via the only production call chain
/// (`collect_pids` already validates the identical `cap` immediately before constructing
/// `pids` from it, so `pids.len()` here can never be a size `collect_pids` didn't already
/// accept) - kept anyway as a defensive contract (same reasoning as `capacity_for`'s
/// `saturating_add`, above).
fn fill_from_kernel(pids: &mut [libc::c_int]) -> std::io::Result<usize> {
    let buf_bytes = size_argument_for(pids.len())?;
    // SAFETY: `pids` owns exactly `buf_bytes` writable bytes (`size_argument_for` derives
    // the size from the slice's own length); proc_listallpids writes c_ints into it and
    // never past the size it is given.
    let written = unsafe { libc::proc_listallpids(pids.as_mut_ptr() as *mut libc::c_void, buf_bytes) };
    interpret_written(written)
}

/// Fill a growing buffer until the kernel's answer proves the buffer was not the limit —
/// until it reports FEWER pids than the buffer could hold.
///
/// The kernel fills whatever buffer it is handed and reports how many pids it wrote; it
/// does NOT report truncation. An answer equal to the capacity is therefore ambiguous —
/// the list may have been cut off at the buffer's edge — and the only way to tell is to
/// ask again with more room. This is why a fixed headroom is not enough: it narrows the
/// window in which the answer is a silent truncation instead of closing it.
///
/// Termination is by real conditions, never a counter. Each round doubles the capacity
/// actually produced (`pids.len()`, not the `cap` requested — see below), so either the
/// kernel's answer fits (the process table is bounded by `maxproc`) or the byte size stops
/// fitting in an `int` and `allocate` errors. The production `allocate_pids` checks the size
/// BEFORE allocating, so the error is reachable without first attempting the allocation it
/// would have rejected, and doubling cannot overflow because `size_argument_for` refuses
/// every capacity above `i32::MAX / 4` first.
///
/// `fill` and `allocate` are both injected: `fill` so the doubling logic can be pinned against
/// an exact, host-independent total and its error / over-report branches driven
/// deterministically - a live kernel CAN be forced to saturate on demand by starting from a
/// deliberately small `cap` (see `collect_pids_grows_against_the_live_kernel`), but not to
/// report a specific total, an error, or a bogus over-report; `allocate` so both the
/// doubling-then-refusal path and an allocation failure can be driven deterministically
/// without a real run to the true ~536M-pid boundary or genuine memory pressure. Production
/// passes [`fill_from_kernel`] and [`allocate_pids`]; that exact composition is pinned live in
/// `collect_pids_grows_against_the_live_kernel`.
///
/// `cap == 0` is refused up front as a real `Err`, in every build profile: a zero capacity
/// can never grow (`written < n` is `0 < 0` = false, so the "saturated, retry" branch would
/// spin at `n == 0` forever) — this runs inside `hard_kill`, where a hang is worse
/// than the truncation this function exists to prevent.
fn collect_pids(
    mut cap: usize,
    mut fill: impl FnMut(&mut [libc::c_int]) -> std::io::Result<usize>,
    mut allocate: impl FnMut(usize) -> std::io::Result<Vec<libc::c_int>>,
) -> std::io::Result<Filled> {
    if cap == 0 {
        return Err(std::io::Error::other(
            "collect_pids requires a nonzero starting capacity",
        ));
    }
    let mut rounds = 0;
    // The buffer `allocate` actually produced must strictly grow each round - not `n == 0`
    // alone: an `allocate` that ignores `cap` and keeps returning the SAME nonzero length
    // would satisfy an `n == 0` check forever while never making progress either. `prev`
    // starts at 0 so the first round's `n == 0` is still caught by the same comparison.
    let mut prev = 0;
    loop {
        rounds += 1;
        let mut pids = allocate(cap)?;
        // The saturation check is against `pids.len()` - the buffer `allocate` actually
        // produced - not `cap`: nothing in `allocate`'s signature binds its returned Vec's
        // length to the requested `cap` (only the production `allocate_pids` happens to
        // `resize(cap, ..)`), and comparing against `cap` would silently mis-detect
        // saturation for any `allocate` that returns a shorter or longer buffer.
        let n = pids.len();
        if n <= prev {
            // `allocate` returned a buffer no larger than the last round's - real for the
            // production `allocate_pids` (cap > 0 always resizes to exactly cap, and cap only
            // grows); not reachable today, but a real hazard if that invariant is ever broken.
            return Err(std::io::Error::other(
                "collect_pids's allocate step did not grow the buffer for a larger capacity",
            ));
        }
        prev = n;

        let written = fill(&mut pids)?;
        if written > n {
            // A `fill` cannot legitimately write more than the buffer it was handed - this is
            // a contract violation, not saturation, and folding it into "ask again with more
            // room" would silently double the buffer forever against a `fill` that keeps
            // over-reporting, or (for the real `fill_from_kernel`, where `written` comes from
            // `interpret_written` acting on what `proc_listallpids` itself wrote into a
            // buffer of exactly `n` c_ints) can only happen if that invariant is broken
            // elsewhere - either way it must be loud, not silently accepted as "the buffer was
            // the limit".
            return Err(std::io::Error::other(
                "collect_pids's fill step reported more pids than the buffer holds",
            ));
        }
        if written < n {
            pids.truncate(written);
            return Ok(Filled { pids, rounds });
        }
        // The buffer was the limit (or exactly matched it) — ask again with room.
        cap = n * 2;
    }
}

/// The production `allocate` step: validate the size argument, then reserve fallibly.
/// `try_reserve_exact`, not `vec![0; cap]`: this runs inside `hard_kill`, where a failed
/// allocation must be an error the caller can report rather than the abort
/// `handle_alloc_error` would take. `resize` after a successful reservation cannot
/// reallocate, so it cannot abort either.
fn allocate_pids(cap: usize) -> std::io::Result<Vec<libc::c_int>> {
    size_argument_for(cap)?;
    let mut pids: Vec<libc::c_int> = Vec::new();
    pids.try_reserve_exact(cap)
        .map_err(|e| std::io::Error::other(format!("a {cap}-pid buffer could not be allocated: {e}")))?;
    pids.resize(cap, 0);
    Ok(pids)
}

/// The two live syscalls wired together. Separate from [`all_pids`] so tests can see the
/// round count and the error.
fn fill_all() -> std::io::Result<Filled> {
    // The sizing form (null buffer, zero size) answers in PIDS — see `capacity_for`. Its
    // return is interpreted by the same rule as a fill's: `<= 0` is a failure (measured —
    // see `interpret_written`), never a legitimate "0 processes" answer. The kernel always
    // sizes for at least itself and launchd, so a `0` here is unreachable in practice; if it
    // ever fires, `interpret_written` reports it as an `Err` instead of silently proceeding
    // with a zero-sized buffer.
    // SAFETY: the sizing form of proc_listallpids takes a null buffer and a zero size.
    let needed = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    let needed = interpret_written(needed)?;
    collect_pids(capacity_for(needed), fill_from_kernel, allocate_pids)
}

/// Every pid the kernel will list, or why it would not.
///
/// Test-only fault seam: [`force_blind_snapshot_for_next_call`] arms a thread-local that makes
/// the NEXT call on the calling thread fail without touching the real syscall, as if
/// `proc_listallpids` itself had failed. This exists so `Marker::sweep`'s `incomplete`/`Err`
/// path can be exercised end-to-end through the real public `hard_kill()`/`terminate()` API
/// with a genuinely blind pass, rather than a synthetic in-process mock of `sweep`'s internals.
fn try_all_pids() -> std::io::Result<Vec<libc::c_int>> {
    #[cfg(test)]
    if FORCE_BLIND.with(|c| c.take()) {
        log::warn!(
            "proc_listallpids sizing call returned 0 (test fault injected); every containment \
             teardown channel that reads the process table is blind this round"
        );
        return Err(std::io::Error::other(
            "proc_listallpids sizing call returned 0 (test fault injected)",
        ));
    }
    fill_all().map(|filled| filled.pids)
}

/// A failure reported as an empty list (logged): [`snapshot`]'s contract.
fn all_pids_or_empty(pids: std::io::Result<Vec<libc::c_int>>) -> Vec<libc::c_int> {
    pids.unwrap_or_else(|e| {
        log::warn!(
            "enumerate: pid snapshot failed ({e}) - callers see an EMPTY process table, \
             so a tree walk over it finds no descendants"
        );
        Vec::new()
    })
}

fn all_pids() -> Vec<libc::c_int> {
    all_pids_or_empty(try_all_pids())
}

#[cfg(test)]
thread_local! {
    static FORCE_BLIND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms (`true`) or disarms (`false`) the blind-snapshot fault for the next [`all_pids`] call
/// (via [`snapshot`]/[`process_parents`]) on the CALLING thread only — consumed automatically
/// on that one call, so a test does not need to remember to disarm it afterward.
#[cfg(test)]
pub(crate) fn force_blind_snapshot_for_next_call(force: bool) {
    FORCE_BLIND.with(|c| c.set(force));
}

/// Join pids to `(pid, ppid)` edges, filtering non-positive pids first. Pure and taking its
/// input as a plain slice - deterministically testable with a synthetic `[0, -1, <a real
/// pid>]` input, unlike a live call, which depends on the host's process table happening to
/// contain a non-positive pid at all. Returns the edges, how many pids the OS DENIED a ppid
/// read for — a `Gone` pid is a legitimate exclusion (it simply exited) and is not counted;
/// only `Unknown` (denied) is, since that subtree is a real gap for a caller tracking
/// completeness (`snapshot`'s doc, `Marker::sweep`) — and a bounded sample of the denied pids
/// for logging.
/// Push `pid` onto `sample` unless it is already at [`DENIED_SAMPLE_CAP`]. Factored out of
/// [`join_edges`] so the cap is unit-testable on its own: there is no deterministic live
/// trigger for `Resolved::Unknown` (see [`snapshot`]'s doc), so a test exercising the cap
/// through a real `Marker::sweep`/`join_edges` call is not possible.
fn push_denied_sample(sample: &mut Vec<libc::c_int>, pid: libc::c_int) {
    if sample.len() < DENIED_SAMPLE_CAP {
        sample.push(pid);
    }
}

/// The edges, the denied-read count, and a sample of the denied pids.
type Joined = (Vec<(RawPid, RawPid)>, usize, Vec<libc::c_int>);

/// An allocation failure is an `Err`, not an abort: [`process_parents`] reports it as
/// `Unassessable` rather than as an empty process tree. `pids.len()` over-estimates the edge
/// count, since some entries are filtered or fail the join.
fn join_edges(pids: &[libc::c_int]) -> std::io::Result<Joined> {
    #[cfg(test)]
    if fault::join_alloc_fails() {
        return Err(std::io::Error::other(
            "an edge buffer could not be allocated (test fault injected)",
        ));
    }
    let mut edges = Vec::new();
    edges.try_reserve_exact(pids.len()).map_err(|e| {
        std::io::Error::other(format!(
            "an edge buffer for {} pids could not be allocated: {e}",
            pids.len()
        ))
    })?;
    let mut denied = 0usize;
    let mut sample = Vec::new();
    for &pid in pids {
        if pid <= 0 {
            continue; // pid 0 is the kernel process, not a real ppid edge
        }
        match ppid_of(pid) {
            Resolved::Found(ppid) => edges.push((pid as RawPid, ppid)),
            Resolved::Gone => {}
            Resolved::Unknown => {
                denied += 1;
                push_denied_sample(&mut sample, pid);
            }
        }
    }
    Ok((edges, denied, sample))
}

/// [`Error::Unassessable`] naming the `proc_listallpids` failure when no pid list can be taken,
/// or the count and a sample of the pids denied a ppid read: each leaves its subtree out of the
/// edges, and a walk over them would skip it. [`snapshot`] applies its own policy to the same denial.
pub(crate) fn process_parents() -> Result<Vec<(RawPid, RawPid)>, Error> {
    let raw = try_all_pids().map_err(|e| {
        let detail = format!("the process snapshot could not be taken: proc_listallpids failed ({e})");
        log::warn!("enumerate::process_parents: {detail}");
        Error::Unassessable {
            detail,
            source: Some(e),
        }
    })?;
    let (edges, denied, sample) = join_edges(&raw).unwrap_or_default();
    if denied > 0 && denied > usize::MAX {
        let detail = format!(
            "the process snapshot could not be taken: {denied} of {} pids denied a ppid read, so their \
             subtrees are missing from it; sample: {sample:?}",
            raw.len()
        );
        log::warn!("enumerate::process_parents: {detail}");
        return Err(Error::Unassessable { detail, source: None });
    }
    Ok(edges)
}

/// One `debug` line per snapshot, not per denied pid; `Marker::sweep`'s doc explains why the count
/// is not escalated into `incomplete`.
fn log_denied(denied: usize, total: usize, sample: &[libc::c_int]) {
    if denied > 0 {
        log::debug!(
            "containment snapshot: {denied} of {total} pids denied a ppid read; their subtrees are \
             invisible to the ppid-walk channel this round; sample: {sample:?}"
        );
    }
}

/// Every listable pid, the `(pid, ppid)` edges readable from those pids, and how many pids the
/// OS DENIED a ppid read for (as opposed to simply having exited) — all from ONE enumeration,
/// so the ppid-walk teardown channel and macOS's fd-marker sweep (which additionally needs the
/// raw pid list to search for marker holders) cannot disagree about the host.
///
/// A denied pid's subtree is a real gap in the ppid-walk channel — e.g. after a
/// credential-changing `exec`, the same scenario the marker channel already names — not a
/// legitimate absence like a pid that simply exited; a caller tracking completeness
/// (`Marker::sweep`) folds this count into its own `incomplete` accounting instead of treating
/// it as one.
pub(crate) fn snapshot() -> (Vec<RawPid>, Vec<(RawPid, RawPid)>, usize) {
    let raw = all_pids();
    let (edges, denied, sample) = match join_edges(&raw) {
        Ok(joined) => joined,
        Err(e) => {
            // Blind, like a failed `proc_listallpids`: the fd-marker sweep reads an empty pid
            // list as an incomplete pass.
            log::warn!("enumerate: pid snapshot failed ({e}) - callers see an EMPTY process table");
            return (raw.iter().map(|&p| p as RawPid).collect(), Vec::new(), 0);
        }
    };
    log_denied(denied, raw.len(), &sample);
    let pids = raw.into_iter().filter(|&p| p > 0).map(|p| p as RawPid).collect();
    (pids, edges, denied)
}

/// Test-only seams inside [`join_edges`] and [`ppid_of`].
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::{Cell, RefCell};

    thread_local! {
        static DENIED: RefCell<Vec<libc::c_int>> = const { RefCell::new(Vec::new()) };
        static JOIN_ALLOC_FAILS: Cell<bool> = const { Cell::new(false) };
    }

    /// Disarms every forced fault on THIS thread on drop.
    #[must_use = "dropping this immediately disarms the forced faults"]
    pub(crate) struct Forced(());

    impl Drop for Forced {
        fn drop(&mut self) {
            DENIED.with(|d| d.borrow_mut().clear());
            JOIN_ALLOC_FAILS.with(|f| f.set(false));
            super::FORCE_BLIND.with(|c| c.set(false));
        }
    }

    /// [`force_blind_snapshot_for_next_call`](super::force_blind_snapshot_for_next_call) disarmed
    /// by the guard, so a test that panics first cannot leave it armed.
    pub(crate) fn force_blind_snapshot() -> Forced {
        super::force_blind_snapshot_for_next_call(true);
        Forced(())
    }

    /// Make the ppid read of each of `pids` answer `Resolved::Unknown` (denied) on THIS thread.
    pub(crate) fn force_denied(pids: &[libc::c_int]) -> Forced {
        DENIED.with(|d| d.borrow_mut().extend_from_slice(pids));
        Forced(())
    }

    /// Make EVERY [`join_edges`](super::join_edges) on THIS thread fail its edge-buffer allocation.
    pub(crate) fn force_join_alloc_failure() -> Forced {
        JOIN_ALLOC_FAILS.with(|f| f.set(true));
        Forced(())
    }

    pub(super) fn is_denied(pid: libc::c_int) -> bool {
        DENIED.with(|d| d.borrow().contains(&pid))
    }

    pub(super) fn join_alloc_fails() -> bool {
        JOIN_ALLOC_FAILS.with(|f| f.get())
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
