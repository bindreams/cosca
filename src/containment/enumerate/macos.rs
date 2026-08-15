//! macOS `(pid, ppid)` snapshot: `proc_listallpids` for the pid set, then
//! `proc_pidinfo(PROC_PIDTBSDINFO).pbi_ppid` per pid (the same call `identity`
//! uses for its start token).
//!
//! Three known gaps:
//!
//! - `proc_pidinfo` is denied (EPERM) for another user's process, so an unprivileged
//!   caller gets no edge for one. `identity` covers the same case with a
//!   `sysctl(KERN_PROC_PID)` fallback; this backend has none. Everything cosca spawns
//!   itself is same-uid and unaffected. `process_parents` reports the aggregate drop count
//!   (and a bounded pid sample) at `warn`; individual drops are not logged - a snapshot with
//!   many drops must not become one log record per pid.
//! - A failed snapshot is reported as an EMPTY one, because `process_parents` has no error
//!   channel. A tree walk over an empty snapshot finds no descendants, so the failure is
//!   logged at `warn` naming that consequence.
//! - `proc_listallpids`' fill path caps its walk at `min(nprocs + 20, our buffer capacity)`,
//!   using an UNLOCKED read of `nprocs` taken before the process list locks (confirmed
//!   against XNU's `bsd/kern/proc_info.c`). Once our buffer exceeds `nprocs + 20` — which it
//!   always does after headroom — growing it further cannot raise this cap. `written < cap`
//!   is therefore not an airtight completeness proof: it closes truncation at the buffer's
//!   own edge, but a narrow, kernel-internal, userspace-invisible race remains (≥20 net new
//!   processes inside that unlocked-read-to-locked-walk window). Nothing in this module can
//!   close it without changing the underlying syscall.

use crate::identity::RawPid;

/// Extra pid slots asked for on top of the kernel's sizing answer, so the common case
/// needs exactly one fill: the process set can grow between the sizing call and the fill.
const HEADROOM: usize = 16;

/// Read the parent pid of `pid` via `proc_bsdinfo`, or `None` if not resolvable (EPERM
/// cross-user, ESRCH mid-snapshot exit). Silent per-call: a dropped edge drops the pid's
/// whole subtree in `treewalk::descendants_with`, so the drop matters, but the caller
/// (`process_parents`, via `join_ppids`) reports it aggregated, not one log record per pid -
/// see the module docs for why per-pid logging here specifically is a problem worth naming.
fn ppid_of(pid: libc::c_int) -> Option<RawPid> {
    // SAFETY: proc_bsdinfo is repr(C) and every field is an integer type, for which an
    // all-zeros bit pattern is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; pointer/size match.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    (n == size).then_some(info.pbi_ppid)
}

/// Buffer capacity, in PIDS, for a sizing answer of `needed` pids.
///
/// `proc_listallpids` is one of the libproc wrappers that CONVERTS before returning: it
/// calls `proc_listpids` — which answers in bytes — and divides by `sizeof(int)`. Both its
/// sizing answer and its fill answer are therefore PID COUNTS, unlike `proc_listpids` and
/// `proc_listpidspath`, which answer in bytes. Dividing this answer again asks for a
/// quarter of the room the kernel said it needed.
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
    #[cfg_attr(not(test), allow(dead_code))]
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
/// `saturating_add`, above). Its refusal branch is not unit-tested directly: proving it
/// deterministically would need a slice long enough to overflow the `int` size argument
/// (~536M elements, ~2GB), too heavy to allocate for a test.
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
/// `fill` and `allocate` are both injected: `fill` so the growth logic is testable without a
/// kernel that can be made to under-report on demand, `allocate` so both the doubling-then-
/// refusal path and an allocation failure can be driven deterministically without a real run
/// to the true ~536M-pid boundary or genuine memory pressure. Production passes
/// [`fill_from_kernel`] and [`allocate_pids`].
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

/// Every pid the kernel will list, given a way to perform the snapshot. Split from
/// [`all_pids`] so the `Err` arm - never reachable from a live syscall in a test, same
/// reasoning as `collect_pids`'s injected `fill` - is exercisable without a genuine
/// kernel-level failure.
fn all_pids_via(fill_all: impl FnOnce() -> std::io::Result<Filled>) -> Vec<libc::c_int> {
    match fill_all() {
        Ok(filled) => filled.pids,
        Err(e) => {
            log::warn!(
                "enumerate: pid snapshot failed ({e}) - callers see an EMPTY process table, \
                 so a tree walk over it finds no descendants"
            );
            Vec::new()
        }
    }
}

/// Every pid the kernel will list. Empty on failure — see the module docs.
fn all_pids() -> Vec<libc::c_int> {
    all_pids_via(fill_all)
}

/// How many pids to name in a drop-sample log line - enough to start a debugging session
/// from, not so many that a snapshot with hundreds of drops floods the log.
const DROP_SAMPLE_CAP: usize = 5;

/// Join pids to `(pid, ppid)` edges, filtering non-positive pids first. Pure and taking its
/// input as a plain slice - deterministically testable with a synthetic `[0, -1, <a real
/// pid>]` input, unlike a live call, which depends on the host's process table happening to
/// contain a non-positive pid at all. Returns the edges, how many attempted joins failed,
/// and a bounded sample of the failed pids for logging.
fn join_ppids(pids: &[libc::c_int]) -> (Vec<(RawPid, RawPid)>, usize, Vec<libc::c_int>) {
    // A plain `Vec::with_capacity`, not a fallible reservation - deliberately outside the
    // no-abort rule's scope, see the Global Constraints note. `pids.len()` over-estimates,
    // since some entries are filtered or fail the join.
    let mut out = Vec::with_capacity(pids.len());
    let mut dropped = 0usize;
    let mut sample = Vec::new();
    for &pid in pids {
        if pid <= 0 {
            continue; // pid 0 is the kernel process, not a real ppid edge
        }
        match ppid_of(pid) {
            Some(ppid) => out.push((pid as RawPid, ppid)),
            None => {
                dropped += 1;
                if sample.len() < DROP_SAMPLE_CAP {
                    sample.push(pid);
                }
            }
        }
    }
    (out, dropped, sample)
}

pub(crate) fn process_parents() -> Vec<(RawPid, RawPid)> {
    let pids = all_pids();
    let (out, dropped, sample) = join_ppids(&pids);
    if dropped > 0 {
        // One line per call, not one per dropped pid: `ppid_of` itself stays silent (see its
        // doc) so a snapshot with many EPERM/ESRCH drops does not flood the log.
        log::warn!(
            "enumerate: {dropped} of {} pids had no resolvable ppid (commonly EPERM cross-user \
             or ESRCH mid-snapshot exit, though `proc_pidinfo`'s exact failure per pid is not \
             recorded) - a tree walk may miss the descendants under each dropped edge; \
             sample: {sample:?}",
            out.len() + dropped
        );
    }
    out
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
