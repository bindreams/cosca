//! The macOS pid listing: `proc_listallpids` sized, filled and grown until the kernel reports
//! fewer pids than the buffer holds. [`host_pids`] is `HostKernel`'s read.
//!
//! One thing worth knowing:
//!
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

/// Extra pid slots asked for on top of the kernel's sizing answer, so the common case
/// needs exactly one fill: the process set can grow between the sizing call and the fill.
const HEADROOM: usize = 16;

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
        allow(dead_code, reason = "read only by pids_tests' grow_loop/live_pid_list assertions")
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
/// spin at `n == 0` forever), and a hang is worse than the truncation this function exists
/// to prevent.
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
/// `try_reserve_exact`, not `vec![0; cap]`: a failed reservation of this buffer is an `Err`
/// the listing's caller reports (`process_parents`: `Unassessable`; `snapshot`: a blind
/// pass) rather than the abort `handle_alloc_error` would take. `resize` after a
/// successful reservation cannot reallocate, so it cannot abort either.
fn allocate_pids(cap: usize) -> std::io::Result<Vec<libc::c_int>> {
    size_argument_for(cap)?;
    let mut pids: Vec<libc::c_int> = Vec::new();
    pids.try_reserve_exact(cap).map_err(|e| {
        crate::error::io_context(
            format!("a {cap}-pid buffer could not be allocated"),
            std::io::Error::from(e),
        )
    })?;
    pids.resize(cap, 0);
    Ok(pids)
}

/// The two live syscalls wired together. Separate from [`host_pids`] so tests can see the
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

/// Every pid the real kernel will list, or why it would not: [`HostKernel::pids`](crate::identity::HostKernel)'s read.
pub(super) fn host_pids() -> std::io::Result<Vec<libc::c_int>> {
    fill_all().map(|filled| filled.pids)
}

#[cfg(test)]
#[path = "pids_tests.rs"]
mod pids_tests;
