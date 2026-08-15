//! macOS pid-snapshot tests.
//!
//! `proc_listallpids` fills whatever buffer it is handed and reports how many pids it
//! wrote — it never reports truncation — so an undersized buffer produces a short list
//! with no error, and asserting the snapshot is non-empty cannot see it. The pins here
//! therefore split in two: `the_first_buffer_is_large_enough` pins the ARITHMETIC (a real
//! sizing answer plus headroom must exceed the answer itself), and
//! `snapshot_count_agrees_with_the_kernels_sizing_answer` checks the delivered LIST against
//! a second source.

use super::{
    all_pids, all_pids_via, allocate_pids, capacity_for, collect_pids, fill_from_kernel, interpret_written, join_ppids,
    ppid_of, process_parents, size_argument_for, DROP_SAMPLE_CAP,
};

// Buffer arithmetic ====================================================================

/// A sizing answer of `needed` pids requires a buffer of at least `needed` pids — see
/// [`super::capacity_for`]'s doc for why the conversion is easy to get wrong.
#[test]
fn capacity_holds_at_least_the_sizing_answer() {
    for needed in [1usize, 20, 283, 1094, 100_000] {
        let cap = capacity_for(needed);
        assert!(
            cap > needed,
            "capacity_for({needed}) = {cap}: must hold {needed} pids plus room to grow"
        );
    }
}

/// Pins `capacity_for`'s documented saturation behavior directly: at `usize::MAX`,
/// `saturating_add` cannot exceed `usize::MAX`, so `cap > needed` (the invariant above)
/// necessarily fails there - that is the known, accepted edge the doc names, not a
/// regression, and `size_argument_for` is what catches an oversized `cap` afterward.
#[test]
fn capacity_for_saturates_rather_than_panics_or_wraps_at_the_boundary() {
    assert_eq!(capacity_for(usize::MAX), usize::MAX);
}

/// See `size_argument_for`'s doc for why an inexpressible size must error rather than wrap.
#[test]
fn a_pid_count_too_large_for_the_int_size_argument_is_an_error() {
    let bytes = size_argument_for(4).expect("4 pids fits in an int");
    assert_eq!(bytes, 4 * std::mem::size_of::<libc::c_int>() as libc::c_int);

    // The exact boundary: the largest pid count whose byte size still fits in an `int` must
    // succeed, not be rejected off-by-one along with the count just past it.
    let boundary = libc::c_int::MAX as usize / std::mem::size_of::<libc::c_int>();
    let boundary_bytes = size_argument_for(boundary).expect("the exact boundary must succeed");
    assert_eq!(
        boundary_bytes,
        (boundary * std::mem::size_of::<libc::c_int>()) as libc::c_int
    );

    let too_many = boundary + 1;
    let err = size_argument_for(too_many).expect_err("an inexpressible size must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);

    // The byte multiply must not wrap on the way to the cast either.
    size_argument_for(usize::MAX).expect_err("an overflowing byte count must fail");
}

// Interpreting the kernel's return value ===============================================

/// Pins `interpret_written`'s `<= 0` failure guard (see its doc) with synthetic values,
/// since a real EFAULT is not easily provoked from safe Rust.
#[test]
fn a_zero_return_is_an_error_not_an_empty_list() {
    interpret_written(0).expect_err("0 means failure, not zero pids");
}

#[test]
fn a_negative_return_is_an_error() {
    interpret_written(-1).expect_err("a negative return is also a failure");
}

#[test]
fn a_positive_return_is_the_written_count() {
    assert_eq!(interpret_written(5).expect("5 is a valid count"), 5);
}

// The real glue, directly - not just through collect_pids's injected closures ==========

/// `allocate_pids` itself, not a synthetic stand-in: proves its size-check ordering (the
/// refusal fires as its own `Err` before `try_reserve_exact` is ever attempted).
#[test]
fn allocate_pids_surfaces_the_size_check_as_its_own_error() {
    let err = allocate_pids(libc::c_int::MAX as usize)
        .expect_err("a pid count this large cannot be described in the size argument");
    assert!(
        err.to_string().contains("int size argument"),
        "expected the size-argument refusal, got: {err}"
    );
}

/// `allocate_pids` itself: a small, real allocation resizes to exactly the requested `cap` -
/// the invariant `collect_pids`'s saturation check relies on for the production path.
#[test]
fn allocate_pids_returns_a_buffer_of_exactly_the_requested_length() {
    let pids = allocate_pids(7).expect("a small allocation succeeds");
    assert_eq!(pids.len(), 7, "allocate_pids must resize to exactly cap");
}

/// `fill_from_kernel` itself, not `collect_pids`'s loop logic standing in for it: a real,
/// deliberately undersized 2-pid buffer against the live kernel. Any real host has far more
/// than 2 processes, so this must report `written == 2` (the buffer saturating) - the real
/// glue (`size_argument_for(pids.len())`, the syscall, `interpret_written`) wired correctly,
/// independent of the loose live completeness pins elsewhere in this file.
#[test]
fn fill_from_kernel_reports_written_equal_to_the_buffers_own_length() {
    let mut buf = [0i32; 2];
    let written = fill_from_kernel(&mut buf).expect("a live host always has more than 2 processes");
    assert_eq!(
        written, 2,
        "a 2-pid buffer against a live host must saturate at exactly 2"
    );
}

// The grow loop ========================================================================

/// A kernel holding `total` pids that fills whatever buffer it is handed and reports how
/// many it wrote — the real `proc_listallpids` contract, including its silence about
/// truncation. Simulated because the host's kernel cannot be made to under-report its own
/// sizing answer on demand; the live pins below drive the real syscall.
fn kernel_with(total: usize) -> impl FnMut(&mut [libc::c_int]) -> std::io::Result<usize> {
    move |buf| {
        let n = total.min(buf.len());
        for (slot, pid) in buf[..n].iter_mut().zip(1..) {
            *slot = pid;
        }
        Ok(n)
    }
}

#[test]
fn grows_until_the_buffer_is_not_the_limit() {
    // The starting capacity was 4 but 100 pids are there: the first fill saturates, and a
    // saturated answer must not be believed. 4 -> 8 -> ... -> 128 is 6 fills.
    let filled = collect_pids(4, kernel_with(100), allocate_pids).expect("fill succeeds");
    assert_eq!(
        filled.pids.len(),
        100,
        "a saturated answer must not be taken as the whole set"
    );
    assert_eq!(filled.rounds, 6, "each saturated fill doubles the buffer and retries");
}

#[test]
fn one_round_when_the_first_buffer_has_room() {
    let filled = collect_pids(16, kernel_with(3), allocate_pids).expect("fill succeeds");
    assert_eq!(
        filled.pids,
        [1, 2, 3],
        "the buffer is cut back to what the kernel wrote"
    );
    assert_eq!(filled.rounds, 1, "a buffer with room needs no retry");
}

#[test]
fn a_failing_fill_is_an_error_not_a_short_list() {
    let err = collect_pids(
        16,
        |_| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        allocate_pids,
    )
    .expect_err("a denied fill must not look like an empty process table");
    assert_eq!(err.raw_os_error(), Some(libc::EPERM));
}

/// Proves the size-argument refusal without ever allocating - the ROUND-1 case:
/// `libc::c_int::MAX` pids already overflows the `int` size argument on the very first
/// `allocate_pids` call, before `collect_pids` ever reaches `cap *= 2`. The doubling-then-
/// refusal path is pinned separately, in `doubling_then_refusal_ends_in_an_error`.
#[test]
fn an_immediate_overflow_ends_in_an_error_without_allocating() {
    let err = collect_pids(libc::c_int::MAX as usize, |buf| Ok(buf.len()), allocate_pids)
        .expect_err("a pid count this large cannot be described in the size argument");
    assert!(
        err.to_string().contains("int size argument"),
        "expected the size-argument refusal, got: {err}"
    );
}

/// A synthetic `allocate` step with a tiny ceiling, so a doubling sequence can be driven to
/// refusal in a few rounds without paying for real allocation anywhere near the true
/// ~536M-pid boundary `size_argument_for` enforces in production.
fn allocate_with_ceiling(limit: usize) -> impl FnMut(usize) -> std::io::Result<Vec<libc::c_int>> {
    move |cap| {
        if cap > limit {
            return Err(std::io::Error::other(format!(
                "synthetic ceiling of {limit} pids exceeded"
            )));
        }
        Ok(vec![0; cap])
    }
}

/// The doubling-then-refusal path: several successful grow rounds, THEN a refusal - distinct
/// production control flow from the immediate round-1 overflow above. 4 -> 8 -> 16 -> 32 ->
/// 64 all succeed against the ceiling of 100; 128 does not.
#[test]
fn doubling_then_refusal_ends_in_an_error() {
    let err = collect_pids(4, |buf| Ok(buf.len()), allocate_with_ceiling(100))
        .expect_err("a ceiling crossed after several successful rounds must still be an error");
    assert!(
        err.to_string().contains("ceiling"),
        "expected the ceiling refusal, got: {err}"
    );
}

/// `collect_pids` must turn an allocation failure into an `Err` it returns, never an abort -
/// pinned directly via the injected `allocate` step, since a real `try_reserve_exact` cannot
/// be made to fail deterministically without genuine memory pressure (see `allocate_pids`'s
/// own doc).
#[test]
fn a_failing_allocation_is_an_error_not_an_abort() {
    let err = collect_pids(
        16,
        |buf| Ok(buf.len()),
        |_cap| Err(std::io::Error::other("synthetic allocation failure")),
    )
    .expect_err("an allocation failure must be an Err, not an abort");
    assert!(
        err.to_string().contains("synthetic allocation failure"),
        "expected the injected allocation failure, got: {err}"
    );
}

/// CONTRACT tests, not production-behavior pins: the real `allocate_pids` always resizes to
/// exactly `cap`, so a buffer that never grows is not reachable through `process_parents()`
/// today. They exist because `allocate` is an injectable seam a future direct caller could
/// misuse, and without this guard `cap` would advance while `pids.len()` never does - the
/// same non-termination hazard the `cap == 0` entry guard prevents, reached from inside the
/// loop instead. Two shapes of "does not grow": empty every round, and a fixed nonzero
/// length that ignores `cap` after the first round.
#[test]
fn an_allocate_returning_an_empty_buffer_is_an_error_not_an_infinite_loop() {
    let err = collect_pids(4, |buf| Ok(buf.len()), |_cap| Ok(Vec::new()))
        .expect_err("an empty buffer for a nonzero capacity cannot make progress");
    assert!(
        err.to_string().contains("did not grow"),
        "expected the no-growth refusal, got: {err}"
    );
}

#[test]
fn an_allocate_that_ignores_cap_is_an_error_not_an_infinite_loop() {
    // Always returns 4 slots regardless of the requested cap - saturates every round
    // (`written == n == 4`), so the loop would spin forever on `cap = n * 2` alone.
    let err = collect_pids(4, |buf| Ok(buf.len()), |_cap| Ok(vec![0; 4]))
        .expect_err("a buffer that never grows cannot make progress");
    assert!(
        err.to_string().contains("did not grow"),
        "expected the no-growth refusal, got: {err}"
    );
}

/// A `fill` cannot legitimately report more pids written than the buffer it was handed -
/// that is a contract violation, not saturation, and must be loud rather than silently
/// folded into "ask again with more room".
#[test]
fn a_fill_reporting_more_than_the_buffer_holds_is_an_error() {
    let err = collect_pids(4, |buf| Ok(buf.len() + 1), allocate_pids)
        .expect_err("written > n must not be treated as saturation");
    assert!(
        err.to_string().contains("more pids than the buffer holds"),
        "expected the over-report refusal, got: {err}"
    );
}

/// See `collect_pids`'s doc for why `cap == 0` is refused rather than looped on.
#[test]
fn a_zero_capacity_is_an_error_not_an_infinite_loop() {
    let err = collect_pids(0, |_| Ok(0), allocate_pids).expect_err("a zero-capacity buffer cannot make progress");
    assert!(
        err.to_string().contains("nonzero starting capacity"),
        "expected the zero-capacity refusal, got: {err}"
    );
}

// Live pid list ========================================================================

fn sizing_answer() -> usize {
    // SAFETY: the sizing form of proc_listallpids takes a null buffer and a zero size.
    let needed = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    assert!(needed > 0, "sizing call failed: {}", std::io::Error::last_os_error());
    needed as usize
}

/// The ARITHMETIC pin, at the live layer: `capacity_for` applied to a REAL sizing answer
/// must still ask for more room than that answer. Not a hard `rounds == 1`: `fill_all()`'s
/// sizing call and its fill are two separate syscalls with a live host between them, and
/// unrelated process churn during that window can legitimately push a correct
/// implementation to a second round (parallel `cargo test` itself spawns processes), so a
/// round-count assertion would be flaky against correct code, not just against the
/// regression it exists to catch.
#[test]
fn the_first_buffer_is_large_enough() {
    let n = sizing_answer();
    assert!(
        capacity_for(n) > n,
        "capacity_for({n}) = {} does not exceed the sizing answer - the /4 regression is back",
        capacity_for(n)
    );
}

/// Pins the snapshot's pid count against the kernel's own sizing answer — bracketing two
/// sizing calls around the snapshot and taking the smaller removes drift from processes
/// created during the window, leaving only the kernel's own small sizing slack plus
/// whatever exited mid-snapshot. The tolerance is PROPORTIONAL, not a fixed constant:
/// requiring at least half the sizing answer's pids to survive catches a units-style
/// regression with a wide margin, while tolerating far more process churn between two
/// back-to-back syscalls than is plausible in practice.
///
/// This has a real, bounded blind spot at low process counts: with the /4 regression
/// present, the delivered length is `expected/4 + 16`, and `2*(expected/4 + 16) >= expected`
/// holds for any `expected <= 64` - i.e. the assertion below would pass even with the bug
/// present on a host/CI runner sized that small. `sizing_answer()` is always at least
/// `nprocs + 20`, so `expected <= 64` means fewer than ~44 live processes - implausible for
/// a full OS, but an explicit floor is cheaper than trusting that. Fails loudly rather than
/// passing vacuously if it's ever wrong.
#[test]
fn snapshot_count_agrees_with_the_kernels_sizing_answer() {
    let before = sizing_answer();
    let pids = all_pids();
    let after = sizing_answer();
    let expected = before.min(after);
    assert!(
        expected > 64,
        "sizing answer of {expected} is below the range where this test's x2 tolerance can \
         discriminate a units regression from a healthy snapshot - this pin is not meaningful \
         on a host this small"
    );
    assert!(
        pids.len() * 2 >= expected,
        "snapshot has {} pids against a sizing answer of {expected} - lost more than half, \
         consistent with a units regression",
        pids.len()
    );
}

// Failure fallback branches ============================================================

/// `all_pids`'s `Err` arm - unreachable from a live syscall in a test, same reasoning as
/// `collect_pids`'s injected `fill` - exercised via the injected closure instead.
#[test]
fn all_pids_is_empty_not_a_panic_when_the_snapshot_fails() {
    let pids = all_pids_via(|| Err(std::io::Error::from_raw_os_error(libc::EPERM)));
    assert!(
        pids.is_empty(),
        "a failed snapshot must produce an empty list, not propagate the error"
    );
}

// The ppid join ========================================================================

/// The `pid <= 0` filter, pinned deterministically with a synthetic pid list rather than a
/// live one: depending on a live run to happen to contain pid 0 (a kernel-internal fact
/// this filter's correctness should not hinge on to be exercised) would let the test pass
/// vacuously on a host/kernel where it's absent. `getpid()` is a real, live pid guaranteed
/// to resolve (`proc_pidinfo` on SELF is always permitted), so it proves the non-positive
/// entries are what's filtered, not that every entry is.
#[test]
fn join_ppids_filters_non_positive_pids() {
    let me = std::process::id() as libc::c_int;
    // Read before and after, same reasoning as `parents_contains_this_process_edge`:
    // nothing holds this process's real parent fixed across the call.
    let parent_before = std::os::unix::process::parent_id();
    let (out, dropped, sample) = join_ppids(&[0, -1, me]);
    let parent_after = std::os::unix::process::parent_id();
    assert_eq!(dropped, 0, "0 and -1 must not be counted as failed ppid lookups");
    assert!(
        sample.is_empty(),
        "nothing was attempted-and-failed, so nothing should be sampled"
    );
    assert_eq!(out.len(), 1, "only the real pid should produce an edge");
    let (pid, ppid) = out[0];
    assert_eq!(pid, me as u32, "the filtered edge must be for the real pid");
    assert!(
        ppid == parent_before || ppid == parent_after,
        "edge's ppid ({ppid}) matched neither parent read ({parent_before}, {parent_after})"
    );
}

/// The drop sample truncates at `DROP_SAMPLE_CAP`, not off-by-one and not unbounded: more
/// than `DROP_SAMPLE_CAP` copies of a pid that can never resolve (see
/// `ppid_of_returns_none_for_an_unallocatable_pid`) must still count every one as dropped
/// while the sample itself stays capped.
#[test]
fn join_ppids_caps_the_drop_sample() {
    let unresolvable = vec![libc::c_int::MAX; DROP_SAMPLE_CAP + 2];
    let (out, dropped, sample) = join_ppids(&unresolvable);
    assert!(out.is_empty(), "none of these pids can resolve to an edge");
    assert_eq!(
        dropped,
        DROP_SAMPLE_CAP + 2,
        "every attempted lookup must be counted as dropped"
    );
    assert_eq!(
        sample.len(),
        DROP_SAMPLE_CAP,
        "the sample must be capped, not grow with the drop count"
    );
}

/// The delivered `(pid, ppid)` snapshot carries this test process's own edge.
///
/// This is the only edge that can be asserted unconditionally: `proc_pidinfo` on SELF is
/// always permitted, so `ppid_of(getpid())` cannot be denied. A broader assertion — every
/// same-uid pid in `all_pids()` has an edge — would be flaky, because a same-uid process
/// that exits between the two calls is a legitimate ESRCH drop. The EPERM gap that bounds
/// this layer is pinned separately, in `ppid_of_denies_a_different_users_process`.
///
/// `parent_id()` is read both before and after `process_parents()`, and either is accepted:
/// nothing holds this process's real parent fixed across the call, so a single read compared
/// for exact equality would be a race against reparenting (rare, but a real TOCTOU, not a
/// hypothetical one) rather than a pin on the join.
#[test]
fn parents_contains_this_process_edge() {
    let me = std::process::id();
    let parent_before = std::os::unix::process::parent_id();
    let parents = process_parents();
    let parent_after = std::os::unix::process::parent_id();
    assert!(
        parents.contains(&(me, parent_before)) || parents.contains(&(me, parent_after)),
        "own edge missing from a {}-edge snapshot (parent read as {parent_before} before, \
         {parent_after} after)",
        parents.len()
    );
}

/// The `None` branch of `ppid_of` — the EPERM gap the module docs trace. pid 1 (launchd) is
/// guaranteed to exist and, outside a root process, guaranteed to be owned by a different
/// (root) user, so it is a deterministic trigger without spawning a cross-uid process. If
/// the test itself runs as root (some CI containers do), the call is expected to SUCCEED
/// instead — that branch is asserted explicitly, not skipped, so the test always checks
/// something regardless of the runner's privilege.
#[test]
fn ppid_of_denies_a_different_users_process() {
    let result = ppid_of(1);
    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        assert!(result.is_some(), "root can read launchd's ppid");
    } else {
        assert!(
            result.is_none(),
            "an unprivileged caller must not read another user's process info"
        );
    }
}

/// The OTHER cause of `ppid_of`'s `None` branch: ESRCH, a pid that does not exist. Triggered
/// deterministically: XNU caps real pids at `PID_MAX` (99999), so `libc::c_int::MAX` can
/// never be live.
#[test]
fn ppid_of_returns_none_for_an_unallocatable_pid() {
    assert!(
        ppid_of(libc::c_int::MAX).is_none(),
        "a pid beyond PID_MAX can never resolve to a ppid"
    );
}
