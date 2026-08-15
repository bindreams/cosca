//! The grow loop: `collect_pids` driven with synthetic `fill`/`allocate` seams.

use super::super::{allocate_pids, collect_pids};

/// A kernel holding `total` pids that fills whatever buffer it is handed and reports how
/// many it wrote — the real `proc_listallpids` contract, including its silence about
/// truncation. Simulated because the host's kernel cannot be made to under-report its own
/// sizing answer on demand; the live pins in `live_pid_list` drive the real syscall.
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
