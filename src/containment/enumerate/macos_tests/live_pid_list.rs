//! Live pid list: the grow loop and buffer arithmetic against the real kernel, not the
//! synthetic seams `grow_loop` and `buffer_arithmetic` use.
//!
//! `proc_listallpids` fills whatever buffer it is handed and reports how many pids it
//! wrote — it never reports truncation — so an undersized buffer produces a short list
//! with no error, and asserting the snapshot is non-empty cannot see it. The pins here
//! therefore split in two: `the_first_buffer_is_large_enough` pins the ARITHMETIC (a real
//! sizing answer plus headroom must exceed the answer itself), and
//! `snapshot_count_agrees_with_the_kernels_sizing_answer` checks the delivered LIST against
//! a second source.

use super::super::{all_pids, allocate_pids, capacity_for, collect_pids, fill_from_kernel};

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

/// The end-to-end grow loop against the REAL kernel and REAL allocator - not a synthetic
/// stand-in for either. Every grow-loop test in `grow_loop` drives `collect_pids` with an
/// injected `fill`; the only test that calls the real `fill_from_kernel`
/// (`fill_from_kernel_reports_written_equal_to_the_buffers_own_length`, in `real_glue`) does
/// exactly one saturating fill and stops, never feeding the result back through the doubling
/// loop. So the composition `collect_pids` + `fill_from_kernel` + `allocate_pids` actually
/// runs in production is otherwise never exercised - a regression at that seam (e.g.
/// `fill_from_kernel` sizing from a stale length, or `collect_pids` reusing the previous
/// buffer instead of the newly allocated one) would pass every other test in this module.
///
/// A starting capacity of 2 cannot hold any real host's process table, forcing at least one
/// real saturate-and-retry round - the live kernel CAN be made to under-report on demand this
/// way, by simply starting deliberately small; that does not require a kernel that reports a
/// specific total, an error, or a bogus over-report on command, which is why `fill` stays
/// injected for those cases (see `collect_pids`'s doc).
///
/// Pinned with the same proportional tolerance as
/// `snapshot_count_agrees_with_the_kernels_sizing_answer`, not a fixed round or pid count:
/// both are host-load-dependent - see that test's doc for why.
#[test]
fn collect_pids_grows_against_the_live_kernel() {
    let before = sizing_answer();
    let filled = collect_pids(2, fill_from_kernel, allocate_pids).expect("fill succeeds");
    let after = sizing_answer();
    let expected = before.min(after);
    assert!(
        expected > 64,
        "sizing answer of {expected} is below the range where this test's tolerance can \
         discriminate a regression from a healthy snapshot - this pin is not meaningful on a \
         host this small"
    );
    assert!(
        filled.rounds > 1,
        "a starting capacity of 2 took only 1 round against a sizing answer of {expected} - \
         either the buffer somehow held the whole table, or growth silently isn't happening"
    );
    assert!(
        filled.pids.len() * 2 >= expected,
        "the live grow loop delivered {} pids against a sizing answer of {expected} - lost \
         more than half, consistent with a units or growth regression",
        filled.pids.len()
    );
}
