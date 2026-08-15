//! Buffer arithmetic: `capacity_for` and `size_argument_for`.

use super::super::{capacity_for, size_argument_for};

/// A sizing answer of `needed` pids requires a buffer of at least `needed` pids — see
/// [`super::super::capacity_for`]'s doc for why the conversion is easy to get wrong.
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
