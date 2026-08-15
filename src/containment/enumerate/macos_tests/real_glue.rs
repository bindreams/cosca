//! The real glue, directly - not just through `collect_pids`'s injected closures.

use super::super::{allocate_pids, fill_from_kernel};

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
/// independent of the loose live completeness pins elsewhere in this module.
#[test]
fn fill_from_kernel_reports_written_equal_to_the_buffers_own_length() {
    let mut buf = [0i32; 2];
    let written = fill_from_kernel(&mut buf).expect("a live host always has more than 2 processes");
    assert_eq!(
        written, 2,
        "a 2-pid buffer against a live host must saturate at exactly 2"
    );
}
