//! Failure fallback branches: `all_pids_or_empty`'s `Err` arm.

use super::super::all_pids_or_empty;

/// A failed snapshot is an empty list for `snapshot`'s callers, not a panic or a propagated error.
#[test]
fn all_pids_is_empty_not_a_panic_when_the_snapshot_fails() {
    let pids = all_pids_or_empty(Err(std::io::Error::from_raw_os_error(libc::EPERM)));
    assert!(
        pids.is_empty(),
        "a failed snapshot must produce an empty list, not propagate the error"
    );
}
