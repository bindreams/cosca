//! Failure fallback branches: `all_pids`'s `Err` arm.

use super::super::all_pids_via;

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
