use super::{std_teardown_action, StdTeardown};

// The a36b0244 fix: the `Std` teardown arm must key on the OBSERVED kill result, NOT on any
// "was elevation requested" flag. A child that gained privilege ON ITS OWN (a setuid helper, or
// `sudo` spawned with no `.elevate()`) yields kill -> EPERM with elevated=false; if the dispatch
// keyed on the flag it would take the blocking-wait branch and HANG in Drop. Encoding the rule
// as a pure function makes the "any Err -> never block" invariant unit-testable without root.

#[test]
fn kill_success_reaps_with_a_blocking_wait() {
    assert_eq!(std_teardown_action(&Ok(())), StdTeardown::ReapBlocking);
}

#[test]
fn eperm_never_blocks_even_without_an_elevated_flag() {
    // The self-privileged-child case: EPERM must route to the NON-blocking reap, never a wait().
    let eperm = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert_eq!(std_teardown_action(&Err(eperm)), StdTeardown::ReapNonBlocking);
}

#[test]
fn any_other_kill_error_also_never_blocks() {
    let other = std::io::Error::from(std::io::ErrorKind::NotFound);
    assert_eq!(std_teardown_action(&Err(other)), StdTeardown::ReapNonBlocking);
}
