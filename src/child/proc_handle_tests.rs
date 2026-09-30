#[cfg(unix)]
use super::ProcHandle;
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

// The reap after a successful kill =====

/// A live blocker adopted as a `Std` handle. The child is ended by the teardown under test.
#[cfg(unix)]
fn std_handle() -> (ProcHandle, std::process::ChildStdin) {
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = crate::identity::ProcessId::of(child.id()).found().expect("identity");
    let shared = crate::child::shared::SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    (ProcHandle::Std(shared), stdin)
}

/// The levels the teardown logged for its child, with the reap after the kill failing with
/// `errno`.
#[cfg(unix)]
fn teardown_levels_when_the_reap_fails(errno: i32) -> Vec<log::Level> {
    use crate::child::shared::seams::{self, ForcedWait};
    crate::log_capture::install();
    let (handle, _stdin) = std_handle();
    let marker = format!("teardown of child {}", handle.id());
    let mark = crate::log_capture::mark();
    let forced = seams::force_unlocked_wait(ForcedWait::Errno(errno));
    handle.teardown_on_drop();
    drop(forced);
    // The forced failure left the killed child unreaped: reap it for real.
    handle.wait().expect("reap the killed child");
    crate::log_capture::records_since_on_current_thread(mark, &marker)
        .into_iter()
        .map(|(level, _)| level)
        .collect()
}

/// A reap that fails after the kill is not dropped silently.
///
/// Mutant: `_ = s.wait()`.
#[cfg(unix)]
#[test]
fn a_failed_teardown_reap_is_warned() {
    assert_eq!(teardown_levels_when_the_reap_fails(libc::EIO), [log::Level::Warn]);
}

/// `ECHILD` (someone else reaped the child) is logged, at `debug`.
///
/// Mutant: every failure at `warn`; or none logged.
#[cfg(unix)]
#[test]
fn a_teardown_reap_that_meets_echild_is_debug() {
    assert_eq!(teardown_levels_when_the_reap_fails(libc::ECHILD), [log::Level::Debug]);
}
