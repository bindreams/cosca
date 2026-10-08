//! The async `Child`'s backend answers [`RootState`] from its own handle, and tells its own reap
//! from a reap by someone else.

use crate::signal::RootState;
use crate::tokio::Command;

/// Every record at `warn` or above that this thread logged since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// This handle's own reap is `Reaped`, is not a reap by someone else, and nothing around it warns.
///
/// Mutant: `reaped_elsewhere` has no `id().is_some()` guard, so it counts tokio's own reap.
#[skuld::test]
async fn state_after_own_wait_is_reaped_without_a_warn() {
    crate::log_capture::install();
    let mut child = Command::new().args(["true"]).spawn().expect("spawn");
    child.wait().await.expect("wait");

    let mark = crate::log_capture::mark();
    let state = child.proc_mut().state();
    let elsewhere = child.proc_mut().reaped_elsewhere();
    drop(child);

    assert!(matches!(state, RootState::Reaped), "{state:?}");
    assert!(!elsewhere, "this handle reaped the child itself");
    assert_eq!(warns_since(mark), Vec::<String>::new());
}

/// A `kill` after a completed `wait` is `Ok` and leaves the cached status for the next `wait`.
///
/// Mutant: `reaped_elsewhere` includes tokio's own reap, so the kill forgets tokio's `Child` and
/// the second `wait` answers `ECHILD`.
#[skuld::test]
async fn tokio_kill_after_a_completed_wait_keeps_the_cached_status() {
    crate::log_capture::install();
    let mut child = Command::new().args(["true"]).spawn().expect("spawn");
    let status = child.wait().await.expect("wait");

    let mark = crate::log_capture::mark();
    child.kill().expect("a kill after the child's own reap answers Ok");
    let again = child.wait().await.expect("the cached status survives the kill");

    assert_eq!(again, status);
    assert_eq!(warns_since(mark), Vec::<String>::new());
}
