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

/// A tokio drop whose root stays `Unknown` through every look warns once: the read, the skip, the
/// second look and the forget are one event.
///
/// Mutants: the skip warns; the second look warns; the forget warns.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_tokio_drop_with_an_unknown_root_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let _failed = force_peeks((0..8).map(|_| Err(std::io::Error::other("forced peek failure"))));

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "one warn for the event: {warns:?}");
    assert!(
        warns[0].contains("RootState::Unknown") && warns[0].contains(&format!("pgid {pid}")),
        "{warns:?}"
    );
}
