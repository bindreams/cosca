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

/// A Session blocker, tokio.
#[cfg(target_os = "linux")]
fn session_blocker(kill_on_drop: bool) -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    cmd.kill_on_drop(kill_on_drop);
    (cmd.spawn().expect("spawn"), writer)
}

#[cfg(target_os = "linux")]
fn failed_peek(what: &str) -> std::io::Result<crate::wait::exit_only::Peek> {
    Err(std::io::Error::other(what.to_owned()))
}

/// A tokio drop whose root stays `Unknown` through both looks warns once, and the warn carries
/// what forgetting tokio's `Child` leaks. The drop makes exactly two looks (the read and the
/// second look), so exactly two peeks are forced.
///
/// Mutants: the skip warns; the second look warns; the forget warns; the warn omits the leak.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_tokio_drop_with_an_unknown_root_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([failed_peek("forced"), failed_peek("forced")]);

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "one warn for the event: {warns:?}");
    assert!(
        warns[0].contains("RootState::Unknown")
            && warns[0].contains(&format!("pgid {pid}"))
            && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// A refused root kill with an unknown root forgets tokio's `Child` once, under the same one warn.
///
/// Mutant: the failed-kill path forgets with its own warn, besides the drop's.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_tokio_drop_whose_kill_fails_on_an_unknown_root_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([failed_peek("forced"), failed_peek("forced")]);
    let _kill = crate::tokio::child::fault::force_kill_failure();

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("RootState::Unknown") && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// An `Unknown` seen only on the second look is logged with its error.
///
/// Mutant: the second look is quiet.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn an_unknown_seen_only_on_the_second_look_names_its_error() {
    use crate::wait::exit_only::seams::force_peeks;
    use crate::wait::exit_only::Peek;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([Ok(Peek::Running), failed_peek("second look failure 91")]);

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("second look failure 91"), "{warns:?}");
}

/// A disarmed drop kills nothing, so its warn does not speak of a skipped kill.
///
/// Mutant: the warn always says "so it does not".
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_disarmed_drop_with_an_unknown_root_does_not_claim_a_skipped_kill() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(false);
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([failed_peek("forced"), failed_peek("forced")]);

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(!warns[0].contains("does not"), "{warns:?}");
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use crate::send_log::{Capture, Via};
    use crate::signal::Sig;
    use crate::wait::exit_only::seams::force_peeks;
    use crate::wait::exit_only::{Foreign, Peek};

    fn walked_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(crate::ContainMode::TreeWalk);
        (cmd.spawn().expect("spawn"), writer)
    }

    /// A root launchd holds is not pinned by this process: nothing is sent to it, tokio's `Child`
    /// is forgotten, and the one warn names the leak.
    ///
    /// Mutant: `Unpinned` is `Unknown` (the drop kills by pid).
    #[skuld::test]
    async fn an_orphaned_root_is_not_signalled_and_warns_once() {
        crate::log_capture::install();
        let (child, _writer) = walked_blocker();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let orphaned = || Ok(Peek::Foreign(Foreign::Orphaned));
        let _orphaned = force_peeks([orphaned(), orphaned()]);

        drop(child);

        assert_eq!(sends.entries(), vec![], "nothing may be sent to a root we do not pin");
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("launchd") && warns[0].contains("leaks"), "{warns:?}");
    }

    /// Any other root we cannot get an answer for is still our unreaped child: still killed through
    /// its handle.
    ///
    /// Mutant: every `Unknown` leaves the root alone.
    #[skuld::test]
    async fn an_unknown_root_we_pin_is_still_killed_through_its_handle() {
        crate::log_capture::install();
        let (child, _writer) = walked_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let _failed = force_peeks([Err(std::io::Error::other("forced peek failure"))]);

        drop(child);

        assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pid)]);
    }
}
