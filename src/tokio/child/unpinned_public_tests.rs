//! macOS: the public kill and terminate paths of the async `Child` leave a root launchd holds
//! alone. Each case forces an `Orphaned` peek, so the root reads as `Unpinned`, and asserts that
//! nothing was sent by pid, by identity or to the group, that the answer is `Unassessable` naming
//! launchd, and that nothing warned. The same call then runs again on the real, unreaped root and
//! must send, so a refusal that never lets go fails too.

use std::time::Duration;

use crate::error::Error;
use crate::send_log::{Capture, Via};
use crate::signal::Sig;
use crate::tokio::Command;
use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once, Forced};
use crate::wait::exit_only::{Foreign, Peek};
use crate::ContainMode;

/// Every record at `warn` or above that this thread logged since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

fn blocker(mode: ContainMode) -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(mode);
    (cmd.spawn().expect("spawn"), writer)
}

/// A tree-walk child: its root is signalled by identity.
fn walked_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
    blocker(ContainMode::TreeWalk)
}

/// A session (fd-marker) child: its group is signalled with `killpg`.
fn session_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
    let (child, writer) = blocker(ContainMode::Session);
    assert!(
        matches!(child.os.attached, crate::containment::Attached::FdMarker(_)),
        "the test needs an fd marker"
    );
    (child, writer)
}

fn orphaned() -> Forced {
    force_peek_once(Ok(Peek::Foreign(Foreign::Orphaned)))
}

/// The refusal: `Unassessable`, no source, naming launchd and the call that sent nothing.
#[track_caller]
fn assert_refused(err: &Error, op: &str) {
    match err {
        Error::Unassessable { detail, source: None } => assert!(
            detail.contains("launchd") && detail.contains(&format!("{op} sent nothing")),
            "{detail}"
        ),
        other => panic!("expected Unassessable without a source, got {other:?}"),
    }
}

/// Nothing was sent to the root by pid or by identity.
#[track_caller]
fn assert_nothing_sent(sends: &Capture) {
    assert_eq!(sends.entries(), vec![], "nothing may be sent to a root we do not pin");
    assert_eq!(sends.by_identity(), vec![], "nothing may be sent by identity either");
}

/// Mutant: `kill` sends without reading the root's state.
#[skuld::test]
async fn kill_of_an_orphaned_root_sends_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    let err = child
        .kill()
        .expect_err("a root this process does not pin is not killed");

    assert_peeks_exhausted();
    assert_refused(&err, "kill");
    assert_nothing_sent(&sends);
    assert_eq!(warns_since(mark), Vec::<String>::new());

    child.kill().expect("an unreaped root is killed");
    assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pid)]);
    drop(writer);
}

/// Mutant: `kill_tree` signals the tree without reading the root's state.
#[skuld::test]
async fn kill_tree_of_an_orphaned_root_walks_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    let err = child
        .kill_tree()
        .expect_err("a root this process does not pin is not killed");

    assert_peeks_exhausted();
    assert_refused(&err, "kill_tree");
    assert_nothing_sent(&sends);
    assert_eq!(warns_since(mark), Vec::<String>::new());

    child.kill_tree().expect("an unreaped root is killed with its tree");
    assert!(
        sends.by_identity().contains(&(pid, libc::SIGKILL)),
        "{:?}",
        sends.by_identity()
    );
    drop(writer);
}

/// Mutant: `kill_tree` fires `killpg` at the group without reading the root's state.
#[skuld::test]
async fn kill_tree_of_an_orphaned_root_sends_nothing_to_its_group() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let groups = crate::containment::unix::fault::record_kill_group();
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let (mut child, writer) = session_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    let err = child
        .kill_tree()
        .expect_err("a root this process does not pin is not killed");

    assert_peeks_exhausted();
    assert_refused(&err, "kill_tree");
    assert_nothing_sent(&sends);
    assert_eq!(groups.killed(), Vec::<i32>::new());
    assert_eq!(holders.killed(), Vec::<u32>::new());
    assert_eq!(warns_since(mark), Vec::<String>::new());

    child.kill_tree().expect("an unreaped root is killed with its group");
    groups.assert_killed_only(pid as i32);
    drop(writer);
}

/// Mutant: `terminate_tree` signals the tree without reading the root's state.
#[skuld::test]
async fn terminate_tree_of_an_orphaned_root_walks_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    let err = child
        .terminate_tree()
        .expect_err("a root this process does not pin is not signalled");

    assert_peeks_exhausted();
    assert_refused(&err, "terminate_tree");
    assert_nothing_sent(&sends);
    assert_eq!(warns_since(mark), Vec::<String>::new());

    child
        .terminate_tree()
        .expect("an unreaped root is signalled with its tree");
    assert!(
        sends.by_identity().contains(&(pid, libc::SIGTERM)),
        "{:?}",
        sends.by_identity()
    );
    drop(writer);
}

/// Mutant: `terminate_tree` fires `killpg` at the group without reading the root's state.
#[skuld::test]
async fn terminate_tree_of_an_orphaned_root_sends_nothing_to_its_group() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let groups = crate::containment::unix::fault::record_term_group();
    let (child, writer) = session_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    let err = child
        .terminate_tree()
        .expect_err("a root this process does not pin is not signalled");

    assert_peeks_exhausted();
    assert_refused(&err, "terminate_tree");
    assert_nothing_sent(&sends);
    assert_eq!(groups.termed(), Vec::<i32>::new());
    assert_eq!(warns_since(mark), Vec::<String>::new());

    child
        .terminate_tree()
        .expect("an unreaped root is signalled with its group");
    assert_eq!(groups.termed(), vec![pid as i32]);
    drop(writer);
}

/// Mutant: `terminate` signals the root without reading its state.
#[skuld::test]
async fn terminate_of_an_orphaned_root_sends_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    let err = child
        .terminate()
        .expect_err("a root this process does not pin is not signalled");

    assert_peeks_exhausted();
    assert_refused(&err, "terminate");
    assert_nothing_sent(&sends);
    assert_eq!(warns_since(mark), Vec::<String>::new());

    child.terminate().expect("an unreaped root is signalled");
    assert_eq!(sends.by_identity(), vec![(pid, libc::SIGTERM)]);
    drop(writer);
}

/// A root that is orphaned when the shutdown begins is refused by its `terminate`, with no grace
/// and no kill.
///
/// Mutant: `terminate` sends without reading the root's state, so the shutdown goes on.
#[skuld::test]
async fn graceful_shutdown_of_an_orphaned_root_sends_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("a root this process does not pin is not shut down");

    assert_peeks_exhausted();
    assert_refused(&err, "terminate");
    assert_nothing_sent(&sends);
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(writer);
}

/// A root that goes orphaned during the grace is not killed by the escalation. The child ignores
/// `SIGTERM`, so the escalation is reached; the hook makes the next peek `Orphaned`.
///
/// Mutant: the escalation kills through the handle without reading the root's state.
#[skuld::test]
async fn graceful_shutdown_does_not_escalate_to_a_root_orphaned_during_the_grace() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = crate::test_child::term_ignoring_blocker_async().await;
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let forced: std::sync::Arc<std::sync::Mutex<Option<Forced>>> = std::sync::Arc::default();
    let _hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::BeforeEscalation, {
        let forced = std::sync::Arc::clone(&forced);
        move || *forced.lock().expect("the hook's slot") = Some(orphaned())
    });

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("a root this process does not pin is not killed");

    assert_peeks_exhausted();
    assert_refused(&err, "kill");
    assert_eq!(
        sends.entries(),
        vec![],
        "the escalation must send nothing to a root we do not pin"
    );
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(writer);
}

/// Mutant: `graceful_shutdown_tree` goes on to wait out the grace and sweep an orphaned root.
#[skuld::test]
async fn graceful_shutdown_tree_of_an_orphaned_root_sends_nothing_and_waits_for_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let groups = crate::containment::unix::fault::record_term_group();
    let (mut child, writer) = session_blocker();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = orphaned();

    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("a root this process does not pin is not shut down");

    assert_peeks_exhausted();
    assert_refused(&err, "graceful_shutdown_tree");
    assert_nothing_sent(&sends);
    assert_eq!(groups.termed(), Vec::<i32>::new());
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(writer);
}
