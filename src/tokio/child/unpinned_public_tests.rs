//! macOS: the public kill and terminate paths of the async `Child` while the root's state is
//! `Unpinned` (launchd holds its zombie) or `Unknown` (the handle cannot vouch for it). The twin of
//! the sync `Child`'s `unpinned_public_tests`, which says what each case asserts and why; the
//! states, assertions and message checks are shared with it.

use ::tokio::io::AsyncBufReadExt as _;

use crate::child::unpinned_public_tests::{
    assert_nothing_sent, assert_refused, assert_tree_refused, orphaned, sorted, warns_since, Untrusted, BOTH,
};
use crate::error::Error;
use crate::send_log::{Capture, Via};
use crate::signal::Sig;
use crate::tokio::Command;
use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peeks, forced_peeks_left};
use crate::wait::exit_only::{Foreign, Peek};
use crate::ContainMode;

pub(super) fn blocker(mode: ContainMode) -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(mode);
    (cmd.spawn().expect("spawn"), writer)
}

/// A blocker spawned with the marker's install made to fail, so the spawn degrades to the
/// mechanism the marker takes priority over.
fn degraded_blocker(mode: ContainMode) -> (crate::tokio::Child, std::io::PipeWriter) {
    use crate::containment::fdmarker::fault::{lock_for_log_assertion, set_fault, Fault};
    // A failed install logs, and a sibling test scans the shared log for its own text.
    let _serialize = lock_for_log_assertion();
    set_fault(Some(Fault::Pipe));
    let spawned = blocker(mode);
    set_fault(None);
    spawned
}

/// A tree-walk child: its root is signalled by identity. (On macOS `TreeWalk` is only the
/// mechanism when the marker cannot be installed, which is made to happen here.)
pub(super) fn walked_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
    let (child, writer) = degraded_blocker(ContainMode::TreeWalk);
    assert!(
        matches!(child.os.attached, crate::containment::Attached::TreeWalk(_)),
        "the test needs a tree walk"
    );
    (child, writer)
}

/// A session (fd-marker) child: its group is signalled with `killpg`.
pub(super) fn session_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
    let (child, writer) = blocker(ContainMode::Session);
    assert!(
        matches!(child.os.attached, crate::containment::Attached::FdMarker(_)),
        "the test needs an fd marker"
    );
    (child, writer)
}

/// A process-group child.
pub(super) fn group_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
    let (child, writer) = degraded_blocker(ContainMode::Session);
    assert!(
        matches!(child.os.attached, crate::containment::Attached::ProcessGroup(_)),
        "the test needs a process group"
    );
    (child, writer)
}

/// A session child whose root `cat` (held on its stdin, so only a signal ends it) holds one
/// descendant `sleep`, a second marker holder, and that descendant's pid, read once the root has
/// started it. Neither exits on its own, so the holders do not change under a sweep.
pub(super) async fn session_tree() -> (crate::tokio::Child, std::io::PipeWriter, u32) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "sleep 600 & echo $!; exec cat"]);
    cmd.stdin(stdin).expect("set stdin");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout");
    cmd.contain_with(ContainMode::Session);
    let mut child = cmd.spawn().expect("spawn");
    let mut line = String::new();
    ::tokio::io::BufReader::new(child.stdout().expect("piped stdout"))
        .read_line(&mut line)
        .await
        .expect("the descendant's pid");
    (child, writer, line.trim().parse().expect("a pid"))
}

// Lone kill and terminate =====

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

/// Mutant: `kill` refuses an `Unknown` root as it does an `Unpinned` one.
#[skuld::test]
async fn kill_of_an_unknown_root_is_sent_through_its_handle() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let _looks = Untrusted::Unknown.peek();

    child.kill().expect("an unknown root is killed through its handle");

    assert_peeks_exhausted();
    assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pid)]);
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

/// Mutant: `terminate` refuses an `Unknown` root as it does an `Unpinned` one.
#[skuld::test]
async fn terminate_of_an_unknown_root_is_sent_through_its_handle() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let _looks = Untrusted::Unknown.peek();

    child.terminate().expect("an unknown root is signalled");

    assert_peeks_exhausted();
    assert_eq!(sends.by_identity(), vec![(pid, libc::SIGTERM)]);
    drop(writer);
}

// kill_tree =====

/// Mutants: `kill_tree` walks without reading the root's state; it refuses only `Unpinned`.
#[skuld::test]
async fn kill_tree_of_an_untrusted_walked_root_sends_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    for state in BOTH {
        let (mut child, writer) = walked_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let walks = crate::containment::treewalk::fault::record_walks();
        let mark = crate::log_capture::mark();
        let looks = state.peek();

        let err = child
            .kill_tree()
            .expect_err("the walk names the tree by the root's number");

        assert_peeks_exhausted();
        assert_tree_refused(&err, "kill_tree", state);
        assert_nothing_sent(&sends);
        assert_eq!(walks.walked(), Vec::<u32>::new(), "{state:?}");
        assert_eq!(warns_since(mark), Vec::<String>::new(), "{state:?}");
        drop(looks);

        child.kill_tree().expect("an unreaped root is killed with its tree");
        assert!(
            sends.by_identity().contains(&(pid, libc::SIGKILL)),
            "{state:?}: {:?}",
            sends.by_identity()
        );
        drop(writer);
    }
}

/// Mutants: `kill_tree` fires `killpg` without reading the root's state; it refuses only `Unpinned`.
#[skuld::test]
async fn kill_tree_of_an_untrusted_group_root_sends_no_killpg() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_kill_group();
        let (mut child, writer) = group_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let looks = state.peek();

        let err = child.kill_tree().expect_err("the group is named by the root's number");

        assert_peeks_exhausted();
        assert_tree_refused(&err, "kill_tree", state);
        assert_nothing_sent(&sends);
        assert_eq!(groups.killed(), Vec::<i32>::new(), "{state:?}");
        assert_eq!(warns_since(mark), Vec::<String>::new(), "{state:?}");
        drop(looks);

        child.kill_tree().expect("an unreaped root is killed with its group");
        assert_eq!(
            groups.killed(),
            vec![pid as i32],
            "{state:?}: the group call was reached"
        );
        drop(writer);
    }
}

/// Mutants: the sweep is skipped; it signals the `Unpinned` root; it spares the `Unknown` root; it
/// fires `killpg` or walks from the root's pid.
#[skuld::test]
async fn kill_tree_of_an_untrusted_session_root_kills_its_holders_only() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_kill_group();
        let walks = crate::containment::treewalk::fault::record_walks();
        let holders = crate::containment::fdmarker::fault::record_holder_kills();
        let (mut child, writer, descendant) = session_tree().await;
        let pid = child.id().pid();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let _looks = state.peek();

        child
            .kill_tree()
            .expect("every holder was reached, so the tree is down");

        assert_peeks_exhausted();
        assert_eq!(groups.killed(), Vec::<i32>::new(), "{state:?}");
        assert_eq!(walks.walked(), Vec::<u32>::new(), "{state:?}");
        assert_eq!(sends.entries(), vec![], "{state:?}: nothing by pid");
        let want = match state {
            Untrusted::Unpinned => vec![descendant],
            Untrusted::Unknown => sorted(vec![pid, descendant]),
        };
        assert_eq!(sorted(holders.killed()), want, "{state:?}");
        assert_eq!(warns_since(mark), Vec::<String>::new(), "{state:?}");
        drop(writer);
    }
}

/// A real control: a trusted session root is killed for real, not through the recorder. The stdin
/// is released after the kill, so a kill that never came ends the root with status 0 instead of
/// hanging the wait.
///
/// Mutant: `kill_tree` of a trusted root signals nothing.
#[skuld::test]
async fn kill_tree_kills_a_trusted_session_root() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = session_blocker();

    child.kill_tree().expect("a trusted root is killed with its group");

    drop(writer);
    crate::test_child::assert_killed("the session root", child.wait().await.expect("wait"));
}

// terminate_tree =====

/// Mutants: `terminate_tree` walks without reading the root's state; it refuses only `Unpinned`.
#[skuld::test]
async fn terminate_tree_of_an_untrusted_walked_root_sends_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    for state in BOTH {
        let (child, writer) = walked_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let walks = crate::containment::treewalk::fault::record_walks();
        let mark = crate::log_capture::mark();
        let looks = state.peek();

        let err = child
            .terminate_tree()
            .expect_err("the walk names the tree by the root's number");

        assert_peeks_exhausted();
        assert_tree_refused(&err, "terminate_tree", state);
        assert_nothing_sent(&sends);
        assert_eq!(walks.walked(), Vec::<u32>::new(), "{state:?}");
        assert_eq!(warns_since(mark), Vec::<String>::new(), "{state:?}");
        drop(looks);

        child
            .terminate_tree()
            .expect("an unreaped root is signalled with its tree");
        assert!(
            sends.by_identity().contains(&(pid, libc::SIGTERM)),
            "{state:?}: {:?}",
            sends.by_identity()
        );
        drop(writer);
    }
}

/// Mutants: `terminate_tree` fires `killpg` without reading the root's state; it refuses only
/// `Unpinned`.
#[skuld::test]
async fn terminate_tree_of_an_untrusted_group_root_sends_no_killpg() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_term_group();
        let (child, writer) = group_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let looks = state.peek();

        let err = child
            .terminate_tree()
            .expect_err("the group is named by the root's number");

        assert_peeks_exhausted();
        assert_tree_refused(&err, "terminate_tree", state);
        assert_nothing_sent(&sends);
        assert_eq!(groups.termed(), Vec::<i32>::new(), "{state:?}");
        assert_eq!(warns_since(mark), Vec::<String>::new(), "{state:?}");
        drop(looks);

        child
            .terminate_tree()
            .expect("an unreaped root is signalled with its group");
        assert_eq!(
            groups.termed(),
            vec![pid as i32],
            "{state:?}: the group call was reached"
        );
        drop(writer);
    }
}

/// Mutants: the sweep is skipped; it signals the `Unpinned` root; it spares the `Unknown` root; it
/// fires `killpg` or walks from the root's pid.
#[skuld::test]
async fn terminate_tree_of_an_untrusted_session_root_signals_its_holders_only() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_term_group();
        let walks = crate::containment::treewalk::fault::record_walks();
        let holders = crate::containment::fdmarker::fault::record_holder_kills();
        let (child, writer, descendant) = session_tree().await;
        let pid = child.id().pid();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let _looks = state.peek();

        child
            .terminate_tree()
            .expect("every holder was reached, so the tree was asked to stop");

        assert_peeks_exhausted();
        assert_eq!(groups.termed(), Vec::<i32>::new(), "{state:?}");
        assert_eq!(walks.walked(), Vec::<u32>::new(), "{state:?}");
        assert_eq!(sends.entries(), vec![], "{state:?}: nothing by pid");
        let want = match state {
            Untrusted::Unpinned => vec![descendant],
            Untrusted::Unknown => sorted(vec![pid, descendant]),
        };
        assert_eq!(sorted(holders.killed()), want, "{state:?}");
        assert_eq!(warns_since(mark), Vec::<String>::new(), "{state:?}");
        drop(writer);
    }
}

/// A real control: a trusted session root is terminated for real, not through the recorder. The
/// stdin is released after the signal, as for `kill_tree_kills_a_trusted_session_root`.
///
/// Mutant: `terminate_tree` of a trusted root signals nothing.
#[skuld::test]
async fn terminate_tree_terminates_a_trusted_session_root() {
    use std::os::unix::process::ExitStatusExt as _;
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = session_blocker();

    child
        .terminate_tree()
        .expect("a trusted root is signalled with its group");

    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGTERM));
    drop(writer);
}

// The backstop =====

/// The tree kill reads the root's state again before its handle backstop. A root orphaned during
/// the sweep is an exited zombie launchd holds, so there is nothing for the backstop to kill: it is
/// skipped, and the sweep's answer stands.
///
/// Mutants: the backstop does not read the state again; it reads it and refuses.
#[skuld::test]
async fn kill_tree_skips_its_backstop_for_a_root_orphaned_during_the_sweep() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let mark = crate::log_capture::mark();
    let _looks = force_peeks([Ok(Peek::Running), Ok(Peek::Foreign(Foreign::Orphaned))]);

    child
        .kill_tree()
        .expect("the sweep killed the tree; the backstop has nothing to do");

    assert_peeks_exhausted();
    assert_eq!(sends.entries(), vec![], "the backstop must send nothing");
    assert!(
        sends.by_identity().contains(&(pid, libc::SIGKILL)),
        "the sweep ran first"
    );
    assert_eq!(warns_since(mark), Vec::<String>::new());
    drop(writer);
}

/// An `Unknown` root at the backstop is still our unreaped child, killed through its handle as the
/// lone `kill` does.
///
/// Mutant: the backstop is skipped for an `Unknown` root too.
#[skuld::test]
async fn kill_tree_keeps_its_backstop_for_an_unknown_root() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let _looks = force_peeks([Ok(Peek::Running), Err(std::io::Error::other("unreadable"))]);

    child.kill_tree().expect("the backstop kills through the handle");

    assert_peeks_exhausted();
    assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pid)]);
    drop(writer);
}

/// The backstop reads the root's state once: it asks, then sends through the gated send, which does
/// not ask again. A third forced read would be an `Orphaned` one that refuses it.
///
/// Mutant: the backstop's send reads the state again (it calls `kill`).
#[skuld::test]
async fn kill_tree_reads_the_root_once_for_its_backstop() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let _looks = force_peeks([
        Ok(Peek::Running),
        Ok(Peek::Running),
        Ok(Peek::Foreign(Foreign::Orphaned)),
    ]);

    child.kill_tree().expect("the backstop kills the root");

    assert_eq!(forced_peeks_left(), 1, "the backstop read the state twice");
    assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pid)]);
    drop(writer);
}

// Guard order =====

/// An uncontained child has no tree: that answer is permanent and about the mechanism, so it
/// outranks the root's state, which is not even read.
///
/// Mutant: a tree path reads the root's state before checking that the child is contained.
#[skuld::test]
async fn an_uncontained_child_hears_why_it_has_no_tree_not_why_its_root_is_unpinned() {
    crate::tokio::test_runtime::assert_current_thread();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let mut child = cmd.spawn().expect("spawn");
    let _looks = force_peeks([Ok(Peek::Foreign(Foreign::Orphaned))]);

    let results = [
        ("kill_tree", child.kill_tree()),
        ("terminate_tree", child.terminate_tree()),
        (
            "graceful_shutdown_tree",
            child.graceful_shutdown_tree(std::time::Duration::ZERO).await.map(drop),
        ),
    ];
    for (op, result) in results {
        assert!(
            matches!(result, Err(Error::Unsupported { .. })),
            "{op}: expected the containment error, got {result:?}"
        );
    }
    assert_eq!(forced_peeks_left(), 1, "the root's state was read");
    drop(writer);
}

/// A front that may not be signalled is refused whatever the root's state: the refusal is
/// permanent and says nothing of the pid, while an unpinned root is a state the caller can do
/// nothing about either way. The state is not even read.
///
/// Mutant: a path reads the root's state before the front's gate.
#[skuld::test]
async fn a_closed_front_gate_outranks_an_unpinned_root() {
    use crate::elevation::front::Front;
    crate::tokio::test_runtime::assert_current_thread();
    for op in ["kill", "terminate", "kill_tree"] {
        let (mut child, writer) = walked_blocker();
        // `sudo` relays a `SIGTERM`, so only `osascript` closes the terminate gate.
        child.set_front(Some(if op == "terminate" {
            Front::Osascript
        } else {
            Front::Sudo
        }));
        // The gate looks at the front (twice for a kill, once for a terminate), and the state, read
        // wrongly first, would take the front's `Running` and let the gate see the `Orphaned`
        // one: an exited front, which is signalled.
        let looks = if op == "terminate" {
            vec![Ok(Peek::Running), Ok(Peek::Foreign(Foreign::Orphaned))]
        } else {
            vec![
                Ok(Peek::Running),
                Ok(Peek::Running),
                Ok(Peek::Foreign(Foreign::Orphaned)),
            ]
        };
        let _looks = force_peeks(looks);

        let err = match op {
            "kill" => child.kill(),
            "terminate" => child.terminate(),
            _ => child.kill_tree(),
        }
        .expect_err("the front is not signalled");

        assert!(
            matches!(
                err,
                Error::Elevation {
                    kind: crate::error::ElevationErrorKind::Unkillable,
                    ..
                }
            ),
            "{op}: {err:?}"
        );
        assert_eq!(
            forced_peeks_left(),
            1,
            "{op}: the root's state was read before the gate, or the gate was not"
        );
        drop(writer);
    }
}
