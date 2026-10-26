//! macOS: the sync `Child`'s public kill and terminate paths while the root's state is `Unpinned`
//! (launchd holds its zombie) or `Unknown` (the handle cannot vouch for it).
//!
//! The lone `kill` and `terminate` refuse an `Unpinned` root and send to an `Unknown` one through
//! its handle. The tree paths send by identity alone, as the drop does: nothing named by the root's
//! number (`killpg`, the walk from its pid, its kill by pid) runs; an fd marker still signals its
//! holders. Each case forces the state with a peek, and a positive control then signals the same
//! child once its state reads true, so a refusal that never lets go fails too.

use std::io::{BufRead as _, BufReader};
use std::time::Duration;

use crate::error::Error;
use crate::send_log::{Capture, Via};
use crate::signal::Sig;
use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once, force_peeks, forced_peeks_left, Forced};
use crate::wait::exit_only::{Foreign, Peek};
use crate::{Command, ContainMode};

/// Every record at `warn` or above that this thread logged since `mark`.
pub(crate) fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

fn blocker(mode: ContainMode) -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(mode);
    (cmd.spawn().expect("spawn"), writer)
}

/// A blocker spawned with the marker's install made to fail, so the spawn degrades to the
/// mechanism the marker takes priority over.
fn degraded_blocker(mode: ContainMode) -> (crate::Child, std::io::PipeWriter) {
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
pub(crate) fn walked_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (child, writer) = degraded_blocker(ContainMode::TreeWalk);
    assert!(
        matches!(child.attached, crate::containment::Attached::TreeWalk(_)),
        "the test needs a tree walk"
    );
    (child, writer)
}

/// A session (fd-marker) child: its group is signalled with `killpg`.
pub(crate) fn session_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (child, writer) = blocker(ContainMode::Session);
    assert!(
        matches!(child.attached, crate::containment::Attached::FdMarker(_)),
        "the test needs an fd marker"
    );
    (child, writer)
}

/// A process-group child.
pub(crate) fn group_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (child, writer) = degraded_blocker(ContainMode::Session);
    assert!(
        matches!(child.attached, crate::containment::Attached::ProcessGroup(_)),
        "the test needs a process group"
    );
    (child, writer)
}

/// A session child whose root `cat` (held on its stdin, so only a signal ends it) holds one
/// descendant `sleep`, a second marker holder, and that descendant's pid, read once the root has
/// started it. Neither exits on its own, so the holders do not change under a sweep.
pub(crate) fn session_tree() -> (crate::Child, std::io::PipeWriter, u32) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "sleep 600 & echo $!; exec cat"]);
    cmd.stdin(stdin).expect("set stdin");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout");
    cmd.contain_with(ContainMode::Session);
    let mut child = cmd.spawn().expect("spawn");
    let mut line = String::new();
    BufReader::new(child.stdout().expect("piped stdout"))
        .read_line(&mut line)
        .expect("the descendant's pid");
    (child, writer, line.trim().parse().expect("a pid"))
}

/// The two states the tree paths cannot send by number for.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Untrusted {
    /// launchd holds the root's zombie.
    Unpinned,
    /// The handle could not say.
    Unknown,
}

pub(crate) const BOTH: [Untrusted; 2] = [Untrusted::Unpinned, Untrusted::Unknown];

impl Untrusted {
    /// The next peek reads as this state.
    pub(crate) fn peek(self) -> Forced {
        force_peek_once(self.result())
    }

    pub(crate) fn result(self) -> std::io::Result<Peek> {
        match self {
            Untrusted::Unpinned => Ok(Peek::Foreign(Foreign::Orphaned)),
            Untrusted::Unknown => Err(std::io::Error::other("unreadable")),
        }
    }

    /// What a message about this state names.
    pub(crate) fn why(self) -> &'static str {
        match self {
            Untrusted::Unpinned => "launchd holds its zombie",
            Untrusted::Unknown => "RootState::Unknown",
        }
    }
}

pub(crate) fn orphaned() -> Forced {
    Untrusted::Unpinned.peek()
}

/// The lone refusal: `Unassessable`, no source, naming launchd and the call that sent nothing.
#[track_caller]
pub(crate) fn assert_refused(err: &Error, op: &str) {
    match err {
        Error::Unassessable { detail, source: None } => assert!(
            detail.contains("launchd")
                && detail.contains(&format!("{op} sent nothing"))
                && !detail.contains("(launchd"),
            "{detail}"
        ),
        other => panic!("expected Unassessable without a source, got {other:?}"),
    }
}

/// The tree refusal: `Unassessable`, no source, naming the state, the call that sent nothing and
/// that its signals are named by the root's number.
#[track_caller]
pub(crate) fn assert_tree_refused(err: &Error, op: &str, state: Untrusted) {
    match err {
        Error::Unassessable { detail, source: None } => assert!(
            detail.contains(state.why())
                && detail.contains(&format!("{op} sent nothing"))
                && detail.contains("named by the root's number"),
            "{state:?}: {detail}"
        ),
        other => panic!("{state:?}: expected Unassessable without a source, got {other:?}"),
    }
}

/// Nothing was sent to the root by pid or by identity.
#[track_caller]
pub(crate) fn assert_nothing_sent(sends: &Capture) {
    assert_eq!(sends.entries(), vec![], "nothing may be sent to a root we do not pin");
    assert_eq!(sends.by_identity(), vec![], "nothing may be sent by identity either");
}

/// The holders a sweep signalled, sorted.
#[track_caller]
pub(crate) fn sorted(mut pids: Vec<u32>) -> Vec<u32> {
    pids.sort_unstable();
    pids.dedup();
    pids
}

// Lone kill and terminate =====

/// Mutant: `kill` sends without reading the root's state.
#[skuld::test]
fn kill_of_an_orphaned_root_sends_nothing() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
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

/// The handle pins an `Unknown` root: our own unreaped child, killed by its pid only while the
/// pid's unique id is still the child's.
///
/// Mutant: `kill` refuses an `Unknown` root as it does an `Unpinned` one.
#[skuld::test]
fn kill_of_an_unknown_root_is_sent_through_its_handle() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
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
fn terminate_of_an_orphaned_root_sends_nothing() {
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
fn terminate_of_an_unknown_root_is_sent_through_its_handle() {
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

/// A tree-walk root is named by its number alone: nothing is sent, the answer says what was skipped.
///
/// Mutants: `kill_tree` walks without reading the root's state; it refuses only `Unpinned`.
#[skuld::test]
fn kill_tree_of_an_untrusted_walked_root_sends_nothing() {
    crate::log_capture::install();
    for state in BOTH {
        let (child, writer) = walked_blocker();
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

/// A process group is named by the root's number: no `killpg`.
///
/// Mutants: `kill_tree` fires `killpg` without reading the root's state; it refuses only `Unpinned`.
#[skuld::test]
fn kill_tree_of_an_untrusted_group_root_sends_no_killpg() {
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_kill_group();
        let (child, writer) = group_blocker();
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

/// An fd marker names its holders by identity, so the sweep still runs on them: the descendant is
/// killed, the root only while it may be (`Unknown`, not `Unpinned`), and the answer is `Ok`. No
/// `killpg`, no walk from the root's pid.
///
/// Mutants: the sweep is skipped; it signals the `Unpinned` root; it spares the `Unknown` root; it
/// fires `killpg` or walks from the root's pid.
#[skuld::test]
fn kill_tree_of_an_untrusted_session_root_kills_its_holders_only() {
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_kill_group();
        let walks = crate::containment::treewalk::fault::record_walks();
        let holders = crate::containment::fdmarker::fault::record_holder_kills();
        let (child, writer, descendant) = session_tree();
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
fn kill_tree_kills_a_trusted_session_root() {
    let (child, writer) = session_blocker();

    child.kill_tree().expect("a trusted root is killed with its group");

    drop(writer);
    crate::test_child::assert_killed("the session root", child.wait().expect("wait"));
}

// terminate_tree =====

/// Mutants: `terminate_tree` walks without reading the root's state; it refuses only `Unpinned`.
#[skuld::test]
fn terminate_tree_of_an_untrusted_walked_root_sends_nothing() {
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
fn terminate_tree_of_an_untrusted_group_root_sends_no_killpg() {
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
fn terminate_tree_of_an_untrusted_session_root_signals_its_holders_only() {
    crate::log_capture::install();
    for state in BOTH {
        let groups = crate::containment::unix::fault::record_term_group();
        let walks = crate::containment::treewalk::fault::record_walks();
        let holders = crate::containment::fdmarker::fault::record_holder_kills();
        let (child, writer, descendant) = session_tree();
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
/// stdin is released after the signal, so a signal that never came ends the root with status 0
/// instead of hanging the wait.
///
/// Mutant: `terminate_tree` signals nothing for a trusted session root.
#[skuld::test]
fn terminate_tree_terminates_a_trusted_session_root() {
    use std::os::unix::process::ExitStatusExt as _;
    let (child, writer) = session_blocker();

    child
        .terminate_tree()
        .expect("a trusted root is signalled with its group");

    drop(writer);
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGTERM));
}

// One look per decision =====

/// `terminate_tree` decides on one look at the root's state. That look reads `Running`, so the group
/// is signalled; the root's orphaning after it is not looked at again, by a check that would let it
/// through.
///
/// Mutant: the untrusted-root check and the reaped-root check each look, and the second look's
/// `Unpinned` is let through to the group signal.
#[skuld::test]
fn terminate_tree_decides_on_one_look_at_the_root() {
    let groups = crate::containment::unix::fault::record_term_group();
    let (child, writer) = group_blocker();
    let pid = child.id().pid();
    let _looks = force_peeks([Ok(Peek::Running), Ok(Peek::Foreign(Foreign::Orphaned))]);

    child.terminate_tree().expect("a running root's group is signalled");

    assert_eq!(forced_peeks_left(), 1, "the decision looked at the root twice");
    assert_eq!(groups.termed(), vec![pid as i32]);
    drop(writer);
}

/// `kill_tree`'s twin of [`terminate_tree_decides_on_one_look_at_the_root`]: one look decides the
/// sweep, and the backstop's own look takes the second.
///
/// Mutant: as there.
#[skuld::test]
fn kill_tree_decides_on_one_look_at_the_root() {
    let groups = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = group_blocker();
    let pid = child.id().pid();
    let _looks = force_peeks([
        Ok(Peek::Running),
        Ok(Peek::Foreign(Foreign::Orphaned)),
        Ok(Peek::Foreign(Foreign::Orphaned)),
    ]);

    child.kill_tree().expect("a running root's group is killed");

    assert_eq!(forced_peeks_left(), 1, "the decision looked at the root twice");
    assert_eq!(groups.killed(), vec![pid as i32]);
    drop(writer);
}

// The backstop =====

/// The tree kill reads the root's state again before its handle backstop. A root orphaned during
/// the sweep is an exited zombie launchd holds, so there is nothing for the backstop to kill: it is
/// skipped, and the sweep's answer stands.
///
/// Mutants: the backstop does not read the state again; it reads it and refuses.
#[skuld::test]
fn kill_tree_skips_its_backstop_for_a_root_orphaned_during_the_sweep() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
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
fn kill_tree_keeps_its_backstop_for_an_unknown_root() {
    crate::log_capture::install();
    let (child, writer) = walked_blocker();
    let pid = child.id().pid();
    let sends = Capture::start();
    let _looks = force_peeks([Ok(Peek::Running), Err(std::io::Error::other("unreadable"))]);

    child.kill_tree().expect("the backstop kills through the handle");

    assert_peeks_exhausted();
    assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pid)]);
    drop(writer);
}

// Guard order =====

/// An uncontained child has no tree: that answer is permanent and about the mechanism, so it
/// outranks the root's state, which is not even read.
///
/// Mutant: a tree path reads the root's state before checking that the child is contained.
#[skuld::test]
fn an_uncontained_child_hears_why_it_has_no_tree_not_why_its_root_is_unpinned() {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let child = cmd.spawn().expect("spawn");
    let _looks = force_peeks([Ok(Peek::Foreign(Foreign::Orphaned))]);

    for (op, result) in [
        ("kill_tree", child.kill_tree()),
        ("terminate_tree", child.terminate_tree()),
        (
            "graceful_shutdown_tree",
            child.graceful_shutdown_tree(Duration::ZERO).map(drop),
        ),
    ] {
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
fn a_closed_front_gate_outranks_an_unpinned_root() {
    use crate::elevation::front::Front;
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
