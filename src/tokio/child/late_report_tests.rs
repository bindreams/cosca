//! The macOS async spawn of a child whose unique-id report came after the spawn returned: twin of
//! `child::spawn::late_report_tests`. The teardown is the same; what differs is tokio's `Child`, which
//! is forgotten (its drop reaps by pid), or released to tokio's orphan reaper when the kill did not
//! end the child.

use std::cell::Cell;
use std::rc::Rc;

use super::drop_fault;
use crate::child::spawn::identity_macos_tests::{has_not_exited, is_reaped, refuse_the_kill};
use crate::child::spawn::late_report_tests::{
    assert_kill_sent, assert_one_warn, SAID_KILLED, SAID_NOT_SENT, SAID_REAPED, SAID_REFUSED_RUNNING,
    SAID_STILL_RUNNING, ZOMBIE,
};
use crate::child::spawn::unique_report;
use crate::error::ChildFate;
use crate::identity::{uniq_fault, ReadPurpose, UniqRead};
use crate::wait::exit_only::seams::force_peek_once;

const LEAKS: &str = "forgetting tokio's handle for it leaks";
const ORPHAN_REAPER: &str = "handed to tokio's orphan reaper";

fn tokio_blocker() -> (crate::tokio::Command, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    (cmd, writer)
}

/// What a late spawn of a live blocker answered, and what it left in the log.
struct Late {
    fate: ChildFate,
    pid: u32,
    id: crate::identity::ProcessId,
    mark: usize,
    forgets: u32,
}

/// Spawns a live blocker whose first report read finds nothing, with `arm` run just before, and
/// answers what the spawn did. `writer` is held until `release` runs, so only the teardown ends the
/// child.
fn late_spawn(arm: impl FnOnce() -> Vec<Box<dyn std::any::Any>>) -> (Late, std::io::PipeWriter) {
    crate::log_capture::install();
    let (mut cmd, writer) = tokio_blocker();
    let forgets = drop_fault::record();
    let mark = crate::log_capture::mark();
    let err = {
        let _armed = arm();
        let _late = unique_report::seams::find_the_report_unwritten();
        cmd.spawn().expect_err("a late child is not adopted")
    };
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    let late = Late {
        fate,
        pid: id.pid(),
        id,
        mark,
        forgets: forgets.forgets(),
    };
    (late, writer)
}

/// A late child is torn down through its unique id: killed, reaped, `Reaped`, one `warn`, and tokio's
/// `Child` forgotten once, which the warn says leaks. The child is live, so only the kill ends it; the
/// hook between the kill and the wait releases it when no kill was sent, so a missing kill fails by
/// assertion, not by hang.
///
/// Mutants: the spawn does not wait for the report; the kill is not sent; the child is left running;
/// the forget is dropped or doubled; the warn is missing, doubled, or lacks the leak.
#[skuld::test]
async fn macos_tokio_spawn_of_a_late_reporting_child_kills_and_reaps_it_through_its_id() {
    let sent = Rc::new(crate::send_log::Capture::start());
    let kill_missing = Rc::new(Cell::new(false));
    let (late, writer) = {
        // The hook releases the writer, so this spawn is not `late_spawn`.
        crate::log_capture::install();
        let (mut cmd, writer) = tokio_blocker();
        let release = Rc::new(Cell::new(Some(writer)));
        let _hook = crate::child::spawn::fault::set_between_kill_and_wait({
            let (sent, missing, release) = (Rc::clone(&sent), Rc::clone(&kill_missing), Rc::clone(&release));
            move || {
                missing.set(
                    sent.entries()
                        .iter()
                        .all(|(_, sig, _)| *sig != crate::signal::Sig::Kill),
                );
                drop(release.take());
            }
        });
        let forgets = drop_fault::record();
        let mark = crate::log_capture::mark();
        let err = {
            let _late = unique_report::seams::find_the_report_unwritten();
            cmd.spawn().expect_err("a late child is not adopted")
        };
        assert!(!kill_missing.get(), "the kill must be sent before the wait");
        let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
        let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
            panic!("the spawn captured the child");
        };
        (
            Late {
                fate,
                pid: id.pid(),
                id,
                mark,
                forgets: forgets.forgets(),
            },
            release,
        )
    };
    drop(writer);
    assert_eq!(late.fate, ChildFate::Reaped);
    assert_kill_sent(late.pid, &sent.entries());
    assert!(is_reaped(late.pid), "nothing is left to wait for");
    assert_eq!(late.forgets, 1, "tokio's `Child` is forgotten, once");
    assert_one_warn(
        late.pid,
        late.mark,
        &[SAID_REAPED, LEAKS],
        &[SAID_REFUSED_RUNNING, SAID_NOT_SENT, ORPHAN_REAPER],
    );
}

/// A refused kill leaves the child running: tokio's `Child` is released to its orphan reaper, not
/// forgotten (which would leave a zombie nothing collects), and the one warn says so. The test then
/// kills the child and turns the runtime, whose every turn reaps tokio's exited orphans, until the
/// zombie is gone: no interval, no bound.
///
/// Mutants: the child is forgotten; the warn says the child was killed; the hand-off is not said.
#[skuld::test]
async fn macos_tokio_spawn_of_a_late_child_whose_kill_is_refused_hands_it_to_the_orphan_reaper() {
    let (late, writer) = late_spawn(|| vec![Box::new(refuse_the_kill())]);
    assert_eq!(late.fate, ChildFate::Running { id: None });
    assert_eq!(late.forgets, 0, "a running child is released, not forgotten");
    assert!(has_not_exited(late.pid), "nothing ended the child");
    assert_one_warn(
        late.pid,
        late.mark,
        &[SAID_REFUSED_RUNNING, SAID_STILL_RUNNING, ORPHAN_REAPER],
        &["was sent SIGKILL", "did not end it", LEAKS, ZOMBIE],
    );
    // SAFETY: `pid` is this test's own child; the orphan reaper collects it.
    assert_eq!(unsafe { libc::kill(late.pid as libc::pid_t, libc::SIGKILL) }, 0);
    while late.id.exists() == crate::identity::Existence::Present {
        ::tokio::task::yield_now().await;
    }
    assert_eq!(
        late.id.exists(),
        crate::identity::Existence::Gone,
        "tokio's orphan reaper collects the zombie"
    );
    drop(writer);
}

/// A late child whose pid the id check shows is gone is sent nothing: `Gone`, forgotten once.
///
/// Mutant: the no-send is worded as a sent kill, or the child is released.
#[skuld::test]
async fn macos_tokio_spawn_of_a_late_child_whose_pid_is_gone_sends_nothing_and_is_gone() {
    let sent = crate::send_log::Capture::start();
    let (late, writer) = late_spawn(|| {
        vec![Box::new(uniq_fault::force_uniq_read_once(
            ReadPurpose::Kill,
            UniqRead::Gone,
        ))]
    });
    assert_eq!(late.fate, ChildFate::Gone);
    assert_eq!(sent.entries(), [], "nothing is sent to a pid that is gone");
    assert_eq!(late.forgets, 1);
    assert_one_warn(
        late.pid,
        late.mark,
        &[SAID_NOT_SENT, "it is gone", LEAKS],
        &["was sent SIGKILL", "signalled"],
    );
    // Nothing was sent: the test ends and reaps the child; the backend was forgotten.
    crate::child::spawn::identity_macos_tests::end_unsignalled_and_reap(late.pid);
    drop(writer);
}

/// A late child whose kill and id read are both refused: nothing shows what became of it, `Unknown`;
/// forgotten once.
///
/// Mutant: the arm answers `Running` (and is released) or `Reaped`.
#[skuld::test]
async fn macos_tokio_spawn_of_a_late_child_with_a_refused_kill_and_read_is_unknown() {
    let (late, writer) = late_spawn(|| {
        vec![
            Box::new(refuse_the_kill()),
            Box::new(uniq_fault::force_uniq_read_once(
                ReadPurpose::Running,
                UniqRead::Refused(libc::EPERM),
            )),
        ]
    });
    assert_eq!(late.fate, ChildFate::Unknown);
    assert_eq!(late.forgets, 1);
    assert_one_warn(
        late.pid,
        late.mark,
        &[SAID_REFUSED_RUNNING, "what became of it is unknown", LEAKS],
        &[ORPHAN_REAPER],
    );
    crate::child::spawn::identity_macos_tests::end_unsignalled_and_reap(late.pid);
    drop(writer);
}

/// A delivered kill and a failed wait: `Killed`, forgotten once.
///
/// Mutant: the arm answers `Reaped`.
#[skuld::test]
async fn macos_tokio_spawn_of_a_late_child_whose_wait_fails_is_killed() {
    let (late, writer) = late_spawn(|| {
        vec![Box::new(force_peek_once(Err(std::io::Error::other(
            "forced wait failure",
        ))))]
    });
    assert_eq!(late.fate, ChildFate::Killed);
    assert_eq!(late.forgets, 1);
    assert_one_warn(
        late.pid,
        late.mark,
        &[SAID_KILLED, "forced wait failure", LEAKS],
        &[SAID_REAPED],
    );
    crate::child::spawn::identity_macos_tests::reap_by_pid(late.pid);
    drop(writer);
}

/// An elevation front whose report came late is sent nothing, forgotten, and left unreaped; the one
/// `warn` says so, and nothing of a kill.
///
/// Mutants: the front is killed; the front's note is dropped; the warn is the torn-down sentence.
#[skuld::test]
async fn macos_tokio_spawn_of_a_late_front_leaves_it_running_and_says_so() {
    use crate::elevation::{front::front, ElevatedVia};
    crate::log_capture::install();
    let front = front(Some(&ElevatedVia::MacosOsascript));
    let (mut cmd, writer) = tokio_blocker();
    cmd.set_elevation_front(front);
    let sent = crate::send_log::Capture::start();
    let forgets = drop_fault::record();
    let mark = crate::log_capture::mark();
    let err = {
        let _late = unique_report::seams::find_the_report_unwritten();
        cmd.spawn().expect_err("a late front is not adopted")
    };
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    assert_eq!(fate, ChildFate::Running { id: None });
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    let pid = id.pid();
    assert_eq!(sent.entries(), [], "a front is sent nothing");
    assert_eq!(forgets.forgets(), 1);
    assert!(has_not_exited(pid), "the front is left running");
    assert_one_warn(
        pid,
        mark,
        &["elevation front", "left unreaped", ZOMBIE, LEAKS],
        &["was sent SIGKILL", SAID_REFUSED_RUNNING, SAID_NOT_SENT],
    );
    assert!(err.to_string().contains("it is left unreaped"), "{err}");
    crate::child::spawn::identity_macos_tests::end_unsignalled_and_reap(pid);
    drop(writer);
}

/// A contained child whose report came late is torn down with its tree, as the sync spawn does: the
/// grandchild it forked is killed too. The hook before the teardown waits until the grandchild runs;
/// the grandchild is released afterwards and writes if it is still alive, so a survivor fails by
/// assertion, not by hang.
///
/// Mutant: the late teardown kills the root alone.
#[skuld::test]
async fn macos_tokio_spawn_of_a_late_contained_child_kills_its_tree() {
    use crate::child::spawn::late_report_tests::{tree_pipes, TREE_ARGV};
    crate::log_capture::install();
    let (tree, ends) = tree_pipes();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(TREE_ARGV).contain();
    for (fd, end) in ends {
        cmd.fd(fd, end).expect("set the fd");
    }
    let tree = Rc::new(std::cell::RefCell::new(Some(tree)));
    let _hook = crate::child::spawn::fault::set_at(crate::child::spawn::fault::SpawnPoint::BeforeLateTeardown, {
        let tree = Rc::clone(&tree);
        move || tree.borrow_mut().as_mut().expect("the tree").await_grandchild()
    });
    let mark = crate::log_capture::mark();
    let err = {
        let _late = unique_report::seams::find_the_report_unwritten();
        cmd.spawn().expect_err("a late child is not adopted")
    };
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    let tree = tree.borrow_mut().take().expect("the tree");
    assert!(
        !tree.grandchild_survived(),
        "the late child's grandchild must be killed"
    );
    assert_eq!(fate, ChildFate::Reaped, "the root is killed and reaped");
    assert_one_warn(id.pid(), mark, &[SAID_REAPED, LEAKS], &["tree was not", "fully killed"]);
}
