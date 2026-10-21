//! The macOS sync spawn of a child whose unique-id report came after the spawn returned.
//!
//! The report hook is registered first, so the child writes its report or dies without one, and the
//! spawn waits on the pipe for whichever comes (see `unique_report::Channel::run`). A report that
//! came late means std's own spawn is not trusted, so the child is torn down through its unique id.

use std::cell::Cell;
use std::rc::Rc;

use super::identity_macos_tests::{
    end_unsignalled_and_reap, has_not_exited, is_reaped, other_unique_id, reap_by_pid, refuse_the_kill,
    std_blocker_with_unique, sync_blocker,
};
use super::unique_report;
use crate::error::ChildFate;
use crate::identity::{uniq_fault, ReadPurpose, UniqRead};
use crate::wait::exit_only::seams::{force_peek_once, force_peeks};
use crate::wait::exit_only::Peek;

// What the one warn says =====

/// The sentence for a kill that was sent, and a child that was reaped.
pub(crate) const SAID_REAPED: &str = "was sent SIGKILL; it was reaped";
/// ... for a kill that was sent, and a status that was not collected.
pub(crate) const SAID_KILLED: &str = "was sent SIGKILL; its status was not collected";
/// ... for a kill that failed, and a child still running.
pub(crate) const SAID_REFUSED_RUNNING: &str = "could not be killed (";
pub(crate) const SAID_STILL_RUNNING: &str = "it is still running";
/// ... for a kill that sent nothing.
pub(crate) const SAID_NOT_SENT: &str = "its pid names another process, so nothing was sent";
pub(crate) const ZOMBIE: &str = "stays a zombie once it exits";

/// The `warn`s since `mark` that name `pid` as `child {pid} `, on this thread, with their text.
pub(crate) fn warns_of(pid: u32, mark: usize) -> Vec<String> {
    let prefix = format!("child {pid} ");
    crate::log_capture::records_since_on_current_thread(mark, &prefix)
        .into_iter()
        .filter(|(level, text)| *level == log::Level::Warn && text.starts_with(&prefix))
        .map(|(_, text)| text)
        .collect()
}

/// Asserts the teardown of `pid` produced exactly one `warn` naming it, that it says each of `says`
/// and none of `not_says`, and that it does not call the child dead before `exec`.
pub(crate) fn assert_one_warn(pid: u32, mark: usize, says: &[&str], not_says: &[&str]) {
    let warns = warns_of(pid, mark);
    assert_eq!(warns.len(), 1, "one event, one warn: {warns:?}");
    assert!(
        warns[0].contains("had not reported its unique id when its spawn returned"),
        "{warns:?}"
    );
    for said in says {
        assert!(warns[0].contains(said), "the warn must say {said:?}: {warns:?}");
    }
    for other in not_says {
        assert!(!warns[0].contains(other), "the warn must not say {other:?}: {warns:?}");
    }
    assert!(
        !warns[0].contains("died before exec"),
        "a late child is not reported dead: {warns:?}"
    );
}

/// Asserts the teardown sent `pid` exactly one `SIGKILL`, by pid.
pub(crate) fn assert_kill_sent(pid: u32, sent: &[crate::send_log::Entry]) {
    let kill = (pid, crate::signal::Sig::Kill, crate::send_log::Via::Pid);
    assert_eq!(
        sent.iter().filter(|e| **e == kill).count(),
        1,
        "the teardown must send the kill: {sent:?}"
    );
}

// The spawn =====

/// A child whose report comes after its spawn returned is torn down through its unique id: killed,
/// reaped, and answered `Reaped`, with one `warn` that says so. The child is live (its stdin writer is
/// held), so only the kill ends it. The hook between the kill and the wait releases it when no kill
/// was sent, so a missing kill fails the assertion on `sent` instead of hanging the wait.
///
/// Mutants: the spawn does not wait for the report (the child is not the late one, and is answered as
/// not started); the kill is not sent; the child is left running; the warn is missing or doubled;
/// the child is logged as dead before `exec`.
#[skuld::test]
fn macos_sync_spawn_of_a_late_reporting_child_kills_and_reaps_it_through_its_id() {
    crate::log_capture::install();
    let (mut cmd, writer) = sync_blocker();
    let sent = Rc::new(crate::send_log::Capture::start());
    let kill_missing = Rc::new(Cell::new(false));
    let _release = crate::child::spawn::fault::set_between_kill_and_wait({
        let (sent, missing) = (Rc::clone(&sent), Rc::clone(&kill_missing));
        move || {
            missing.set(
                sent.entries()
                    .iter()
                    .all(|(_, sig, _)| *sig != crate::signal::Sig::Kill),
            );
            drop(writer);
        }
    });
    let mark = crate::log_capture::mark();
    let err = {
        let _late = unique_report::seams::find_the_report_unwritten();
        cmd.spawn().expect_err("a late child is not adopted")
    };
    assert!(!kill_missing.get(), "the kill must be sent before the wait");
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    let pid = id.pid();
    assert_eq!(fate, ChildFate::Reaped, "a late child is killed and reaped");
    assert_kill_sent(pid, &sent.entries());
    assert!(is_reaped(pid), "nothing is left to wait for");
    assert!(err.to_string().contains("exec cannot be confirmed"), "{err}");
    assert_one_warn(pid, mark, &[SAID_REAPED], &[SAID_REFUSED_RUNNING, SAID_NOT_SENT]);
}

/// With two of fds 0 to 2 closed in the parent, std's close-on-exec pipe takes a child's stdio number
/// and std returns before the child's hooks run. Whether the report is late is the child's race to
/// win: either the spawn adopts the child, or it tears the late one down. Neither leaves a child
/// behind. Runs in a process of its own, since closing fds is process-wide.
///
/// Mutant: a late child is left running and unreaped.
#[skuld::test]
fn macos_sync_spawn_with_fds_0_and_1_closed_leaves_no_child_behind() {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;
    use crate::test_stdio::RestoreStdio;

    let Some(done) = own_process(
        test_path!(macos_sync_spawn_with_fds_0_and_1_closed_leaves_no_child_behind),
        spawn,
    ) else {
        return;
    };
    crate::log_capture::install();
    let (mut cmd, writer) = sync_blocker();
    // Opened before the close, so it lands above stdio: a closed stdout cannot be inherited.
    let null = std::fs::File::open("/dev/null").expect("open /dev/null");
    cmd.stdout(crate::stdio::Stdio::from_file(null)).expect("set stdout");
    let restore = RestoreStdio::close(&done, &[0, 1]);
    let spawned = cmd.spawn();
    drop(restore);
    match spawned {
        Ok(child) => {
            child.kill().expect("kill the adopted child");
            child.wait().expect("reap it");
        }
        Err(err) => {
            let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
            assert_eq!(fate, ChildFate::Reaped, "the late child is reaped");
            let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
                panic!("the spawn captured the child");
            };
            assert!(is_reaped(id.pid()), "nothing is left to wait for");
        }
    }
    drop(writer);
}

/// An elevation front whose report came late is sent nothing and left unreaped, as every front is.
/// The one `warn` says so, and says nothing of a kill.
///
/// Mutants: the front is killed; the front's note is dropped; the warn is the torn-down sentence.
#[skuld::test]
fn macos_sync_spawn_of_a_late_front_leaves_it_running_and_says_so() {
    use crate::elevation::{front::front, ElevatedVia};
    crate::log_capture::install();
    let front = front(Some(&ElevatedVia::MacosOsascript));
    let (mut cmd, writer) = sync_blocker();
    cmd.set_elevation_front(front);
    let sent = crate::send_log::Capture::start();
    let mark = crate::log_capture::mark();
    let err = {
        let _late = unique_report::seams::find_the_report_unwritten();
        cmd.spawn().expect_err("a late front is not adopted")
    };
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    assert_eq!(fate, ChildFate::Running { id: None }, "a front is left running");
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    let pid = id.pid();
    assert_eq!(sent.entries(), [], "a front is sent nothing");
    assert!(has_not_exited(pid), "the front is left running");
    assert_one_warn(
        pid,
        mark,
        &["elevation front", "left unreaped", ZOMBIE],
        &["was sent SIGKILL", SAID_REFUSED_RUNNING, SAID_NOT_SENT],
    );
    assert!(err.to_string().contains("it is left unreaped"), "{err}");
    // The writer stays open until the reap: closing it would let the child exit by itself.
    end_unsignalled_and_reap(pid);
    drop(writer);
}

/// The ends of a [`TREE_ARGV`] spawn the test keeps.
pub(crate) struct Tree {
    /// Gives one byte once the grandchild runs.
    ready: std::io::PipeReader,
    /// The grandchild blocks reading this pipe until the writer is dropped.
    hold: std::io::PipeWriter,
    /// What the grandchild writes if it outlives the teardown, then EOF.
    out: std::io::PipeReader,
}

/// A root `sh` with a grandchild that says it runs on fd 3, blocks reading fd 4, and once that
/// returns writes `survived` to fd 5.
pub(crate) const TREE_ARGV: [&str; 3] = [
    "/bin/sh",
    "-c",
    "(printf r >&3; read x <&4; printf survived >&5) & wait",
];

/// The pipes of a [`TREE_ARGV`] spawn: the child's ends for fds 3, 4 and 5, and the test's.
pub(crate) fn tree_pipes() -> (Tree, [(i32, crate::stdio::Stdio); 3]) {
    use std::os::fd::OwnedFd;
    let child_end = |end: OwnedFd| crate::stdio::Stdio::from_file(std::fs::File::from(end));
    let (ready, ready_w) = std::io::pipe().expect("pipe");
    let (hold_r, hold) = std::io::pipe().expect("pipe");
    let (out, out_w) = std::io::pipe().expect("pipe");
    let ends = [
        (3, child_end(ready_w.into())),
        (4, child_end(hold_r.into())),
        (5, child_end(out_w.into())),
    ];
    (Tree { ready, hold, out }, ends)
}

impl Tree {
    /// Blocks until the grandchild runs. A root that died first closes the pipe, which fails here.
    pub(crate) fn await_grandchild(&mut self) {
        use std::io::Read;
        let mut byte = [0u8; 1];
        let n = self.ready.read(&mut byte).expect("read the ready pipe");
        assert_eq!(n, 1, "the grandchild must run before the teardown");
    }

    /// Releases the grandchild, and answers whether it was still alive to say so.
    pub(crate) fn grandchild_survived(self) -> bool {
        use std::io::Read;
        let Tree { ready, hold, mut out } = self;
        drop((ready, hold));
        let mut said = String::new();
        out.read_to_string(&mut said).expect("read the grandchild's word");
        !said.is_empty()
    }
}

/// A contained child whose report came late is torn down with its tree: the grandchild it forked is
/// killed too. The hook before the teardown waits until the grandchild runs, so it is in the tree
/// before the kill. The grandchild is released afterwards and writes if it is still alive, so a
/// survivor fails by assertion, not by hang.
///
/// Mutant: the late teardown kills the root alone.
#[skuld::test]
fn macos_sync_spawn_of_a_late_contained_child_kills_its_tree() {
    crate::log_capture::install();
    let (tree, ends) = tree_pipes();
    let mut cmd = crate::Command::new();
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
    assert_one_warn(id.pid(), mark, &[SAID_REAPED], &["tree was not"]);
}

// The teardown's sentence =====

/// Runs the teardown of a late child `child` (a real blocker with the id `unique`, its stdin held by
/// `stdin`) with the faults `arm` sets, and answers its fate, its `warn`s, and the signals it sent.
/// The hook between the kill and the wait releases the blocker, so a teardown that sent no kill fails
/// the caller's assertion on the signals instead of hanging the wait.
fn tear_down(
    child: std::process::Child,
    stdin: &Rc<Cell<Option<std::process::ChildStdin>>>,
    unique: u64,
    arm: impl FnOnce(u32) -> Vec<Box<dyn std::any::Any>>,
) -> (ChildFate, Vec<String>, Vec<crate::send_log::Entry>) {
    crate::log_capture::install();
    let pid = child.id();
    let sent = crate::send_log::Capture::start();
    let _release = crate::child::spawn::fault::set_between_kill_and_wait({
        let stdin = Rc::clone(stdin);
        move || drop(stdin.take())
    });
    let mark = crate::log_capture::mark();
    let _armed = arm(pid);
    let uncontained = crate::containment::Prepared {
        mode: None,
        is_root: true,
        marker: None,
    };
    let done = crate::child::spawn::kill_and_reap_unreported(pid, unique, uncontained);
    let tail = done.zombie_tail();
    let fate = done.warn(pid, tail);
    drop(child);
    (fate, warns_of(pid, mark), sent.entries())
}

fn only(warns: &[String]) -> &str {
    assert_eq!(warns.len(), 1, "one event, one warn: {warns:?}");
    &warns[0]
}

/// A delivered kill and a reaped child: the clean sentence, with nothing about a refusal.
///
/// Mutant: the sentence is built from the fate alone, so a refusal or a no-send reads as a kill.
#[skuld::test]
fn macos_late_teardown_of_a_live_child_is_reaped() {
    let (child, stdin, unique) = std_blocker_with_unique();
    let pid = child.id();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let (fate, warns, sent) = tear_down(child, &stdin, unique, |_| vec![]);
    assert_eq!(fate, ChildFate::Reaped);
    let warn = only(&warns);
    assert_kill_sent(pid, &sent);
    assert!(warn.contains(SAID_REAPED) && !warn.contains(ZOMBIE), "{warn}");
}

/// A refused kill leaves the child running: the sentence says the kill failed and the child runs,
/// never that a kill was sent or did not end it, and a sync child is left a zombie, which it says.
///
/// Mutants: a refused kill is worded as a sent one; the zombie is not said.
#[skuld::test]
fn macos_late_teardown_with_a_refused_kill_leaves_it_running_and_says_so() {
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let (fate, warns, sent) = tear_down(child, &stdin, unique, |_| vec![Box::new(refuse_the_kill())]);
    assert_eq!(fate, ChildFate::Running { id: None });
    let warn = only(&warns);
    assert_eq!(sent, [], "a refused kill sends nothing");
    assert!(
        warn.contains(SAID_REFUSED_RUNNING) && warn.contains(SAID_STILL_RUNNING) && warn.contains(ZOMBIE),
        "{warn}"
    );
    assert!(
        !warn.contains("was sent SIGKILL") && !warn.contains("did not end it"),
        "{warn}"
    );
    end_unsignalled_and_reap(pid);
}

/// An id read that shows the pid gone or another process's sends nothing: `Gone`, and the sentence
/// says nothing was sent, never that a kill was.
///
/// Mutant: the no-send is worded as a sent kill.
#[skuld::test]
fn macos_late_teardown_of_a_pid_that_is_not_the_child_sends_nothing_and_is_gone() {
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let other = other_unique_id(pid);
    let (fate, warns, sent) = tear_down(child, &stdin, unique, |_| {
        vec![Box::new(uniq_fault::force_uniq_read_once(ReadPurpose::Kill, other))]
    });
    assert_eq!(fate, ChildFate::Gone);
    let warn = only(&warns);
    assert_eq!(sent, [], "nothing is sent to a pid that is not the child");
    assert!(warn.contains(SAID_NOT_SENT) && warn.contains("it is gone"), "{warn}");
    assert!(
        !warn.contains("was sent SIGKILL") && !warn.contains("signalled"),
        "{warn}"
    );
    end_unsignalled_and_reap(pid);
}

/// A refused kill and a refused id read: nothing shows what became of the child, `Unknown`.
///
/// Mutant: the arm answers `Running` or `Reaped`.
#[skuld::test]
fn macos_late_teardown_with_a_refused_kill_and_a_refused_read_is_unknown() {
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let (fate, warns, sent) = tear_down(child, &stdin, unique, |_| {
        vec![
            Box::new(refuse_the_kill()),
            Box::new(uniq_fault::force_uniq_read_once(
                ReadPurpose::Running,
                UniqRead::Refused(libc::EPERM),
            )),
        ]
    });
    assert_eq!(fate, ChildFate::Unknown);
    let warn = only(&warns);
    assert_eq!(sent, [], "a refused kill sends nothing");
    assert!(
        warn.contains(SAID_REFUSED_RUNNING) && warn.contains("what became of it is unknown"),
        "{warn}"
    );
    end_unsignalled_and_reap(pid);
}

/// A delivered kill, then a wait that shows someone else reaped the child (`Waited::Gone`): `Killed`.
///
/// Mutant: the arm says the child was reaped, or `Gone`.
#[skuld::test]
fn macos_late_teardown_of_a_child_reaped_elsewhere_after_the_kill_is_killed() {
    use crate::wait::exit_only::Foreign;
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let (fate, warns, sent) = tear_down(child, &stdin, unique, |_| {
        vec![Box::new(force_peek_once(Ok(Peek::Foreign(Foreign::Gone))))]
    });
    assert_eq!(fate, ChildFate::Killed);
    assert_kill_sent(pid, &sent);
    assert!(only(&warns).contains(SAID_KILLED), "{warns:?}");
    reap_by_pid(pid);
}

/// A delivered kill, then a zombie launchd holds (`Waited::Orphaned`): `Killed`, and the warn says why.
///
/// Mutant: the arm says the child was reaped.
#[skuld::test]
fn macos_late_teardown_of_an_orphaned_zombie_after_the_kill_is_killed_and_says_so() {
    use crate::wait::exit_only::Foreign;
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let (fate, warns, sent) = tear_down(child, &stdin, unique, |_| {
        vec![Box::new(force_peek_once(Ok(Peek::Foreign(Foreign::Orphaned))))]
    });
    assert_eq!(fate, ChildFate::Killed);
    assert_kill_sent(pid, &sent);
    let warn = only(&warns);
    assert!(
        warn.contains(SAID_KILLED) && warn.contains("launchd holds its zombie"),
        "{warn}"
    );
    reap_by_pid(pid);
}

/// A delivered kill, then a failed wait: `Killed`, with the failure in the warn.
///
/// Mutant: the arm says the child was reaped.
#[skuld::test]
fn macos_late_teardown_with_a_failed_wait_is_killed() {
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let (fate, warns, sent) = tear_down(child, &stdin, unique, |_| {
        vec![Box::new(force_peek_once(Err(std::io::Error::other(
            "forced wait failure",
        ))))]
    });
    assert_eq!(fate, ChildFate::Killed);
    assert_kill_sent(pid, &sent);
    let warn = only(&warns);
    assert!(
        warn.contains(SAID_KILLED) && warn.contains("forced wait failure"),
        "{warn}"
    );
    reap_by_pid(pid);
}

/// A delivered kill, a wait that sees the exit, then a reap whose peek is refused: the child is
/// dead and its status is not shown ours to take, `Unknown`.
///
/// Mutant: the arm says the child was reaped.
#[skuld::test]
fn macos_late_teardown_whose_reap_peek_fails_after_the_kill_is_unknown() {
    use crate::wait::exit_only::Reaped;
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let (fate, warns, sent) = tear_down(child, &stdin, unique, |_| {
        vec![Box::new(force_peeks([
            Ok(Peek::Exit(Reaped::Unreadable { si_code: 0 })),
            Err(std::io::Error::other("forced reap-peek failure")),
        ]))]
    });
    assert_eq!(fate, ChildFate::Unknown);
    assert_kill_sent(pid, &sent);
    let warn = only(&warns);
    assert!(
        warn.contains("was sent SIGKILL") && warn.contains("what became of it is unknown"),
        "{warn}"
    );
    reap_by_pid(pid);
}
