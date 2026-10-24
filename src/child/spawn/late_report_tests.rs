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
use crate::test_groups::{tracer_group, Group};
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

/// Closes this process's fds 0 and 1, and asserts they are the lowest free numbers, so that std's
/// close-on-exec pipe takes them: the child's stdio then closes that pipe before its hooks run, and
/// std returns before them. A spawn that waited for `exec` instead would deadlock against a child
/// held before its report, so this fails first.
pub(crate) fn close_fds_0_and_1(done: &crate::test_own_process::Completion) -> crate::test_stdio::RestoreStdio {
    use std::os::fd::AsRawFd;
    let restore = crate::test_stdio::RestoreStdio::close(done, &[0, 1]);
    let (read, write) = std::io::pipe().expect("pipe");
    let fds = [read.as_raw_fd(), write.as_raw_fd()];
    drop((read, write));
    assert_eq!(fds, [0, 1], "precondition: a new pipe must take fds 0 and 1");
    restore
}

/// A stdio for a spawn while fds 0 and 1 are closed: `/dev/null`, opened before the close so it
/// lands above stdio, since a closed descriptor cannot be inherited.
pub(crate) fn null_stdio() -> crate::stdio::Stdio {
    crate::stdio::Stdio::from_file(std::fs::File::open("/dev/null").expect("open /dev/null"))
}

/// With two of fds 0 to 2 closed in the parent, std's close-on-exec pipe takes a child's stdio number
/// and std returns before the child's hooks run. The child's report hook waits until the parent's
/// first read of the report has returned, so the report is late, and the spawn tears the child down.
/// Runs in a process of its own, since closing fds is process-wide.
///
/// Mutant: a late child is left running and unreaped.
#[skuld::test]
fn macos_sync_spawn_with_fds_0_and_1_closed_leaves_no_child_behind() {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    let Some(done) = own_process(
        test_path!(macos_sync_spawn_with_fds_0_and_1_closed_leaves_no_child_behind),
        spawn,
    ) else {
        return;
    };
    crate::log_capture::install();
    let (mut cmd, writer) = sync_blocker();
    cmd.stdout(null_stdio()).expect("set stdout");
    // Opened before the close too, so the gate's ends are above stdio.
    let held = unique_report::seams::hold_the_report_until_the_first_read();
    let restore = close_fds_0_and_1(&done);
    let spawned = cmd.spawn();
    drop(restore);
    drop(held);
    let err = spawned.expect_err("a late child is not adopted");
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    assert_eq!(fate, ChildFate::Reaped, "the late child is reaped");
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    assert!(is_reaped(id.pid()), "nothing is left to wait for");
    drop(writer);
}

/// With two of fds 0 to 2 closed in the parent, std returns before the child's hooks run and cannot
/// see whether its `exec` ran, so the child is late even when its report beats the parent's first
/// read: the seam holds that read until the report is in the pipe. The child is torn down through
/// its id, not adopted. Runs in a process of its own, since closing fds is process-wide.
///
/// Mutant: the report's timing decides, so an id read on the first read is adopted.
#[skuld::test]
fn macos_sync_spawn_with_fds_0_and_1_closed_tears_down_a_child_whose_report_came_first() {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    let Some(done) = own_process(
        test_path!(macos_sync_spawn_with_fds_0_and_1_closed_tears_down_a_child_whose_report_came_first),
        spawn,
    ) else {
        return;
    };
    crate::log_capture::install();
    let (mut cmd, writer) = sync_blocker();
    cmd.stdout(null_stdio()).expect("set stdout");
    let first = unique_report::seams::let_the_report_come_first();
    let mark = crate::log_capture::mark();
    let restore = close_fds_0_and_1(&done);
    let spawned = cmd.spawn();
    drop(restore);
    drop(first);
    let err = spawned.expect_err("a child whose exec std could not see is not adopted");
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    assert!(err.to_string().contains("exec cannot be confirmed"), "{err}");
    assert_eq!(fate, ChildFate::Reaped, "the child is torn down through its id");
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    assert!(is_reaped(id.pid()), "nothing is left to wait for");
    assert_one_warn(id.pid(), mark, &[SAID_REAPED], &[]);
    drop(writer);
}

/// A spawn waiting for a late report does not hold `spawn_lock`: another spawn, on another thread,
/// completes meanwhile. The child is held before its report, and the wait's first block starts the
/// other spawn and waits for its first word: `completed` once it returns, or `contended` from the
/// seam if it finds the lock held. Either arrives without the held child, so a wait under the lock
/// fails the assertion instead of hanging; the report is released afterwards. Runs in a process of
/// its own with fds 0 and 1 closed, so the child can be held before its report while the spawn goes
/// on.
///
/// Mutant: the wait for the report runs under `spawn_lock`.
#[skuld::test]
fn macos_a_spawn_waiting_for_a_late_report_lets_another_spawn_complete() {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    let Some(done) = own_process(
        test_path!(macos_a_spawn_waiting_for_a_late_report_lets_another_spawn_complete),
        spawn,
    ) else {
        return;
    };
    crate::log_capture::install();
    let (mut cmd, writer) = sync_blocker();
    cmd.stdout(null_stdio()).expect("set stdout");
    // Set up before the close, so its stdio lands above fds 0 to 2.
    let mut other = crate::Command::new();
    other.args(["/usr/bin/true"]);
    other.stdin(null_stdio()).expect("set stdin");
    other.stdout(null_stdio()).expect("set stdout");
    let (said, heard) = std::sync::mpsc::channel::<&'static str>();
    let _contended = crate::child::spawn::fault::on_spawn_lock_contended({
        let said = said.clone();
        move || {
            // The receiver may be gone: the hook took the first word already.
            said.send("contended").ok();
        }
    });
    let first_word = Rc::new(Cell::new(None));
    let second = Rc::new(std::cell::RefCell::new(None));
    let _hook = unique_report::seams::on_first_block({
        let (first_word, second) = (Rc::clone(&first_word), Rc::clone(&second));
        move || {
            let thread = std::thread::spawn(move || {
                let spawned = other.spawn();
                said.send("completed").ok();
                // Whatever it answered: a spawn with fds 0 and 1 closed is late, and torn down.
                drop(spawned);
            });
            first_word.set(Some(heard.recv().expect("the other spawn's first word")));
            unique_report::seams::release_the_report();
            *second.borrow_mut() = Some(thread);
        }
    });
    let held = unique_report::seams::hold_the_report();
    let restore = close_fds_0_and_1(&done);
    let spawned = cmd.spawn();
    drop(restore);
    drop(held);
    second
        .borrow_mut()
        .take()
        .expect("the wait blocked and started the other spawn")
        .join()
        .expect("the other spawn's thread");
    assert_eq!(
        first_word.get(),
        Some("completed"),
        "another spawn must complete while this one waits for its report"
    );
    let err = spawned.expect_err("a late child is not adopted");
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    assert_eq!(fate, ChildFate::Reaped, "the late child is torn down");
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
    hold: Option<std::io::PipeWriter>,
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
    (
        Tree {
            ready,
            hold: Some(hold),
            out,
        },
        ends,
    )
}

impl Tree {
    /// Blocks until the grandchild runs. Called from a spawn hook ([`fault::spawn_pid`] names the
    /// root). The spawn holds a copy of the ready pipe's write end until it returns, so a root that
    /// died first would not close the pipe: one kqueue watches the root's exit too, which fails here.
    ///
    /// [`fault::spawn_pid`]: crate::child::spawn::fault::spawn_pid
    pub(crate) fn await_grandchild(&mut self) {
        use std::io::Read;
        use std::os::fd::AsRawFd;

        use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

        let root = crate::child::spawn::fault::spawn_pid();
        let kq = Kqueue::new().expect("kqueue");
        let add = |ident: usize, filter, fflags| {
            let change = KEvent::new(ident, filter, EvFlags::EV_ADD | EvFlags::EV_RECEIPT, fflags, 0, 0);
            crate::wait::backend::add_with_receipt(&kq, change).expect("register with the kqueue")
        };
        let read = add(
            self.ready.as_raw_fd() as usize,
            EventFilter::EVFILT_READ,
            FilterFlag::empty(),
        );
        assert_eq!(read, 0, "watch the ready pipe: errno {read}");
        let exit = add(root as usize, EventFilter::EVFILT_PROC, FilterFlag::NOTE_EXIT);
        assert_eq!(
            exit, 0,
            "the root {root} must be alive until its grandchild runs: errno {exit}"
        );
        let blank = KEvent::new(0, EventFilter::EVFILT_READ, EvFlags::empty(), FilterFlag::empty(), 0, 0);
        let mut events = [blank; 2];
        let n = loop {
            match kq.kevent(&[], &mut events, None) {
                Err(nix::errno::Errno::EINTR) => continue,
                other => break other.expect("wait for the grandchild or the root's exit"),
            }
        };
        assert!(
            events[..n].iter().any(|e| e.filter() == Ok(EventFilter::EVFILT_READ)),
            "the root {root} exited before its grandchild ran"
        );
        let mut byte = [0u8; 1];
        let n = self.ready.read(&mut byte).expect("read the ready pipe");
        assert_eq!(n, 1, "the grandchild must run before the teardown");
    }

    /// Lets the grandchild run on, so it and its root exit by themselves.
    pub(crate) fn release(&mut self) {
        self.hold = None;
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
    assert_one_warn(id.pid(), mark, &[SAID_REAPED], &["tree was not", "fully killed"]);
}

/// A late [`TREE_ARGV`] child under `TreeWalk` without a marker, whose first tree sweep is spoiled by
/// `spoil`, armed once the grandchild runs. Answers the root's pid, its fate, whether the grandchild
/// survived the teardown, and the log mark taken before the spawn.
fn late_tree_walk(spoil: impl FnOnce() + 'static) -> (u32, ChildFate, bool, usize) {
    use crate::containment::ContainMode;
    crate::log_capture::install();
    let (tree, ends) = tree_pipes();
    let mut cmd = crate::Command::new();
    cmd.args(TREE_ARGV).contain_with(ContainMode::TreeWalk);
    cmd.suppress_fd_marker();
    for (fd, end) in ends {
        cmd.fd(fd, end).expect("set the fd");
    }
    let tree = Rc::new(std::cell::RefCell::new(Some(tree)));
    let _hook = crate::child::spawn::fault::set_at(crate::child::spawn::fault::SpawnPoint::BeforeLateTeardown, {
        let tree = Rc::clone(&tree);
        move || {
            tree.borrow_mut().as_mut().expect("the tree").await_grandchild();
            spoil();
        }
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
    let survived = tree.borrow_mut().take().expect("the tree").grandchild_survived();
    (id.pid(), fate, survived, mark)
}

/// A walk that cannot take its snapshot kills nothing; the root's kill then reparents the grandchild
/// to launchd, so the walk from the zombie finds nothing and succeeds. That success does not erase
/// the first failure: the warn says the tree may not be fully killed.
///
/// Mutant: each sweep's result overwrites the last one's.
#[skuld::test]
fn macos_late_tree_walk_that_fails_before_the_root_kill_says_its_tree_may_be_left() {
    let (pid, fate, survived, mark) =
        late_tree_walk(|| crate::containment::enumerate::force_blind_snapshot_for_next_call(true));
    assert!(survived, "a walk that could not take its snapshot kills nothing");
    assert_eq!(fate, ChildFate::Reaped, "the root is killed and reaped");
    assert_one_warn(
        pid,
        mark,
        &[SAID_REAPED, "its tree may not be fully killed", "test fault injected"],
        &[],
    );
}

/// A walk that left a member it could not kill is not a complete kill, though it returns `Ok`: the
/// warn says so, even when a later walk is complete.
///
/// Mutant: the sweep reads only the walk's `Ok`, not whether it was complete.
#[skuld::test]
fn macos_late_tree_walk_that_leaves_a_member_says_its_tree_may_be_left() {
    let (pid, fate, _, mark) = late_tree_walk(crate::containment::treewalk::fault::force_incomplete_once);
    assert_eq!(fate, ChildFate::Reaped, "the root is killed and reaped");
    assert_one_warn(
        pid,
        mark,
        &[
            SAID_REAPED,
            "its tree may not be fully killed",
            "a member could not be killed",
        ],
        &[],
    );
}

/// A Session child without a marker, held between its report and its `setsid`, is torn down with
/// what it starts after that. The first kill of its tree finds no group yet; the hook between that
/// kill and the root's lets the child run on, `setsid`, `exec` and fork its grandchild, and waits
/// until the grandchild runs. Only a kill of the group once the root is dead reaches the grandchild.
/// Runs in a process of its own with fds 0 and 1 closed, so the report is late for real and the
/// child can be held before its `setsid` while the spawn goes on. The hook between the root's kill
/// and its wait releases the grandchild when no kill was sent, so the root exits and the missing kill
/// fails an assertion instead of hanging the wait.
///
/// Mutants: the late teardown kills the tree only before the root's kill; the root's kill is not sent.
#[skuld::test]
fn macos_late_session_child_without_a_marker_is_torn_down_with_what_it_starts_after_its_report() {
    use crate::containment::ContainMode;
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    let Some(done) = own_process(
        test_path!(macos_late_session_child_without_a_marker_is_torn_down_with_what_it_starts_after_its_report),
        spawn,
    ) else {
        return;
    };
    crate::log_capture::install();
    let (tree, ends) = tree_pipes();
    let mut cmd = crate::Command::new();
    cmd.args(TREE_ARGV).contain_with(ContainMode::Session);
    cmd.suppress_fd_marker();
    cmd.stdin(null_stdio()).expect("set stdin");
    cmd.stdout(null_stdio()).expect("set stdout");
    for (fd, end) in ends {
        cmd.fd(fd, end).expect("set the fd");
    }
    let tree = Rc::new(std::cell::RefCell::new(Some(tree)));
    let root = Rc::new(Cell::new(None));
    let _hook = crate::child::spawn::fault::set_at(crate::child::spawn::fault::SpawnPoint::BeforeLateRootKill, {
        let (tree, root) = (Rc::clone(&tree), Rc::clone(&root));
        move || {
            root.set(Some(crate::child::spawn::fault::spawn_pid()));
            unique_report::seams::release_the_child_after_its_report();
            tree.borrow_mut().as_mut().expect("the tree").await_grandchild();
        }
    });
    let sent = Rc::new(crate::send_log::Capture::start());
    let kill_missing = Rc::new(Cell::new(false));
    let _release = crate::child::spawn::fault::set_between_kill_and_wait({
        let (tree, root, sent, missing) = (
            Rc::clone(&tree),
            Rc::clone(&root),
            Rc::clone(&sent),
            Rc::clone(&kill_missing),
        );
        move || {
            let root = root
                .get()
                .expect("the root's kill comes after the first kill of its tree");
            let kill = (root, crate::signal::Sig::Kill, crate::send_log::Via::Pid);
            if !sent.entries().contains(&kill) {
                missing.set(true);
                tree.borrow_mut().as_mut().expect("the tree").release();
            }
        }
    });
    let mark = crate::log_capture::mark();
    let held = unique_report::seams::hold_the_report_until_the_first_read();
    let after = unique_report::seams::hold_the_child_after_its_report();
    let restore = close_fds_0_and_1(&done);
    let spawned = cmd.spawn();
    drop(restore);
    drop((held, after));
    assert!(!kill_missing.get(), "the root's kill must be sent before its wait");
    let err = spawned.expect_err("a late child is not adopted");
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    let tree = tree.borrow_mut().take().expect("the tree");
    assert!(
        !tree.grandchild_survived(),
        "the grandchild the child started after its first tree kill must be killed"
    );
    assert_eq!(fate, ChildFate::Reaped, "the root is killed and reaped");
    assert_one_warn(
        id.pid(),
        mark,
        &[SAID_REAPED],
        &["tree was not", "fully killed", "not shown an unreaped zombie"],
    );
}

/// A contained child whose report came late, and that is reaped before its teardown: its pid names
/// nothing of its own any more, but its fd marker still names its tree, so the grandchild that holds
/// the marker is killed. The hook before the teardown waits until the grandchild runs, then kills
/// and reaps the root, as a host that ignores `SIGCHLD` would reap it.
///
/// Mutant: a late root that is gone leaves its tree running.
#[skuld::test]
fn macos_sync_spawn_of_a_late_child_reaped_before_its_teardown_kills_its_marked_tree() {
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
        move || {
            tree.borrow_mut().as_mut().expect("the tree").await_grandchild();
            let root = crate::child::spawn::fault::spawn_pid();
            // SAFETY: the root is this test's own unreaped child.
            assert_eq!(unsafe { libc::kill(root as libc::pid_t, libc::SIGKILL) }, 0);
            reap_by_pid(root);
        }
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
        "the grandchild that holds the marker must be killed"
    );
    assert_eq!(fate, ChildFate::Gone, "the root was reaped before the teardown");
    assert_one_warn(
        id.pid(),
        mark,
        &[SAID_NOT_SENT, "reached only through its marker's holders"],
        &["was sent SIGKILL", "fully killed", "tree was not killed"],
    );
}

/// A child a tracer holds while its report is still unwritten is not taken for dead: the parent's
/// `waitid` answers `ECHILD` for it, yet this process forked it, so the spawn waits on, and the
/// report it writes once released is late, not missing. The helper attaches after the spawn's first
/// read of the report, and the report is released when the wait first blocks. The child is torn down
/// through its id, and the helper hands its zombie back.
/// Runs in a process of its own with fds 0 and 1 closed, so the child can be held before its report
/// while the spawn goes on.
///
/// Mutant: `ECHILD` in the wait is taken for the child gone, so the spawn answers it died before
/// `exec` (`NotStarted`).
#[skuld::test]
fn macos_late_child_held_by_a_tracer_is_not_answered_dead(#[fixture(tracer_group)] _group: &Group) {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;
    use crate::test_support::tracer::{self, Mode, Report, TracerHelper};

    let Some(done) = own_process(
        test_path!(macos_late_child_held_by_a_tracer_is_not_answered_dead),
        spawn,
    ) else {
        return;
    };
    crate::log_capture::install();
    let pending = Rc::new(std::cell::RefCell::new(Some(tracer::start(Mode::Auto))));
    let helper: Rc<std::cell::RefCell<Option<TracerHelper<'static>>>> = Rc::default();
    let (mut cmd, writer) = sync_blocker();
    cmd.stdout(null_stdio()).expect("set stdout");
    let _attach = unique_report::seams::on_first_read({
        let helper = Rc::clone(&helper);
        move |pid| {
            let pending = pending.borrow_mut().take().expect("the helper");
            let mut attached = pending.attach_unheld(pid);
            assert_eq!(attached.recv(), Report::Attached);
            *helper.borrow_mut() = Some(attached);
        }
    });
    let _release = unique_report::seams::on_each_block(|n, _| {
        if n == 1 {
            unique_report::seams::release_the_report();
        }
    });
    let held = unique_report::seams::hold_the_report();
    let restore = close_fds_0_and_1(&done);
    let spawned = cmd.spawn();
    drop(restore);
    drop(held);
    let err = spawned.expect_err("a late child is not adopted");
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    assert_eq!(
        fate,
        ChildFate::Reaped,
        "the late child is killed, handed back and reaped"
    );
    let mut helper = helper.borrow_mut().take().expect("the helper attached");
    assert_eq!(helper.recv(), Report::Reaped);
    drop(helper);
    drop(writer);
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
    let uncontained = crate::containment::Prepared {
        mode: None,
        is_root: true,
        marker: None,
    };
    tear_down_with(uncontained, child, stdin, unique, arm)
}

/// [`tear_down`] of a child contained by `prepared`.
fn tear_down_with(
    prepared: crate::containment::Prepared,
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
    let done = crate::child::spawn::kill_and_reap_unreported(pid, unique, prepared);
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

/// A refused kill of a child whose tree attach read its identity: the child is left running, and its
/// fate names it by that identity. The tree walk is forced blind, so it kills nothing.
///
/// Mutant: the teardown drops the attach's identity (`Running { id: None }`).
#[skuld::test]
fn macos_late_teardown_of_a_contained_child_with_a_refused_kill_names_it_running() {
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let walked = crate::containment::Prepared {
        mode: Some(crate::containment::ContainMode::TreeWalk),
        is_root: true,
        marker: None,
    };
    let (fate, _warns, sent) = tear_down_with(walked, child, &stdin, unique, |_| {
        crate::containment::enumerate::force_blind_snapshot_for_next_call(true);
        vec![Box::new(refuse_the_kill())]
    });
    assert!(
        matches!(fate, ChildFate::Running { id: Some(id) } if id.pid() == pid),
        "{fate:?}"
    );
    assert_eq!(sent, [], "a refused kill and a blind walk send nothing");
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

// A root not shown a zombie after its kill =====

/// What [`late_tree_not_zombie`] saw.
struct NotZombie {
    fate: ChildFate,
    /// Whether the grandchild outlived the teardown.
    survived: bool,
    /// The walks from the root's pid after the root's kill.
    walks_after: Vec<u32>,
    /// The marker holders signalled after the root's kill.
    holders_after: Vec<u32>,
    warn: String,
}

/// A late [`TREE_ARGV`] child contained as `contain` sets, whose wait after the root's kill is forced
/// to `waited`, so the root is not shown an unreaped zombie. `spoil` runs once the grandchild runs,
/// before the first sweep. The root is left a zombie, which this reaps.
fn late_tree_not_zombie(
    contain: impl FnOnce(&mut crate::Command),
    waited: crate::wait::exit_only::Foreign,
    spoil: impl FnOnce() + 'static,
) -> NotZombie {
    use crate::child::spawn::fault::{set_at, SpawnPoint};
    use std::cell::RefCell;
    crate::log_capture::install();
    let (tree, ends) = tree_pipes();
    let mut cmd = crate::Command::new();
    cmd.args(TREE_ARGV);
    contain(&mut cmd);
    for (fd, end) in ends {
        cmd.fd(fd, end).expect("set the fd");
    }
    let tree = Rc::new(RefCell::new(Some(tree)));
    let walks = Rc::new(crate::containment::treewalk::fault::record_walks());
    let holders = crate::containment::fdmarker::fault::record_holder_kills();
    let _first = set_at(SpawnPoint::BeforeLateTeardown, {
        let tree = Rc::clone(&tree);
        move || {
            tree.borrow_mut().as_mut().expect("the tree").await_grandchild();
            spoil();
        }
    });
    let marks = Rc::new(Cell::new((0, 0)));
    let forced: Rc<RefCell<Option<crate::wait::exit_only::seams::Forced>>> = Rc::default();
    let _second = set_at(SpawnPoint::BeforeLateRootKill, {
        let (walks, marks, forced) = (Rc::clone(&walks), Rc::clone(&marks), Rc::clone(&forced));
        move || {
            let holders = crate::containment::fdmarker::fault::holder_kills_so_far();
            marks.set((walks.walked().len(), holders.len()));
            *forced.borrow_mut() = Some(force_peek_once(Ok(Peek::Foreign(waited))));
        }
    });
    let mark = crate::log_capture::mark();
    let err = {
        let _late = unique_report::seams::find_the_report_unwritten();
        cmd.spawn().expect_err("a late child is not adopted")
    };
    drop(forced.borrow_mut().take());
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    let survived = tree.borrow_mut().take().expect("the tree").grandchild_survived();
    let (walk_mark, holder_mark) = marks.get();
    let seen = NotZombie {
        fate,
        survived,
        walks_after: walks.walked()[walk_mark..].to_vec(),
        holders_after: holders.killed()[holder_mark..].to_vec(),
        warn: only(&warns_of(id.pid(), mark)).to_owned(),
    };
    reap_by_pid(id.pid());
    seen
}

/// The note of a root not shown an unreaped zombie after its kill.
const NOT_SWEPT_AGAIN: &str = "not shown an unreaped zombie, so its tree was not killed again by its pid";

/// A marked tree whose root is not shown a zombie after its kill: its marker's holders are still
/// swept, and the root's pid is not walked again. The first sweep is spoiled (a blind snapshot), so
/// only that holders' sweep can reach the grandchild.
///
/// Mutant: a root not shown a zombie gets no sweep of its marker's holders.
#[skuld::test]
fn macos_late_marked_tree_whose_root_is_not_shown_a_zombie_still_sweeps_its_holders() {
    use crate::containment::ContainMode;
    let seen = late_tree_not_zombie(
        |cmd| {
            cmd.contain_with(ContainMode::TreeWalk);
        },
        crate::wait::exit_only::Foreign::Gone,
        || crate::containment::enumerate::force_blind_snapshot_for_next_call(true),
    );
    assert!(!seen.survived, "the grandchild holds the marker, so its sweep kills it");
    assert!(
        !seen.holders_after.is_empty(),
        "the marker's holders are swept after the root's kill"
    );
    assert_eq!(
        seen.walks_after,
        Vec::<u32>::new(),
        "the root's pid is not walked again"
    );
    assert_eq!(seen.fate, ChildFate::Killed);
    assert!(
        seen.warn.contains(NOT_SWEPT_AGAIN) && seen.warn.contains("its tree was not fully killed"),
        "{}",
        seen.warn
    );
}

/// A tree walked from its root, whose root launchd holds after its kill: the root's pid is not
/// walked again, and the warn says what that may leave.
///
/// Mutants: the root's pid is walked again; the note is dropped.
#[skuld::test]
fn macos_late_walked_tree_whose_root_is_not_shown_a_zombie_is_not_walked_again() {
    use crate::containment::ContainMode;
    let seen = late_tree_not_zombie(
        |cmd| {
            cmd.contain_with(ContainMode::TreeWalk).suppress_fd_marker();
        },
        crate::wait::exit_only::Foreign::Orphaned,
        || {},
    );
    assert!(!seen.survived, "the first sweep kills the grandchild");
    assert_eq!(
        seen.walks_after,
        Vec::<u32>::new(),
        "the root's pid is not walked again"
    );
    assert_eq!(seen.fate, ChildFate::Killed);
    assert!(seen.warn.contains(NOT_SWEPT_AGAIN), "{}", seen.warn);
}

/// A Session tree whose root is shown gone after its kill: the warn says its group was not killed
/// again.
///
/// Mutant: the note is dropped.
#[skuld::test]
fn macos_late_session_tree_whose_root_is_not_shown_a_zombie_says_so() {
    use crate::containment::ContainMode;
    let seen = late_tree_not_zombie(
        |cmd| {
            cmd.contain_with(ContainMode::Session).suppress_fd_marker();
        },
        crate::wait::exit_only::Foreign::Gone,
        || {},
    );
    assert!(!seen.survived, "the first sweep kills the grandchild");
    assert_eq!(seen.fate, ChildFate::Killed);
    assert!(seen.warn.contains(NOT_SWEPT_AGAIN), "{}", seen.warn);
}

/// Resets a spawn fault flag when dropped.
struct Unforce(fn(bool));

impl Drop for Unforce {
    fn drop(&mut self) {
        (self.0)(false);
    }
}

/// Sets a spawn fault flag until the guard drops.
fn force(set: fn(bool)) -> Box<dyn std::any::Any> {
    set(true);
    Box::new(Unforce(set))
}

/// A contained child whose identity cannot be read, and that has no marker: its tree is not killed,
/// and the warn says why. The root's own kill, checked against its id, still runs.
///
/// Mutants: the note is dropped; it calls the child gone.
#[skuld::test]
fn macos_late_teardown_of_an_unreadable_child_without_a_marker_says_its_tree_was_not_killed() {
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let walked = crate::containment::Prepared {
        mode: Some(crate::containment::ContainMode::TreeWalk),
        is_root: true,
        marker: None,
    };
    let (fate, warns, sent) = tear_down_with(walked, child, &stdin, unique, |_| {
        vec![force(crate::child::spawn::fault::set_force_identity_unknown)]
    });
    assert_eq!(fate, ChildFate::Reaped);
    assert_kill_sent(pid, &sent);
    let warn = only(&warns);
    assert!(
        warn.contains("its tree was not killed: the child's identity could not be read"),
        "{warn}"
    );
}

/// A contained child whose identity cannot be read, with a marker: its tree is reached through the
/// marker's holders alone, which kill the grandchild, and the warn says so.
///
/// Mutants: the marker's holders are not swept; the note is dropped.
#[skuld::test]
fn macos_late_teardown_of_an_unreadable_marked_child_sweeps_its_holders() {
    use crate::child::spawn::fault::{set_at, SpawnPoint};
    crate::log_capture::install();
    let (tree, ends) = tree_pipes();
    let mut cmd = crate::Command::new();
    cmd.args(TREE_ARGV).contain();
    for (fd, end) in ends {
        cmd.fd(fd, end).expect("set the fd");
    }
    let tree = Rc::new(std::cell::RefCell::new(Some(tree)));
    let unknown = Rc::new(std::cell::RefCell::new(None));
    let _hook = set_at(SpawnPoint::BeforeLateTeardown, {
        let (tree, unknown) = (Rc::clone(&tree), Rc::clone(&unknown));
        move || {
            tree.borrow_mut().as_mut().expect("the tree").await_grandchild();
            *unknown.borrow_mut() = Some(force(crate::child::spawn::fault::set_force_identity_unknown));
        }
    });
    let mark = crate::log_capture::mark();
    let err = {
        let _late = unique_report::seams::find_the_report_unwritten();
        cmd.spawn().expect_err("a late child is not adopted")
    };
    drop(unknown.borrow_mut().take());
    let (_err, _fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
        panic!("the spawn captured the child");
    };
    let tree = tree.borrow_mut().take().expect("the tree");
    assert!(!tree.grandchild_survived(), "the marker's holders are swept");
    let warn = only(&warns_of(id.pid(), mark)).to_owned();
    assert!(
        warn.contains(
            "the child's identity could not be read, so its tree is reached only through its marker's holders"
        ),
        "{warn}"
    );
}

/// A child whose identity was read but whose tree attach failed: its tree is not killed, and the
/// warn gives the attach's error. The root's own kill still runs.
///
/// Mutant: the attach's note is dropped.
#[skuld::test]
fn macos_late_teardown_whose_tree_attach_fails_says_its_tree_was_not_killed() {
    let (child, stdin, unique) = std_blocker_with_unique();
    let stdin = Rc::new(Cell::new(Some(stdin)));
    let pid = child.id();
    let walked = crate::containment::Prepared {
        mode: Some(crate::containment::ContainMode::TreeWalk),
        is_root: true,
        marker: None,
    };
    let (fate, warns, sent) = tear_down_with(walked, child, &stdin, unique, |_| {
        vec![force(crate::child::spawn::fault::set_force_attach_failure)]
    });
    assert_eq!(fate, ChildFate::Reaped);
    assert_kill_sent(pid, &sent);
    let warn = only(&warns);
    assert!(
        warn.contains("its tree was not killed: ") && warn.contains("forced attach failure"),
        "{warn}"
    );
}

/// A child that could not be verified is said to be unsignalled for that reason, never gone.
///
/// Mutant: the outcome is worded as the no-send of a pid that names another process.
#[skuld::test]
fn macos_an_unverified_child_is_said_to_be_unsignalled_because_it_could_not_be_verified() {
    let said = super::said(&super::KillOutcome::Unverified, ChildFate::Running { id: None });
    assert!(
        said.contains("could not be verified, so it was not signalled"),
        "{said}"
    );
    assert!(!said.contains("was gone"), "{said}");
}
