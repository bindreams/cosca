//! `Child::drop` once the root is reaped: a kill that names the tree by the root's number
//! (`killpg`, a ppid walk from the root's pid) could hit an unrelated process that reused the
//! number, so the drop skips it and warns instead. On Linux 6.9+ the root's pidfd decides a
//! process group instead (`drop_group_exact_tests`), so the tests here refuse that flag.
//!
//! The recorder tests replace `killpg` with a recorder (`unix::fault::record_kill_group`) and
//! record the ppid walks (`treewalk::fault::record_walks`). The behavioural tests use real groups
//! of this test's own children, all signalled before their root is reaped.

use std::io::Read as _;

use crate::test_child::Console;

use crate::child::owned::seams::record_root_teardowns;
use crate::child::spawn::fault::{release_at_drop_kill, release_between_kill_and_wait};
use crate::command::Command;
use crate::containment::treewalk::fault::record_walks;
use crate::containment::unix::fault::record_kill_group;
#[cfg(target_os = "linux")]
use crate::test_groups::cgroup;
use crate::test_groups::{stray_signal, Group};
use crate::{ContainMode, Containment, Stdio};

/// [`root_that_leaves_a_cat`]'s shell, with the `cat` in a shell that prints `eof` if the `cat`
/// ends by itself, as it does on EOF. A `cat` a kill ended exits by a signal, so the `&&` prints no `eof`.
#[cfg(target_os = "linux")]
const ROOT_LEAVING_A_CAT_THAT_SAYS_EOF: &str = "exec 3<&0; { cat <&3 3<&- && echo eof; } & echo started; exit 0";

/// Every record of the drop's warn starts with this.
const WARN: &str = "Child::drop: the root is already reaped";

/// A command in its own session: a process group off macOS, an fd marker on it.
fn session(argv: &[&str]) -> Command {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(argv.iter().copied());
    cmd.contain_with(ContainMode::Session);
    cmd
}

/// A session-contained [`BLOCKER_ARGV`](crate::test_child::BLOCKER_ARGV) root and the write end of
/// its stdin. Dropping the writer is the only way for it to end on its own (status 0), so a test that
/// must see a kill end it drops the writer only after the kill: a `kill` that sent nothing then
/// fails the assertion on how the root ended, instead of leaving a wait unbounded. A drop that
/// blocks until the root is reaped gets its writer through [`release_at_drop_kill`].
fn session_blocker() -> (crate::Child, crate::PipeWriter) {
    let mut cmd = session(&crate::test_child::BLOCKER_ARGV);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    (child, stdin)
}

/// Root `sh` (which points a background job's stdin at `/dev/null` unless told otherwise, hence the
/// `exec 3<&0`) prints `started` and exits, leaving a `cat` in its group. The `cat` reads the stdin
/// pipe, which the test holds, and echoes it to stdout, so a round trip proves it alive
/// ([`assert_echoes`](crate::test_child::assert_echoes)); it ends only when killed or when the
/// test closes stdin. It holds the stderr pipe's write end: stderr reaches EOF exactly when `cat`
/// is gone.
fn root_that_leaves_a_cat() -> Command {
    root_that_leaves("exec 3<&0; cat <&3 3<&- & echo started; exit 0")
}

/// [`root_that_leaves_a_cat`] running `script`.
fn root_that_leaves(script: &str) -> Command {
    let mut cmd = session(&["sh", "-c", script]);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    cmd.stderr(Stdio::pipe_out()).expect("stderr pipe");
    cmd
}

/// The pipes of a [`spawn_cat_tree`]: the `cat`'s stdin, and its stdout and stderr.
struct CatPipes {
    stdin: crate::PipeWriter,
    stdout: crate::PipeReader,
    stderr: crate::PipeReader,
}

/// Spawn [`root_that_leaves_a_cat`] and read its `started`: the `cat` is forked, and the root is
/// exiting, a zombie, or already reaped by the spawn (a mutant `OwnedChild::new` reaps a root that has
/// exited by then).
fn spawn_cat_tree() -> (crate::Child, CatPipes) {
    let mut child = root_that_leaves_a_cat().spawn().expect("spawn");
    assert_eq!(child.containment(), crate::test_child::session_gives());
    let mut stdout = child.stdout().expect("stdout pipe");
    let mut started = [0u8; 8];
    stdout.read_exact(&mut started).expect("read `started`");
    assert_eq!(&started, b"started\n");
    let stdin = child.stdin().expect("stdin pipe");
    let stderr = child.stderr().expect("stderr pipe");
    (child, CatPipes { stdin, stdout, stderr })
}

fn drop_warns_since(mark: usize) -> Vec<(log::Level, String)> {
    crate::log_capture::records_since_on_current_thread(mark, WARN)
}

/// The drop's warn over a `TreeWalk` whose walk found no root: the tree call's answer, as the
/// settlement words it. Not macOS, where a `TreeWalk` root is a groupless marker.
#[cfg(not(target_os = "macos"))]
const WALK_WARN: &str = "Child::drop: contained-tree teardown did not fully succeed";

#[cfg(not(target_os = "macos"))]
fn drop_walk_warns_since(mark: usize) -> Vec<(log::Level, String)> {
    crate::log_capture::records_since_on_current_thread(mark, WALK_WARN)
}

/// Mutants: `killpg` still sent after the reap; no warn; the warn without the pgid.
#[skuld::test]
fn dropping_a_foreign_reaped_process_group_child_warns_with_the_pgid(#[fixture(stray_signal)] _stray: &Group) {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let child = session(&["true"]).spawn().expect("spawn");
    let pid = child.pid();
    crate::test_child::reaped_elsewhere::reap_behind(pid);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "a reaped root's number may name another group: no killpg"
    );
    assert_eq!(
        teardowns.count(),
        0,
        "a reaped root is neither killed nor waited for by pid"
    );
    let warns = drop_warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn, got {warns:?}");
    let (level, text) = &warns[0];
    assert_eq!(*level, log::Level::Warn);
    assert!(text.contains(&format!("pgid {pid}")), "the warn names the pgid: {text}");
    assert!(
        text.contains("so this drop does not") && text.contains("by this drop"),
        "the drop calls itself a drop: {text}"
    );
}

/// The same skip in the teardown a helper runs after its failed run is worded as that teardown,
/// under its own label, not as a drop.
///
/// Mutant: the shared text says "this drop", or the label is `Child::drop`.
#[skuld::test]
fn tearing_down_a_foreign_reaped_process_group_child_after_a_failed_run_does_not_call_itself_a_drop(
    #[fixture(stray_signal)] _stray: &Group,
) {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let _recorder = record_kill_group();
    let child = session(&["true"]).spawn().expect("spawn");
    crate::test_child::reaped_elsewhere::reap_behind(child.pid());

    let mark = crate::log_capture::mark();
    let (fate, handed_back) =
        crate::test_child::tear_down_holding(child, (), crate::child::owned::teardown::Disposition::HandBack);

    assert!(handed_back.is_none(), "the teardown handed the child back");
    assert_eq!(fate, crate::error::ChildFate::Gone, "nothing of ours reaped it");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "the root is already reaped");
    assert_eq!(warns.len(), 1, "exactly one warn, got {warns:?}");
    let text = &warns[0].1;
    assert!(
        text.starts_with("teardown after a failed run: the root is already reaped"),
        "{text}"
    );
    assert!(
        text.contains("so this teardown does not") && text.contains("by this teardown") && !text.contains("drop"),
        "{text}"
    );
}

/// The warn is for the skip only. Mutant: the reaped test is inverted or dropped, so a running
/// root is skipped too.
#[skuld::test]
fn dropping_a_running_process_group_child_still_kills_the_group_and_does_not_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let (child, stdin) = session_blocker();
    let blocker = release_at_drop_kill(stdin);
    let pid = child.pid();

    let mark = crate::log_capture::mark();
    drop(child);

    recorder.assert_killed_only(pid as i32);
    blocker.assert_killed();
    assert_eq!(teardowns.count(), 1, "an unreaped root is killed and reaped");
    assert_eq!(drop_warns_since(mark), []);
}

/// A root that exited but is not reaped is a zombie: it still pins its group number, so the group
/// kill is safe and still reaches the descendants. Mutant: reaped judged with `try_wait`, which
/// reaps the zombie and then skips.
#[skuld::test]
fn dropping_an_exited_but_unreaped_process_group_child_still_kills_the_group() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let (child, stdin) = session_blocker();
    let pid = child.pid();
    child.kill().expect("kill the root");
    drop(stdin);
    crate::test_child::assert_zombie_sigkilled("the root", pid);

    let mark = crate::log_capture::mark();
    drop(child);

    recorder.assert_killed_only(pid as i32);
    assert_eq!(drop_warns_since(mark), []);
}

/// Real `killpg`: `kill_tree()` before `wait()` ends a descendant that outlives the root.
#[skuld::test]
fn kill_tree_before_wait_ends_a_descendant_of_an_exited_root() {
    let (child, mut pipes) = spawn_cat_tree();

    child.kill_tree().expect("kill_tree");
    crate::test_child::write_to_possibly_dead_stdin(&mut pipes.stdin, b"x");
    let mut echoed = [0u8; 1];
    let n = pipes.stdout.read(&mut echoed).expect("EOF once the cat is gone");
    assert_eq!(n, 0, "kill_tree must end the cat");
    child.wait().expect("reap the root");
}

/// For a bare process group below Linux 6.9, and for a macOS fd marker: after `wait()` the root is
/// still a zombie that pins its group's number, so the drop kills the group by it and ends the
/// descendant.
///
/// Mutant: a wait consumes the zombie, so the number is unproven and the drop sends nothing.
#[skuld::test]
fn drop_after_wait_ends_a_descendant_of_a_waited_root() {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let (child, mut pipes) = spawn_cat_tree();
    child.wait().expect("the root's exit is seen");
    drop(child);

    crate::test_child::write_to_possibly_dead_stdin(&mut pipes.stdin, b"x");
    let mut echoed = [0u8; 1];
    let n = pipes.stdout.read(&mut echoed).expect("EOF once the cat is gone");
    assert_eq!(n, 0, "the drop must end the cat");
    let mut rest = Vec::new();
    pipes
        .stderr
        .read_to_end(&mut rest)
        .expect("stderr reaches EOF once the cat is gone");
}

/// A `TreeWalk` proves its root still holds its pid before it walks, as a tree call's does. A reaped
/// root fails that proof, so the drop walks nothing (the recorder notes a walk only once the proof
/// passed) and warns that no walk ran. Mutant: the reaped `TreeWalk` still walks. Not macOS: there a
/// `TreeWalk` root is an fd marker without a group, which
/// `fd_marker_without_a_group_drop_after_a_foreign_reap_only_sweeps_the_marker_holders` pins.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn dropping_a_foreign_reaped_tree_walk_child_walks_nothing_and_warns_that_no_walk_ran(
    #[fixture(stray_signal)] _stray: &Group,
) {
    crate::log_capture::install();
    let walks = record_walks();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(["true"]);
    cmd.contain_with(ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn");
    crate::test_child::reaped_elsewhere::reap_behind(child.pid());

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(
        walks.walked(),
        Vec::<u32>::new(),
        "a reaped root's number names no tree"
    );
    let warns = drop_walk_warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn, got {warns:?}");
    let (level, text) = &warns[0];
    assert_eq!(*level, log::Level::Warn);
    assert!(
        text.contains("no walk ran and nothing was killed"),
        "the warn says no walk ran: {text}"
    );
}

/// Positive control for the recorder above, and the warn's other half: a running `TreeWalk` root
/// is walked, and nothing is warned. Mutant: the reaped test is inverted or dropped.
#[skuld::test]
fn dropping_a_running_tree_walk_child_walks_from_its_pid_and_does_not_warn() {
    crate::log_capture::install();
    let walks = record_walks();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.contain_with(ContainMode::TreeWalk);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    let blocker = release_at_drop_kill(child.stdin().expect("stdin pipe"));
    let pid = child.pid();

    let mark = crate::log_capture::mark();
    drop(child);

    // A macOS fd marker walks on every pass of its sweep, so more than once is fine.
    let walked = walks.walked();
    assert!(!walked.is_empty() && walked.iter().all(|w| *w == pid), "{walked:?}");
    assert_eq!(drop_warns_since(mark), []);
    blocker.assert_killed();
}

/// Linux: a `TreeWalk` root whose handle cannot say whether it is reaped is walked and killed by the
/// drop all the same: the walk proves its root itself, so the unanswered state skips nothing. Mutant:
/// the walk is skipped on `Unknown` (off macOS), as the group mechanisms skip a number they cannot
/// trust.
#[cfg(target_os = "linux")]
#[skuld::test]
fn dropping_a_tree_walk_child_whose_handle_cannot_say_still_walks_from_its_pid() {
    crate::log_capture::install();
    let walks = record_walks();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.contain_with(ContainMode::TreeWalk);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    let blocker = release_at_drop_kill(child.stdin().expect("stdin pipe"));
    let pid = child.pid();
    let fake = child
        .proc
        .script_over(|f| f.peeks([Err(std::io::Error::other("forced peek failure"))]));

    drop(child);

    fake.assert_peeks_exhausted();
    let walked = walks.walked();
    assert!(!walked.is_empty() && walked.iter().all(|w| *w == pid), "{walked:?}");
    blocker.assert_killed();
}

/// An `Unknown` read of the root's number means the root is not known to be reaped: the drop kills as
/// for any unreaped root, and says the read failed. Mutant: `Unknown` is treated as reaped.
#[skuld::test]
fn dropping_an_unreaped_child_whose_number_reads_unknown_kills_and_logs_the_failed_read() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let (mut child, stdin) = session_blocker();
    let blocker = release_at_drop_kill(stdin);
    let pid = child.pid();
    let fake = child.proc.script_over(|f| {
        f.number_reads([(
            crate::identity::Resolved::Unknown,
            crate::identity::UnknownCause::default(),
        )])
    });

    let mark = crate::log_capture::mark();
    drop(child);

    fake.assert_number_reads_exhausted();
    recorder.assert_killed_only(pid as i32);
    blocker.assert_killed();
    assert_eq!(teardowns.count(), 1);
    assert_eq!(drop_warns_since(mark), []);
    let reads = crate::log_capture::records_since_on_current_thread(mark, "could not be read");
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert_eq!(reads[0].0, log::Level::Debug);
    assert!(reads[0].1.contains(&format!("{pid}")), "{reads:?}");
}

/// A root reaped by someone else is seen through its number. Mutant: the identity read dropped.
#[skuld::test]
fn dropping_a_foreign_reaped_process_group_child_sends_no_killpg(#[fixture(stray_signal)] _stray: &Group) {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let (child, stdin) = session_blocker();
    let pid = child.pid();
    child.kill().expect("kill the root");
    drop(stdin);
    crate::test_child::assert_zombie_sigkilled("the root", pid);
    let mut status = 0;
    // SAFETY: `pid` is this test's own zombie child. This plays the application that reaps it.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new());
    assert_eq!(
        teardowns.count(),
        0,
        "the number may belong to another child by now: no kill and no wait by pid"
    );
    assert_eq!(drop_warns_since(mark).len(), 1);
}

/// A root this handle's wait saw exit, and a foreign reaper then took, is `Gone` to the teardown,
/// not `Reaped`: the handle's own consume is at its end, so it consumed nothing, and no send went.
///
/// Mutant: the fate is `Reaped` for any root whose exit the handle's wait recorded.
#[skuld::test]
fn tearing_down_a_waited_root_a_foreign_reaper_then_took_is_gone_not_reaped(#[fixture(stray_signal)] _stray: &Group) {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let _recorder = record_kill_group();
    let child = session(&["true"]).spawn().expect("spawn");
    child.wait().expect("wait");
    crate::test_child::reaped_elsewhere::reap_behind(child.pid());

    let (fate, handed_back) =
        crate::test_child::tear_down_holding(child, (), crate::child::owned::teardown::Disposition::HandBack);

    assert!(handed_back.is_none(), "the teardown handed the child back");
    assert_eq!(fate, crate::error::ChildFate::Gone, "this handle reaped nothing");
}

/// A failed elevated spawn's cleanup kills the tree, then kills and reaps the root, then drops the
/// handle: an internal path with no call order for the user to change, and a handle the caller never
/// received. It is disarmed, so the drop says nothing at all.
///
/// Mutant: the cleanup leaves the handle armed (the drop logs its skip).
#[skuld::test]
fn a_failed_elevated_spawns_cleanup_drops_its_handle_silently() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let (child, stdin) = session_blocker();
    let blocker = release_between_kill_and_wait(stdin);
    let pid = child.pid();

    let mark = crate::log_capture::mark();
    let (err, fate) = super::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "no password".into(),
            source: None,
        }),
    )
    .expect_err("the password write failed")
    .expect_may_have_started_with();

    assert!(matches!(err, crate::error::Error::Elevation { .. }), "{err:?}");
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "the group's kill and the root's reap"
    );
    recorder.assert_killed_only(pid as i32);
    blocker.assert_killed();
    assert_eq!(crate::log_capture::records_since_on_current_thread(mark, WARN), []);
}

/// The same for a `TreeWalk` whose walk left a descendant, which is an `Err` of its own variant. Not
/// on macOS, where `TreeWalk` mode is an fd marker (the test above).
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn drop_after_an_incomplete_tree_walk_kill_and_wait_still_warns(#[fixture(stray_signal)] _stray: &Group) {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Descendant);
    let left = child
        .kill_tree()
        .expect_err("a tree walk that left a member is an error");
    assert!(matches!(left, crate::error::Error::MembersLeft { .. }), "{left:?}");
    // Released after the kill so a no-op kill fails the assertion, not the wait.
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));

    let mark = crate::log_capture::mark();
    drop(child);

    let records = drop_walk_warns_since(mark);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn);
}

/// The handle remembers a member a walk left: its backstop killed the root, which stays a zombie
/// until it is reaped, so a second walk from it finds no member. The member's identity was never
/// read, so the second `kill_tree` reports it again instead of settling the tree as killed.
///
/// Mutant: a walk that finds less settles the tree as killed.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_second_kill_tree_after_a_walk_left_a_member_reports_it_again_and_does_not_mark_the_tree(
    #[fixture(stray_signal)] _stray: &Group,
) {
    use crate::containment::treewalk::fault::LeftBehind;
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Descendant);
    let first = child.kill_tree().expect_err("the walk left a member");
    let second = child
        .kill_tree()
        .expect_err("the member the first walk left is not shown killed");
    let pid_of = |error: &crate::error::Error| match error.left_members()[0] {
        crate::error::Error::MemberNotKilled { pid, .. } => *pid,
        other => panic!("expected MemberNotKilled, got {other:?}"),
    };
    assert_eq!(pid_of(&second), pid_of(&first), "{first:?}, {second:?}");
    assert!(!child.tree.is_killed(), "a member was left");
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));
}

/// The drop is the second reader of what a walk left. After a `kill_tree` that left a member, the
/// root is still an unreaped zombie, so the drop kills as usual, and its walk finds nothing: the
/// drop still warns of the member, once.
///
/// Mutant: the drop's walk settles the tree as killed and warns nothing.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_drop_after_a_kill_tree_that_left_a_member_warns_of_it(#[fixture(stray_signal)] _stray: &Group) {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Descendant);
    child.kill_tree().expect_err("the walk left a member");

    let mark = crate::log_capture::mark();
    drop(child);

    let records = crate::log_capture::records_since_on_current_thread(mark, "was not killed");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn);
    drop(stdin);
}

/// The handle's memory of a member outlives the root's reap: once `wait` has reaped the root, a
/// `kill_tree` has no root to walk from, and still answers with the member the first one left, not
/// with the gone root.
///
/// Mutant: the held members are retried only when the new kill ran.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_kill_tree_after_wait_reports_the_member_an_earlier_kill_left(#[fixture(stray_signal)] _stray: &Group) {
    use crate::containment::treewalk::fault::LeftBehind;
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Descendant);
    let first = child.kill_tree().expect_err("the walk left a member");
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));

    let second = child
        .kill_tree()
        .expect_err("the root is gone, and the member is not shown killed");

    let pid_of = |error: &crate::error::Error| match error.left_members()[0] {
        crate::error::Error::MemberNotKilled { pid, .. } => *pid,
        other => panic!("expected MemberNotKilled, got {other:?}"),
    };
    assert_eq!(pid_of(&second), pid_of(&first), "{first:?}, {second:?}");
    assert!(!child.tree.is_killed(), "a member was left");
}

/// The drop after `wait` is the same reader: the root is reaped, so the drop's walk has no root, and
/// it still warns of the member a `kill_tree` left, once.
///
/// Mutant: the drop's reaped path does not retry the held members.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_drop_after_a_kill_tree_that_left_a_member_and_a_wait_warns_of_it(#[fixture(stray_signal)] _stray: &Group) {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Descendant);
    child.kill_tree().expect_err("the walk left a member");
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));

    let mark = crate::log_capture::mark();
    drop(child);

    let records = crate::log_capture::records_since_on_current_thread(mark, "was not killed");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn);
}

/// A walk that saw the root running and left it, whose backstop then killed it, is `Ok` for the
/// caller but leaves the tree unvouched (the root may have forked first). The drop walks as a tree
/// call does and finds no root, so it warns that the tree could not be walked from the gone root and
/// what it forked is unknown, and speaks of no members. Mutant: the tree is marked killed.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn drop_after_a_walk_that_left_only_the_root_and_a_backstop_kill_warns_of_an_unvouched_tree(
    #[fixture(stray_signal)] _stray: &Group,
) {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Root);
    child.kill_tree().expect("the backstop killed the only member left");
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));

    let mark = crate::log_capture::mark();
    drop(child);

    let warns = drop_walk_warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn, "{warns:?}");
    assert!(warns[0].1.contains("what it forked is unknown"), "{warns:?}");
    assert!(!warns[0].1.contains("members"), "{warns:?}");
}

/// A `kill_tree` on a `TreeWalk` whose root this handle reaped finds no root to walk from, so it kills
/// nothing: it is `Unassessable`, and does not mark the tree killed, so the drop still warns that no
/// walk ran, as it would without the call.
///
/// Mutants: a walk that found no root counts as a kill that ran; it answers `Ok`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn kill_tree_on_a_tree_walk_whose_root_is_reaped_is_unassessable_and_does_not_mark_the_tree_killed(
    #[fixture(stray_signal)] _stray: &Group,
) {
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker();
    drop(stdin);
    child.wait().expect("reap the root");

    let err = child
        .kill_tree()
        .expect_err("a root that is gone leaves no tree to walk: nothing was killed");
    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");

    assert!(!child.tree.is_killed(), "a walk that found no root killed nothing");
    let mark = crate::log_capture::mark();
    drop(child);
    let records = drop_walk_warns_since(mark);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn, "{records:?}");
}

/// A drop whose walk leaves a descendant reports it once, after the root's kill; the root is killed
/// and reaped. Mutant: the walk's per-member warn is kept beside the drop's.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_drop_whose_walk_leaves_a_descendant_warns_once_and_kills_the_root() {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Descendant);
    let blocker = release_between_kill_and_wait(stdin);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let mark = crate::log_capture::mark();
    drop(child);

    blocker.assert_killed();
    let records = crate::log_capture::records_since_on_current_thread(mark, "was not killed");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn);
    let drop_records = crate::log_capture::warns_since(mark, "Child::drop");
    assert_eq!(drop_records.len(), 1, "one report of the event: {drop_records:?}");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "the drop reaped the root"
    );
}

/// A drop whose walk leaves only the root, which the drop's own kill of the root then ends, does not
/// call the root "left behind", but warns once that the tree could not be vouched for: the walk saw
/// the root running, and no later settlement is left to warn. Mutants: the drop reports the walk's
/// error before the root's kill; the drop is silent.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_drop_whose_walk_leaves_only_the_root_warns_it_could_not_vouch_for_the_tree() {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Root);
    let blocker = release_between_kill_and_wait(stdin);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let mark = crate::log_capture::mark();
    drop(child);

    blocker.assert_killed();
    let warns = crate::log_capture::warns_since(mark, "Child::drop");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("could not be vouched for"), "{warns:?}");
    assert!(!warns[0].contains("members"), "{warns:?}");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "the drop reaped the root"
    );
}

/// A walk that left a descendant and the root, then the root's kill by the handle: the report names
/// the descendant alone, for `kill_tree` and for the drop. The root is dead, so a line about it would
/// be stale.
///
/// Mutant: the walk warns of every member it left, the root included, before the root's kill.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn kill_tree_after_a_walk_that_left_a_descendant_and_the_root_names_the_descendant_alone(
    #[fixture(stray_signal)] _stray: &Group,
) {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::RootAndDescendant);
    let root = child.pid();
    let mark = crate::log_capture::mark();

    let err = child.kill_tree().expect_err("a descendant was left");

    assert!(
        matches!(err.left_members()[..], [crate::error::Error::MemberNotKilled { pid, .. }] if *pid == root.wrapping_add(1)),
        "{err:?}"
    );
    let stale = crate::log_capture::records_since_on_current_thread(mark, &format!("pid {root} was not killed"));
    assert_eq!(stale, [], "the root was killed by the handle");
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));
}

/// [`kill_tree_after_a_walk_that_left_a_descendant_and_the_root_names_the_descendant_alone`] for the
/// drop: one report, of the descendant.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_drop_whose_walk_leaves_a_descendant_and_the_root_names_the_descendant_alone(
    #[fixture(stray_signal)] _stray: &Group,
) {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (child, stdin) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::RootAndDescendant);
    let blocker = release_between_kill_and_wait(stdin);
    let root = child.pid();
    let mark = crate::log_capture::mark();

    drop(child);

    blocker.assert_killed();
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(warns.len(), 1, "one report of the event: {warns:?}");
    let text = &warns[0];
    assert!(
        text.contains(&format!("pid {} was not killed", root.wrapping_add(1))),
        "{text}"
    );
    assert!(!text.contains(&format!("pid {root} was not killed")), "{text}");
}

/// A cgroup names its tree without the root's number, so the reaped root does not stop the drop's
/// kill.
/// Mutant: the skip applied to every mechanism, which logs the warn here.
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_drop_after_wait_still_kills_the_tree_and_does_not_warn(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let mut cmd = root_that_leaves(ROOT_LEAVING_A_CAT_THAT_SAYS_EOF);
    cmd.contain_with(ContainMode::Strongest);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::CgroupV2);
    let mut started = [0u8; 8];
    let mut stdout = child.stdout().expect("stdout pipe");
    stdout.read_exact(&mut started).expect("read `started`");
    let stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    child.wait().expect("reap the root");
    // Released as the kill returns; see [`KillRelease`].
    let release = crate::child::front_cgroup_tests::release_after_cgroup_kill(stdin);

    let mark = crate::log_capture::mark();
    drop(child);

    release.assert_killed();
    assert_eq!(drop_warns_since(mark), []);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .expect("the cgroup kill ended the cat, closing stderr");
    let mut said = Vec::new();
    stdout.read_to_end(&mut said).expect("every holder of stdout is gone");
    crate::child::front_cgroup_tests::assert_nothing_ended_by_itself(&said);
}

/// A root that exited and is not reaped leaves a descendant in its leaf, and the drop's `cgroup.kill`
/// ends it: the kill that an unwind from a failed tree helper (`tests/common`'s
/// `spawn_tree_ending_a_failure`) leaves to the drop. Mutant: the drop's `cgroup.kill` write sends
/// nothing.
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_drop_of_an_exited_unreaped_root_kills_its_orphaned_descendant(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let mut cmd = root_that_leaves(ROOT_LEAVING_A_CAT_THAT_SAYS_EOF);
    cmd.contain_with(ContainMode::Strongest);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::CgroupV2);
    let mut started = [0u8; 8];
    let mut stdout = child.stdout().expect("stdout pipe");
    stdout.read_exact(&mut started).expect("read `started`");
    let stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    crate::test_child::wait_until_zombie(child.pid());
    // Released as the kill returns; see [`KillRelease`].
    let release = crate::child::front_cgroup_tests::release_after_cgroup_kill(stdin);

    let mark = crate::log_capture::mark();
    drop(child);

    release.assert_killed();
    assert_eq!(drop_warns_since(mark), []);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .expect("the cgroup kill ended the cat, closing stderr");
    let mut said = Vec::new();
    stdout.read_to_end(&mut said).expect("every holder of stdout is gone");
    crate::child::front_cgroup_tests::assert_nothing_ended_by_itself(&said);
}

/// A macOS fd marker names its marker holders by identity, so after a foreign reap the drop still
/// sweeps them and skips every channel that names the root's number: the `killpg`, the ppid walk and
/// the root's own kill. Mutants: the sweep skipped too; the `killpg` or the walk still run.
#[cfg(target_os = "macos")]
#[skuld::test]
fn fd_marker_drop_after_a_foreign_reap_sweeps_the_marker_holders_but_names_nothing_by_the_roots_number() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let walks = record_walks();
    let sweeps = crate::containment::fdmarker::fault::record_holder_kills();
    let mut cmd = root_that_leaves_a_cat();
    cmd.contain_with(ContainMode::Strongest);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::FdMarker);
    let mut started = [0u8; 8];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut started)
        .expect("read `started`");
    let _stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    crate::test_child::reaped_elsewhere::reap_behind(child.pid());

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new(), "no killpg after the reap");
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no ppid walk from the reaped root");
    assert!(!sweeps.killed().is_empty(), "the marker-holder sweep still runs");
    assert_eq!(drop_warns_since(mark).len(), 1);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .expect("the sweep ended the cat, closing stderr, with stdin still held");
}

/// A root that is alive when its marker is attached, then killed and reaped behind its handle's
/// back. A root that exits before the attach has no identity to walk from (`Marker::root` is
/// `None`), which would make a "no walk" assertion vacuous.
#[cfg(target_os = "macos")]
fn reaped_blocker_root(mode: ContainMode) -> (u32, crate::Child) {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    cmd.contain_with(mode);
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    assert_eq!(child.containment(), Containment::FdMarker);
    let pid = child.pid();
    child.kill().expect("kill the root");
    // Released after the kill: a `kill` that sent nothing fails the assertion, not the reap.
    drop(stdin);
    crate::test_child::assert_killed("the root", crate::test_child::reaped_elsewhere::reap_behind_status(pid));
    (pid, child)
}

/// An fd marker with no group (`TreeWalk` mode): after a foreign reap nothing but the holder sweep
/// runs. A reaper elsewhere leaves no read of the root's number that shows the walk from it empty,
/// so the drop warns once that it did not walk.
///
/// Mutant: the walk still runs from the reaped root's pid.
#[cfg(target_os = "macos")]
#[skuld::test]
fn fd_marker_without_a_group_drop_after_a_foreign_reap_only_sweeps_the_marker_holders(
    #[fixture(stray_signal)] _stray: &Group,
) {
    crate::log_capture::install();
    let walks = record_walks();
    let (pid, child) = reaped_blocker_root(ContainMode::TreeWalk);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(walks.walked(), Vec::<u32>::new(), "no ppid walk from the reaped root");
    let warns = drop_warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0]
            .1
            .contains(&format!("walk the process table from the root's pid (root pid {pid})")),
        "{warns:?}"
    );
}

/// The same with a group: no `killpg`, no walk, one warn. Mutant: the walk still runs for a marker
/// that has a group.
#[cfg(target_os = "macos")]
#[skuld::test]
fn fd_marker_with_a_group_drop_after_a_foreign_reap_neither_signals_the_group_nor_walks(
    #[fixture(stray_signal)] _stray: &Group,
) {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let walks = record_walks();
    let (pid, child) = reaped_blocker_root(ContainMode::Strongest);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new(), "no killpg after the reap");
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no ppid walk from the reaped root");
    let warns = drop_warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].1.contains(&format!("pgid {pid}")), "{warns:?}");
}

/// The decision from its inputs, over every handle-peek and number-read combination. Mutants: the
/// handle's peek ignored; `Unknown` read as reaped; the different-process arm dropped.
#[skuld::test]
fn a_root_is_reaped_by_its_handle_peek_or_by_its_number_reading_gone_or_different() {
    use crate::identity::{ProcessId, Resolved};
    let id = ProcessId::from_parts_for_test(4242, crate::identity::Key::for_test(7));
    let other = id.with_other_value();
    for (handle_reaped, now, reaped) in [
        (true, Resolved::Found(id), true),
        (true, Resolved::Found(other), true),
        (true, Resolved::Gone, true),
        (true, Resolved::Unknown, true),
        (false, Resolved::Found(id), false),
        (false, Resolved::Found(other), true),
        (false, Resolved::Gone, true),
        (false, Resolved::Unknown, false),
    ] {
        assert_eq!(
            super::root_reaped(handle_reaped, Some(id), now),
            reaped,
            "handle_reaped {handle_reaped}, now {now:?}"
        );
    }
}

/// A root with no identity has nothing its number can be compared with: the number shows it reaped
/// only by naming no process, and the handle decides otherwise.
///
/// Mutants: a number that names a process reads as another process; a number that names none reads
/// as reaped no more.
#[skuld::test]
fn a_root_with_no_identity_is_reaped_by_its_handle_peek_or_a_number_naming_no_process() {
    use crate::identity::{ProcessId, Resolved};

    let other = ProcessId::from_parts_for_test(4242, crate::identity::Key::for_test(7));
    for (handle_reaped, now, reaped) in [
        (true, Resolved::Found(other), true),
        (true, Resolved::Gone, true),
        (true, Resolved::Unknown, true),
        (false, Resolved::Found(other), false),
        (false, Resolved::Gone, true),
        (false, Resolved::Unknown, false),
    ] {
        assert_eq!(
            super::root_reaped(handle_reaped, None, now),
            reaped,
            "handle_reaped {handle_reaped}, now {now:?}"
        );
    }
}
