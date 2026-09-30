//! `Child::drop` once the root is reaped: a kill that names the tree by the root's number
//! (`killpg`, a ppid walk from the root's pid) could hit an unrelated process that reused the
//! number, so the drop skips it and warns instead.
//!
//! The recorder tests replace `killpg` with a recorder (`unix::fault::record_kill_group`) and
//! record the ppid walks (`treewalk::fault::record_walks`), so a mutant that still sends either
//! never reaches an unrelated process. The behavioural tests use real groups of this test's own
//! children, all signalled before their root is reaped.

use std::io::Read as _;

use crate::child::fault::record_root_teardowns;
use crate::command::Command;
use crate::containment::treewalk::fault::record_walks;
use crate::containment::unix::fault::record_kill_group;
use crate::{ContainMode, Containment, Stdio};

/// Every record of the drop's warn starts with this.
const WARN: &str = "Child::drop: the root is already reaped";

/// What `ContainMode::Session` resolves to here: macOS puts every mode but `TreeWalk` behind an fd
/// marker that also carries the group; elsewhere it is a bare process group.
#[cfg(target_os = "macos")]
const SESSION_CONTAINMENT: Containment = Containment::FdMarker;
#[cfg(not(target_os = "macos"))]
const SESSION_CONTAINMENT: Containment = Containment::Session;

/// A command in its own session: `Attached::ProcessGroup` off macOS, `Attached::FdMarker` on it.
fn session(argv: &[&str]) -> Command {
    let mut cmd = Command::new();
    cmd.args(argv.iter().copied());
    cmd.contain_with(ContainMode::Session);
    cmd
}

/// Root `sh` (which points a background job's stdin at `/dev/null` unless told otherwise, hence the
/// `exec 3<&0`) prints `started` and exits, leaving a `cat` in its group. The `cat` reads the stdin
/// pipe, which the test holds, and echoes it to stdout, so a round trip proves it alive
/// ([`assert_echoes`](crate::test_child::assert_echoes)); it ends only when killed or when the
/// test closes stdin. It holds the stderr pipe's write end: stderr reaches EOF exactly when `cat`
/// is gone.
fn root_that_leaves_a_cat() -> Command {
    let mut cmd = session(&["sh", "-c", "exec 3<&0; cat <&3 3<&- & echo started; exit 0"]);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    cmd.stderr(Stdio::pipe_out()).expect("stderr pipe");
    cmd
}

/// The pipes of a [`spawn_cat_tree`]: the `cat`'s stdin, and its stdout and stderr.
#[cfg_attr(
    target_os = "macos",
    allow(dead_code, reason = "the echo round trip is the non-macOS test's")
)]
struct CatPipes {
    stdin: std::io::PipeWriter,
    stdout: std::io::PipeReader,
    stderr: std::io::PipeReader,
}

/// Spawn [`root_that_leaves_a_cat`] and read its `started`: the `cat` is forked, and the root is
/// exiting, a zombie, or already reaped by the spawn (`SharedChild::new` reaps a root that has
/// exited by then).
fn spawn_cat_tree() -> (crate::Child, CatPipes) {
    let mut child = root_that_leaves_a_cat().spawn().expect("spawn");
    assert_eq!(child.containment(), SESSION_CONTAINMENT);
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

/// Mutants: `killpg` still sent after the reap; no warn; the warn without the pgid.
#[test]
fn dropping_a_waited_on_process_group_child_sends_no_killpg_and_warns_with_the_pgid() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let child = session(&["true"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child.wait().expect("reap the root");

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
        text.contains("kill_tree()") && text.contains("wait()"),
        "the warn says how to end descendants: {text}"
    );
}

/// The warn is for the skip only. Mutant: the reaped test is inverted or dropped, so a running
/// root is skipped too.
#[test]
fn dropping_a_running_process_group_child_still_kills_the_group_and_does_not_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let mut cmd = session(&["sleep", "300"]);
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    drop(child);

    recorder.assert_killed_only(pid as i32);
    assert_eq!(teardowns.count(), 1, "an unreaped root is killed and reaped");
    assert_eq!(drop_warns_since(mark), []);
}

/// A root that exited but is not reaped is a zombie: it still pins its group number, so the group
/// kill is safe and still reaches the descendants. Mutant: reaped judged with `try_wait`, which
/// reaps the zombie and then skips.
#[test]
fn dropping_an_exited_but_unreaped_process_group_child_still_kills_the_group() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    crate::test_child::wait_until_zombie(pid);

    let mark = crate::log_capture::mark();
    drop(child);

    recorder.assert_killed_only(pid as i32);
    assert_eq!(drop_warns_since(mark), []);
}

/// Real `killpg`: `kill_tree()` before `wait()` ends a descendant that outlives the root.
#[test]
fn kill_tree_before_wait_ends_a_descendant_of_an_exited_root() {
    let (child, mut pipes) = spawn_cat_tree();

    child.kill_tree().expect("kill_tree");
    let mut rest = Vec::new();
    pipes
        .stderr
        .read_to_end(&mut rest)
        .expect("stderr reaches EOF once the cat is dead");
    child.wait().expect("reap the root");
}

/// The contract this fix sets for a bare process group: after `wait()` the drop leaves the
/// descendant running, proven by an echo round trip; the test then ends it by closing its stdin.
///
/// Not on macOS: there the tree is an fd marker, whose drop still sweeps the marker holders by
/// identity after a reap and so ends this descendant. That path is
/// `fd_marker_drop_after_wait_sweeps_the_marker_holders_but_sends_no_killpg`.
#[cfg(not(target_os = "macos"))]
#[test]
fn drop_after_wait_leaves_a_descendant_running_until_it_is_ended_explicitly() {
    let (child, mut pipes) = spawn_cat_tree();
    child.wait().expect("reap the root");
    drop(child);

    crate::test_child::assert_echoes(&mut pipes.stdin, &mut pipes.stdout);

    drop(pipes.stdin);
    let mut rest = Vec::new();
    pipes
        .stderr
        .read_to_end(&mut rest)
        .expect("stderr reaches EOF once the cat is gone");
}

/// A `TreeWalk` names its tree by ppid edges from the root's number. After the reap the only
/// processes with that ppid belong to whoever reused the number, so the drop walks nothing and
/// warns naming the root. Mutant: the reaped `TreeWalk` still walks.
#[test]
fn dropping_a_waited_on_tree_walk_child_walks_nothing_and_warns_with_the_root_pid() {
    crate::log_capture::install();
    let walks = record_walks();
    let mut cmd = Command::new();
    cmd.args(["true"]);
    cmd.contain_with(ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    child.wait().expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(
        walks.walked(),
        Vec::<u32>::new(),
        "a reaped root's number names no tree"
    );
    let warns = drop_warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn, got {warns:?}");
    let (level, text) = &warns[0];
    assert_eq!(*level, log::Level::Warn);
    assert!(
        text.contains(&format!("root pid {pid}")),
        "the warn names the root: {text}"
    );
    assert!(
        text.contains("kill_tree()"),
        "the warn says how to end descendants: {text}"
    );
}

/// Positive control for the recorder above, and the warn's other half: a running `TreeWalk` root
/// is walked, and nothing is warned. Mutant: the reaped test is inverted or dropped.
#[test]
fn dropping_a_running_tree_walk_child_walks_from_its_pid_and_does_not_warn() {
    crate::log_capture::install();
    let walks = record_walks();
    let mut cmd = Command::new();
    cmd.args(["sleep", "300"]);
    cmd.contain_with(ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    drop(child);

    // A macOS fd marker walks on every pass of its sweep, so more than once is fine.
    let walked = walks.walked();
    assert!(!walked.is_empty() && walked.iter().all(|w| *w == pid), "{walked:?}");
    assert_eq!(drop_warns_since(mark), []);
}

/// A `sleep` root, killed and then waited for, so that only `wait()` sets the own-reap flag.
fn waited_on_sleep_root() -> (u32, crate::Child) {
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().expect("reap the root");
    (pid, child)
}

/// This handle's own reap is exact, and the OS refusing to name the root's number (`Unknown`, as
/// under a `/proc` whose view is another pid namespace's) must not read as "not reaped". A live
/// process on the number would be needed to provoke a real `Unknown`, so the seam forces the read.
/// Mutants: the own-reap flag is ignored; `wait()` does not set it.
#[test]
fn dropping_a_waited_on_child_whose_number_reads_unknown_still_sends_no_killpg() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let (_, child) = waited_on_sleep_root();
    let _unknown = super::fault::force_next_root_read(crate::identity::Resolved::Unknown);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "this handle reaped the root: no killpg"
    );
    assert_eq!(teardowns.count(), 0);
    assert_eq!(drop_warns_since(mark).len(), 1);
}

/// With no own reap, an `Unknown` read means the root is not known to be reaped: the drop kills as
/// for any unreaped root, and says the read failed. Mutant: `Unknown` is treated as reaped.
#[test]
fn dropping_an_unreaped_child_whose_number_reads_unknown_kills_and_logs_the_failed_read() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    let _unknown = super::fault::force_next_root_read(crate::identity::Resolved::Unknown);

    let mark = crate::log_capture::mark();
    drop(child);

    recorder.assert_killed_only(pid as i32);
    assert_eq!(teardowns.count(), 1);
    assert_eq!(drop_warns_since(mark), []);
    let reads = crate::log_capture::records_since_on_current_thread(mark, "could not be read");
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert_eq!(reads[0].0, log::Level::Debug);
    assert!(reads[0].1.contains(&format!("{pid}")), "{reads:?}");
}

/// A root reaped by someone else is seen through its number. Mutant: the identity read dropped.
#[test]
fn dropping_a_foreign_reaped_process_group_child_sends_no_killpg() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let teardowns = record_root_teardowns();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    crate::test_child::wait_until_zombie(pid);
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

/// The skip is quiet once this handle has already hard-killed the tree: the warn's own remedy
/// (`kill_tree()` then `wait()`) must not draw it. Mutant: the tree-killed flag is ignored.
#[test]
fn drop_after_kill_tree_and_wait_skips_at_debug_and_does_not_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session(&["true"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill_tree().expect("kill_tree");
    child.wait().expect("reap the root");
    recorder.assert_killed_only(pid as i32);
    let sent = recorder.killed();

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), sent, "the drop sends no further killpg");
    assert_skipped_at_debug(mark);
}

/// `graceful_shutdown_tree` sweeps with `kill_tree` and reaps the root, so its drop is quiet too.
#[test]
fn drop_after_graceful_shutdown_tree_skips_at_debug_and_does_not_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child
        .graceful_shutdown_tree(std::time::Duration::from_secs(60))
        .expect("graceful_shutdown_tree");
    recorder.assert_killed_only(pid as i32);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_skipped_at_debug(mark);
}

/// A failed elevated spawn's cleanup kills the tree, then kills and reaps the root, then drops the
/// handle: an internal path with no call order for the user to change.
#[test]
fn a_failed_elevated_spawns_cleanup_drops_its_handle_at_debug() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let err = super::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Io(std::io::Error::other("no password"))),
    )
    .expect_err("the password write failed");

    assert!(matches!(err, crate::error::Error::Elevation { .. }), "{err:?}");
    recorder.assert_killed_only(pid as i32);
    assert_skipped_at_debug(mark);
}

/// A `kill_tree` that failed may have left members running, so the drop still warns. Mutant: the
/// tree-killed flag is set on the attempt.
#[test]
fn drop_after_a_failed_kill_tree_and_wait_still_warns() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    recorder.fail_with_unassessable();
    let child = session(&["true"]).spawn().expect("spawn");
    child.kill_tree().expect_err("the forced refusal");
    child.wait().expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    let records = drop_warns_since(mark);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn);
}

/// The same for a `TreeWalk` whose walk was incomplete but returned `Ok`. Not on macOS, where
/// `TreeWalk` mode is an fd marker, whose incompleteness is an `Err` (the test above).
#[cfg(not(target_os = "macos"))]
#[test]
fn drop_after_an_incomplete_tree_walk_kill_and_wait_still_warns() {
    crate::log_capture::install();
    let mut cmd = Command::new();
    cmd.args(["sleep", "300"]);
    cmd.contain_with(ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn");
    crate::containment::treewalk::fault::force_incomplete_once();
    child.kill_tree().expect("a tree walk reports Ok");
    child.wait().expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    let records = drop_warns_since(mark);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn);
}

/// Exactly one record of the drop's skip since `mark`, at `debug`.
#[track_caller]
fn assert_skipped_at_debug(mark: usize) {
    let records = drop_warns_since(mark);
    assert_eq!(records.len(), 1, "exactly one skip record, got {records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
}

/// A cgroup names its tree without the root's number, so the reaped root does not stop the drop's
/// kill. Needs a delegated cgroup, so it belongs to the cgroup lane: `COSCA_TEST_CGROUP_DROP` is
/// `0` everywhere else, and the lane gives consent with `COSCA_TEST_CGROUP_DROP_CONSENT=1`.
/// Mutant: the skip applied to every mechanism, which logs the warn here.
#[cfg(target_os = "linux")]
#[test]
fn cgroup_drop_after_wait_still_kills_the_tree_and_does_not_warn() {
    if !crate::test_support::require_group("CGROUP_DROP") {
        return;
    }
    crate::log_capture::install();
    let mut cmd = root_that_leaves_a_cat();
    cmd.contain_with(ContainMode::Strongest);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::CgroupV2);
    let mut started = [0u8; 8];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut started)
        .expect("read `started`");
    let _stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    child.wait().expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(drop_warns_since(mark), []);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .expect("the cgroup kill ended the cat, closing stderr, with stdin still held");
}

/// A macOS fd marker names its marker holders by identity, so after a reap the drop still sweeps
/// them and skips every channel that names the root's number: the `killpg`, the ppid walk and the
/// root's own kill. The macOS counterpart of
/// `drop_after_wait_leaves_a_descendant_running_until_it_is_ended_explicitly`. Mutants: the sweep
/// skipped too; the `killpg` or the walk still run.
#[cfg(target_os = "macos")]
#[test]
fn fd_marker_drop_after_wait_sweeps_the_marker_holders_but_names_nothing_by_the_roots_number() {
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
    child.wait().expect("reap the root");

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

/// A root that is alive when its marker is attached, then killed and reaped. A root that exits
/// before the attach has no identity to walk from (`Marker::root` is `None`), which would make a
/// "no walk" assertion vacuous.
#[cfg(target_os = "macos")]
fn reaped_sleep_root(mode: ContainMode) -> (u32, crate::Child) {
    let mut cmd = Command::new();
    cmd.args(["sleep", "300"]);
    cmd.contain_with(mode);
    let child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::FdMarker);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().expect("reap the root");
    (pid, child)
}

/// An fd marker with no group (`TreeWalk` mode): after a reap nothing but the holder sweep runs.
/// Mutant: the walk or the root kill still run for it.
#[cfg(target_os = "macos")]
#[test]
fn fd_marker_without_a_group_drop_after_wait_only_sweeps_the_marker_holders() {
    crate::log_capture::install();
    let walks = record_walks();
    let (pid, child) = reaped_sleep_root(ContainMode::TreeWalk);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(walks.walked(), Vec::<u32>::new(), "no ppid walk from the reaped root");
    let warns = drop_warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].1.contains(&format!("root pid {pid}")), "{warns:?}");
}

/// The same with a group: no `killpg`, no walk, one warn. Mutant: the walk still runs for a marker
/// that has a group.
#[cfg(target_os = "macos")]
#[test]
fn fd_marker_with_a_group_drop_after_wait_neither_signals_the_group_nor_walks() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let walks = record_walks();
    let (pid, child) = reaped_sleep_root(ContainMode::Strongest);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new(), "no killpg after the reap");
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no ppid walk from the reaped root");
    let warns = drop_warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].1.contains(&format!("pgid {pid}")), "{warns:?}");
}

/// The decision from its inputs, over every own-reap and number-read combination. Mutants: the
/// own-reap input ignored; `Unknown` read as reaped; the different-process arm dropped.
#[test]
fn a_root_is_reaped_by_its_own_reap_or_by_its_number_reading_gone_or_different() {
    use crate::identity::{ProcessId, Resolved};
    let id = ProcessId::from_parts_for_test(4242, 7);
    let other = ProcessId::from_parts_for_test(4242, 8);
    for (own, now, reaped) in [
        (true, Resolved::Found(id), true),
        (true, Resolved::Found(other), true),
        (true, Resolved::Gone, true),
        (true, Resolved::Unknown, true),
        (false, Resolved::Found(id), false),
        (false, Resolved::Found(other), true),
        (false, Resolved::Gone, true),
        (false, Resolved::Unknown, false),
    ] {
        assert_eq!(super::root_reaped(own, id, now), reaped, "own {own}, now {now:?}");
    }
}
