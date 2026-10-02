//! Async twins of `child/drop_reaped_tests.rs`: `cosca::tokio::Child`'s drop once the root is
//! reaped. A pgid-based group kill would name a number that may now belong to an unrelated
//! group, so the drop skips it and warns instead.
//!
//! The recorder replaces `killpg` (`unix::fault::record_kill_group`), so a mutant that still
//! sends it never reaches a real group. The recorder is thread-local and `#[tokio::test]` is
//! current-thread, so the drop's kill runs on the recording thread.

use crate::containment::treewalk::fault::record_walks;
use crate::containment::unix::fault::record_kill_group;
use crate::tokio::child::drop_fault;
use crate::tokio::Command;
use crate::{ContainMode, Containment};

/// Every record of the drop's warn starts with this. It is the sync drop's wording verbatim.
const WARN: &str = "Child::drop: the root is already reaped";

/// What `ContainMode::Session` resolves to here: macOS puts every mode but `TreeWalk` behind an fd
/// marker that also carries the group; elsewhere it is a bare process group.
#[cfg(target_os = "macos")]
const SESSION_CONTAINMENT: Containment = Containment::FdMarker;
#[cfg(not(target_os = "macos"))]
const SESSION_CONTAINMENT: Containment = Containment::Session;

fn session(argv: &[&str]) -> Command {
    let mut cmd = Command::new();
    cmd.args(argv.iter().copied());
    cmd.contain_with(ContainMode::Session);
    cmd
}

fn drop_warns_since(mark: usize) -> Vec<(log::Level, String)> {
    crate::log_capture::records_since_on_current_thread(mark, WARN)
}

/// Mutants: the drop still calls `hard_kill`; `root_reaped` is always false; no warn; the warn
/// without the pgid.
#[skuld::test]
async fn dropping_a_waited_on_process_group_child_sends_no_killpg_and_warns_with_the_pgid() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let root = drop_fault::record();
    let mut child = session(&["true"]).spawn().expect("spawn");
    assert_eq!(child.containment(), SESSION_CONTAINMENT);
    let pid = child.id().pid();
    child.wait().await.expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "a reaped root's number may name another group: no killpg"
    );
    assert_eq!(
        (root.kills(), root.forgets()),
        (0, 0),
        "tokio reaped it; nothing is left to do"
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
#[skuld::test]
async fn dropping_a_running_process_group_child_still_kills_the_group_and_does_not_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let root = drop_fault::record();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    drop(child);

    recorder.assert_killed_only(pid as i32);
    assert_eq!((root.kills(), root.forgets()), (1, 0));
    assert_eq!(drop_warns_since(mark), []);
}

/// A root that exited but is not reaped is a zombie: it still pins its group number, so the group
/// kill is safe. Mutant: reaped judged with `try_wait`, which reaps the zombie and then skips.
#[skuld::test]
async fn dropping_an_exited_but_unreaped_process_group_child_still_kills_the_group() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let mut child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    crate::test_child::wait_until_zombie(pid);

    let mark = crate::log_capture::mark();
    drop(child);

    recorder.assert_killed_only(pid as i32);
    assert_eq!(drop_warns_since(mark), []);
}

/// A `TreeWalk` names its tree by ppid edges from the root's number, which after the reap belong to
/// whoever reused it: the drop walks nothing and warns naming the root. Mutant: the reaped
/// `TreeWalk` still walks.
#[skuld::test]
async fn dropping_a_waited_on_tree_walk_child_walks_nothing_and_warns_with_the_root_pid() {
    crate::log_capture::install();
    let walks = record_walks();
    let mut cmd = Command::new();
    cmd.args(["true"]);
    cmd.contain_with(ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    child.wait().await.expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(
        walks.walked(),
        Vec::<u32>::new(),
        "a reaped root's number names no tree"
    );
    let warns = drop_warns_since(mark);
    assert_eq!(warns.len(), 1, "exactly one warn, got {warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn);
    assert!(
        warns[0].1.contains(&format!("root pid {pid}")),
        "the warn names the root: {warns:?}"
    );
}

/// Positive control for the recorder above: a running `TreeWalk` root is walked, and nothing is
/// warned.
#[skuld::test]
async fn dropping_a_running_tree_walk_child_walks_from_its_pid_and_does_not_warn() {
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

/// A root reaped by someone else is invisible to tokio's own state (it stays `Running` until
/// polled), so the drop reads the root's number too, as the sync drop does. Mutant: tokio's drop
/// takes only its own state.
#[skuld::test]
async fn dropping_a_foreign_reaped_process_group_child_sends_no_killpg() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let root = drop_fault::record();
    let mut child = session(&["sleep", "300"]).spawn().expect("spawn");
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
        (root.kills(), root.forgets()),
        (0, 1),
        "the number may belong to another child by now: no kill, and tokio's `Child` is forgotten so \
         its own drop cannot reap by pid"
    );
    assert_eq!(drop_warns_since(mark).len(), 1);
}

/// A spawned `sleep` whose root something else (the application's own `waitpid`) has reaped,
/// while the handle still reads it as running.
fn foreign_reaped(mut cmd: Command) -> crate::tokio::Child {
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    crate::test_child::wait_until_zombie(pid);
    let mut status = 0;
    // SAFETY: `pid` is this test's own zombie child. This plays the application that reaps it.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
    child
}

/// A disarmed drop signals nothing, but tokio's own `Child` drop still `try_wait`s the root's
/// number, so a foreign reap must forget it there too. Mutant: the foreign-reap check runs only
/// under `kill_on_drop`.
#[skuld::test]
async fn a_detached_drop_after_a_foreign_reap_forgets_tokios_child() {
    crate::log_capture::install();
    let root = drop_fault::record();
    let backend_drops = crate::tokio::child::fault::count_backend_drops();
    let mut child = foreign_reaped(session(&["sleep", "300"]));
    child.detach();
    drop(child);
    assert_eq!(
        (root.kills(), root.forgets(), backend_drops.get()),
        (0, 1, 0),
        "a detached drop must not run tokio's `Child` drop, which reaps by the reused number"
    );
}

/// The same through the command's opt-out. Mutant: as above.
#[skuld::test]
async fn a_kill_on_drop_false_drop_after_a_foreign_reap_forgets_tokios_child() {
    crate::log_capture::install();
    let root = drop_fault::record();
    let backend_drops = crate::tokio::child::fault::count_backend_drops();
    let mut cmd = session(&["sleep", "300"]);
    cmd.kill_on_drop(false);
    let child = foreign_reaped(cmd);
    drop(child);
    assert_eq!((root.kills(), root.forgets(), backend_drops.get()), (0, 1, 0));
}

/// The skip is quiet once this handle has already hard-killed the tree. Mutant: the tree-killed
/// flag is ignored.
#[skuld::test]
async fn drop_after_kill_tree_and_wait_skips_at_debug_and_does_not_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let mut child = session(&["true"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill_tree().expect("kill_tree");
    child.wait().await.expect("reap the root");
    recorder.assert_killed_only(pid as i32);
    let sent = recorder.killed();

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), sent, "the drop sends no further killpg");
    assert_skipped_at_debug(mark);
}

/// `graceful_shutdown_tree` sweeps with `kill_tree` and reaps the root, so its drop is quiet too.
#[skuld::test]
async fn drop_after_graceful_shutdown_tree_skips_at_debug_and_does_not_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let mut child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child
        .graceful_shutdown_tree(std::time::Duration::from_secs(60))
        .await
        .expect("graceful_shutdown_tree");
    recorder.assert_killed_only(pid as i32);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_skipped_at_debug(mark);
}

/// A failed elevated spawn's cleanup kills the tree, then kills the root and waits for its exit
/// without reaping (`WNOWAIT`), so tokio's own drop reaps it. The root is still a zombie when the
/// handle drops, its number is pinned, and the drop has nothing to skip or to warn about. Mutant:
/// a skip decided on anything but the reaped root.
#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_drops_its_handle_without_a_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    let err = crate::tokio::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Io(std::io::Error::other("no password"))),
    )
    .expect_err("the password write failed");

    assert!(matches!(err, crate::error::Error::Elevation { .. }), "{err:?}");
    recorder.assert_killed_only(pid as i32);
    assert_eq!(drop_warns_since(mark), []);
}

/// A `sleep` root, killed and then waited for, so that only `wait()` marks tokio's state.
async fn waited_on_sleep_root() -> crate::tokio::Child {
    let mut child = session(&["sleep", "300"]).spawn().expect("spawn");
    child.kill().expect("kill the root");
    child.wait().await.expect("reap the root");
    child
}

/// Tokio's own reaped state is enough when the number's read is refused (`Unknown`). Mutant: the
/// drop takes only the number's read.
#[skuld::test]
async fn dropping_a_waited_on_child_whose_number_reads_unknown_still_sends_no_killpg() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let root = drop_fault::record();
    let child = waited_on_sleep_root().await;
    let _unknown = crate::child::fault::force_next_root_read(crate::identity::Resolved::Unknown);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new());
    assert_eq!((root.kills(), root.forgets()), (0, 0));
    assert_eq!(drop_warns_since(mark).len(), 1);
}

/// With tokio's state not reaped, an `Unknown` read means "not known to be reaped": the drop kills.
/// Mutant: `Unknown` is treated as reaped.
#[skuld::test]
async fn dropping_an_unreaped_child_whose_number_reads_unknown_kills_and_logs_the_failed_read() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let root = drop_fault::record();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    let _unknown = crate::child::fault::force_next_root_read(crate::identity::Resolved::Unknown);

    let mark = crate::log_capture::mark();
    drop(child);

    recorder.assert_killed_only(pid as i32);
    assert_eq!((root.kills(), root.forgets()), (1, 0));
    assert_eq!(drop_warns_since(mark), []);
    let reads = crate::log_capture::records_since_on_current_thread(mark, "could not be read");
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert_eq!(reads[0].0, log::Level::Debug);
}

/// A `kill_tree` that failed may have left members running, so the drop still warns. Mutant: the
/// tree-killed flag is set on the attempt.
#[skuld::test]
async fn drop_after_a_failed_kill_tree_and_wait_still_warns() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    recorder.fail_with_unassessable();
    let mut child = session(&["true"]).spawn().expect("spawn");
    child.kill_tree().expect_err("the forced refusal");
    child.wait().await.expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    let records = drop_warns_since(mark);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn);
}

/// The same for a `TreeWalk` whose walk was incomplete but returned `Ok`. Not on macOS, where
/// `TreeWalk` mode is an fd marker, whose incompleteness is an `Err` (the test above).
#[cfg(not(target_os = "macos"))]
#[skuld::test]
async fn drop_after_an_incomplete_tree_walk_kill_and_wait_still_warns() {
    crate::log_capture::install();
    let mut cmd = Command::new();
    cmd.args(["sleep", "300"]);
    cmd.contain_with(ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    crate::containment::treewalk::fault::force_incomplete_once();
    child.kill_tree().expect("a tree walk reports Ok");
    child.wait().await.expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    let records = drop_warns_since(mark);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Warn);
}

// The integration tests' cgroup helpers, compiled from their real source.
#[cfg(target_os = "linux")]
#[path = "../../tests/common/cgroup.rs"]
#[allow(
    dead_code,
    reason = "this file needs `drain_and_remove_leaf` alone; the integration binaries use the rest"
)]
mod cgroup_common;

/// A cgroup names its tree without the root's number, so the reaped root does not stop the drop's
/// kill. The cgroup lane's counterpart of the sync test of the same name; `COSCA_TEST_CGROUP`
/// is `0` everywhere else. Mutant: the skip applied to every mechanism, which logs the warn here.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_drop_after_wait_still_kills_the_tree_and_does_not_warn() {
    use ::tokio::io::AsyncReadExt as _;

    if !crate::test_support::require_group("CGROUP") {
        return;
    }
    crate::log_capture::install();
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "exec 3<&0; cat <&3 3<&- & echo started; exit 0"]);
    cmd.contain_with(ContainMode::Strongest);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::pipe_out()).expect("stderr pipe");
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::CgroupV2);
    // The drop is under test, so it stays the killer; the leaf is the test's to remove afterwards.
    let leaf = match &child.os.attached {
        crate::containment::Attached::Cgroup(leaf) => leaf.path().to_path_buf(),
        other => panic!("a cgroup child holds its leaf, got {other:?}"),
    };
    let mut started = [0u8; 8];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut started)
        .await
        .expect("read `started`");
    let _stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    child.wait().await.expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(drop_warns_since(mark), []);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .await
        .expect("the cgroup kill ended the cat, closing stderr, with stdin still held");
    // Stderr's EOF only proves the member is exiting. The drop may have left the leaf undrained:
    // wait for the kernel's drain event, then remove it.
    cgroup_common::drain_and_remove_leaf(&leaf);
}

/// Exactly one record of the drop's skip since `mark`, at `debug`.
#[track_caller]
fn assert_skipped_at_debug(mark: usize) {
    let records = drop_warns_since(mark);
    assert_eq!(records.len(), 1, "exactly one skip record, got {records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
}

/// A macOS fd marker names its marker holders by identity, so after a reap the drop still sweeps
/// them and skips every channel that names the root's number: the `killpg`, the ppid walk and the
/// root's own kill. Mutants: the sweep skipped too; the `killpg` or the walk still run.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn fd_marker_drop_after_wait_sweeps_the_marker_holders_but_names_nothing_by_the_roots_number() {
    use ::tokio::io::AsyncReadExt as _;

    crate::log_capture::install();
    let recorder = record_kill_group();
    let walks = record_walks();
    let sweeps = crate::containment::fdmarker::fault::record_holder_kills();
    // `exec 3<&0` because `sh` points a background job's stdin at /dev/null otherwise. The `cat`
    // reads the stdin pipe, which the test holds, and holds stderr's write end: stderr reaches EOF
    // exactly when the `cat` is gone.
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "exec 3<&0; cat <&3 3<&- >/dev/null & echo started; exit 0"]);
    cmd.contain_with(ContainMode::Strongest);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::pipe_out()).expect("stderr pipe");
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::FdMarker);
    let mut out = String::new();
    child
        .stdout()
        .expect("stdout pipe")
        .read_to_string(&mut out)
        .await
        .expect("read stdout to the root's exit");
    assert_eq!(out, "started\n");
    let _stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    child.wait().await.expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new(), "no killpg after the reap");
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no ppid walk from the reaped root");
    assert!(!sweeps.killed().is_empty(), "the marker-holder sweep still runs");
    assert_eq!(drop_warns_since(mark).len(), 1);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .await
        .expect("the sweep ended the cat, closing stderr, with stdin still held");
}

/// A root that is alive when its marker is attached, then killed and reaped. A root that exits
/// before the attach has no identity to walk from, which would make a "no walk" assertion vacuous.
#[cfg(target_os = "macos")]
async fn reaped_sleep_root(mode: ContainMode) -> (u32, crate::tokio::Child) {
    let mut cmd = Command::new();
    cmd.args(["sleep", "300"]);
    cmd.contain_with(mode);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::FdMarker);
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    child.wait().await.expect("reap the root");
    (pid, child)
}

/// An fd marker with no group (`TreeWalk` mode): after a reap nothing but the holder sweep runs.
/// Mutant: the walk or the root kill still run for it.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn fd_marker_without_a_group_drop_after_wait_only_sweeps_the_marker_holders() {
    crate::log_capture::install();
    let walks = record_walks();
    let (pid, child) = reaped_sleep_root(ContainMode::TreeWalk).await;

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
#[skuld::test]
async fn fd_marker_with_a_group_drop_after_wait_neither_signals_the_group_nor_walks() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let walks = record_walks();
    let (pid, child) = reaped_sleep_root(ContainMode::Strongest).await;

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new(), "no killpg after the reap");
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no ppid walk from the reaped root");
    let warns = drop_warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].1.contains(&format!("pgid {pid}")), "{warns:?}");
}
