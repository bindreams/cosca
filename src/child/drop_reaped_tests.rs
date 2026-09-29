//! `Child::drop` once the root is reaped (#382): a pgid-based group kill would name a number that
//! may now belong to an unrelated process group, so the drop skips it and warns instead.
//!
//! The recorder tests replace `killpg` with a recorder (`unix::fault::record_kill_group`), so a
//! mutant that still sends it never reaches a real group. The behavioural tests use real groups
//! of this test's own children, all signalled before their root is reaped.

use std::io::Read as _;

use crate::command::Command;
use crate::containment::unix::fault::record_kill_group;
use crate::{ContainMode, Containment, Stdio};

/// Every record of the drop's warn starts with this.
const WARN: &str = "Child::drop: the root is already reaped";

/// A command in its own session, so the mechanism is `Attached::ProcessGroup` on every Unix.
fn session(argv: &[&str]) -> Command {
    let mut cmd = Command::new();
    cmd.args(argv.iter().copied());
    cmd.contain_with(ContainMode::Session);
    cmd
}

/// Root `sh` (which points a background job's stdin at `/dev/null` unless told otherwise, hence the
/// `exec 3<&0`) prints `started` and exits, leaving a `cat` in its group. The `cat` reads the stdin
/// pipe, which the test holds, so it ends only when killed or when the test closes stdin. It holds
/// the stderr pipe's write end: stderr reaches EOF exactly when `cat` is gone.
fn root_that_leaves_a_cat() -> Command {
    let mut cmd = session(&["sh", "-c", "exec 3<&0; cat <&3 3<&- >/dev/null & echo started; exit 0"]);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    cmd.stderr(Stdio::pipe_out()).expect("stderr pipe");
    cmd
}

/// Spawn [`root_that_leaves_a_cat`] and read its `started`: the `cat` is forked, and the root is
/// exiting or a zombie, not yet reaped.
fn spawn_cat_tree() -> (crate::Child, std::io::PipeWriter, std::io::PipeReader) {
    let mut child = root_that_leaves_a_cat().spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::Session);
    let mut out = String::new();
    child
        .stdout()
        .expect("stdout pipe")
        .read_to_string(&mut out)
        .expect("read stdout to the root's exit");
    assert_eq!(out, "started\n");
    let stdin = child.stdin().expect("stdin pipe");
    let stderr = child.stderr().expect("stderr pipe");
    (child, stdin, stderr)
}

fn set_nonblocking(pipe: &std::io::PipeReader, on: bool) {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = OFlag::from_bits_retain(fcntl(pipe, FcntlArg::F_GETFL).expect("F_GETFL"));
    let flags = if on {
        flags | OFlag::O_NONBLOCK
    } else {
        flags & !OFlag::O_NONBLOCK
    };
    fcntl(pipe, FcntlArg::F_SETFL(flags)).expect("F_SETFL");
}

fn drop_warns_since(mark: usize) -> Vec<(log::Level, String)> {
    crate::log_capture::records_since_on_current_thread(mark, WARN)
}

/// Block until `pid` has exited without reaping it: a zombie, which still pins its group number.
fn wait_until_zombie(pid: u32) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out-parameter. WNOWAIT leaves the child reapable.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
}

/// Mutants: `killpg` still sent after the reap; no warn; the warn without the pgid.
#[test]
fn dropping_a_waited_on_process_group_child_sends_no_killpg_and_warns_with_the_pgid() {
    crate::log_capture::install();
    let recorder = record_kill_group();
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
    let mut cmd = session(&["sleep", "300"]);
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), [pid as i32]);
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
    wait_until_zombie(pid);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), [pid as i32]);
    assert_eq!(drop_warns_since(mark), []);
}

/// Real `killpg`: `kill_tree()` before `wait()` ends a descendant that outlives the root.
#[test]
fn kill_tree_before_wait_ends_a_descendant_of_an_exited_root() {
    let (child, _stdin, mut stderr) = spawn_cat_tree();

    child.kill_tree().expect("kill_tree");
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .expect("stderr reaches EOF once the cat is dead");
    child.wait().expect("reap the root");
}

/// The contract this fix sets: after `wait()` the drop leaves the descendant running, and the
/// test ends it by closing its stdin.
#[test]
fn drop_after_wait_leaves_a_descendant_running_until_it_is_ended_explicitly() {
    let (child, stdin, mut stderr) = spawn_cat_tree();
    child.wait().expect("reap the root");
    drop(child);

    set_nonblocking(&stderr, true);
    let mut buf = [0u8; 1];
    let err = stderr
        .read(&mut buf)
        .expect_err("the cat holds stderr open: no data, no EOF");
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    set_nonblocking(&stderr, false);

    drop(stdin);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .expect("stderr reaches EOF once the cat is gone");
}

/// A cgroup names its tree without the root's number, so the reaped root does not stop the drop's
/// kill. Needs a delegated cgroup: `COSCA_TEST_CGROUP` (see `containment/cgroup/leaf_tests.rs`).
/// Mutant: the skip applied to every mechanism, which logs the warn here.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_drop_after_wait_still_kills_the_tree_and_does_not_warn() {
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "this #[ignore]d test was requested explicitly, but COSCA_TEST_CGROUP is unset"
    );
    crate::log_capture::install();
    let mut cmd = root_that_leaves_a_cat();
    cmd.contain_with(ContainMode::Strongest);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::CgroupV2);
    let mut out = String::new();
    child
        .stdout()
        .expect("stdout pipe")
        .read_to_string(&mut out)
        .expect("read stdout to the root's exit");
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
/// them and skips only the `killpg`. Mutants: the sweep skipped too (the whole `hard_kill`
/// skipped); the `killpg` still sent.
#[cfg(target_os = "macos")]
#[test]
fn fd_marker_drop_after_wait_sweeps_the_marker_holders_but_sends_no_killpg() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let sweeps = crate::containment::fdmarker::fault::record_holder_kills();
    let mut cmd = root_that_leaves_a_cat();
    cmd.contain_with(ContainMode::Strongest);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::FdMarker);
    let mut out = String::new();
    child
        .stdout()
        .expect("stdout pipe")
        .read_to_string(&mut out)
        .expect("read stdout to the root's exit");
    let _stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    child.wait().expect("reap the root");

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new(), "no killpg after the reap");
    assert!(!sweeps.killed().is_empty(), "the marker-holder sweep still runs");
    assert_eq!(drop_warns_since(mark).len(), 1);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .expect("the sweep ended the cat, closing stderr, with stdin still held");
}
