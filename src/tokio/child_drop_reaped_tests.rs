//! Async twins of `child/drop_reaped_tests.rs`: `cosca::tokio::Child`'s drop once the root is
//! reaped (#382). A pgid-based group kill would name a number that may now belong to an unrelated
//! group, so the drop skips it and warns instead.
//!
//! The recorder replaces `killpg` (`unix::fault::record_kill_group`), so a mutant that still
//! sends it never reaches a real group. The recorder is thread-local and `#[tokio::test]` is
//! current-thread, so the drop's kill runs on the recording thread.

use crate::containment::unix::fault::record_kill_group;
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

/// Block until `pid` has exited without reaping it: a zombie, which still pins its group number.
fn wait_until_zombie(pid: u32) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out-parameter. WNOWAIT leaves the child reapable.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
}

/// Mutants: the drop still calls `hard_kill`; `root_reaped` is always false; no warn; the warn
/// without the pgid.
#[tokio::test]
async fn dropping_a_waited_on_process_group_child_sends_no_killpg_and_warns_with_the_pgid() {
    crate::log_capture::install();
    let recorder = record_kill_group();
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
#[tokio::test]
async fn dropping_a_running_process_group_child_still_kills_the_group_and_does_not_warn() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), [pid as i32]);
    assert_eq!(drop_warns_since(mark), []);
}

/// A root that exited but is not reaped is a zombie: it still pins its group number, so the group
/// kill is safe. Mutant: reaped judged with `try_wait`, which reaps the zombie and then skips.
#[tokio::test]
async fn dropping_an_exited_but_unreaped_process_group_child_still_kills_the_group() {
    crate::log_capture::install();
    let recorder = record_kill_group();
    let mut child = session(&["sleep", "300"]).spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    wait_until_zombie(pid);

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(recorder.killed(), [pid as i32]);
    assert_eq!(drop_warns_since(mark), []);
}

/// A macOS fd marker names its marker holders by identity, so after a reap the drop still sweeps
/// them and skips only the `killpg`. Mutants: the sweep skipped too; the `killpg` still sent.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn fd_marker_drop_after_wait_sweeps_the_marker_holders_but_sends_no_killpg() {
    use ::tokio::io::AsyncReadExt as _;

    crate::log_capture::install();
    let recorder = record_kill_group();
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
    assert!(!sweeps.killed().is_empty(), "the marker-holder sweep still runs");
    assert_eq!(drop_warns_since(mark).len(), 1);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .await
        .expect("the sweep ended the cat, closing stderr, with stdin still held");
}
