use std::os::fd::AsFd as _;

use super::{classify_kill, classify_pidfd, has_exited};
use crate::identity::ProcessId;
use crate::refusal::Verdict;

// Has the target exited? =====

fn cat() -> (std::process::Child, ProcessId) {
    let mut cmd = std::process::Command::new("cat");
    cmd.stdin(std::process::Stdio::piped());
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn cat");
    let id = ProcessId::of(child.id()).found().expect("identity of a live child");
    (child, id)
}

fn pidfd_of(id: ProcessId) -> rustix::fd::OwnedFd {
    let pid = rustix::process::Pid::from_raw(id.pid() as i32).expect("nonzero pid");
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open")
}

// Kills a `cat` (closing its stdin) and returns once it is a zombie, unreaped.
fn make_zombie(child: &mut std::process::Child, id: ProcessId) {
    drop(child.stdin.take());
    assert!(
        crate::wait::block_until_exit(id, None).expect("watch the exit"),
        "the watch returns on the exit"
    );
}

#[test]
fn a_running_own_child_has_not_exited() {
    let (mut child, id) = cat();
    let pidfd = pidfd_of(id);
    assert!(!has_exited(id, pidfd.as_fd()).expect("waitid"));
    drop(child.stdin.take());
    child.wait().expect("reap");
}

#[test]
fn an_unreaped_zombie_own_child_has_exited() {
    let (mut child, id) = cat();
    let pidfd = pidfd_of(id);
    make_zombie(&mut child, id);
    assert!(has_exited(id, pidfd.as_fd()).expect("waitid"));
    child.wait().expect("reap");
}

// `waitid(WNOWAIT)` must leave the zombie for its parent: the check never reaps.
#[test]
fn the_exit_check_does_not_reap() {
    let (mut child, id) = cat();
    let pidfd = pidfd_of(id);
    make_zombie(&mut child, id);
    assert!(has_exited(id, pidfd.as_fd()).expect("waitid"));
    assert!(has_exited(id, pidfd.as_fd()).expect("a second check still sees the zombie"));
    let status = child
        .try_wait()
        .expect("try_wait")
        .expect("the zombie is still there to reap");
    assert!(status.success());
}

// Not our child: `waitid(P_PIDFD)` answers `ECHILD`, and the check falls back on the target's
// `/proc` state. Pid 1 is live and never our child.
#[test]
fn a_live_process_that_is_not_our_child_has_not_exited() {
    let init = ProcessId::of(1).found().expect("pid 1 resolves");
    let pidfd = pidfd_of(init);
    assert!(!has_exited(init, pidfd.as_fd()).expect("the fallback"));
}

// What would a refused signal at this target mean? =====

#[test]
fn eperm_at_an_exited_child_is_exited() {
    let (mut child, id) = cat();
    let pidfd = pidfd_of(id);
    make_zombie(&mut child, id);
    assert_eq!(classify_kill(id).expect("classify"), Verdict::Exited);
    assert_eq!(classify_pidfd(id, pidfd.as_fd()).expect("classify"), Verdict::Exited);
    child.wait().expect("reap");
}

// Reaped before the classification: nothing to refuse.
#[test]
fn eperm_at_a_reaped_child_is_exited() {
    let (mut child, id) = cat();
    drop(child.stdin.take());
    child.wait().expect("reap");
    assert_eq!(classify_kill(id).expect("classify"), Verdict::Exited);
}
