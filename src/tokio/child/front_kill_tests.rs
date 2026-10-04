//! Async twins of `child/front_kill_tests.rs`: no forced kill of a `cosca::tokio::Child` may
//! signal a live elevation front. The front is an ordinary `cat`, reported as launched by `sudo`,
//! that exits 0 once its stdin closes and dies of `SIGKILL` if it was killed first.

use std::time::Duration;

use crate::child::front_kill_tests::{assert_unkillable_front, report};
use crate::containment::unix::fault::record_kill_group;
use crate::elevation::{Backend, ElevatedVia};
use crate::tokio::child::{drop_fault, Child};
use crate::tokio::{ChildStdin, Command};
use crate::{ContainMode, Containment, Stdio};

fn spawn_as(mut cmd: Command, via: ElevatedVia) -> (Child, ChildStdin) {
    cmd.stdin(Stdio::pipe()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    child.set_elevation(report(via));
    let stdin = child.stdin().expect("stdin pipe");
    (child, stdin)
}

fn cat() -> Command {
    let mut cmd = Command::new();
    cmd.args(["cat"]);
    cmd
}

/// Closes the `cat`'s stdin and reaps it: it must exit 0, so nothing signalled it.
async fn assert_ends_unsignalled(child: &mut Child, stdin: ChildStdin) {
    drop(stdin);
    let status = child.wait().await.expect("wait");
    assert!(status.success(), "the front was signalled: {status:?}");
}

/// Mutant: `kill()` signals the front.
#[skuld::test]
async fn kill_of_a_live_front_is_unkillable_and_sends_nothing() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();
    assert_unkillable_front(child.kill(), pid);
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// Mutant: the front's exit is not read, so the kill of an exited front is `Unkillable`.
#[skuld::test]
async fn kill_of_an_exited_front_is_ok() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    child.kill().expect("an exited front is killed like any child");
    assert!(child.wait().await.expect("wait").success());
}

/// Mutants: `kill_tree` runs the group kill; it signals the front.
#[skuld::test]
async fn kill_tree_of_a_live_front_outside_a_cgroup_is_unkillable_and_sends_nothing() {
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (mut child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    assert_ne!(child.containment(), Containment::CgroupV2);
    let pid = child.id().pid();
    assert_unkillable_front(child.kill_tree(), pid);
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// Mutant: the escalation signals the front directly.
#[skuld::test]
async fn graceful_shutdown_of_a_front_that_outlives_the_grace_is_unkillable() {
    use tokio::io::AsyncReadExt as _;
    let mut cmd = Command::new();
    // An ignored disposition survives `exec`; `ready` says it is set.
    cmd.args(["sh", "-c", "trap '' TERM; echo ready; exec cat"]);
    cmd.stdout(Stdio::pipe()).expect("stdout pipe");
    let (mut child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .await
        .expect("read `ready`");
    assert_eq!(&ready, b"ready\n");
    let pid = child.id().pid();
    assert_unkillable_front(child.graceful_shutdown(Duration::ZERO).await, pid);
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// The drop signals neither the front nor its group, and says so. The `killpg` recorder stands in
/// for the group kill. Mutants: the drop kills the root; it kills the group; it warns of nothing.
#[skuld::test]
async fn drop_of_a_live_front_signals_nothing_and_warns() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let groups = record_kill_group();
    let roots = drop_fault::record();
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (child, _stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(roots.kills(), 0, "the drop must not kill a live front");
    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "the drop must not kill a live front's group"
    );
    let warns = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn);
    assert!(warns[0].1.contains(&format!("pid {pid} is sudo")), "{warns:?}");
}

/// In a cgroup the kill goes through `cgroup.kill`. Needs a delegated cgroup: the cgroup lane.
/// Mutants: a front in a cgroup is refused; its kill signals the front alone.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_kill_of_a_front_goes_through_the_cgroup() {
    use std::os::unix::process::ExitStatusExt as _;
    if !crate::test_support::require_group("CGROUP") {
        return;
    }
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Strongest);
    let (mut child, _stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    assert_eq!(child.containment(), Containment::CgroupV2);
    child.kill().expect("the cgroup kill reaches the program");
    assert!(child.tree_killed.is_set(), "the kill must go through the cgroup");
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

/// Mutant: the front is signalled after a failed cgroup kill.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_a_failed_kill_of_a_front_leaves_the_front_alone() {
    if !crate::test_support::require_group("CGROUP") {
        return;
    }
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Strongest);
    let (mut child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    assert_eq!(child.containment(), Containment::CgroupV2);
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        assert!(child.kill().is_err(), "the forced cgroup.kill failure surfaces");
        assert!(child.kill_tree().is_err(), "the forced cgroup.kill failure surfaces");
    }
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// The drop, too, leaves a front alone when its cgroup kill fails. The front's end is read through
/// a pidfd without reaping it: tokio owns the reap, and this test does not yield to its runtime
/// before reading. Mutant: the drop kills the front after a failed cgroup kill.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_a_failed_drop_kill_of_a_front_leaves_the_front_alone() {
    use std::os::fd::AsFd as _;
    if !crate::test_support::require_group("CGROUP") {
        return;
    }
    crate::tokio::test_runtime::assert_current_thread();
    let roots = drop_fault::record();
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Strongest);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let crate::containment::Attached::Cgroup(leaf) = &child.os.attached else {
        panic!("expected a cgroup leaf, got {:?}", child.os.attached);
    };
    let leaf = leaf.path().to_path_buf();
    let pid = rustix::process::Pid::from_raw(child.id().pid() as i32).expect("a positive pid");
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open");
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        drop(child);
    }
    assert_eq!(roots.kills(), 0, "the drop must not kill the front");
    drop(stdin);
    let status = loop {
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(status)) => break status,
            Ok(None) => unreachable!("a blocking waitid returns a status"),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => panic!("waitid on the front's pidfd (ECHILD: the drop reaped a killed front): {e}"),
        }
    };
    assert_eq!(
        (status.exit_status(), status.terminating_signal()),
        (Some(0), None),
        "the drop signalled the front"
    );
    // The failed kill left the leaf behind; it is empty once the front has exited.
    std::fs::remove_dir(&leaf).unwrap_or_else(|e| panic!("remove the leaf {}: {e}", leaf.display()));
}

/// Async twin of the sync `a_failed_password_write_signals_neither_a_live_front_nor_its_group`.
/// Mutants: the teardown runs the group kill; it signals the front.
#[skuld::test]
async fn a_failed_password_write_signals_neither_a_live_front_nor_its_group() {
    crate::tokio::test_runtime::assert_current_thread();
    let groups = record_kill_group();
    let roots = drop_fault::record();
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (child, _stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();
    let err = crate::tokio::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "no group kill of a live front: {err}"
    );
    assert_eq!(roots.kills(), 0, "no kill of a live front, by its drop either: {err}");
    let crate::error::Error::Elevation { detail, .. } = &err else {
        panic!("expected an Elevation error, got {err:?}");
    };
    assert!(detail.contains("could not be terminated"), "{detail}");
    assert!(detail.contains(&format!("pid {pid} is sudo")), "{detail}");
}
