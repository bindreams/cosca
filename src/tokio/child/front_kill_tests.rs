//! Async twins of `child/front_kill_tests.rs`: no forced kill of a `cosca::tokio::Child` may
//! signal a live elevation front, and no `SIGTERM` a live osascript. The front is an ordinary `cat`,
//! reported as launched by `sudo` or `osascript`, that exits 0 once its stdin closes and dies of a
//! signal if it was sent one first. The cgroup lane's cases are in `front_cgroup_tests.rs`.

use std::time::Duration;

use crate::child::front_kill_tests::{assert_refused_by, assert_unkillable_front, report};
use crate::containment::unix::fault::record_kill_group;
use crate::elevation::{Backend, ElevatedVia};
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, Group};
use crate::tokio::child::{drop_fault, Child};
use crate::tokio::{ChildStdin, Command};
use crate::{ContainMode, Containment, Stdio};

pub(super) fn spawn_as(mut cmd: Command, via: ElevatedVia) -> (Child, ChildStdin) {
    cmd.stdin(Stdio::pipe()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    child.set_elevation(report(via));
    let stdin = child.stdin().expect("stdin pipe");
    (child, stdin)
}

pub(super) fn cat() -> Command {
    let mut cmd = Command::new();
    cmd.args(["cat"]);
    cmd
}

/// Closes the `cat`'s stdin and reaps it: it must exit 0, so nothing signalled it.
pub(super) async fn assert_ends_unsignalled(child: &mut Child, stdin: ChildStdin) {
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
    assert!(
        warns[0].1.contains(&format!("pid {pid} is what sudo left")),
        "{warns:?}"
    );
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
    assert!(detail.contains(&format!("pid {pid} is what sudo left")), "{detail}");
}

/// Mutant: osascript's `SIGTERM` is sent.
#[skuld::test]
async fn terminate_of_a_live_osascript_is_unkillable_and_sends_nothing() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::MacosOsascript);
    let pid = child.id().pid();
    assert_refused_by(child.terminate(), &format!("pid {pid} is osascript"));
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// Mutants: the graceful path signals osascript; a kill after it does.
#[skuld::test]
async fn graceful_shutdown_of_a_live_osascript_is_unkillable_and_sends_nothing() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::MacosOsascript);
    let pid = child.id().pid();
    assert_refused_by(
        child.graceful_shutdown(Duration::ZERO).await,
        &format!("pid {pid} is osascript"),
    );
    assert_refused_by(child.kill(), &format!("pid {pid} is osascript"));
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// Mutant: every front's `SIGTERM` is refused.
#[skuld::test]
async fn terminate_of_a_live_sudo_front_is_sent() {
    use std::os::unix::process::ExitStatusExt as _;
    let (mut child, _stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    child.terminate().expect("sudo relays SIGTERM");
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGTERM));
}

/// Async twin of the sync `a_failed_spawn_leaves_an_elevation_front_running_and_says_so`.
/// Mutants: the teardown kills the front; the error's variant is replaced; it does not say so.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_spawn_leaves_an_elevation_front_running_and_says_so() {
    use crate::child::front_kill_tests::{assert_noted, failed_front_spawns, reap};
    let failures = failed_front_spawns(None, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
    assert_noted(&failures, "the elevated program may be running; it is left unreaped");
    for (_, pid) in &failures {
        let status = reap(*pid).expect("the front must be left unreaped");
        assert!(status.success(), "the teardown signalled the front: {status:?}");
    }
}

/// A tokio spawn that fails after its fork, as when its reaper registration is refused
/// (`epoll_ctl`'s `ENOSPC`), sends an elevation front nothing, leaves it unreaped, and says so on
/// the error, its variant kept. The `cat`'s stdin is a pipe this test owns: tokio's `Child`, whose
/// streams the failure leaks, holds none of it. Mutant: the handshake's teardown kills the front.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_spawn_failing_after_its_fork_leaves_an_elevation_front_running_and_says_so() {
    use std::os::fd::OwnedFd;

    use crate::child::front_kill_tests::reap;
    use crate::child::spawn::fault;
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut cmd = crate::command::Command::new();
    cmd.args(["cat"]);
    cmd.stdin(Stdio::from_file(std::fs::File::from(OwnedFd::from(reader))))
        .expect("stdin");
    cmd.set_elevation_front(crate::elevation::front::front(Some(&ElevatedVia::Wrapped(
        Backend::Sudo,
    ))));
    let err = {
        let _failing = fault::fail_tokio_spawns_after_fork();
        crate::tokio::spawn::spawn(&mut cmd)
            .map(drop)
            .expect_err("the forced failure fails the spawn")
    };
    let pid = fault::take_forgotten_pid().expect("the seam forked a child");
    let crate::error::Error::Io(io) = &err else {
        panic!("the spawn's error keeps its variant: {err:?}");
    };
    assert_eq!(io.raw_os_error(), None, "noted, with the original as its source: {io}");
    let text = err.to_string();
    assert!(text.contains("the spawned child is what sudo left"), "{text}");
    assert!(
        text.contains("the elevated program may be running; it is left unreaped"),
        "{text}"
    );
    drop(writer);
    let status = reap(pid).expect("the front must be left unreaped");
    assert!(status.success(), "the teardown signalled the front: {status:?}");
}

/// Async twin of the sync `cgroup_a_failed_spawn_tears_a_contained_front_down_as_any_child`.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_a_failed_spawn_tears_a_contained_front_down_as_any_child(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::{failed_front_spawns, reap};
    for (err, pid) in failed_front_spawns(Some(ContainMode::Strongest), |cmd| {
        crate::tokio::spawn::spawn(cmd).map(drop)
    }) {
        assert!(!err.to_string().contains("what sudo left"), "no note: {err}");
        assert_eq!(reap(pid), None, "the teardown reaps it");
    }
}
