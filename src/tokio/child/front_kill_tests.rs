//! Async twins of `child/front_kill_tests.rs`: no forced kill of a `cosca::tokio::Child` may
//! signal a live elevation front, and no `SIGTERM` a live osascript. The front is an ordinary `cat`,
//! reported as launched by `sudo` or `osascript`, that exits 0 once its stdin closes and dies of a
//! signal if it was sent one first. The cgroup lane's cases are in `front_cgroup_tests.rs`.

use std::time::Duration;

use crate::child::front_kill_tests::{assert_refused_by, assert_unkillable_front, report};
use crate::containment::unix::fault::record_kill_group;
use crate::elevation::{Backend, ElevatedVia};
use crate::tokio::child::{drop_fault, Child};
use crate::tokio::{ChildStdin, Command};
use crate::{ContainMode, Containment, Stdio};

pub(super) fn spawn_as(mut cmd: Command, via: ElevatedVia) -> (Child, ChildStdin) {
    cmd.stdin(Stdio::pipe()).expect("stdin pipe");
    cmd.set_elevation_front(crate::elevation::front::front(Some(&via)));
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

#[skuld::test]
async fn kill_of_a_live_front_is_unkillable_and_sends_nothing() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();
    assert_unkillable_front(child.kill(), pid);
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// Async twin of the sync `kill_of_an_exited_front_is_ok`.
#[skuld::test]
async fn kill_of_an_exited_front_is_ok() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    let refused = crate::signal::seams::refuse_kills();
    child.kill().expect("an exited front is killed like any child");
    drop(refused);
    assert!(child.wait().await.expect("wait").success());
}

/// Async twin of the sync `kill_of_an_exited_front_returns_any_other_failure`.
#[skuld::test]
async fn kill_of_an_exited_front_returns_any_other_failure() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    let failing = crate::signal::seams::fail_kills_with(libc::EINVAL);
    match child.kill() {
        Err(crate::error::Error::Io(io)) => assert_eq!(io.kind(), std::io::ErrorKind::InvalidInput, "{io}"),
        other => panic!("expected the kill's own failure, got {other:?}"),
    }
    drop(failing);
    assert!(child.wait().await.expect("wait").success());
}

/// Async twin of the sync `kill_tree_of_an_exited_front_is_ok`.
#[skuld::test]
async fn kill_tree_of_an_exited_front_is_ok() {
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (mut child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    let refused = crate::signal::seams::refuse_kills();
    child
        .kill_tree()
        .expect("an exited front's tree is killed like any child's");
    drop(refused);
    assert!(child.wait().await.expect("wait").success());
}

/// Async twin of the sync `drop_of_an_exited_front_reaps_it_and_warns_of_nothing`.
#[skuld::test]
async fn drop_of_an_exited_front_reaps_it_and_warns_of_nothing() {
    use crate::child::front_kill_tests::reap;
    crate::log_capture::install();
    let (child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();
    drop(stdin);
    crate::test_child::wait_until_zombie(pid);
    let mark = crate::log_capture::mark();
    drop(child);
    let warns = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
    assert!(warns.is_empty(), "{warns:?}");
    assert_eq!(reap(pid), None, "the drop reaps an exited front");
}

/// Async twin of the sync `kill_reads_the_front_its_spawn_found_not_its_report`.
#[skuld::test]
async fn kill_reads_the_front_its_spawn_found_not_its_report() {
    use std::os::unix::process::ExitStatusExt as _;
    let mut cmd = cat();
    cmd.stdin(Stdio::pipe()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    child.set_elevation(report(ElevatedVia::Wrapped(Backend::Sudo)));
    let _stdin = child.stdin().expect("stdin pipe");
    child.kill().expect("a child with no front is killed as any child");
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

/// Async twin of the sync `kill_of_a_live_doas_front_is_unkillable_and_sends_nothing`.
#[skuld::test]
async fn kill_of_a_live_doas_front_is_unkillable_and_sends_nothing() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Doas));
    let pid = child.id().pid();
    assert_refused_by(child.kill(), &format!("pid {pid} is what doas left"));
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// The tokio twins of the sync `uncontained_cats`.
fn uncontained_cats() -> [Command; 2] {
    let mut walked = cat();
    walked.contain_with(ContainMode::TreeWalk);
    [cat(), walked]
}

/// Async twin of the sync `kill_of_a_live_front_without_a_group_sends_nothing`.
#[skuld::test]
async fn kill_of_a_live_front_without_a_group_sends_nothing() {
    for cmd in uncontained_cats() {
        let (mut child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
        let pid = child.id().pid();
        assert_unkillable_front(child.kill(), pid);
        assert_ends_unsignalled(&mut child, stdin).await;
    }
}

/// Async twin of the sync `drop_of_a_live_front_without_a_group_sends_nothing`.
#[skuld::test]
async fn drop_of_a_live_front_without_a_group_sends_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    for cmd in uncontained_cats() {
        let roots = drop_fault::record();
        let (child, _stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
        drop(child);
        assert_eq!(roots.kills(), 0, "the drop must not kill a live front");
    }
}

/// Async twin of the sync `a_failed_password_write_sends_a_live_front_without_a_group_nothing`.
#[skuld::test]
async fn a_failed_password_write_sends_a_live_front_without_a_group_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    for cmd in uncontained_cats() {
        let roots = drop_fault::record();
        let (child, _stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
        let pid = child.id().pid();
        let detail = failed_password_write_detail(child);
        assert!(detail.contains("could not be terminated"), "{detail}");
        assert!(detail.contains(&format!("pid {pid} is what sudo left")), "{detail}");
        assert_eq!(roots.kills(), 0, "no kill of a live front, by its drop either");
    }
}

/// The `detail` of the error the tokio `finish_elevated` returns for `child` after a failed
/// password write.
fn failed_password_write_detail(child: Child) -> String {
    let err = crate::tokio::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    let crate::error::Error::Elevation { detail, .. } = err else {
        panic!("expected an Elevation error, got {err:?}");
    };
    detail
}

/// Async twin of the sync `graceful_shutdown_of_a_front_that_exits_within_the_grace_returns_its_status`.
#[skuld::test]
async fn graceful_shutdown_of_a_front_that_exits_within_the_grace_returns_its_status() {
    use std::os::unix::process::ExitStatusExt as _;
    let (mut child, _stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    let status = child
        .graceful_shutdown(Duration::from_secs(3600))
        .await
        .expect("the relayed SIGTERM ends the front");
    assert_eq!(status.signal(), Some(libc::SIGTERM));
}

/// Async twin of the sync `a_failed_password_write_to_a_front_someone_else_reaped_says_it_had_exited`.
#[skuld::test]
async fn a_failed_password_write_to_a_front_someone_else_reaped_says_it_had_exited() {
    use crate::child::front_kill_tests::reap;
    let mut cmd = cat();
    cmd.kill_on_drop(false);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();
    drop(stdin);
    crate::test_child::wait_until_zombie(pid);
    assert!(reap(pid).is_some(), "the test reaps the front itself");
    let detail = failed_password_write_detail(child);
    assert!(
        detail.contains("the elevated child had already exited, and was reaped by someone else"),
        "{detail}"
    );
}

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
/// for the group kill.
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

/// Async twin of the sync `a_failed_password_write_to_a_front_that_had_exited_says_so`.
#[skuld::test]
async fn a_failed_password_write_to_a_front_that_had_exited_says_so() {
    let mut cmd = cat();
    // The drop, whose own teardown would ask the gate again, is opted out of.
    cmd.kill_on_drop(false);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    let _refused = crate::signal::seams::refuse_kills();
    let gates = crate::elevation::front::seams::count_kill_gates();
    let err = crate::tokio::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    assert_eq!(gates.count(), 1, "{err}");
    let crate::error::Error::Elevation { detail, .. } = &err else {
        panic!("expected an Elevation error, got {err:?}");
    };
    assert!(detail.contains("the elevated child had already exited"), "{detail}");
    assert!(!detail.contains("terminated"), "{detail}");
}

#[skuld::test]
async fn terminate_of_a_live_osascript_is_unkillable_and_sends_nothing() {
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::MacosOsascript);
    let pid = child.id().pid();
    assert_refused_by(child.terminate(), &format!("pid {pid} is osascript"));
    assert_ends_unsignalled(&mut child, stdin).await;
}

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

#[skuld::test]
async fn terminate_of_a_live_sudo_front_is_sent() {
    use std::os::unix::process::ExitStatusExt as _;
    let (mut child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    child.terminate().expect("sudo relays SIGTERM");
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGTERM));
}

/// Async twin of the sync `a_failed_spawn_leaves_an_elevation_front_running_and_says_so`.
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
/// streams the failure leaks, holds none of it.
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

/// A front whose exec fails never ran the program: std collected the child, so its error carries no
/// note that the program may be running. The exec fails on an argument longer than `MAX_ARG_STRLEN`
/// (`E2BIG`).
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_front_whose_exec_fails_is_not_noted() {
    let mut cmd = crate::command::Command::new();
    cmd.args(["true".to_owned(), "x".repeat(256 * 1024)]);
    cmd.set_elevation_front(crate::elevation::front::front(Some(&ElevatedVia::Wrapped(
        Backend::Sudo,
    ))));
    let err = crate::tokio::spawn::spawn(&mut cmd)
        .map(drop)
        .expect_err("an argument over MAX_ARG_STRLEN fails the exec");
    let crate::error::Error::Io(io) = &err else {
        panic!("an exec failure is an Io error: {err:?}");
    };
    assert_eq!(io.raw_os_error(), Some(libc::E2BIG), "{io}");
    assert!(!err.to_string().contains("what sudo left"), "no note: {err}");
}

/// Async twin of the sync `macos_a_front_whose_report_read_fails_is_left_and_noted`.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_a_front_whose_report_read_fails_is_left_and_noted() {
    use crate::child::front_kill_tests::{assert_unadopted_front_noted, fail_a_front_spawn, fail_the_report_read};
    let (err, pid) = fail_a_front_spawn(
        |_| {},
        fail_the_report_read,
        |cmd| crate::tokio::spawn::spawn(cmd).map(drop),
    );
    assert_unadopted_front_noted(&err, pid);
}

/// Async twin of the sync `macos_a_front_whose_identity_is_refused_is_left_and_noted`.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_a_front_whose_identity_is_refused_is_left_and_noted() {
    use crate::child::front_kill_tests::{assert_unadopted_front_noted, fail_a_front_spawn, refuse_the_identity};
    let (err, pid) = fail_a_front_spawn(
        |_| {},
        refuse_the_identity,
        |cmd| crate::tokio::spawn::spawn(cmd).map(drop),
    );
    assert_unadopted_front_noted(&err, pid);
}

/// Async twin of the sync `macos_a_front_whose_attach_fails_is_left_unreaped_and_noted`.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_a_front_whose_attach_fails_is_left_unreaped_and_noted() {
    use crate::child::front_kill_tests::{assert_attach_failure_left_the_front, fail_a_front_spawn, fail_the_attach};
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (err, pid) = fail_a_front_spawn(|_| {}, fail_the_attach, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
    assert_attach_failure_left_the_front(&err, pid, mark);
}

/// Async twin of the sync `macos_an_identity_check_that_found_the_front_gone_does_not_claim_it_unreaped`.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_an_identity_check_that_found_the_front_gone_does_not_claim_it_unreaped() {
    use crate::child::front_kill_tests::{assert_noted_unaccounted, fail_a_front_spawn, identity_finds_the_front_gone};
    let (err, _pid) = fail_a_front_spawn(
        |_| {},
        identity_finds_the_front_gone,
        |cmd| crate::tokio::spawn::spawn(cmd).map(drop),
    );
    assert_noted_unaccounted(&err);
}
