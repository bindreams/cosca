//! Tests for the raw-spawn helpers. Unix only: they observe the fork from a `pre_exec` closure.
#![cfg(unix)]

#[cfg(target_os = "linux")]
#[path = "test_spawn_tests/window.rs"]
mod window;

#[cfg(target_os = "linux")]
#[path = "test_spawn_tests/executable.rs"]
mod executable;

use super::locked;
use crate::test_own_process::{own_process, test_path};

use std::io::Read;
use std::os::fd::AsRawFd;
use std::process::Command;

/// A `/usr/bin/true` command whose `pre_exec` writes one byte to `report_fd`: 1 if the fork ran
/// inside a locked section of [`super`], else 0.
fn true_reporting_lock_held(report_fd: std::os::fd::RawFd) -> Command {
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new("/usr/bin/true");
    // SAFETY: the closure reads a const-initialised thread-local `Cell<bool>` and calls
    // `write(2)`, both async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            let held: u8 = super::held_by_this_thread().into();
            libc::write(report_fd, (&raw const held).cast(), 1);
            Ok(())
        });
    }
    cmd
}

/// Runs `spawn` on a command that reports, from its forked child, whether the fork ran under the
/// lock. `None` if the child never reported.
fn lock_held_at_fork(spawn: impl FnOnce(&mut Command)) -> Option<bool> {
    let (mut report_read, report_write) = std::io::pipe().expect("open the report pipe");
    let mut cmd = true_reporting_lock_held(report_write.as_raw_fd());
    spawn(&mut cmd);
    drop(cmd);
    drop(report_write);
    let mut byte = [0u8; 1];
    (report_read.read(&mut byte).expect("read the report") == 1).then(|| byte[0] == 1)
}

#[test]
fn spawn_forks_under_the_lock() {
    let held = lock_held_at_fork(|cmd| {
        super::spawn(cmd).expect("spawn").wait().expect("wait");
    });
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[test]
fn output_captured_forks_under_the_lock() {
    let held = lock_held_at_fork(|cmd| {
        super::output_captured(cmd).expect("output");
    });
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[test]
fn status_forks_under_the_lock() {
    let held = lock_held_at_fork(|cmd| {
        super::status(cmd).expect("status");
    });
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

/// Control: a plain `Command::spawn` reports unlocked, so the tests above measure the helpers, not
/// ambient state.
#[test]
fn a_plain_spawn_forks_outside_the_lock() {
    let Some(_alone) = own_process(test_path!(a_plain_spawn_forks_outside_the_lock), super::spawn) else {
        return;
    };
    let held = lock_held_at_fork(|cmd| {
        super::spawn_unlocked(cmd).expect("spawn").wait().expect("wait");
    });
    assert_eq!(held, Some(false));
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn spawn_tokio_forks_under_the_lock() {
    let (mut report_read, report_write) = std::io::pipe().expect("open the report pipe");
    let report_fd = report_write.as_raw_fd();
    let mut cmd = ::tokio::process::Command::new("/usr/bin/true");
    // SAFETY: as in `true_reporting_lock_held`.
    unsafe {
        cmd.pre_exec(move || {
            let held: u8 = super::held_by_this_thread().into();
            libc::write(report_fd, (&raw const held).cast(), 1);
            Ok(())
        });
    }
    let mut child = super::spawn_tokio(&mut cmd).expect("spawn");
    drop(cmd);
    drop(report_write);
    child.wait().await.expect("wait");
    let mut byte = [0u8; 1];
    assert_eq!(report_read.read(&mut byte).expect("read the report"), 1, "no report");
    assert_eq!(byte[0], 1, "the fork must run under spawn_lock");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn output_captured_tokio_forks_under_the_lock() {
    let held =
        lock_held_at_fork_tokio(|cmd| Box::pin(async move { super::output_captured_tokio(cmd).await.map(drop) })).await;
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn status_tokio_forks_under_the_lock() {
    let held = lock_held_at_fork_tokio(|cmd| Box::pin(async move { super::status_tokio(cmd).await.map(drop) })).await;
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[cfg(feature = "tokio")]
type TokioRun<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + 'a>>;

#[cfg(feature = "tokio")]
async fn lock_held_at_fork_tokio(
    run: impl for<'a> FnOnce(&'a mut ::tokio::process::Command) -> TokioRun<'a>,
) -> Option<bool> {
    let (mut report_read, report_write) = std::io::pipe().expect("open the report pipe");
    let report_fd = report_write.as_raw_fd();
    let mut cmd = ::tokio::process::Command::new("/usr/bin/true");
    // SAFETY: as in `true_reporting_lock_held`.
    unsafe {
        cmd.pre_exec(move || {
            let held: u8 = super::held_by_this_thread().into();
            libc::write(report_fd, (&raw const held).cast(), 1);
            Ok(())
        });
    }
    run(&mut cmd).await.expect("run");
    drop(cmd);
    drop(report_write);
    let mut byte = [0u8; 1];
    (report_read.read(&mut byte).expect("read the report") == 1).then(|| byte[0] == 1)
}

// The integration tests' wrappers =====

#[test]
fn spawn_locked_forks_under_the_lock() {
    let held = lock_held_at_fork(|cmd| {
        locked::spawn_locked(cmd).expect("spawn").wait().expect("wait");
    });
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[test]
fn output_locked_forks_under_the_lock() {
    let held = lock_held_at_fork(|cmd| {
        locked::output_locked(cmd).expect("output");
    });
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[test]
fn status_locked_forks_under_the_lock() {
    let held = lock_held_at_fork(|cmd| {
        locked::status_locked(cmd).expect("status");
    });
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn spawn_locked_tokio_forks_under_the_lock() {
    let held =
        lock_held_at_fork_tokio(|cmd| Box::pin(async move { locked::spawn_locked_tokio(cmd)?.wait().await.map(drop) }))
            .await;
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn output_locked_tokio_forks_under_the_lock() {
    let held =
        lock_held_at_fork_tokio(|cmd| Box::pin(async move { locked::output_locked_tokio(cmd).await.map(drop) })).await;
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn status_locked_tokio_forks_under_the_lock() {
    let held =
        lock_held_at_fork_tokio(|cmd| Box::pin(async move { locked::status_locked_tokio(cmd).await.map(drop) })).await;
    assert_eq!(held, Some(true), "the fork must run under spawn_lock");
}

// Results =====

const CHATTY: &str = "echo out; echo err >&2; exit 3";

fn chatty() -> Command {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", CHATTY]);
    cmd
}

#[test]
fn output_captured_returns_the_streams_and_the_exit_status() {
    let out = super::output_captured(&mut chatty()).expect("output_captured");
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, b"err\n");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn output_captured_overrides_the_callers_stdio() {
    let mut cmd = Command::new("/bin/sh");
    // `cat` sees the null stdin as EOF; the caller's inherited stdout and stderr are replaced.
    cmd.args(["-c", "cat; echo out; echo err >&2"])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    let out = super::output_captured(&mut cmd).expect("output_captured");
    assert_eq!(
        (out.stdout.as_slice(), out.stderr.as_slice()),
        (&b"out\n"[..], &b"err\n"[..])
    );
}

#[test]
fn status_returns_the_exit_code() {
    let mut cmd = chatty();
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    assert_eq!(super::status(&mut cmd).expect("status").code(), Some(3));
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn output_captured_tokio_returns_the_streams_and_the_exit_status() {
    let mut cmd = ::tokio::process::Command::new("/bin/sh");
    cmd.args(["-c", CHATTY]);
    let out = super::output_captured_tokio(&mut cmd)
        .await
        .expect("output_captured_tokio");
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, b"err\n");
    assert_eq!(out.status.code(), Some(3));
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn status_tokio_returns_the_exit_code() {
    let mut cmd = ::tokio::process::Command::new("/bin/sh");
    cmd.args(["-c", "exit 3"]);
    assert_eq!(
        super::status_tokio(&mut cmd).await.expect("status_tokio").code(),
        Some(3)
    );
}

// The lock is not held across the wait =====

/// Arms the seam to record whether this thread holds `spawn_lock` between the spawn and the wait.
fn record_lock_held_at_wait() -> (std::rc::Rc<std::cell::Cell<Option<bool>>>, crate::oneshot_hook::Armed) {
    let held = std::rc::Rc::new(std::cell::Cell::new(None));
    let armed = super::set_between_spawn_and_wait({
        let held = held.clone();
        move || held.set(Some(super::held_by_this_thread()))
    });
    (held, armed)
}

fn true_command() -> Command {
    Command::new("/usr/bin/true")
}

#[test]
fn output_captured_releases_the_lock_before_the_wait() {
    let (held, _armed) = record_lock_held_at_wait();
    super::output_captured(&mut true_command()).expect("output_captured");
    assert_eq!(held.get(), Some(false), "the lock must not be held across the wait");
}

#[test]
fn status_releases_the_lock_before_the_wait() {
    let (held, _armed) = record_lock_held_at_wait();
    super::status(&mut true_command()).expect("status");
    assert_eq!(held.get(), Some(false), "the lock must not be held across the wait");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn output_captured_tokio_releases_the_lock_before_the_wait() {
    let (held, _armed) = record_lock_held_at_wait();
    super::output_captured_tokio(&mut ::tokio::process::Command::new("/usr/bin/true"))
        .await
        .expect("output_captured_tokio");
    assert_eq!(held.get(), Some(false), "the lock must not be held across the wait");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn status_tokio_releases_the_lock_before_the_wait() {
    let (held, _armed) = record_lock_held_at_wait();
    super::status_tokio(&mut ::tokio::process::Command::new("/usr/bin/true"))
        .await
        .expect("status_tokio");
    assert_eq!(held.get(), Some(false), "the lock must not be held across the wait");
}
