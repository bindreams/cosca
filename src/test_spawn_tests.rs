//! Tests for the raw-spawn helpers. Unix only: they observe the fork from a `pre_exec` closure.
#![cfg(unix)]

#[cfg(target_os = "linux")]
#[path = "test_spawn_tests/window.rs"]
mod window;

use std::io::Read;
use std::os::fd::AsRawFd;
use std::process::Command;

/// A `/bin/true` command whose `pre_exec` writes one byte to `report_fd`: 1 if the fork ran
/// inside a locked section of [`super`], else 0. `pre_exec` runs in the forked child, so the byte
/// is the child's inherited copy of the forking thread's state at the instant of the fork.
fn true_reporting_lock_held(report_fd: std::os::fd::RawFd) -> Command {
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new("/bin/true");
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
    // EOF (no byte) means the child never reported.
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
fn output_forks_under_the_lock() {
    let held = lock_held_at_fork(|cmd| {
        super::output(cmd).expect("output");
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

/// Control: a plain `Command::spawn` does not fork under the lock, so the reports above measure
/// the helpers and not something ambient.
#[test]
fn a_plain_spawn_forks_outside_the_lock() {
    let held = lock_held_at_fork(|cmd| {
        cmd.spawn().expect("spawn").wait().expect("wait");
    });
    assert_eq!(held, Some(false));
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn spawn_tokio_forks_under_the_lock() {
    let (mut report_read, report_write) = std::io::pipe().expect("open the report pipe");
    let report_fd = report_write.as_raw_fd();
    let mut cmd = ::tokio::process::Command::new("/bin/true");
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
