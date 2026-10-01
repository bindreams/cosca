//! An executable a test writes, and a fork from another thread while it is still open for writing.
//! A forked child keeps a copy of the writable descriptor until it execs or exits, and `execve` of
//! the file fails with `ETXTBSY` meanwhile.
//!
//! Each test forks a child that parks while the writer's `fill` runs, then execs the file. Only a
//! fork that lands inside the write makes that exec fail.

use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, RawFd};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;

use crate::containment::cgroup::test_support::block_on;

const SCRIPT: &[u8] = b"#!/bin/sh\nexit 7\n";

/// Execs `tool` and requires its own exit code.
fn assert_runs(tool: &Path, status: std::io::Result<std::process::ExitStatus>) {
    match status {
        Ok(status) => assert_eq!(status.code(), Some(7), "{tool:?} ran but exited {status:?}"),
        Err(e) => panic!("exec {tool:?}: {e}; a fork inside the write still holds it open for writing"),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Contended,
    Forked,
}

/// Forks a child that parks until a byte arrives on `gate_fd`, then `_exit`s. Returns its pid.
fn fork_parked(gate_fd: RawFd) -> libc::pid_t {
    // SAFETY: the child runs only `block_on` (async-signal-safe) and `_exit`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        block_on(gate_fd);
        // SAFETY: async-signal-safe.
        unsafe { libc::_exit(0) };
    }
    pid
}

fn reap(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: `pid` is this process's own child, reaped once.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
}

/// A fork under `spawn_lock` from another thread, started inside the write: it waits out the
/// write, so the file runs while its child is parked.
#[test]
fn a_locked_fork_cannot_land_inside_write_executable_locked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tool = dir.path().join("tool");
    let (gate_read, mut gate_write) = std::io::pipe().expect("gate pipe");
    let gate_fd = gate_read.as_raw_fd();
    let (events, events_rx) = mpsc::channel::<Event>();
    let mut forker = None;
    super::locked::write_executable_locked(&tool, 0o755, |file| {
        file.write_all(SCRIPT)?;
        forker = Some(std::thread::spawn(move || {
            let guard = crate::child::spawn::spawn_lock_tracked(|| {
                _ = events.send(Event::Contended);
            });
            let pid = fork_parked(gate_fd);
            drop(guard);
            _ = events.send(Event::Forked);
            pid
        }));
        // Leave the write only once the fork has landed inside it, or is shut out until it ends.
        // Contention alone may be another test's spawn, which ends while this write goes on.
        loop {
            match events_rx.recv().expect("the forker reports") {
                Event::Forked => break,
                Event::Contended if crate::test_spawn::held_by_this_thread() => break,
                Event::Contended => {}
            }
        }
        Ok(())
    })
    .expect("write the tool");
    let status = crate::test_spawn::status(&mut Command::new(&tool));
    gate_write.write_all(&[1]).expect("release the parked child");
    reap(forker.expect("the forker started").join().expect("forker"));
    assert_runs(&tool, status);
}

/// The unlocked control spawn, started from another thread inside the write, is refused before
/// it forks: this suite's process runs other tests.
#[test]
fn an_unlocked_spawn_is_refused_in_a_process_shared_with_other_tests() {
    use std::os::unix::process::CommandExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let tool = dir.path().join("tool");
    let (gate_read, mut gate_write) = std::io::pipe().expect("gate pipe");
    let gate_fd = gate_read.as_raw_fd();
    let (mut spawner, mut forked) = (None, false);
    super::locked::write_executable_locked(&tool, 0o755, |file| {
        file.write_all(SCRIPT)?;
        let (mut report_read, report_write) = std::io::pipe()?;
        let report_fd = report_write.as_raw_fd();
        spawner = Some(std::thread::spawn(move || {
            // Dropped by a refused spawn, so the read below sees EOF.
            let _report_write = report_write;
            let mut cmd = Command::new("/bin/true");
            // SAFETY: `write` and `block_on` are async-signal-safe.
            unsafe {
                cmd.pre_exec(move || {
                    libc::write(report_fd, [1u8].as_ptr().cast(), 1);
                    block_on(gate_fd);
                    Ok(())
                });
            }
            crate::test_spawn::spawn_unlocked(&mut cmd)
        }));
        // One byte: the child forked and is parked inside this write. EOF: refused before the fork.
        forked = report_read.read(&mut [0u8; 1])? == 1;
        Ok(())
    })
    .expect("write the tool");
    let status = crate::test_spawn::status(&mut Command::new(&tool));
    gate_write.write_all(&[1]).expect("release a parked child");
    let spawned = spawner.expect("the spawner started").join();
    if forked {
        if let Ok(Ok(mut child)) = spawned {
            child.wait().expect("wait for the unlocked child");
        }
        assert_runs(&tool, status);
        panic!("the unlocked spawn forked in a process shared with other tests");
    }
    let refusal = spawned.expect_err("the unlocked spawn must be refused, not fail");
    let message = refusal
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| refusal.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(message.contains("a fork without spawn_lock"), "{message}");
    assert_runs(&tool, status);
}

/// `unshare(CLONE_FILES)` from another thread, started inside the write: the private table it
/// copies is a fork's in all but name, so it waits out the write too. Container seccomp profiles
/// refuse `unshare`; the cgroup lane, which runs unconfined, runs this.
#[test]
fn cgroup_an_unshared_fd_table_cannot_copy_a_write_in_progress() {
    if !crate::test_support::require_group("CGROUP") {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let tool = dir.path().join("tool");
    let (gate_read, mut gate_write) = std::io::pipe().expect("gate pipe");
    let gate_fd = gate_read.as_raw_fd();
    let (events, events_rx) = mpsc::channel::<Event>();
    let mut unsharer = None;
    super::locked::write_executable_locked(&tool, 0o755, |file| {
        file.write_all(SCRIPT)?;
        let contended = events.clone();
        let unshared = events.clone();
        unsharer = Some(std::thread::spawn(move || {
            let result = crate::test_spawn::unshare_files_locked(|| {
                _ = contended.send(Event::Contended);
            });
            _ = unshared.send(Event::Forked);
            // The private table lives as long as this thread.
            block_on(gate_fd);
            result
        }));
        // As in `a_locked_fork_cannot_land_inside_write_executable_locked`.
        loop {
            match events_rx.recv().expect("the unsharer reports") {
                Event::Forked => break,
                Event::Contended if crate::test_spawn::held_by_this_thread() => break,
                Event::Contended => {}
            }
        }
        Ok(())
    })
    .expect("write the tool");
    let status = crate::test_spawn::status(&mut Command::new(&tool));
    gate_write.write_all(&[1]).expect("release the unsharing thread");
    let unshared = unsharer.expect("the unsharer started").join().expect("unsharer");
    unshared.expect("unshare(CLONE_FILES)");
    assert_runs(&tool, status);
}
