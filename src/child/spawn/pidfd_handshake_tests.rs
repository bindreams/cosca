//! Tests for the Linux pre-fork probe and the `pre_exec` pidfd handshake.
//!
//! A program that "ran" is told apart from one that did not by its stdout: the test owns the only
//! write end besides the child's, so reading to EOF returns once the child is gone, with data
//! exactly if the program ran. No timing is involved.

use std::io::Read;
use std::os::fd::OwnedFd;

use rustix::io::Errno;

use super::fault::{self, ChildFault};
use crate::command::Command;
use crate::error::Error;
use crate::stdio::Stdio;

/// A command that writes `ran` to a pipe and exits, and the read end of that pipe.
fn marker_command() -> (Command, std::io::PipeReader) {
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "echo ran"]);
    cmd.stdout(Stdio::from_file(std::fs::File::from(OwnedFd::from(writer))))
        .expect("set stdout");
    (cmd, reader)
}

/// Whether the program ran: `cmd` is dropped first, so the child holds the only write end.
fn program_ran(cmd: Command, mut reader: std::io::PipeReader) -> bool {
    drop(cmd);
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read the marker to EOF");
    out == "ran\n"
}

/// The calling thread has no child, running or zombie. `__WNOTHREAD` keeps the answer to this
/// thread's own children, so a concurrent test's child cannot change it.
fn assert_no_child_of_this_thread(what: &str) {
    // SAFETY: a `waitid` with no output buffer, `WNOWAIT`: it consumes nothing.
    let rc = unsafe {
        libc::waitid(
            libc::P_ALL,
            0,
            std::ptr::null_mut(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WNOTHREAD,
        )
    };
    let err = std::io::Error::last_os_error();
    assert!(
        rc == -1 && err.raw_os_error() == Some(libc::ECHILD),
        "{what}: this thread must have no child, got rc {rc} ({err})"
    );
}

// Normal spawns =====

/// Mutant: a handshake that leaves the child held forever (the spawn hangs) or aborts it.
#[test]
fn a_normal_spawn_runs_the_program_and_forks_once() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let child = cmd.spawn().expect("a normal spawn succeeds");
    assert_eq!(fault::spawns(), 1);
    assert!(child.wait().expect("wait").success());
    assert_no_child_of_this_thread("after the wait");
    assert!(program_ran(cmd, reader));
}

// The pre-fork probe =====

/// A refusal before the fork is `Unsupported` naming `spawn`, and no child is ever forked.
///
/// Mutant: the probe is skipped (the refusal then lands after the fork, so `spawns()` is 1).
#[test]
fn a_refused_probe_fails_unsupported_and_forks_nothing() {
    for (errno, name) in [
        (Errno::PERM, "EPERM"),
        (Errno::ACCESS, "EACCES"),
        (Errno::NODEV, "ENODEV"),
        (Errno::NOSYS, "ENOSYS"),
    ] {
        let (mut cmd, reader) = marker_command();
        fault::reset_spawns();
        let forced = crate::wait::backend::fault::force_pidfd_open_errno_once(errno);
        let err = cmd.spawn().err();
        drop(forced);

        let err = err.unwrap_or_else(|| panic!("{name}: a refused pidfd_open must fail the spawn"));
        assert_eq!(
            err.to_string(),
            format!(
                "spawn is not supported on linux: cosca requires pidfd_open (Linux \u{2265} 5.3), \
                 refused here: pidfd_open answered {name}"
            ),
            "{err:?}"
        );
        assert_eq!(fault::spawns(), 0, "{name}: the fork must not be reached");
        assert_no_child_of_this_thread(name);
        assert!(!program_ran(cmd, reader), "{name}: the program must not run");
    }
}

/// A transient failure of the probe itself fails the spawn as `Io` naming `pidfd_open`, before any
/// fork.
#[test]
fn a_probe_that_hits_emfile_fails_io_and_forks_nothing() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let forced = crate::wait::backend::fault::force_pidfd_open_errno_once(Errno::MFILE);
    let err = cmd.spawn().err();
    drop(forced);

    match err.expect("a failed probe must fail the spawn") {
        Error::Io(e) => assert_eq!(e.to_string(), "pidfd_open: Too many open files (os error 24)"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(fault::spawns(), 0);
    assert!(!program_ran(cmd, reader));
}

// The handshake =====

/// The probe passes and the open after the fork hits `EMFILE`: the spawn fails `Io` naming
/// `pidfd_open`, and the program never ran. std collected the child.
///
/// Mutants: the hook does not wait for the verdict; the parent says "go" on failure.
#[test]
fn emfile_after_the_fork_fails_io_and_the_program_never_runs() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    fault::reset_leaked_pid();
    let forced = crate::wait::backend::fault::force_pidfd_open_script([None, Some(Errno::MFILE)]);
    let err = cmd.spawn().err();
    drop(forced);

    match err.expect("a failed pidfd_open must fail the spawn") {
        Error::Io(e) => assert_eq!(e.to_string(), "pidfd_open: Too many open files (os error 24)"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(fault::spawns(), 1, "the child was forked and held");
    assert_eq!(fault::take_leaked_pid(), None, "std collected the aborted child");
    assert_no_child_of_this_thread("after the abort");
    assert!(!program_ran(cmd, reader), "the aborted child must never exec");
}

/// A refusal that only shows after the fork is still `Unsupported`, and the program never ran.
#[test]
fn a_refusal_after_the_fork_is_unsupported_and_the_program_never_runs() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let forced = crate::wait::backend::fault::force_pidfd_open_script([None, Some(Errno::PERM)]);
    let err = cmd.spawn().err();
    drop(forced);

    assert!(
        matches!(err, Some(Error::Unsupported { platform: "linux", .. })),
        "{err:?}"
    );
    assert_eq!(fault::spawns(), 1);
    assert_no_child_of_this_thread("after the abort");
    assert!(!program_ran(cmd, reader));
}

// Deadlock paths =====

/// A child whose hook fails before it reports its pid ends the helper at EOF, and the spawn
/// reports the child's error.
///
/// Mutant: the parent keeps its copy of the child's end open (the helper never sees EOF and the
/// spawn hangs).
#[test]
fn a_child_that_fails_before_reporting_its_pid_ends_the_spawn() {
    let (mut cmd, reader) = marker_command();
    let armed = fault::arm_child_fault(ChildFault::Fail);
    let err = cmd.spawn().err();
    drop(armed);

    match err.expect("a child that fails before exec fails the spawn") {
        Error::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{e:?}"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_no_child_of_this_thread("std collected the failed child");
    assert!(!program_ran(cmd, reader));
}

/// A child killed before it reports its pid: std reads the closed status pipe as success, the
/// helper reads EOF. The child is dead, unreaped and pidless-to-us, so it is left unreaped and
/// named, and the spawn fails.
#[test]
fn a_child_killed_before_reporting_its_pid_is_left_unreaped_and_named() {
    use std::os::unix::process::ExitStatusExt;

    let (mut cmd, reader) = marker_command();
    fault::reset_leaked_pid();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let err = cmd.spawn().err();
    drop(armed);

    let err = err.expect("a child killed before it reports fails the spawn");
    let pid = fault::take_leaked_pid()
        .expect("the unreaped child is named")
        .expect("it has a pid");
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    // The test owns this cleanup: the pid is this thread's unreaped zombie.
    let mut status = 0;
    // SAFETY: `pid` is this thread's own zombie child, so waiting on it is sound.
    let reaped = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(reaped, pid as i32);
    assert_eq!(std::process::ExitStatus::from_raw(status).signal(), Some(libc::SIGKILL));
    assert!(!program_ran(cmd, reader));
}

/// A spawn that fails before any fork still ends the helper thread: `run` returns.
///
/// Mutant: the parent keeps its copy of the child's end open (`run` hangs).
#[test]
fn a_spawn_that_fails_before_the_fork_ends_the_helper() {
    let mut std_cmd = std::process::Command::new("true");
    let guard = super::super::spawn_lock();
    let handshake = super::install(&mut std_cmd, &guard).expect("install");
    let result = handshake.run(
        || Err::<(), _>(std::io::Error::other("failed before the fork")),
        |()| None,
    );
    drop(guard);

    match result {
        Err(Error::Io(e)) => assert_eq!(e.to_string(), "failed before the fork"),
        other => panic!("expected the spawn's own error, got {:?}", other.err()),
    }
}

/// The helper has run to its end when `run` returns: it is joined, not detached.
///
/// Mutant: the helper is detached (a `thread::spawn` that is never joined). The probe holds the
/// helper at its very end until the join point opens its gate, so an unjoined helper is never
/// released and never finishes.
#[test]
fn the_helper_is_joined_before_the_spawn_returns() {
    let (mut cmd, reader) = marker_command();
    let probe = fault::arm_helper_probe();
    let child = cmd.spawn().expect("spawn");
    assert!(
        probe.finished(),
        "the helper thread must be joined before spawn returns"
    );
    assert!(child.wait().expect("wait").success());
    assert!(program_ran(cmd, reader));
}
