//! The async spawn's pre-fork probe and `pre_exec` pidfd handshake; the sync twins are in
//! `child/spawn/pidfd_handshake_tests.rs`. A program that "ran" is told apart by its stdout, read
//! to EOF after the command is dropped.

use std::io::Read;
use std::os::fd::OwnedFd;

use rustix::io::Errno;

use crate::child::spawn::pidfd_handshake::fault;
use crate::error::Error;
use crate::stdio::Stdio;
use crate::tokio::Command;

fn marker_command() -> (Command, std::io::PipeReader) {
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "echo ran"]);
    cmd.stdout(Stdio::from_file(std::fs::File::from(OwnedFd::from(writer))))
        .expect("set stdout");
    (cmd, reader)
}

fn program_ran(cmd: Command, mut reader: std::io::PipeReader) -> bool {
    drop(cmd);
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read the marker to EOF");
    out == "ran\n"
}

/// Mutant: the probe is skipped (the refusal lands after the fork, so `spawns()` is 1).
#[tokio::test]
async fn a_refused_probe_fails_unsupported_and_forks_nothing() {
    for (errno, name) in [(Errno::PERM, "EPERM"), (Errno::NOSYS, "ENOSYS")] {
        let (mut cmd, reader) = marker_command();
        fault::reset_spawns();
        let forced = crate::wait::backend::fault::force_pidfd_open_errno_once(errno);
        let err = cmd.spawn().err();
        drop(forced);

        assert!(
            matches!(err, Some(Error::Unsupported { platform: "linux", .. })),
            "{name}: {err:?}"
        );
        assert_eq!(fault::spawns(), 0, "{name}: the fork must not be reached");
        assert!(!program_ran(cmd, reader), "{name}: the program must not run");
    }
}

/// Mutants: the hook does not wait for the verdict; the parent says "go" on failure.
#[tokio::test]
async fn emfile_after_the_fork_fails_io_and_the_program_never_runs() {
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
    assert_eq!(fault::take_leaked_pid(), None);
    assert!(!program_ran(cmd, reader), "the aborted child must never exec");
}

#[tokio::test]
async fn a_normal_spawn_runs_the_program() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let mut child = cmd.spawn().expect("a normal spawn succeeds");
    assert_eq!(fault::spawns(), 1);
    assert!(child.wait().await.expect("wait").success());
    assert!(program_ran(cmd, reader));
}
