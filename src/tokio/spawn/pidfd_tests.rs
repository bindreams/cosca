//! The async spawn's pre-fork probe and `pre_exec` pidfd handshake; the sync twins are in
//! `child/spawn/pidfd_handshake_tests.rs`. A program that "ran" is told apart by its stdout, read
//! to EOF after the command is dropped.

use std::io::Read;
use std::os::fd::OwnedFd;

use rustix::io::Errno;

use crate::child::spawn::pidfd_handshake::fault::{self, ChildFault};
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

/// Mutants: the child execs despite its failed `pidfd_open`; the parent ignores its errno report.
#[tokio::test]
async fn emfile_in_the_child_fails_io_and_the_program_never_runs() {
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
    let probes = fault::arm_end_probes();
    let mut child = cmd.spawn().expect("a normal spawn succeeds");
    drop(probes);
    let ends = fault::take_ends().expect("the end probes saw the run");
    assert!(!ends.child_end_copy_held && ends.eof_reached, "{ends:?}");
    assert_eq!(fault::spawns(), 1);
    assert!(child.wait().await.expect("wait").success());
    assert!(program_ran(cmd, reader));
}

/// A child that sent its pidfd and died before it could be told to go never ran the program: the
/// spawn fails, and tokio reaps the child once the pidfd shows it exited.
///
/// Mutant: `Gone` is a successful spawn.
#[tokio::test]
async fn a_child_gone_before_its_go_ahead_fails_the_spawn_and_is_reaped() {
    let (mut cmd, reader) = marker_command();
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns(|_| {});
    let err = cmd.spawn().err();
    drop(held);
    drop(armed);

    let err = err.expect("a child that never ran the program must fail the spawn");
    assert!(
        err.to_string().ends_with("died before exec: the program never ran"),
        "{err}"
    );
    crate::child::spawn::pidfd_handshake::pidfd_handshake_tests::assert_no_child_of_this_thread(
        "tokio reaped the child",
    );
    assert!(!program_ran(cmd, reader));
}

/// A tokio runtime built without IO makes tokio panic inside the spawn, after std's fork. With a
/// forked copy of the child's end held, the unwind still does not wait on the holder: EOF is
/// forced before the helper is joined.
///
/// Mutant: no forced EOF on unwind (the unwind checks shut the channel and record it).
#[test]
fn a_runtime_without_io_panics_without_waiting_on_a_held_copy() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime without IO");
    let (mut cmd, _reader) = marker_command();
    fault::reset_spawns();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let result = rt.block_on(async { catch_unwind(AssertUnwindSafe(|| cmd.spawn().err())) });
    drop(armed);
    let unwound = fault::take_unwound();
    drop(holder);

    assert!(result.is_err(), "tokio panics in a runtime without IO");
    assert_eq!(fault::spawns(), 1, "the panic came after the fork");
    assert_eq!(
        unwound.map(|u| u.eof_reached),
        Some(true),
        "the helper must read EOF by the time the unwind guards are done"
    );
}
