//! Faults, foreign reaps, descriptors, and the shim dying.

use std::io::Read;
use std::os::fd::AsFd;

use super::*;
use crate::elevation::shim::hooks::Inject;
use crate::elevation::shim::protocol::{Errno, NotExecuted};
use rustix::process::{pidfd_send_signal, Signal};

#[skuld::test]
fn fault_before_exec_kills_the_child_and_is_reported_as_its_status() {
    // Each synchronous fault signal, sent to the child while it waits before `exec`, kills it. A
    // handler there would return to the faulting instruction for ever, so the first loop is the
    // test: it ends before any spin.
    let faults = [
        (Signal::SEGV, libc::SIGSEGV),
        (Signal::BUS, libc::SIGBUS),
        (Signal::ILL, libc::SIGILL),
        (Signal::FPE, libc::SIGFPE),
        (Signal::ABORT, libc::SIGABRT),
        (Signal::TRAP, libc::SIGTRAP),
        (Signal::SYS, libc::SIGSYS),
    ];
    for (signal, number) in faults {
        let rig = ShimRig::new();
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("ran");
        let mut run = rig.spawn(marker_program(&marker).child_gate());
        run.wait_for("child: waiting at gate");
        let child = run.program_pidfd();
        pidfd_send_signal(&child, signal).expect("the child is alive at its gate");
        // A child that survived the signal is released, and then runs the program to its end.
        run.release_child_if_waiting();
        assert_eq!(
            killed_by(rig.link.link.wait().unwrap()),
            Some(number),
            "signal {number}"
        );
        assert!(!marker.exists(), "signal {number}: the program ran");
        run.finish();
    }
    // Only now a real fault before `exec`: the child dies of it, and the program never runs.
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut run = rig.spawn(marker_program(&marker).child_fault());
    run.wait_for("first byte: A");
    assert_eq!(killed_by(rig.link.link.wait().unwrap()), Some(libc::SIGSEGV));
    assert!(!marker.exists(), "the program ran");
    run.finish();
}

/// The signal a program died of, whether or not it dumped core (a core pattern that pipes to a handler
/// can dump whatever the limit says).
fn killed_by(outcome: LinkOutcome) -> Option<i32> {
    match outcome {
        LinkOutcome::Exited(status) if status & 0x7f != 0 => Some(status & 0x7f),
        _ => None,
    }
}

#[skuld::test]
fn stolen_status_is_status_lost_not_zero() {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::sh("exit 0").inject(Inject::StealReap));
    run.wait_for("first byte: A");
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::StatusLost);
    assert_eq!(run.finish().code, Some(112));
}

#[skuld::test]
fn a_reaping_host_thread_gives_status_lost() {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::sh("exit 3").inject(Inject::ReapingHostThread));
    run.wait_for("first byte: A");
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::StatusLost);
    let done = run.finish();
    assert_eq!(done.code, Some(112));
    assert!(done.logged("host thread: reaped pid"), "{:#?}", done.lines);
}

#[skuld::test]
fn exec_failure_with_a_stolen_reap_is_not_started() {
    // The positive evidence of the status pipe wins over a status that was reaped elsewhere.
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::new("/nonexistent/tool", &[]).inject(Inject::StealReap));
    run.wait_for("first byte: A");
    assert_eq!(
        rig.link.link.wait().unwrap(),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: true,
            cause: NotStartedCause::NotExecuted(NotExecuted::ExecFailed(Errno(libc::ENOENT))),
        })
    );
    assert_eq!(run.finish().code, Some(117));
}

#[skuld::test]
fn shim_closing_its_own_fds_lets_the_reader_see_eof() {
    let rig = ShimRig::new();
    // The program closes its stdout and says so on stderr, then waits on stdin.
    let mut run = rig.spawn(
        Spec::sh("exec 1>&-; echo closed >&2; read line; exit 0")
            .stdin_held()
            .gate(crate::elevation::shim::hooks::Gate::BeforeLoop),
    );
    let (mut stdout, mut stderr) = (run.take_stdout(), run.take_stderr());
    // The shim has replaced its own stdio by the time it waits at this gate.
    run.wait_for("gate: waiting at before-loop");
    let mut said = [0u8; 7];
    stderr.read_exact(&mut said).expect("the program's stderr");
    assert_eq!(&said, b"closed\n");
    // Every copy of the pipe's write end is closed now only if the shim closed its own.
    rustix::fs::fcntl_setfl(stdout.as_fd(), rustix::fs::OFlags::NONBLOCK).unwrap();
    let mut rest = [0u8; 1];
    match stdout.read(&mut rest) {
        Ok(0) => {}
        other => panic!("the shim's stdout did not reach end of file: {other:?}"),
    }
    run.release(crate::elevation::shim::hooks::Gate::BeforeLoop);
    run.close_stdin();
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(0));
    run.finish();
}

#[skuld::test]
fn shim_death_before_pdeathsig_is_119_and_never_execs() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(shim_death_before_pdeathsig_is_119_and_never_execs),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    // This process adopts the orphan, so that it can reap it.
    // SAFETY: `prctl` with a boolean argument; the test runs in a process of its own.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut run = rig.spawn(marker_program(&marker).inject(Inject::DieAfterFork).child_gate());
    let child = run.program_pid();
    // The child writes its line, and may do so after the shim has gone.
    run.wait_for_in_log("child: waiting at gate");
    run.wait_for_in_log("seam: shim exits after fork");
    assert_eq!(run.wait_exit().code(), Some(118));
    // The shim is gone and its child, held at the gate, is ours now. It arms `PDEATHSIG` too late to
    // be told, sees that its parent is not the shim, and exits.
    run.release_child();
    let status = rustix::process::waitpid(
        Some(rustix::process::Pid::from_raw(child).unwrap()),
        rustix::process::WaitOptions::empty(),
    )
    .expect("the orphan is ours to reap")
    .expect("it exited");
    assert_eq!(status.1.exit_status(), Some(119), "{status:?}");
    assert!(!marker.exists(), "the program ran");
    run.finish();
}

#[skuld::test]
fn a_setup_the_child_cannot_finish_is_f_and_never_runs_the_program() {
    // The child asks the kernel for a parent-death signal that does not exist, which `prctl` refuses.
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut run = rig.spawn(marker_program(&marker).inject(Inject::ChildSetupFails));
    run.wait_for("first byte: A");
    assert_eq!(
        rig.link.link.wait().unwrap(),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: true,
            cause: NotStartedCause::NotExecuted(NotExecuted::SetupFailed(Errno(libc::EINVAL))),
        })
    );
    assert_eq!(run.finish().code, Some(117));
    assert!(!marker.exists(), "the program ran");
}
