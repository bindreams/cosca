//! Signals to the shim and to the program before its `exec`.

use super::*;
use crate::elevation::shim::hooks::Gate;
use crate::elevation::shim::link::KillOutcome;
use crate::elevation::shim::protocol::{NotExecuted, Refusal, Signal as ReportedSignal};
use rustix::process::{pidfd_send_signal, Signal};

/// A started shim whose program blocks until the test lets go of its stdin.
fn blocked(rig: &ShimRig) -> rig::Run {
    let mut run = rig.spawn(Spec::new("cat", &[]).stdin_held());
    run.wait_for("status pipe: EOF");
    run
}

fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}

/// A program is terminated before its `exec`: the child records it, and does not exec.
fn terminated_before_exec(signal_the_child: impl FnOnce(&ShimRig, &mut rig::Run), wait_for: &str, expected: i32) {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut run = rig.spawn(marker_program(&marker).child_gate());
    run.wait_for("child: waiting at gate");
    signal_the_child(&rig, &mut run);
    // The signal is recorded by the child's handler; the gate is released after the shim logged it.
    run.wait_for(wait_for);
    run.release_child();
    assert_eq!(
        rig.link.link.wait().unwrap(),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: true,
            cause: NotStartedCause::NotExecuted(NotExecuted::TerminatedBeforeExec(ReportedSignal(expected))),
        })
    );
    let done = run.finish();
    assert_eq!(done.code, Some(117), "{}", done.stderr);
    assert!(!marker.exists(), "the program ran");
}

#[skuld::test]
fn terminate_before_exec_is_not_started() {
    // `T` is what `terminate()` sends; the shim relays it as SIGTERM.
    terminated_before_exec(
        |rig, _| rig.link.link.send_control(b'T').unwrap(),
        "control: signal Term",
        libc::SIGTERM,
    );
}

#[skuld::test]
fn sigint_before_exec_is_not_started() {
    // A terminal's SIGINT reaches the child directly.
    terminated_before_exec(
        |_, run| {
            let child = run.program_pidfd();
            pidfd_send_signal(&child, Signal::INT).expect("the child is alive at its gate");
        },
        "forked child pid=",
        libc::SIGINT,
    );
}

#[skuld::test]
fn unknown_control_byte_kills_and_reports_the_status() {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::new("cat", &[]).stdin_held().gate(Gate::BeforeLoop));
    run.wait_for("gate: waiting at before-loop");
    // Both bytes are queued before the loop reads either: the `X` ends the program, and a shim that
    // finished before the `P` was sent would make that send fail.
    rig.link.link.send_control(b'X').unwrap();
    // The ping comes after the `X` on one stream: its answer orders the check.
    rig.link.link.send_control(b'P').unwrap();
    run.release(Gate::BeforeLoop);
    run.wait_for("pong");
    assert!(
        run.lines().iter().any(|l| l.contains("protocol violation: byte 0x58")),
        "{:#?}",
        run.lines()
    );
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(libc::SIGKILL));
    assert_eq!(run.finish().code, Some(128 + libc::SIGKILL));
}

#[skuld::test]
fn catchable_terminating_signal_to_the_shim_kills_the_program_and_reports_its_status() {
    let signals = [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        // A Rust runtime starts with it ignored, so the shim cannot tell the caller's wish, and
        // catches it like the rest.
        libc::SIGPIPE,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGALRM,
        libc::SIGVTALRM,
        libc::SIGPROF,
        libc::SIGIO,
        libc::SIGPWR,
        libc::SIGSTKFLT,
        libc::SIGXCPU,
        libc::SIGXFSZ,
        libc::SIGRTMIN() + 1,
        libc::SIGRTMAX(),
    ];
    for signal in signals {
        let rig = ShimRig::new();
        let run = blocked(&rig);
        // Caught: an uncaught one would leave the program running and the wait below unending.
        let caught = run.signal_mask("SigCgt");
        assert_ne!(caught & bit(signal), 0, "signal {signal} is not caught: {caught:#x}");
        // SAFETY: the shim is this test's unreaped child, signalled through its pidfd.
        let signal = unsafe { rustix::process::Signal::from_raw_unchecked(signal) };
        run.signal(signal);
        assert_eq!(
            rig.link.link.wait().unwrap(),
            LinkOutcome::Exited(libc::SIGKILL),
            "signal {signal:?}"
        );
        assert_eq!(run.finish().code, Some(128 + libc::SIGKILL), "signal {signal:?}");
    }
}

#[skuld::test]
fn stop_signals_leave_the_shim_serving_control() {
    let rig = ShimRig::new();
    let mut run = blocked(&rig);
    // Caught, so that the default action (stopping the shim) never happens.
    let caught = run.signal_mask("SigCgt");
    for signal in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
        assert_ne!(caught & bit(signal), 0, "signal {signal} is not caught: {caught:#x}");
    }
    for signal in [Signal::TSTP, Signal::TTIN, Signal::TTOU] {
        run.signal(signal);
    }
    rig.link.link.send_control(b'P').unwrap();
    run.wait_for("pong");
    assert_eq!(rig.link.link.kill().unwrap(), KillOutcome::Delivered);
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(libc::SIGKILL));
    run.finish();
}

#[skuld::test]
fn signal_ignored_by_the_caller_stays_ignored_by_the_shim() {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::new("cat", &[]).stdin_held().ignoring(libc::SIGHUP));
    run.wait_for("status pipe: EOF");
    assert_ne!(run.signal_mask("SigIgn") & bit(libc::SIGHUP), 0, "SIGHUP stays ignored");
    assert_eq!(run.signal_mask("SigCgt") & bit(libc::SIGHUP), 0, "SIGHUP is not caught");
    run.signal(Signal::HUP);
    rig.link.link.send_control(b'P').unwrap();
    run.wait_for("pong");
    assert_eq!(rig.link.link.kill().unwrap(), KillOutcome::Delivered);
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(libc::SIGKILL));
    run.finish();
}

#[skuld::test]
fn exit_racing_kill_reports_the_programs_own_status() {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::sh("exit 42").gate(Gate::BeforeLoop));
    let program = run.program_pidfd();
    run.wait_for("gate: waiting at before-loop");
    // The program has exited (its pidfd is readable) before the shim looks, and `K` arrives too.
    wait_until_exited(&program);
    assert_eq!(rig.link.link.kill().unwrap(), KillOutcome::Delivered);
    run.release(Gate::BeforeLoop);
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(42 << 8));
    assert_eq!(run.finish().code, Some(42));
}

/// Blocks until the process behind `pidfd` has exited.
fn wait_until_exited(pidfd: &rustix::fd::OwnedFd) {
    let mut fds = [rustix::event::PollFd::new(pidfd, rustix::event::PollFlags::IN)];
    loop {
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => return,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => panic!("poll: {e}"),
        }
    }
}

#[skuld::test]
fn lost_after_exec_is_l_not_f() {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::new("cat", &[]).stdin_held().loop_failure());
    run.wait_for("status pipe: EOF");
    run.fail_loop();
    // The program had exec'd, so there is no evidence it never ran: the shim killed it, and says so.
    assert_eq!(
        rig.link.link.wait().unwrap(),
        LinkOutcome::SupervisionLost(libc::SIGKILL)
    );
    assert_eq!(run.finish().code, Some(118));
}

#[skuld::test]
fn sigchld_ignored_by_the_caller_does_not_lose_status() {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::sh("exit 7").ignoring(libc::SIGCHLD));
    run.wait_for("first byte: A");
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(7 << 8));
    assert_eq!(run.finish().code, Some(7));
}

// Before the program starts -----

/// A shim that is held between cosca's answer and the start, signalled with `signal`, and released.
fn signalled_at_the_answer(signal: Signal) -> (rig::Finished, LinkOutcome, bool) {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut run = rig.spawn(marker_program(&marker).gate(Gate::AfterAnswer));
    run.wait_for("gate: waiting at after-answer");
    run.signal(signal);
    run.release(Gate::AfterAnswer);
    let outcome = rig.link.link.wait().unwrap();
    (run.finish(), outcome, marker.exists())
}

#[skuld::test]
fn a_signal_after_the_answer_and_before_the_start_is_not_started() {
    // Each of these kills a shim that has not caught it, and cosca then reports a shim that may
    // still be running a program that never started.
    for signal in [Signal::TERM, Signal::INT, Signal::HUP, Signal::PIPE] {
        let (done, outcome, ran) = signalled_at_the_answer(signal);
        assert_eq!(
            outcome,
            LinkOutcome::NotStarted(NotStarted {
                shim_connected: true,
                cause: NotStartedCause::ShimRefused(Refusal::NoAnswer),
            }),
            "{signal:?}: {}\n{:#?}",
            done.stderr,
            done.lines
        );
        assert_eq!(done.code, Some(124), "{signal:?}: {}", done.stderr);
        assert!(done.stderr.contains("(exit 124)"), "{signal:?}: {}", done.stderr);
        assert!(!done.logged("forked child"), "{signal:?}: {:#?}", done.lines);
        assert!(!ran, "{signal:?}: the program ran");
    }
}

#[skuld::test]
fn a_signal_while_the_child_is_held_is_not_started() {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut run = rig.spawn(marker_program(&marker).gate(Gate::BeforeClone));
    run.wait_for("gate: waiting at before-clone");
    run.signal(Signal::TERM);
    run.release(Gate::BeforeClone);
    // The child is created, held before it arms anything, and killed unreleased.
    assert_eq!(
        rig.link.link.wait().unwrap(),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: true,
            cause: NotStartedCause::ShimRefused(Refusal::NoAnswer),
        })
    );
    let done = run.finish();
    assert_eq!(done.code, Some(124), "{}", done.stderr);
    assert!(done.logged("forked child"), "{:#?}", done.lines);
    assert!(done.logged("held child reaped"), "{:#?}", done.lines);
    assert!(!marker.exists(), "the program ran");
}

#[skuld::test]
fn a_signal_before_the_answer_ends_the_wait() {
    // The acceptor never answers, and a copy of the listener keeps the connection open: only the
    // signal can end the shim's wait.
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut owner = super::rig::Owner::start("hold-copy");
    let mut run = super::owner_tests::owned_by(&rig, &owner, marker_program(&marker));
    run.wait_for("hello sent");
    run.signal(Signal::TERM);
    let done = run.finish();
    // The copy's close would end a wait that ignored the signal, so that such a shim fails by its exit code.
    owner.close_stdin();
    super::owner_tests::assert_never_started(&done, &marker, 124);
    assert!(
        done.logged("a signal reached the shim before the answer"),
        "{:#?}",
        done.lines
    );
}
