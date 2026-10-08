//! What a started program's end looks like to cosca.

use super::*;
use crate::elevation::shim::hooks::Inject;
use crate::elevation::shim::link::KillOutcome;
use crate::elevation::shim::protocol::{Errno, NotExecuted};

#[skuld::test]
fn real_link_and_real_shim_with_no_front() {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::sh("exit 42"));
    run.wait_for("first byte: A");
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(42 << 8));
    let done = run.finish();
    assert_eq!(done.code, Some(42), "{}", done.stderr);
}

fn started(rig: &ShimRig, spec: Spec) -> rig::Run {
    let mut run = rig.spawn(spec);
    run.wait_for("first byte: A");
    run
}

fn not_executed(cause: NotExecuted) -> LinkOutcome {
    LinkOutcome::NotStarted(NotStarted {
        shim_connected: true,
        cause: NotStartedCause::NotExecuted(cause),
    })
}

#[skuld::test]
fn exec_failure_is_f_not_127() {
    let rig = ShimRig::new();
    let run = started(&rig, Spec::new("/nonexistent/tool", &[]));
    assert_eq!(
        rig.link.link.wait().unwrap(),
        not_executed(NotExecuted::ExecFailed(Errno(libc::ENOENT)))
    );
    let done = run.finish();
    assert_eq!(done.code, Some(117), "{}", done.stderr);
    assert!(done.stderr.is_empty(), "{}", done.stderr);
}

#[skuld::test]
fn fork_failure_is_f() {
    let rig = ShimRig::new();
    let run = started(&rig, Spec::sh("true").inject(Inject::ForkFails));
    assert_eq!(
        rig.link.link.wait().unwrap(),
        not_executed(NotExecuted::ForkFailed(Errno(libc::EAGAIN)))
    );
    assert_eq!(run.finish().code, Some(117));
}

#[skuld::test]
fn fork_pipe_and_exec_failures_are_distinct_causes() {
    let cases = [
        (
            Spec::sh("true").inject(Inject::ForkFails),
            NotExecuted::ForkFailed(Errno(libc::EAGAIN)),
        ),
        (
            Spec::sh("true").inject(Inject::PipeFails),
            NotExecuted::SetupFailed(Errno(libc::EMFILE)),
        ),
        (
            Spec::new("/nonexistent/tool", &[]),
            NotExecuted::ExecFailed(Errno(libc::ENOENT)),
        ),
    ];
    for (spec, cause) in cases {
        let rig = ShimRig::new();
        let run = started(&rig, spec);
        assert_eq!(rig.link.link.wait().unwrap(), not_executed(cause));
        run.finish();
    }
}

#[skuld::test]
fn sigkill_before_exec_is_reported_as_the_programs_status() {
    let rig = ShimRig::new();
    let mut run = started(&rig, Spec::sh("exit 0").child_gate());
    run.wait_for("child: waiting at gate");
    assert_eq!(rig.link.link.kill().unwrap(), KillOutcome::Delivered);
    run.wait_for("control: signal Kill");
    // Killed before `exec`: there is no evidence the program never ran, so it is its status.
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(libc::SIGKILL));
    assert_eq!(run.finish().code, Some(128 + libc::SIGKILL));
}
