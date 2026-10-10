//! The shim as a host ships it: `cosca::init()` with no hooks. The other tests run it with the test
//! seams, which change what the shim does, so what a host really gets is checked here.

use super::*;
use crate::elevation::shim::link::probe::LinkEvent;
use crate::elevation::shim::protocol::Command;

#[skuld::test]
fn a_shipped_shim_starts_the_program_and_reports_its_exit() {
    let rig = ShimRig::new();
    let run = rig.spawn(Spec::sh("exit 42").shipped());
    // No log to wait on: the link's own events say the shim has been answered.
    rig.link.expect_event(LinkEvent::Accepted);
    rig.link.expect_event(LinkEvent::Answered(Command::Allow));
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(42 << 8));
    let done = run.finish();
    assert_eq!(done.code, Some(42), "{}", done.stderr);
    assert!(done.stderr.is_empty(), "{}", done.stderr);
}

#[skuld::test]
fn a_shipped_shim_takes_p_for_a_protocol_violation() {
    // With hooks `P` is a ping and the `T` after it ends the program with SIGTERM. Shipped, `P` is
    // a byte no cosca sends: the program is killed, and the `T` that follows finds it dead.
    let rig = ShimRig::new();
    let run = rig.spawn(Spec::new("cat", &[]).stdin_held().shipped());
    rig.link.expect_event(LinkEvent::Accepted);
    rig.link.expect_event(LinkEvent::Answered(Command::Allow));
    rig.link.link.send_control(b'P').unwrap();
    rig.link.link.send_control(b'T').unwrap();
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(libc::SIGKILL));
    assert_eq!(run.finish().code, Some(128 + libc::SIGKILL));
}

#[skuld::test]
fn a_shipped_shim_logs_to_stderr_and_to_nothing_else() {
    // The rig names a seam log; only the hooks write to it. The same refusal with hooks is the control.
    let hooked = ShimRig::new().run_to_end(Spec::sh("true").cosca_pid(std::process::id() ^ 1));
    assert!(hooked.logged("refused 122"), "{:#?}", hooked.lines);

    let shipped = ShimRig::new().run_to_end(Spec::sh("true").cosca_pid(std::process::id() ^ 1).shipped());
    assert_eq!(shipped.code, Some(122), "{}", shipped.stderr);
    assert!(shipped.stderr.contains("(exit 122)"), "{}", shipped.stderr);
    assert_eq!(
        shipped.stderr.lines().count(),
        1,
        "one line, and nothing of the log: {}",
        shipped.stderr
    );
    assert!(
        shipped.lines.is_empty(),
        "the shim wrote to a log: {:#?}",
        shipped.lines
    );
}
