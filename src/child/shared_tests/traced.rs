//! A child held by a tracer, as a debugger holds it: the parent's `waitid` answers `ECHILD` for
//! it, yet it is not reaped. `TRACER`-group tests, run in CI only.

use std::time::Instant;

use crate::identity::{pbi_start_quiet, ReadPurpose, Resolved};
use crate::test_support::tracer::{self, Mode, Report};
use crate::wait::backend::{await_reapable, Waited};
use crate::wait::exit_only::{self, Reap, Target};

/// A held child is running until the tracer hands it back: the by-pid `ECHILD` is not a reap,
/// the kqueue wait keeps waiting, and the hand-back's `NOTE_EXIT` ends it as `Reapable`.
///
/// Mutant: a by-pid `ECHILD` taken for a foreign reap without checking the pid still names the
/// child.
#[test]
fn a_child_held_by_a_tracer_is_running_until_the_hand_back() {
    if !crate::test_support::require_group("TRACER") {
        return;
    }
    let mut tracee = tracer::spawn_tracee(false);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    let pid = tracee.id().pid();
    let start = match pbi_start_quiet(pid, ReadPurpose::Echild) {
        Resolved::Found(start) => start,
        other => panic!("the tracee's start: {other:?}"),
    };
    let mut helper = tracer::start(Mode::Auto).attach(&mut tracee);
    assert_eq!(helper.recv(), Report::Attached);

    let target = Target::pid(pid, Some(start));
    assert_eq!(exit_only::try_reap(&target).expect("try_reap"), Reap::Running);
    // An expired deadline: one look, no blocking.
    let held = await_reapable(pid, Some(start), Some(Instant::now())).expect("wait");
    assert_eq!(held, Waited::DeadlinePassed);

    drop(stdin);
    assert_eq!(helper.recv(), Report::Reaped);
    // The zombie is ours again: an unbounded wait sees the exit.
    assert_eq!(await_reapable(pid, Some(start), None).expect("wait"), Waited::Reapable);
    drop(helper);
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
}
