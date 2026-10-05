//! A cgroup placement verdict that failed closed (`cgroup::fault::set_force_fail_closed`), met by a
//! failed identity check or a failed attach: the cgroup lane (the `cgroup` group, as root). The
//! front is an ordinary `cat` reported as launched by `sudo`.
//!
//! A failed-closed verdict does not always leave a killed child in its leaf. A child that did not
//! enter its leaf is not contained by it: a front there is left unreaped when the leaf could not
//! signal it, and noted as killed outside its leaf when it was.

use std::io::PipeWriter;

use crate::child::front_cgroup_tests::contained_cat;
use crate::child::front_kill_tests::{assert_reaped_unsignalled, reap};
use crate::command::Command;
use crate::error::Error;
use crate::test_groups::{cgroup, Group};

/// What fails the spawn besides its verdict.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Cause {
    /// The identity check is refused (`Unknown`): `Error::Unassessable`.
    IdentityRefused,
    /// The identity check finds the child gone: `Error::Io`.
    IdentityGone,
    /// The attach, which takes the verdict: `Error::Containment`.
    Attach,
}

/// One case: how the child stands to its leaf when the verdict fails closed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Case {
    pub(crate) cause: Cause,
    /// Whether the child entered its leaf (its placement write is made to fail when not).
    pub(crate) entered: bool,
    /// Whether the leaf's kill of the child itself is refused (`EPERM`).
    pub(crate) denied: bool,
    pub(crate) front: bool,
}

/// Spawns `case`'s child through `spawn` and returns the error, the child's pid and its stdin.
pub(crate) fn failed_closed_spawn(
    case: Case,
    spawn: impl FnOnce(&mut Command) -> Result<(), Error>,
) -> (Error, u32, PipeWriter) {
    use crate::child::spawn::fault;
    use crate::containment::cgroup::fault as cgroup_fault;

    let (mut cmd, stdin) = contained_cat(case.front);
    if !case.entered {
        cgroup_fault::set_force_placement_write_result(0);
    }
    cgroup_fault::set_force_signal_denied(case.denied);
    cgroup_fault::set_force_fail_closed(true);
    match case.cause {
        Cause::IdentityRefused => fault::set_force_identity_unknown(true),
        Cause::IdentityGone => fault::set_force_identity_vanished(true),
        Cause::Attach => {}
    }
    let result = spawn(&mut cmd);
    // The child took the placement fault in its own copy of the flag; this process's is still set.
    let _ = cgroup_fault::take_force_placement_write_result();
    fault::set_force_identity_unknown(false);
    fault::set_force_identity_vanished(false);
    assert!(
        !cgroup_fault::take_force_fail_closed(),
        "the verdict must have been taken, and failed closed"
    );
    assert!(
        !cgroup_fault::take_force_signal_denied(),
        "the leaf's kill of the child must have been attempted"
    );
    let err = result.expect_err("a failed-closed verdict fails the spawn");
    let crate::identity::Resolved::Found(id) = fault::take_captured().expect("the seam captured the child") else {
        panic!("the seam must capture a resolved identity");
    };
    (err, id.pid(), stdin)
}

/// `err` is what `case` must answer: the failure's own variant, the leaf's account, and for a front
/// outside its leaf its fate; and the child is left or reaped as that fate says.
#[track_caller]
pub(crate) fn assert_case(case: Case, err: &Error, pid: u32, stdin: PipeWriter) {
    let text = err.to_string();
    match case.cause {
        Cause::IdentityRefused => assert!(matches!(err, Error::Unassessable { .. }), "{case:?}: {err:?}"),
        Cause::IdentityGone => assert!(matches!(err, Error::Io(_)), "{case:?}: {err:?}"),
        Cause::Attach => assert!(matches!(err, Error::Containment { .. }), "{case:?}: {err:?}"),
    }
    assert!(
        text.contains(&format!("cannot tell whether child {pid} entered its cgroup leaf")),
        "{case:?}: the leaf's own account must be kept: {text}"
    );
    let outside_leaf_front = case.front && !case.entered;
    if !outside_leaf_front {
        assert!(
            !text.contains("what sudo left"),
            "{case:?}: no front is left alone: {text}"
        );
        drop(stdin);
        assert_eq!(reap(pid), None, "{case:?}: the teardown reaps it");
        return;
    }
    assert!(
        text.contains(&format!("pid {pid} is what sudo left")),
        "{case:?}: {text}"
    );
    if case.denied {
        // The leaf could not signal it: it is left running, unreaped.
        assert!(
            text.contains("the elevated program may be running; it is left unreaped"),
            "{case:?}: {text}"
        );
        drop(stdin);
        assert_reaped_unsignalled(pid);
    } else {
        assert!(
            text.contains("it was killed outside its leaf, so the elevated program may be running"),
            "{case:?}: {text}"
        );
        drop(stdin);
        assert_eq!(reap(pid), None, "{case:?}: the teardown reaps it");
    }
}

/// Every case, with and without a front.
pub(crate) fn cases() -> Vec<Case> {
    let mut all = Vec::new();
    for cause in [Cause::IdentityRefused, Cause::IdentityGone, Cause::Attach] {
        for (entered, denied) in [(true, false), (false, false), (false, true)] {
            for front in [true, false] {
                all.push(Case {
                    cause,
                    entered,
                    denied,
                    front,
                });
            }
        }
    }
    all
}

/// A failed-closed verdict is acted on by what it says of the child: one that did not enter its
/// leaf is not contained by it, so a front there is kept, sent no further kill, and noted. One
/// that did is dead through its leaf and no front. The leaf's account is kept either way.
///
/// Mutants: `FailedClosed` carries no fate, so a front outside its leaf is taken for a killed
/// child; a front is derived from `cgroup_leaf.is_some()`.
#[skuld::test]
fn cgroup_a_failed_closed_verdict_is_acted_on_by_where_the_child_stands(#[fixture(cgroup)] _group: &Group) {
    for case in cases() {
        let (err, pid, stdin) = failed_closed_spawn(case, |cmd| cmd.spawn().map(drop));
        assert_case(case, &err, pid, stdin);
    }
}
