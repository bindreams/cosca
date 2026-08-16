//! Unit tests for the public `Child::wait_tree`/`wait_tree_timeout`. Every test branches on
//! `Containment::can_observe_drain()` and asserts a real, non-trivial outcome on BOTH sides
//! rather than skipping either — this crate's "never silently skip" testing convention.

use std::time::Duration;

/// The `TreeDrain` variant a fully-drained tree reports on `containment`'s mechanism:
/// `AllMembersExited` everywhere authoritative (cgroup v2, Windows job object), but
/// `AllMarkersClosed` on macOS's advisory fd marker — see `TreeDrain`'s own doc for why the two
/// are not interchangeable. Centralized here so every test below asserts the SAME real,
/// mechanism-correct verdict rather than assuming the authoritative one everywhere.
fn expected_drained_verdict(containment: crate::containment::Containment) -> crate::containment::TreeDrain {
    match containment {
        crate::containment::Containment::FdMarker => crate::containment::TreeDrain::AllMarkersClosed,
        _ => crate::containment::TreeDrain::AllMembersExited,
    }
}

/// A quick, self-terminating contained child: the drain edge (when the mechanism has one)
/// fires almost immediately, so an UNBOUNDED `wait_tree()` call below is safe — it is a real
/// blocking wait on a genuinely-terminating event, not an indefinite one.
fn quick_contained_child() -> crate::Child {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    cmd.contain();
    cmd.spawn().expect("spawn")
}

/// A long-lived contained child, for the deadline-not-met case.
fn long_lived_contained_child() -> crate::Child {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    cmd.spawn().expect("spawn")
}

/// Drained case: on a drain-observable mechanism, an unbounded `wait_tree()` against a tree
/// that fully exits on its own reports the mechanism-correct drained verdict
/// (`expected_drained_verdict`). On a mechanism with no kernel drain edge, the SAME call must
/// fail `Unsupported` instead — both are real, exercised assertions.
#[test]
fn wait_tree_reports_the_drained_verdict_when_the_tree_drains() {
    let child = quick_contained_child();
    let containment = child.containment();
    let drainable = containment.can_observe_drain();
    let result = child.wait_tree();
    if drainable {
        assert_eq!(
            result.expect("a fully-exited tree must report a drained verdict"),
            expected_drained_verdict(containment)
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    // wait_tree never reaps — the root's exit still needs collecting either way.
    let _ = child.wait();
}

/// Deadline-not-met case: on a drain-observable mechanism, `wait_tree_timeout` against a tree
/// that is still alive at expiry reports `MembersRemain` — NOT an error, per its own doc. On a
/// non-drainable mechanism the same call must still fail `Unsupported`.
#[test]
fn wait_tree_timeout_reports_members_remain_before_the_deadline() {
    let child = long_lived_contained_child();
    let drainable = child.containment().can_observe_drain();
    let result = child.wait_tree_timeout(Duration::from_millis(200));
    if drainable {
        assert_eq!(
            result.expect("an unmet deadline on a live tree must not be an error"),
            crate::containment::TreeDrain::MembersRemain
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree_timeout");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    let _ = child.kill_tree();
    let _ = child.wait();
}

/// `Duration::ZERO` against a still-alive tree: a one-shot, non-blocking probe (see
/// `crate::wait::deadline_from`/`remaining`'s own docs) — `MembersRemain`, not an error, and
/// returned without ever entering the backend's blocking wait (every `wait_drained`
/// implementation checks `remaining == Duration::ZERO` before its first blocking syscall).
#[test]
fn wait_tree_timeout_zero_reports_members_remain_on_a_live_tree() {
    let child = long_lived_contained_child();
    let drainable = child.containment().can_observe_drain();
    let result = child.wait_tree_timeout(Duration::ZERO);
    if drainable {
        assert_eq!(
            result.expect("a ZERO probe against a live tree must not be an error"),
            crate::containment::TreeDrain::MembersRemain
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree_timeout");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    let _ = child.kill_tree();
    let _ = child.wait();
}

/// `Duration::ZERO` against an ALREADY-drained tree: the one-shot probe must still observe and
/// report the real, mechanism-correct drained verdict — not `MembersRemain` by default, and not
/// blocked on by the deadline being in the past (see `marker_eof::block_until_drained`'s own doc
/// on why a past deadline still performs exactly one check). The unbounded `wait_tree()` call
/// first is the genuine happens-before edge that the tree has fully drained before the ZERO
/// probe below ever runs.
#[test]
fn wait_tree_timeout_zero_reports_the_drained_verdict_after_the_tree_has_already_drained() {
    let child = quick_contained_child();
    let containment = child.containment();
    let drainable = containment.can_observe_drain();
    let first = child.wait_tree();
    if drainable {
        first.expect("a fully-exited tree must report a drained verdict");
        assert_eq!(
            child
                .wait_tree_timeout(Duration::ZERO)
                .expect("a ZERO probe against an already-drained tree must not be an error"),
            expected_drained_verdict(containment),
            "a ZERO probe must observe the SAME drained state an unbounded wait already found, \
             not report MembersRemain just because the deadline is already past"
        );
    } else {
        first.expect_err("a non-drainable mechanism must refuse wait_tree");
        let err = child.wait_tree_timeout(Duration::ZERO);
        assert!(
            matches!(err, Err(crate::error::Error::Unsupported { .. })),
            "got {err:?}"
        );
    }
    let _ = child.wait();
}

/// `Unsupported` on a non-drainable mechanism — explicitly REQUESTING `ContainMode::TreeWalk`,
/// the one mode with no kernel drain edge on every platform where it is actually honored as
/// requested (`Attached::TreeWalk` carries no `#[cfg]` gate reserving it to one OS, unlike the
/// per-OS drainable variants). **Not** portable to a single unconditional assertion, though:
/// on macOS the fd marker is installed for every contained root regardless of the requested
/// mode (`dispatch.rs`'s `attach()`, macOS branch — it is what survives `setsid`/reparenting/
/// `exec` that a mode-specific mechanism does not), so a macOS `TreeWalk` request still comes
/// back `Containment::FdMarker`, which IS drainable. Branches on the actual reported
/// `can_observe_drain()` like the two tests above, rather than assuming a platform from the
/// requested mode, so this asserts something real and non-tautological on every platform: the
/// `Unsupported` refusal where `TreeWalk` is honored as non-drainable, and — on macOS — that
/// an explicit `TreeWalk` request still drains correctly through the marker it was promoted to.
#[test]
fn wait_tree_is_unsupported_on_a_non_drainable_mechanism() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let treewalk_child = cmd.spawn().expect("spawn");
    let containment = treewalk_child.containment();
    let drainable = containment.can_observe_drain();
    let err = treewalk_child.wait_tree_timeout(Duration::from_millis(200));
    if drainable {
        assert_eq!(
            err.expect("macOS promotes an explicit TreeWalk request to the drainable fd marker"),
            expected_drained_verdict(containment),
            "a quick-exiting tree must still be observed as drained through the promoted mechanism"
        );
    } else {
        let err = err.expect_err("TreeWalk, honored as requested, has no kernel drain edge");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
        let err2 = treewalk_child
            .wait_tree()
            .expect_err("TreeWalk, honored as requested, has no kernel drain edge");
        assert!(matches!(err2, crate::error::Error::Unsupported { .. }), "got {err2:?}");
    }
    let _ = treewalk_child.wait();
}
