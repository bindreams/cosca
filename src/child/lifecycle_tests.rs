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

/// A contained [`crate::test_child::BLOCKER_ARGV`] child and its stdin writer, which the caller
/// must keep for exactly as long as the child must stay running.
fn long_lived_contained_child() -> (crate::Child, std::io::PipeWriter) {
    crate::test_child::held_contained_blocker(crate::Stdio::null())
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
    _ = child.wait();
}

/// Deadline-not-met case: on a drain-observable mechanism, `wait_tree_timeout` against a tree
/// that is still alive at expiry reports `MembersRemain` — NOT an error, per its own doc. On a
/// non-drainable mechanism the same call must still fail `Unsupported`.
#[test]
fn wait_tree_timeout_reports_members_remain_before_the_deadline() {
    let (child, _stdin) = long_lived_contained_child();
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
    _ = child.kill_tree();
    _ = child.wait();
}

/// `Duration::ZERO` against a still-alive tree: a one-shot, non-blocking probe (see
/// `crate::wait::deadline_from`/`remaining`'s own docs) — `MembersRemain`, not an error, and
/// returned without ever entering the backend's blocking wait (every `wait_drained`
/// implementation checks `remaining == Duration::ZERO` before its first blocking syscall).
#[test]
fn wait_tree_timeout_zero_reports_members_remain_on_a_live_tree() {
    let (child, _stdin) = long_lived_contained_child();
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
    _ = child.kill_tree();
    _ = child.wait();
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
    _ = child.wait();
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
    _ = treewalk_child.wait();
}

// `Child::wait_deadline`'s own recheck loop (site 5 of the "deadline-windows-never-early" bug
// family; see docs/principles.md #13 — PR #233, not yet merged, and this function's own doc):
// a `None` ("still running") from the underlying backend must never be trusted as proof the
// real `deadline` passed. Portable — this loop is cosca's own code, not Windows-specific — even
// though the bug it defends against (`shared_child`'s Windows `wait_deadline_noreap` only
// rechecking when ITS OWN per-call timeout was clamped) only manifests on Windows.

/// A live, uncontained child that blocks reading its own piped stdin until EOF — it never
/// exits on its own. `cat` (Unix) / `cmd /C more` (Windows, already used by this crate's
/// Windows-only wait tests, e.g. `src/wait/windows_tests.rs`) — no new external dependency.
fn spawn_never_exiting() -> (crate::Child, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["cat"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "more"]);
    cmd.stdin(crate::Stdio::pipe_in()).expect("configure piped stdin");
    cmd.stdout(crate::Stdio::null()).expect("configure null stdout");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin was just configured above");
    (child, stdin)
}

/// `early_none_seam` fakes the OBSERVABLE effect of `shared_child`'s own early-`WAIT_TIMEOUT`
/// bug deterministically — there is no seam into that third-party dependency's internals to
/// force ITS bug directly (upstream tracking: cosca #237, not filed here). The loop's FIRST
/// iteration receives a synthetic `None` without ever calling the real underlying wait; a hook
/// fires the instant that's consumed, closing the fixture's piped stdin so it exits for real.
/// The loop's SECOND (real) iteration must then correctly detect that genuine exit — the
/// synthetic `None` must never be returned to the caller as "still running".
///
/// Mutant: revert `Child::wait_deadline` to a single `self.proc.wait_deadline(deadline)` call
/// with no loop at all (this function's pre-fix shape) -> fails deterministically: the
/// (possibly-forced) `None` is returned immediately, hours before the real deadline, and the
/// fixture — per the hook, which never even got a chance to matter on this path since the
/// forced value IS what gets returned directly — would leak running (`kill()`/`wait()` below
/// still clean it up regardless, since they run unconditionally, not conditioned on the
/// assertion having passed).
#[test]
fn wait_deadline_never_reports_still_running_before_the_deadline() {
    let (child, stdin) = spawn_never_exiting();
    crate::wait::early_none_seam::arm(move || drop(stdin)); // EOF -> the fixture exits for real
    let deadline = std::time::Instant::now() + Duration::from_secs(3600); // hours off
    let result = child.wait_deadline(deadline);
    let status = result.expect("a genuinely-exiting child must not report a wait failure");
    assert!(
        status.is_some(),
        "must report exited once the child genuinely exits, not falsely conclude still-running \
         from an early, synthetic None"
    );
    let _ = child.kill();
    let _ = child.wait();
}
