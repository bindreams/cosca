//! Unit tests for `child.rs`. Most of these exercise `root_pid_was_recycled`, a pure,
//! synthetic-value-friendly helper — see its own doc comment for why it must stay pure rather
//! than a live-syscall check: constructing a genuinely recycled pid in a test is a race against
//! the kernel's own allocator, not something to synchronize on. The macOS-only test below is
//! the one exception: it spawns a real contained child to exercise the real
//! `dispatch.rs`/`is_teardown_mechanism_failure` path end to end — see its own doc comment.

use crate::identity::{Liveness, ProcessId, Resolved};

#[cfg(target_os = "macos")]
use super::is_teardown_mechanism_failure;
use super::root_pid_was_recycled;

fn id(pid: u32, token: u64) -> ProcessId {
    ProcessId::from_parts_for_test(pid, token)
}

#[test]
fn recycled_root_pid_resolving_gone_is_not_recycled() {
    let original = id(100, 1);
    // Regardless of the liveness reading passed in (there is nothing to read a liveness OF
    // when nothing resolved) — `Resolved::Gone` alone must never trip this.
    assert!(!root_pid_was_recycled(original, Resolved::Gone, Liveness::Unknown));
    assert!(!root_pid_was_recycled(original, Resolved::Gone, Liveness::Alive));
}

#[test]
fn recycled_root_pid_unknown_resolution_is_not_recycled() {
    let original = id(100, 1);
    // The OS refused the query — positive evidence, not absence of counter-evidence, is what
    // this predicate requires.
    assert!(!root_pid_was_recycled(original, Resolved::Unknown, Liveness::Unknown));
}

#[test]
fn recycled_root_pid_resolving_back_to_the_same_identity_is_not_recycled() {
    let original = id(100, 1);
    // The pid resolves to itself again (an unreaped zombie the caller hasn't reaped yet, or a
    // still-running process) — the ordinary, harmless case this predicate must not flag.
    assert!(!root_pid_was_recycled(
        original,
        Resolved::Found(original),
        Liveness::Alive
    ));
}

#[test]
fn recycled_root_pid_a_different_but_dead_identity_is_not_recycled() {
    let original = id(100, 1);
    let different = id(100, 2); // same pid, different start token — a zombie, not yet reaped
                                // Resolved but not confirmed ALIVE (e.g. a zombie of the recycled process, itself unreaped)
                                // is not the hazardous case: `killpg` on it is still harmless.
    assert!(!root_pid_was_recycled(
        original,
        Resolved::Found(different),
        Liveness::Dead
    ));
    assert!(!root_pid_was_recycled(
        original,
        Resolved::Found(different),
        Liveness::Unknown
    ));
}

#[test]
fn recycled_root_pid_a_different_live_identity_is_recycled() {
    let original = id(100, 1);
    let different = id(100, 2); // same pid, different start token, confirmed running
    assert!(root_pid_was_recycled(
        original,
        Resolved::Found(different),
        Liveness::Alive
    ));
}

/// Regression test: the group-signal step's ordinary refusal outcomes (`Error::Containment` /
/// `Error::Unassessable { source: None, .. }`, distinguished from a genuine teardown-mechanism
/// failure since #61) were being stringified into an opaque `Error::Io` on the way out of
/// `Marker::sweep`, which made `Child::drop`'s `debug_assert!(!is_teardown_mechanism_failure(e),
/// ...)` fire on an entirely ordinary outcome — reintroducing the bug #61 fixed.
///
/// `fdmarker_tests.rs` calls `Marker::hard_kill`/`terminate` DIRECTLY, bypassing
/// `dispatch.rs`'s `Attached::FdMarker` arm where the laundering sat, so none of those tests
/// could catch this. This test goes through the real public path instead: `Command::spawn` →
/// `dispatch.rs`'s `Attached::FdMarker` → `Child::kill_tree`/`Drop` →
/// `is_teardown_mechanism_failure`.
///
/// A live cross-uid refuser needs real root to construct (see `tests/group_teardown_setuid.rs`
/// for why that is not reliably provisionable on macOS: SIP). This instead drives the group
/// channel's OTHER real, privilege-free refusal path: `containment::unix::signal_group`'s
/// `pgid <= 0` guard, reached via `Child::test_force_fdmarker_pgid` the same way this codebase's
/// other otherwise-untriggerable branches already are (`force_blind_snapshot_for_next_call` and
/// friends).
#[cfg(target_os = "macos")]
#[test]
fn kill_tree_reports_an_ordinary_group_refusal_through_the_real_dispatch_and_classifier_path() {
    let mut child = crate::Command::new()
        .executable("/usr/bin/true")
        .arg("true") // argv[0]; `executable` alone selects the loaded image, not argv
        .contain_with(crate::ContainMode::Strongest)
        .spawn()
        .expect("spawn a contained macOS root");
    child.test_force_fdmarker_pgid(0);

    let err = child
        .kill_tree()
        .expect_err("an unsignallable (pgid 0) group channel must report Err, not silently succeed");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: None, .. }),
        "an invalid-pgid refusal is the ORDINARY, expected outcome unix::signal_group's own \
         guard documents — got {err:?} instead"
    );
    assert!(
        !is_teardown_mechanism_failure(&err),
        "an ordinary group-signal refusal must never classify as a teardown MECHANISM \
         failure — got {err:?}"
    );

    // The forced pgid persists into `Drop` (`kill_on_drop` defaults to true) — this is the
    // literal reported bug: `Child::drop`'s `debug_assert!(!is_teardown_mechanism_failure(e),
    // ...)` must not fire here. If the laundering regresses, this line panics.
    drop(child);
}
