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

/// A failed `cgroup.kill` write reached during `Child::drop`'s OWN teardown — not a caller's own
/// `kill_tree()` — is a real OS outcome (`EACCES`/`EIO`, say), which this crate's own principle 7
/// forbids asserting on: it must be handled and logged, in every build, never a `debug_assert!`
/// that panics only when `debug_assertions` happen to be on. Forced via the same EISDIR technique
/// `hard_kill_propagates_a_kill_the_kernel_refused`
/// (`containment/cgroup/leaf_tests.rs`) uses: `open(O_WRONLY)` on a real directory always fails,
/// no test-only production branch needed.
#[cfg(target_os = "linux")]
#[test]
fn drop_warns_instead_of_asserting_on_a_real_teardown_mechanism_failure() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-drop-kill-fail-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill a directory");
    crate::child::spawn::fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });

    let mut cmd = crate::Command::new();
    cmd.args(["sleep", "30"]);
    // `kill_on_drop` defaults to true, and the override above is consumed on THIS spawn — `Drop`
    // below takes the armed path this test targets, through the real public API.
    let child = cmd.spawn().expect("spawn");

    let mark = crate::log_capture::mark();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(child)));
    assert!(
        unwound.is_ok(),
        "Child::drop must not panic on a real teardown-mechanism failure: {unwound:?}"
    );

    // Not leaf-path-scoped (unlike other tests in this crate that force a cgroup-leaf failure):
    // `Child::drop`'s own message here doesn't carry the path, only the OS reason, so the
    // narrowest available marker is the message's own constant prefix. The window between `mark`
    // above and this check is one `drop` call, on this thread — narrow enough that a colliding
    // record from an unrelated concurrently-running test is not a realistic risk in practice.
    let marker = "Child::drop: contained-tree teardown did not fully succeed";
    let records = crate::log_capture::records_since(mark, marker);
    assert_eq!(
        crate::log_capture::levels_since(mark, marker),
        [log::Level::Warn],
        "a real teardown-mechanism failure during Drop must be logged at warn, got {records:?}"
    );
}
