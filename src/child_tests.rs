//! Unit tests for `child.rs`. Most of these exercise `root_pid_was_recycled`, a pure,
//! synthetic-value-friendly helper — see its own doc comment for why it must stay pure rather
//! than a live-syscall check: constructing a genuinely recycled pid in a test is a race against
//! the kernel's own allocator, not something to synchronize on. The macOS-only test below is
//! the one exception: it spawns a real contained child to exercise the real
//! `dispatch.rs`/`is_teardown_mechanism_failure` path end to end — see its own doc comment.

use crate::identity::{Liveness, ProcessId, Resolved};

use super::root_pid_was_recycled;
#[cfg(target_os = "macos")]
use crate::containment::fdmarker::is_teardown_mechanism_failure;

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
/// `Marker::sweep`, so an entirely ordinary outcome classified as a teardown-mechanism failure
/// — reintroducing the bug #61 fixed.
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

    // `Drop` (`kill_on_drop` defaults to true) re-runs the teardown with the forced pgid: it must
    // return normally. The classification assert above is the sole guard for the laundering bug.
    drop(child);
}

/// A failed `cgroup.kill` write during `Child::drop`'s own teardown is a real OS outcome: Drop
/// must warn, not panic. Forced via the EISDIR technique of
/// `hard_kill_propagates_a_kill_the_kernel_refused` (`containment/cgroup/leaf_tests.rs`):
/// `open(O_WRONLY)` on a directory always fails.
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
    // The override is consumed by this spawn; `kill_on_drop` defaults to true.
    let child = cmd.spawn().expect("spawn");

    // Pin that the forced failure is the mechanism class this test claims (a raw `EISDIR` from
    // the `cgroup.kill` write, surfaced as `Error::Io`), so it cannot go vacuous if the forcing
    // stops reaching the kill.
    let forced = child
        .kill_tree()
        .expect_err("the forced cgroup.kill failure must surface from kill_tree");
    assert!(
        matches!(&forced, crate::error::Error::Io(io) if io.raw_os_error() == Some(libc::EISDIR)),
        "the forced failure must be a mechanism-class Error::Io(EISDIR), got {forced:?}"
    );

    let mark = crate::log_capture::mark();
    // A same-text record from ANOTHER thread, fixed before the drop by the join: the thread-filtered
    // scan below must not count it (a concurrent test's identical record would look the same).
    let marker = "Child::drop: contained-tree teardown did not fully succeed";
    std::thread::spawn(move || log::warn!("{marker}: from another thread"))
        .join()
        .expect("emit from another thread");
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(child)));
    assert!(
        unwound.is_ok(),
        "Child::drop must not panic on a real teardown-mechanism failure: {unwound:?}"
    );

    // `Drop` logs on the dropping thread (the tree kill runs there before any reaper hand-off),
    // so the current-thread scan sees exactly its record.
    let records = crate::log_capture::records_since_on_current_thread(mark, marker);
    assert_eq!(
        records.iter().map(|(level, _)| *level).collect::<Vec<_>>(),
        [log::Level::Warn],
        "a real teardown-mechanism failure during Drop must be logged at warn, got {records:?}"
    );
}
