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
/// `Marker::sweep`, which made `Child::drop` misclassify an entirely ordinary outcome as a
/// mechanism failure — reintroducing the bug #61 fixed. (Round-4 downgraded that classification's
/// only consequence from a `debug_assert!` to a log-severity choice — `error` vs `warn` — so a
/// misclassification here is now a wrong log level, not a panic; still worth catching, since the
/// severity is the one thing a consumer's `Log` impl can act on.)
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

    // The forced pgid persists into `Drop` (`kill_on_drop` defaults to true), which classifies
    // the identical refusal again on its own path — exercised here for coverage, though a
    // misclassification no longer panics (round-4): it would only log this at the wrong level.
    drop(child);
}

/// Regression test: `Child::drop` (`kill_on_drop` true, the default) sweeps the contained tree
/// itself via its own explicit `self.attached.hard_kill()` call, then reaps the root
/// (`teardown_on_drop`). Once that has happened, `self.attached` (an `Attached::FdMarker` on
/// macOS) falls out of scope and runs `Drop for Marker`, which — before this fix — was still
/// armed and fired `hard_kill` a SECOND time, unconditionally re-sending `sweep_pass`'s pass-1
/// group signal (`killpg` on the marker's `pgid`) over a process group `Child::drop`'s own sweep
/// already tore down.
///
/// That second, unconditional `killpg` is not harmless: `sweep_pass`'s pass-1 fire has no
/// liveness gate (see its own doc — only a LATER pass's re-fire is gated on a freshly confirmed
/// live member), so it reaches whatever the OS may since have recycled that pgid number onto,
/// entirely unrelated to this `Child`'s own tree. This test does not need to engineer an actual
/// recycled pgid (a race against the kernel's own allocator, not something to synchronize on) —
/// counting `Marker::hard_kill` invocations across one `Child::drop` proves the hazard directly:
/// every invocation's OWN first pass fires the group signal unconditionally, so two invocations
/// means two unconditional `killpg` calls, the second one blind to whatever now holds the pgid.
#[cfg(target_os = "macos")]
#[test]
fn dropping_an_armed_fdmarker_child_calls_hard_kill_exactly_once() {
    let child = crate::Command::new()
        .executable("/usr/bin/true")
        .arg("true") // argv[0]; `executable` alone selects the loaded image, not argv
        .contain_with(crate::ContainMode::Strongest)
        .spawn()
        .expect("spawn a contained macOS root");
    // Keyed on this marker's own dedicated, never-reused hard-kill-count key — NOT its real OS
    // pipe handle, which this process's own kernel can reissue to an unrelated, concurrently
    // spawned marker once this one's read end is dropped, before this assertion even runs. See
    // `fault::HARD_KILL_CALLS`'s own doc for the false failure that caused, measured.
    let key = child
        .test_marker_hard_kill_key()
        .expect("Strongest attaches FdMarker on macOS");

    drop(child); // kill_on_drop defaults to true: this is the armed path under test.

    assert_eq!(
        crate::containment::fdmarker::fault::take_hard_kill_calls(key),
        1,
        "Child::drop's own explicit hard_kill must be the ONLY sweep of this tree; a second \
         (from an armed Drop for Marker still running after that sweep already tore the tree \
         down) unconditionally re-fires killpg on a pgid that may since have been recycled"
    );
}
