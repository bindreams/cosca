//! Unit tests for `child.rs`'s pure, synthetic-value-friendly helpers — see
//! `root_pid_was_recycled`'s own doc comment for why this must stay a pure function rather
//! than a live-syscall check: constructing a genuinely recycled pid in a test is a race against
//! the kernel's own allocator, not something to synchronize on.

use crate::identity::{Liveness, ProcessId, Resolved};

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
