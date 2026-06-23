use super::{ProcessId, RawPid, StartToken};
use std::collections::HashSet;

// Build a ProcessId directly from parts (this test module can access the
// private fields and the private StartToken). Mirrors the crate-internal,
// test-only `ProcessId::from_parts_for_test`.
fn id(pid: RawPid, tok: u64) -> ProcessId {
    ProcessId {
        pid,
        start: StartToken::from_raw(tok),
    }
}

#[test]
fn equal_when_pid_and_token_match() {
    assert_eq!(id(42, 1000), id(42, 1000));
}

#[test]
fn differ_when_pid_differs() {
    assert_ne!(id(42, 1000), id(43, 1000));
}

#[test]
fn differ_when_token_differs_same_pid() {
    // The PID-reuse case: same pid, different start token => different process.
    assert_ne!(id(42, 1000), id(42, 2000));
}

#[test]
fn hash_is_consistent_with_eq() {
    let mut set = HashSet::new();
    set.insert(id(7, 9));
    assert!(set.contains(&id(7, 9)));
    assert!(!set.contains(&id(7, 10)));
}

#[test]
fn is_copy_and_exposes_pid() {
    let a = id(5, 1);
    let b = a; // Copy: `a` remains usable below.
    assert_eq!(a.pid(), 5);
    assert_eq!(b.pid(), 5);
}

#[test]
fn current_process_resolves_exists_and_is_alive() {
    let me = ProcessId::current();
    assert!(me.exists());
    assert!(me.is_alive());
    assert_eq!(Some(me), ProcessId::of(me.pid()));
    assert!(me.created_at().is_some());
}

#[test]
fn start_token_raw_is_stable_and_matches_reresolved() {
    let me = ProcessId::current();
    // Stable across two calls on the same identity.
    assert_eq!(me.start_token_raw(), me.start_token_raw());
    // Equals the token of a freshly re-resolved identity for the same pid.
    let again = ProcessId::of(me.pid()).expect("current pid resolves");
    assert_eq!(me.start_token_raw(), again.start_token_raw());
}

#[test]
fn imposter_token_neither_exists_nor_is_alive() {
    let me = ProcessId::current();
    // Same live PID, deliberately wrong start token => a different identity.
    let imposter = ProcessId {
        pid: me.pid(),
        start: StartToken::from_raw(me.start.raw().wrapping_add(1)),
    };
    assert!(!imposter.exists(), "wrong token must not resolve to our process");
    assert!(!imposter.is_alive(), "wrong token is not a running process");
}
