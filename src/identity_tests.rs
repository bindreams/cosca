#[cfg(windows)]
use super::{Existence, Liveness};
use super::{ProcessId, RawPid, Resolved, StartToken};
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
    assert_eq!(me.exists(), crate::identity::Existence::Present);
    assert_eq!(me.is_alive(), crate::identity::Liveness::Alive);
    assert_eq!(ProcessId::of(me.pid()), Resolved::Found(me));
    assert!(me.created_at().is_some());
}

#[test]
fn start_token_raw_is_stable_and_matches_reresolved() {
    let me = ProcessId::current();
    // Stable across two calls on the same identity.
    assert_eq!(me.start_token_raw(), me.start_token_raw());
    // Equals the token of a freshly re-resolved identity for the same pid.
    let again = ProcessId::of(me.pid()).found().expect("current pid resolves");
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
    assert_eq!(
        imposter.exists(),
        crate::identity::Existence::Gone,
        "wrong token must not resolve to our process"
    );
    assert_eq!(
        imposter.is_alive(),
        crate::identity::Liveness::Dead,
        "wrong token is not a running process"
    );
}

#[cfg(windows)]
#[test]
fn an_access_denied_live_process_is_unknown_everywhere() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(PROCESS_SYNCHRONIZE.0);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    // We cannot name it by pid at all...
    assert_eq!(ProcessId::of(child.pid()), Resolved::Unknown);
    // ...and every question about the identity we DO hold is Unknown.
    assert_eq!(id.exists(), Existence::Unknown, "denied must not read as Gone");
    assert_eq!(id.is_alive(), Liveness::Unknown, "denied must not read as Dead");
    assert!(child.is_running(), "and it must still have been live throughout");
}

#[cfg(windows)]
#[test]
fn a_process_denying_only_synchronize_exists_but_has_unknown_liveness() {
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    let child = crate::identity::windows_fixture::spawn_restricted(PROCESS_QUERY_LIMITED_INFORMATION.0);
    assert!(child.is_running(), "precondition: the subject must be live");
    let Resolved::Found(id) = ProcessId::of(child.pid()) else {
        panic!("QUERY_LIMITED is granted, so the identity must resolve");
    };
    assert_eq!(id.exists(), Existence::Present);
    assert_eq!(
        id.is_alive(),
        Liveness::Unknown,
        "is_alive must never claim Dead for a process whose exit it could not establish"
    );
    assert!(child.is_running());
}
