#[cfg(windows)]
use super::{Existence, Liveness};
use super::{Key, ProcessId, RawPid, Resolved};
use std::collections::HashSet;

fn id(pid: RawPid, tok: u64) -> ProcessId {
    ProcessId::from_parts_for_test(pid, Key::for_test(tok))
}

#[skuld::test]
fn equal_when_pid_and_token_match() {
    assert_eq!(id(42, 1000), id(42, 1000));
}

#[skuld::test]
fn differ_when_pid_differs() {
    assert_ne!(id(42, 1000), id(43, 1000));
}

#[skuld::test]
fn differ_when_token_differs_same_pid() {
    // The PID-reuse case: same pid, different start token => different process.
    assert_ne!(id(42, 1000), id(42, 2000));
}

#[skuld::test]
fn hash_is_consistent_with_eq() {
    let mut set = HashSet::new();
    set.insert(id(7, 9));
    assert!(set.contains(&id(7, 9)));
    assert!(!set.contains(&id(7, 10)));
}

#[skuld::test]
fn is_copy_and_exposes_pid() {
    let a = id(5, 1);
    let b = a; // Copy: `a` remains usable below.
    assert_eq!(a.pid(), 5);
    assert_eq!(b.pid(), 5);
}

#[skuld::test]
fn current_process_resolves_exists_and_is_alive() {
    let me = ProcessId::current();
    assert_eq!(me.exists(), crate::identity::Existence::Present);
    assert_eq!(me.is_alive(), crate::identity::Liveness::Alive);
    assert_eq!(ProcessId::of(me.pid()), Resolved::Found(me));
    assert!(me.created_at().is_some());
}

/// Mutant: "the non-Linux entry ignores the pid".
#[skuld::test]
fn the_host_kernel_resolves_a_live_child_through_of_with_and_exists_with() {
    let mut child =
        crate::test_spawn::spawn(&mut crate::test_child::held_std_killable_blocker()).expect("spawn the child");
    let live = ProcessId::of(child.id()).found().expect("the live child resolves");
    assert_eq!(
        ProcessId::of_with(&super::HostKernel, child.id()).0,
        Resolved::Found(live)
    );
    assert_eq!(
        live.exists_with(&super::HostKernel).0,
        crate::identity::Existence::Present
    );
    let stale = live.with_other_value();
    assert_eq!(
        stale.exists_with(&super::HostKernel).0,
        crate::identity::Existence::Gone
    );
    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
}

#[skuld::test]
fn the_key_is_stable_and_matches_reresolved() {
    let me = ProcessId::current();
    // Stable across two calls on the same identity.
    assert_eq!(me.key(), me.key());
    // Equals the key of a freshly re-resolved identity for the same pid.
    let again = ProcessId::of(me.pid()).found().expect("current pid resolves");
    assert_eq!(me.key(), again.key());
}

#[skuld::test]
fn imposter_token_neither_exists_nor_is_alive() {
    let me = ProcessId::current();
    // Same live PID, deliberately wrong key => a different identity.
    let imposter = me.with_other_value();
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
#[skuld::test]
fn an_access_denied_live_process_is_unknown_everywhere() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(an_access_denied_live_process_is_unknown_everywhere),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
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
#[skuld::test]
fn a_process_denying_only_synchronize_exists_but_has_unknown_liveness() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_process_denying_only_synchronize_exists_but_has_unknown_liveness),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    let child = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
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

// A candidate's parent number =====

/// What the parent number a read found says about the read, before the parent is proved again:
/// another number, or one no pid has, is `Gone` whatever the rest of the read said; an unreadable one
/// leaves a found or unknown read `Unknown`; the named parent's number leaves the read, found or
/// unknown, for the proof of the parent.
///
/// Mutants: a refused read of anything else hides another parent's number; an unreadable number
/// reads as a match, or as another parent's; an unreadable number turns a `Gone` read `Unknown`; a
/// number no pid has reads `Unknown`; an unknown read with the named parent's number is settled
/// without the proof (a parent that is gone then blames the candidate, not `Gone`).
#[skuld::test]
fn a_candidates_parent_number_decides_its_read() {
    use super::{Judged, OrderKey, OrderedRead, ParentRead, UnknownCause};
    const PARENT: RawPid = 100;
    let found = || Resolved::Found((Key::for_test(5), OrderKey::for_test(9)));
    let judged = |read, parent| {
        OrderedRead {
            read,
            parent,
            cause: UnknownCause::default(),
        }
        .judged(7, PARENT)
    };
    let settled = |judged: Judged, what: &str| match judged {
        Judged::Settled(answer) => answer,
        Judged::IfParentHolds(_) => panic!("{what} is settled before the parent is proved"),
    };
    let candidate = id(7, 5);
    let order = OrderKey::for_test(9);

    let Judged::IfParentHolds((answer, _)) = judged(found(), ParentRead::Is(PARENT)) else {
        panic!("the named parent leaves a found read for the proof");
    };
    assert_eq!(answer, Resolved::Found((candidate, order)));
    let Judged::IfParentHolds((answer, _)) = judged(Resolved::Unknown, ParentRead::Is(PARENT)) else {
        panic!("the named parent leaves an unknown read for the proof");
    };
    assert_eq!(answer, Resolved::Unknown);

    for (what, rest) in [
        ("found", found()),
        ("unknown", Resolved::Unknown),
        ("gone", Resolved::Gone),
    ] {
        let others = [
            ("another parent", ParentRead::Is(PARENT + 1)),
            #[cfg(windows)]
            ("no pid", ParentRead::NoPid),
        ];
        for (which, parent) in others {
            let (answer, cause) = settled(judged(rest, parent), which);
            assert_eq!(answer, Resolved::Gone, "{which} over a {what} read");
            assert!(cause.into_error("pid 7").is_none());
        }
    }

    for (what, rest, expected) in [
        ("found", found(), Resolved::Unknown),
        ("unknown", Resolved::Unknown, Resolved::Unknown),
        ("gone", Resolved::Gone, Resolved::Gone),
    ] {
        let (answer, _) = settled(judged(rest, ParentRead::Unreadable), "an unreadable parent number");
        assert_eq!(answer, expected, "an unreadable parent over a {what} read");
    }

    let (answer, _) = settled(judged(Resolved::Gone, ParentRead::Is(PARENT)), "a gone read");
    assert_eq!(answer, Resolved::Gone);
}
