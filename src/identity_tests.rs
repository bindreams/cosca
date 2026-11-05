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

/// Who an answer's cause blames: nobody, the candidate's own read (its cause carried through), or
/// the parent whose proof failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    Nobody,
    Candidate,
    Parent,
}

/// What one ordered read of a candidate and the proof of its named parent say together, over the
/// whole grid. With a parent named:
///
/// - Another parent's number is `Gone` whatever the rest of the read said, and the proof is never
///   needed.
/// - A `Gone` read is `Gone`, with its own cause, whatever the proof says.
/// - Otherwise the parent proof comes first: a parent that is gone is `Gone`; one that cannot be
///   proved is `Unknown` blaming the parent. Only a held parent lets the candidate's own read answer:
///   found with the parent's number, `Found`; found with an unreadable number, or `Unknown`, `Unknown`
///   with the candidate's cause.
///
/// With no parent named, the read is the answer, its cause the candidate's.
///
/// Mutants: another parent's number is hidden by a refused read or by the proof; an unreadable
/// number, a missing record or a missing order key settles `Unknown` before the proof (a gone parent
/// then blames the candidate); an unreadable number reads as a match or as another parent's; a failed
/// proof blames the candidate or answers `Gone`; a `Gone` read becomes `Unknown`.
#[skuld::test]
fn a_candidates_read_and_its_parents_proof_give_one_answer() {
    use super::{OrderKey, Ordered, OrderedRead, ParentRead, UnknownCause};
    const CANDIDATE: RawPid = 7;
    const PARENT: RawPid = 100;
    const OTHER: RawPid = 101;
    // The candidate's own cause, as a stated marker: no cause but the parent's has a pid in it here.
    const STATED: RawPid = 900;

    let stated = || UnknownCause::default().of_parent(STATED);
    let order = OrderKey::for_test(9);
    let found = Resolved::Found((Key::for_test(5), order));

    let nobody_gone = (Resolved::Gone, Owner::Nobody);
    let own_gone = (Resolved::Gone, Owner::Candidate);
    let own_found = (Resolved::Found((id(CANDIDATE, 5), order)), Owner::Candidate);
    let own_unknown = (Resolved::Unknown, Owner::Candidate);
    let parent_unknown = (Resolved::Unknown, Owner::Parent);
    type Proof = fn() -> Result<(), Ordered>;
    // The expected answer under each proof, in this order: held, gone, unknown.
    let proofs: [(&str, Proof); 3] = [
        ("held", || Ok(())),
        ("gone", || Err((Resolved::Gone, UnknownCause::default()))),
        ("unknown", || {
            Err((Resolved::Unknown, UnknownCause::default().of_parent(PARENT)))
        }),
    ];
    let table = [
        // The parent number is another's.
        ("found", found, "another's", ParentRead::Is(OTHER), [nobody_gone; 3]),
        (
            "gone",
            Resolved::Gone,
            "another's",
            ParentRead::Is(OTHER),
            [nobody_gone; 3],
        ),
        (
            "unknown",
            Resolved::Unknown,
            "another's",
            ParentRead::Is(OTHER),
            [nobody_gone; 3],
        ),
        // The parent number is the named parent's.
        (
            "found",
            found,
            "the parent's",
            ParentRead::Is(PARENT),
            [own_found, nobody_gone, parent_unknown],
        ),
        (
            "gone",
            Resolved::Gone,
            "the parent's",
            ParentRead::Is(PARENT),
            [own_gone; 3],
        ),
        (
            "unknown",
            Resolved::Unknown,
            "the parent's",
            ParentRead::Is(PARENT),
            [own_unknown, nobody_gone, parent_unknown],
        ),
        // The parent number could not be read.
        (
            "found",
            found,
            "unreadable",
            ParentRead::Unreadable,
            [own_unknown, nobody_gone, parent_unknown],
        ),
        (
            "gone",
            Resolved::Gone,
            "unreadable",
            ParentRead::Unreadable,
            [own_gone; 3],
        ),
        (
            "unknown",
            Resolved::Unknown,
            "unreadable",
            ParentRead::Unreadable,
            [own_unknown, nobody_gone, parent_unknown],
        ),
    ];
    let owner_of = |cause: UnknownCause| match cause.blamed_parent() {
        None => Owner::Nobody,
        Some(STATED) => Owner::Candidate,
        Some(PARENT) => Owner::Parent,
        Some(other) => panic!("a cause blaming pid {other}"),
    };

    for (read_name, read, number_name, claimed, expected) in table {
        for ((proof_name, proof), expected) in proofs.into_iter().zip(expected) {
            let (answer, cause) = OrderedRead {
                read,
                parent: claimed,
                cause: stated(),
            }
            .judged(CANDIDATE, PARENT)
            .proved(proof);
            assert_eq!(
                (answer, owner_of(cause)),
                expected,
                "a {read_name} read, its parent number {number_name}, the parent {proof_name}"
            );
        }
    }

    for (read_name, read, expected) in [
        ("found", found, own_found),
        ("gone", Resolved::Gone, own_gone),
        ("unknown", Resolved::Unknown, own_unknown),
    ] {
        let (answer, cause) = OrderedRead {
            read,
            parent: ParentRead::NotAsked,
            cause: stated(),
        }
        .unclaimed(CANDIDATE);
        assert_eq!(
            (answer, owner_of(cause)),
            expected,
            "a {read_name} read with no parent named"
        );
    }
}

/// A read that found no record says its parent number could not be read only if it asked for it
/// (the table above judges each `parent` value).
///
/// Mutant: `missing` reads `Unreadable` for a read that did not ask, or `NotAsked` for one that did
/// (a `NotAsked` that is judged against a named parent breaks the debug assertion there).
#[skuld::test]
fn a_missing_record_reads_the_parent_number_as_asked() {
    use super::{OrderedRead, ParentRead, UnknownCause};

    let asked = OrderedRead::missing(Resolved::Unknown, UnknownCause::default(), true);
    assert_eq!(asked.parent, ParentRead::Unreadable);
    let alone = OrderedRead::missing(Resolved::Unknown, UnknownCause::default(), false);
    assert_eq!(alone.parent, ParentRead::NotAsked);
}
