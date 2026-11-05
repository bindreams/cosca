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
/// whole grid. The table is the contract: rows are (read, its parent number), columns the parent's
/// proof. With no parent named, the read is the answer.
///
/// Mutants: another parent's number is hidden by a refused read or by the proof; an unreadable
/// number, a missing record or a missing order key settles `Unknown` before the proof (a gone parent
/// then blames the candidate); an unreadable number reads as a match or as another parent's; a failed
/// proof blames the candidate or answers `Gone`; a `Gone` read becomes `Unknown`; a read before the
/// order bound, or one with no order key under a bound, waits for the proof, or is `Unknown` when the
/// proof fails (the proof is asked for, here a panic).
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
    let found = Resolved::Found((Key::for_test(5), Some(order)));

    let nobody_gone = (Resolved::Gone, Owner::Nobody);
    let own_gone = (Resolved::Gone, Owner::Candidate);
    let own_found = (Resolved::Found((id(CANDIDATE, 5), Some(order))), Owner::Candidate);
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
            .judged(CANDIDATE, PARENT, None)
            .proved(proof);
            assert_eq!(
                (answer, owner_of(cause)),
                expected,
                "a {read_name} read, its parent number {number_name}, the parent {proof_name}"
            );
        }
    }

    // The bound rows: a bound is handed out only where `ORDER_AFTER_PARENT` (Windows), and `judged`
    // asserts it.
    #[cfg(windows)]
    {
        // A found read whose order key does not follow the bound is gone, whatever its parent number and
        // before any proof: a proof that would fail is never asked for. A key that follows it, or none
        // bound, leaves the table's answer. An equal key does not follow it.
        for (key_name, bound, follows) in [("before", 10, false), ("equal to", 9, false), ("after", 8, true)] {
            for claimed in [ParentRead::Is(PARENT), ParentRead::Is(OTHER), ParentRead::Unreadable] {
                let judged = |bound| {
                    OrderedRead {
                        read: found,
                        parent: claimed,
                        cause: stated(),
                    }
                    .judged(CANDIDATE, PARENT, bound)
                };
                let held: Proof = || Ok(());
                let (answer, cause) = if follows {
                    judged(Some(OrderKey::for_test(bound))).proved(held)
                } else {
                    judged(Some(OrderKey::for_test(bound))).proved(|| panic!("the parent's proof is asked for"))
                };
                let (unbound, unbound_cause) = judged(None).proved(held);
                let expected = if follows {
                    (unbound, owner_of(unbound_cause))
                } else {
                    nobody_gone
                };
                assert_eq!(
                    (answer, owner_of(cause)),
                    expected,
                    "a read whose key is {key_name} the bound, its parent number {claimed:?}"
                );
            }
        }

        // Where a bound applies, a found read with no order key is not kept, as `ProcessId::parent` has it.
        for claimed in [ParentRead::Is(PARENT), ParentRead::Is(OTHER), ParentRead::Unreadable] {
            let (answer, cause) = OrderedRead {
                read: Resolved::Found((Key::for_test(5), None)),
                parent: claimed,
                cause: stated(),
            }
            .judged(CANDIDATE, PARENT, Some(OrderKey::for_test(8)))
            .proved(|| panic!("the parent's proof is asked for"));
            assert_eq!(
                (answer, owner_of(cause)),
                nobody_gone,
                "a read with no order key under a bound, its parent number {claimed:?}"
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

/// The keep-predicate is strict: a key after the bound is kept, one before it (a stale-creator
/// impostor) or equal to it is not. `judged` applies it to the candidate's key, and `ProcessId::parent`
/// to the key of `self` against its parent's, where [`ORDER_AFTER_PARENT`](super::ORDER_AFTER_PARENT).
///
/// Mutants: `>=` for `>` (the equal row); `<` for `>`.
#[skuld::test]
fn the_keep_predicate_keeps_only_a_key_after_the_bound() {
    use super::{keeps_order, OrderKey};
    let bound = OrderKey::for_test(1_000);
    for (name, key, kept) in [
        ("after", 1_005, true),
        ("equal to", 1_000, false),
        ("before", 999, false),
    ] {
        assert_eq!(keeps_order(OrderKey::for_test(key), bound), kept, "{name}");
    }
}

/// The keep rule over optional keys, on every host: with no bound a read is kept, with or without
/// an order key; under a bound a read with no order key is not, and one with a key is kept only
/// after it.
///
/// Mutants: a read with no order key under a bound is kept; a missing bound drops a read.
#[skuld::test]
fn the_keep_rule_over_optional_keys_drops_a_keyless_read_only_under_a_bound() {
    use super::{keeps, OrderKey};
    let key = |k| Some(OrderKey::for_test(k));
    for (name, order, bound, kept) in [
        ("no bound, a key", key(5), None, true),
        ("no bound, no key", None, None, true),
        ("a bound, no key", None, key(1), false),
        ("a bound, a key after it", key(5), key(1), true),
        ("a bound, a key equal to it", key(1), key(1), false),
        ("a bound, a key before it", key(1), key(5), false),
    ] {
        assert_eq!(keeps(order, bound), kept, "{name}");
    }
}

/// The walk's filter over a reused-creator table: `x` is the root's child, and `y` was created by an
/// earlier holder of `x`'s pid (its read shows `x`'s pid as its parent number) and orders before `x`.
/// Where the order after the parent is the proof ([`ORDER_AFTER_PARENT`](super::ORDER_AFTER_PARENT),
/// Windows) `y` is dropped; elsewhere its parent number is the proof and it is kept. The resolver
/// states each pid's read, with an order key only where the backends read one, and applies `judged`,
/// the read's own rule, so only the bounds the filter hands out are on test. A real stale creator
/// needs a Windows process table: that is `treewalk_tests`' live Windows rows.
///
/// The root's bound is stated here, so what the anchor hands out off Windows is not on test; the
/// row pins how the filter passes bounds down.
///
/// Mutants: the walk hands out no bound on Windows, or the root's rather than the accepted parent's
/// (`y` is kept).
#[skuld::test]
fn a_reused_creator_edge_is_dropped_only_where_the_order_after_the_parent_is_the_proof() {
    use super::{resolution_of, OrderKey, OrderedRead, ParentRead, UnknownCause, ORDER_AFTER_PARENT};
    use crate::containment::treewalk::descendants_with;

    const ROOT: RawPid = 100;
    const X: RawPid = 200;
    const Y: RawPid = 300;
    // Each pid's order key and the parent number its read shows.
    let table = [(X, 200, ROOT), (Y, 150, X)];
    let order_of = |order| ORDER_AFTER_PARENT.then(|| OrderKey::for_test(order));
    let resolve = |pid: RawPid, parent: ProcessId, bound| {
        let &(_, order, shown) = table.iter().find(|(p, ..)| *p == pid).expect("a stated pid");
        let read = OrderedRead {
            read: Resolved::Found((Key::for_test(order), order_of(order))),
            parent: ParentRead::Is(shown),
            cause: UnknownCause::default(),
        };
        resolution_of("pid", pid, read.judged(pid, parent.pid(), bound).proved(|| Ok(())))
    };

    let root_bound = order_of(100);
    let walk = descendants_with(id(ROOT, 100), root_bound, &[(X, ROOT), (Y, X)], resolve);

    let members: Vec<RawPid> = walk.members.iter().map(ProcessId::pid).collect();
    let expected: &[RawPid] = if cfg!(windows) { &[X] } else { &[X, Y] };
    assert_eq!(members, expected);
    assert!(walk.unassessed.is_empty());
}

/// A read that found no record says its parent number could not be read only if it asked for it.
///
/// Mutant: `not_read` reads `Unreadable` for a read that did not ask, or `NotAsked` for one that did
/// (a `NotAsked` that is judged against a named parent breaks the debug assertion there).
#[skuld::test]
fn a_missing_record_reads_the_parent_number_as_asked() {
    use super::ParentRead;

    assert_eq!(ParentRead::not_read(true), ParentRead::Unreadable);
    assert_eq!(ParentRead::not_read(false), ParentRead::NotAsked);
    #[cfg(not(windows))]
    for asked in [true, false] {
        let read = super::OrderedRead::missing(Resolved::Unknown, super::UnknownCause::default(), asked);
        assert_eq!(
            read.parent,
            ParentRead::not_read(asked),
            "missing passes `asked` through"
        );
    }
}
