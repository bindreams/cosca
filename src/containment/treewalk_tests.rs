//! Tests for the identity-aware descendant filters. Most are pure and run on every host: synthetic
//! `(pid, ppid)` edges plus a stub resolver closure drive the filters'
//! structure: the subtree, the dedup, the unassessed list, and what the resolver is handed. The
//! stub applies no order rule: the rule is the read's (`identity_tests`, `keeps` and `judged`),
//! whose answers the stub states. The anchor row reads this live process; the `cfg(windows)` rows
//! below run only on Windows, with their own short-lived children.

use super::{descendants_with, AnchorReads, Resolution, Walk};
use crate::error::Error;
use crate::identity::{Key, OrderKey, ProcessId, RawPid, UnknownCause};
#[cfg(unix)]
use crate::test_groups::setuid;
use std::collections::HashMap;

const ROOT_PID: RawPid = 100;
const ROOT_TOKEN: u64 = 1_000;

/// A tree call given no owner kills and terminates the root by identity, as a member is: it walks
/// and sends, it does not refuse. The blocker's stdin stays open, so only the kill ends it.
///
/// Mutant: a call given no owner answers `Unwalked` and sends nothing.
#[cfg(any(unix, windows))]
#[skuld::test]
fn a_tree_call_given_no_owner_sends_the_roots_kill_by_identity() {
    let (child, stdin) = crate::test_child::held_uncontained_blocker(false);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);

    super::kill_tree(&crate::identity::HostKernel, id, None)
        .outcome()
        .into_result()
        .expect("the walk found the root and killed it");

    let status = child.wait().expect("the killed root is reaped");
    assert!(!status.success(), "the kill ended the root, not its stdin: {status:?}");
    drop(stdin);
}

/// [`a_tree_call_given_no_owner_sends_the_roots_kill_by_identity`], for the `SIGTERM`.
///
/// Mutant: a call given no owner answers an error and sends nothing.
#[cfg(unix)]
#[skuld::test]
fn a_tree_call_given_no_owner_sends_the_roots_term_by_identity() {
    use std::os::unix::process::ExitStatusExt as _;

    let (child, stdin) = crate::test_child::held_uncontained_blocker(false);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);

    match super::terminate_tree(
        &crate::identity::HostKernel,
        id,
        None,
        crate::containment::TreeStop::default(),
    ) {
        (crate::containment::TerminateOutcome::Sent { result: Ok(()), .. }, Some(_)) => {}
        other => panic!("the walk found the root and signalled it: {other:?}"),
    }

    let status = child.wait().expect("the signalled root is reaped");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
    drop(stdin);
}

/// An unverified send, which no handle a walk sends through gives, asserts in debug. Mutant: it is
/// read as an ordinary answer.
#[cfg(debug_assertions)]
#[skuld::test]
fn an_unverified_send_is_a_contract_breach() {
    assert!(
        std::panic::catch_unwind(|| super::KillOutcome::of(Ok(crate::signal::Sent::Unverified))).is_err(),
        "the breach did not assert"
    );
}

/// Release reads an unverified send as nothing sent to a process that may be running. Mutant: it
/// is read as delivered or gone.
#[cfg(not(debug_assertions))]
#[skuld::test]
fn an_unverified_send_is_not_attempted_in_release() {
    match super::KillOutcome::of(Ok(crate::signal::Sent::Unverified)) {
        super::KillOutcome::NotAttempted(Error::Unassessable { .. }) => {}
        other => panic!("an unverified send is not attempted, Unassessable: {other:?}"),
    }
}

/// The one reading of a send's answer, for a walk's members and the root alike. Mutants: a refusal
/// is read as delivered or gone.
#[skuld::test]
fn a_sends_answer_is_one_outcome_whoever_sent() {
    use super::KillOutcome;
    use crate::signal::Sent;

    assert!(matches!(KillOutcome::of(Ok(Sent::Delivered)), KillOutcome::Terminated));
    assert!(matches!(KillOutcome::of(Ok(Sent::Gone)), KillOutcome::AlreadyGone));
    match KillOutcome::of(Err(Error::Io(std::io::Error::from(
        std::io::ErrorKind::PermissionDenied,
    )))) {
        KillOutcome::NotAttempted(Error::Io(refused)) => {
            assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("a refusal is not attempted, with the OS's own error: {other:?}"),
    }
}

fn id(pid: RawPid, token: u64) -> ProcessId {
    ProcessId::from_parts_for_test(pid, Key::for_test(token))
}

/// The bound a candidate's children follow, as a resolver hands it out where the platform orders.
fn bound_of(token: u64) -> Option<OrderKey> {
    Some(OrderKey::for_test(token))
}

/// What the live resolver returns for a process whose identity token and order key agree.
fn resolved(pid: RawPid, token: u64) -> (ProcessId, Option<OrderKey>) {
    (id(pid, token), bound_of(token))
}

/// Build a resolver from a (pid -> token) table. A pid absent from the table is
/// unresolvable (`Ok(None)`, modelling an already-gone process, or one the read found out of order).
fn resolver(tokens: &HashMap<RawPid, u64>) -> impl Fn(RawPid, ProcessId, Option<OrderKey>) -> Resolution + '_ {
    move |pid, _parent, _bound| Ok(tokens.get(&pid).map(|&t| resolved(pid, t)))
}

/// What the live resolver returns for a pid whose read was `Unknown`.
fn unreadable(pid: RawPid) -> Error {
    crate::identity::unqueryable_read("pid", pid, UnknownCause::default())
}

/// Collect the member pids into a sorted Vec for order-independent comparison.
fn pids(walk: Walk) -> Vec<RawPid> {
    let mut v = walk.members;
    v.sort_by_key(|i| i.pid());
    v.into_iter().map(|i| i.pid()).collect()
}

/// The pids a walk could not assess, sorted.
fn unassessed(walk: &Walk) -> Vec<RawPid> {
    let mut v: Vec<RawPid> = walk.unassessed.iter().map(|&(pid, _)| pid).collect();
    v.sort_unstable();
    v
}

fn root() -> ProcessId {
    id(ROOT_PID, ROOT_TOKEN)
}

fn root_bound() -> Option<OrderKey> {
    bound_of(ROOT_TOKEN)
}

// Deep trees recurse =====

#[skuld::test]
fn recurses_into_deep_tree() {
    // root(100) -> 200 -> 300 -> 400, all created after the root.
    let parents = [(200, ROOT_PID), (300, 200), (400, 300)];
    let tokens = HashMap::from([
        (200u32, ROOT_TOKEN + 1),
        (300u32, ROOT_TOKEN + 2),
        (400u32, ROOT_TOKEN + 3),
    ]);
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens), &no_reads());
    assert_eq!(pids(got), [200, 300, 400]);
}

// A reparented orphan (ppid no longer == root) is honestly missed =====

#[skuld::test]
fn reparented_orphan_is_missed() {
    // 300 was a grandchild, but its parent 200 exited and 300 was reparented to
    // pid 1; its ppid no longer chains to the root, so the walk cannot reach it.
    let parents = [(300, 1)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 9)]);
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens), &no_reads());
    assert!(
        got.members.is_empty(),
        "reparented orphan is honestly missed (documented)"
    );
}

// The root itself is never included =====

#[skuld::test]
fn root_is_never_included() {
    // An edge naming the root as its own child would be degenerate; ensure the
    // root pid never appears in the descendant set even if such an edge exists.
    let parents = [(ROOT_PID, ROOT_PID), (200, ROOT_PID)];
    let tokens = HashMap::from([(ROOT_PID, ROOT_TOKEN), (200u32, ROOT_TOKEN + 1)]);
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens), &no_reads());
    assert_eq!(pids(got), [200], "root excluded; genuine child kept");
}

// A duplicate edge enumerates the pid only once =====

#[skuld::test]
fn duplicate_edge_yields_pid_once() {
    // A snapshot that lists the same (pid, ppid) edge twice must not enumerate
    // (or later double-kill) the same process twice.
    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN + 1)]);
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens), &no_reads());
    assert_eq!(pids(got), [200], "duplicate edge collapses to a single result");
}

// An unresolvable candidate (already gone) is skipped =====

#[skuld::test]
fn unresolvable_candidate_is_skipped() {
    // 200 chains to the root but is absent from the resolver (it exited between
    // snapshot and resolve); it is dropped along with anything under it.
    let parents = [(200, ROOT_PID), (300, 200)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5)]); // 200 missing
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens), &no_reads());
    assert!(got.members.is_empty(), "gone candidate and its subtree are skipped");
    assert!(got.unassessed.is_empty(), "a gone candidate is not unassessed");
}

// A candidate the resolver cannot read is unassessed, and its subtree is pruned =====

#[skuld::test]
fn an_unreadable_candidate_and_its_subtree_are_out_of_the_walk_and_it_is_unassessed() {
    // 200 is unreadable; 300 under it is unreachable through it. 400 is a sibling that reads.
    let parents = [(200, ROOT_PID), (300, 200), (400, ROOT_PID)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5), (400u32, ROOT_TOKEN + 6)]);
    let read = resolver(&tokens);
    let got = descendants_with(
        root(),
        root_bound(),
        &parents,
        |pid, parent, bound| {
            if pid == 200 {
                Err(unreadable(200))
            } else {
                read(pid, parent, bound)
            }
        },
        &no_reads(),
    );
    assert_eq!(unassessed(&got), [200]);
    assert!(matches!(&got.unassessed[0].1, Error::Unassessable { detail, .. } if detail.contains("pid 200")));
    assert_eq!(pids(got), [400]);
}

/// `complete_members` is the first unassessed candidate's error, its variant and detail kept, with
/// the first's own cause and every other candidate's whole error below it as a `Several`, in order.
/// No other candidate's words are in the detail.
///
/// Mutants: the others' errors are dropped, or put in the detail as text; the first's own cause is
/// dropped; a `Several` is built of the others alone.
#[skuld::test]
fn complete_members_keeps_every_unassessed_candidate_as_a_cause_in_order() {
    let parents = [(200, ROOT_PID), (300, ROOT_PID), (400, ROOT_PID)];
    // A code per pid, so a cause paired with another candidate fails.
    let os_code = |pid: RawPid| match pid {
        200 => 2,
        300 => 3,
        _ => 5,
    };
    let got = descendants_with(
        root(),
        root_bound(),
        &parents,
        |pid, _, _| {
            Err(Error::Unassessable {
                detail: format!("cause of {pid}"),
                source: Some(Error::io_cause(std::io::Error::from_raw_os_error(os_code(pid)))),
            })
        },
        &no_reads(),
    );
    let order: Vec<RawPid> = got.unassessed.iter().map(|(pid, _)| *pid).collect();
    let error = got.complete_members().expect_err("three candidates were not assessed");

    let Error::Unassessable {
        detail,
        source: Some(source),
    } = &error
    else {
        panic!("the first's variant is kept: {error:?}");
    };
    assert_eq!(*detail, format!("cause of {}", order[0]));
    let Error::Several(list) = &**source else {
        panic!("expected Several, got {source:?}");
    };
    let codes: Vec<_> = list
        .iter()
        .map(|member| crate::error::first_os_code(&**member))
        .collect();
    assert_eq!(codes, order.iter().map(|pid| Some(os_code(*pid))).collect::<Vec<_>>());
    for other in &order[1..] {
        let member = list
            .iter()
            .nth(order.iter().position(|pid| pid == other).expect("listed"))
            .expect("a member");
        assert!(
            matches!(&**member, Error::Unassessable { detail, .. } if *detail == format!("cause of {other}")),
            "{member:?}"
        );
    }
}

/// When the first unassessed candidate's error is an `Error::Io` (a leaf, with no slot for peers), the
/// answer is an `Unassessable` with that `Io` and every other candidate's error below it, in order.
///
/// Mutants: the others are dropped behind the `Io`; the `Io` is returned bare.
#[skuld::test]
fn complete_members_keeps_every_candidate_below_an_unassessable_when_the_first_is_an_io_error() {
    let parents = [(200, ROOT_PID), (300, ROOT_PID)];
    let got = descendants_with(
        root(),
        root_bound(),
        &parents,
        |pid, _, _| {
            let code = if pid == 200 { 2 } else { 3 };
            Err(if pid == 200 {
                Error::Io(std::io::Error::from_raw_os_error(code))
            } else {
                Error::Unassessable {
                    detail: "the second".to_owned(),
                    source: Some(Error::io_cause(std::io::Error::from_raw_os_error(code))),
                }
            })
        },
        &no_reads(),
    );
    let order: Vec<RawPid> = got.unassessed.iter().map(|(pid, _)| *pid).collect();
    assert_eq!(order, [200, 300]);

    let error = got.complete_members().expect_err("two candidates were not assessed");

    let Error::Unassessable {
        source: Some(source), ..
    } = &error
    else {
        panic!("expected Unassessable, got {error:?}");
    };
    let Error::Several(list) = &**source else {
        panic!("expected Several, got {source:?}");
    };
    let codes: Vec<_> = list
        .iter()
        .map(|member| crate::error::first_os_code(&**member))
        .collect();
    assert_eq!(codes, [Some(2), Some(3)]);
}

/// A snapshot that lists the unreadable pid twice reads it once and counts it once.
#[skuld::test]
fn a_duplicate_edge_to_an_unreadable_candidate_is_one_unassessed_entry() {
    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let got = descendants_with(
        root(),
        root_bound(),
        &parents,
        |pid, _, _| Err(unreadable(pid)),
        &no_reads(),
    );
    assert_eq!(unassessed(&got), [200]);
    assert!(got.members.is_empty());
}

/// Only a candidate the resolver finds gone is logged as "gone, or an impostor"; one it errs on was
/// warned where the read was made, and the filters say nothing more of it. The pids are this row's
/// own, as the capture is shared by parallel rows. Mutant: the `Err` arm logs the same line.
#[skuld::test]
fn only_a_gone_candidate_is_logged_as_gone_or_an_impostor() {
    use super::children_of_with;
    const UNREADABLE: RawPid = 61_001;
    const GONE: RawPid = 61_002;
    crate::log_capture::install();
    let parents = [(UNREADABLE, ROOT_PID), (GONE, ROOT_PID)];
    let resolve = |pid: RawPid, _parent: ProcessId, _bound: Option<OrderKey>| -> Resolution {
        if pid == UNREADABLE {
            Err(unreadable(pid))
        } else {
            Ok(None)
        }
    };
    let mark = crate::log_capture::mark();
    descendants_with(root(), root_bound(), &parents, resolve, &no_reads());
    children_of_with(root(), root_bound(), &parents, resolve, &no_reads());
    assert!(crate::log_capture::contains_since(
        mark,
        &format!("pid {GONE} gone, or an impostor")
    ));
    assert!(!crate::log_capture::contains_since(
        mark,
        &format!("pid {UNREADABLE} gone, or an impostor")
    ));
}

#[skuld::test]
fn an_unreadable_direct_child_is_unassessed_in_the_one_level_filter_too() {
    use super::children_of_with;
    let parents = [(200, ROOT_PID), (200, ROOT_PID), (300, ROOT_PID), (400, 200)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5)]);
    let read = resolver(&tokens);
    let got = children_of_with(
        root(),
        root_bound(),
        &parents,
        |pid, parent, bound| {
            if pid == 200 {
                Err(unreadable(200))
            } else {
                read(pid, parent, bound)
            }
        },
        &no_reads(),
    );
    assert_eq!(unassessed(&got), [200]);
    assert_eq!(pids(got), [300]);
}

/// A pid is resolved once however many edges list it: when its first read finds it and a second
/// would be `Unknown`, it is a member, listed once, and not unassessed. Mutant: the one-level filter
/// resolves each duplicate edge again.
#[skuld::test]
fn a_duplicate_edge_is_resolved_once_in_both_filters() {
    use super::children_of_with;
    use std::cell::Cell;

    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let reads = Cell::new(0);
    let first_reads_second_does_not = |pid: RawPid, _parent: ProcessId, _bound: Option<OrderKey>| {
        reads.set(reads.get() + 1);
        if reads.get() == 1 {
            Ok(Some(resolved(pid, ROOT_TOKEN + 5)))
        } else {
            Err(unreadable(pid))
        }
    };
    let got = children_of_with(root(), root_bound(), &parents, first_reads_second_does_not, &no_reads());
    assert_eq!((pids(got), reads.get()), (vec![200], 1), "one level");

    reads.set(0);
    let got = descendants_with(root(), root_bound(), &parents, first_reads_second_does_not, &no_reads());
    assert!(got.unassessed.is_empty(), "{:?}", got.unassessed);
    assert_eq!((pids(got), reads.get()), (vec![200], 1), "whole subtree");
}

// One-level child filter keeps only genuine direct children =====

#[skuld::test]
fn children_of_keeps_one_level_genuine_children_only() {
    use super::children_of_with;
    // root 100; direct child 101; grandchild 102 (ppid 101, not one level); 103 ppid 100, which the
    // resolver finds gone (an impostor, or exited).
    let root = id(100, 50);
    let parents = [(101, 100), (102, 101), (103, 100)];
    let tokens = HashMap::from([(101u32, 60), (102u32, 70)]);
    let got = children_of_with(root, bound_of(50), &parents, resolver(&tokens), &no_reads());
    assert!(got.unassessed.is_empty());
    assert_eq!(pids(got), [101]);
}

// A duplicate edge enumerates a direct child only once =====

#[skuld::test]
fn children_of_duplicate_edge_yields_pid_once() {
    use super::children_of_with;
    // A snapshot listing the same (pid, ppid) edge twice must not enumerate (or later
    // double-kill) the same child twice.
    let root = id(100, ROOT_TOKEN);
    let parents = [(101, 100), (101, 100)];
    let tokens = HashMap::from([(101u32, ROOT_TOKEN + 1)]);
    assert_eq!(
        pids(children_of_with(
            root,
            root_bound(),
            &parents,
            resolver(&tokens),
            &no_reads()
        )),
        [101],
        "duplicate edge collapses to a single child"
    );
}

/// The resolver is told the accepted process the snapshot made each candidate's parent, so a backend
/// can drop a candidate whose parent's number has another holder now, and the bound it must follow:
/// the accepted parent's, which the resolver handed out with it. The parent of a grandchild is the
/// id the walk accepted for the child. Mutants: "the resolver is asked the root for every
/// candidate"; "the bound is the root's for a deeper candidate".
#[skuld::test]
fn the_resolver_is_asked_for_each_candidates_accepted_parent() {
    use std::cell::RefCell;

    use super::children_of_with;

    let asked = RefCell::new(Vec::new());
    let resolve = |pid: u32, parent: ProcessId, bound: Option<OrderKey>| -> Resolution {
        asked.borrow_mut().push((pid, parent, bound));
        Ok(Some(resolved(pid, ROOT_TOKEN + 1)))
    };
    let parents = [(200, ROOT_PID), (300, 200)];
    descendants_with(root(), root_bound(), &parents, resolve, &no_reads());
    assert_eq!(
        asked.take(),
        [
            (200, root(), root_bound()),
            (300, id(200, ROOT_TOKEN + 1), bound_of(ROOT_TOKEN + 1))
        ]
    );

    children_of_with(root(), root_bound(), &parents, resolve, &no_reads());
    assert_eq!(asked.take(), [(200, root(), root_bound())]);
}

/// The bound the filters hand the resolver for the root's children is the `root_bound` argument,
/// not the root id's token: here the root's token is `ROOT_TOKEN` and its bound is another number,
/// or none, as where no order is relied on. Mutants: "the filters hand out `root.key()`"; "the
/// filters hand out a bound the platform did not give".
#[skuld::test]
fn the_bound_is_the_roots_bound_not_its_id_token() {
    use std::cell::RefCell;

    use super::children_of_with;
    let parents = [(200, ROOT_PID)];
    let asked = RefCell::new(Vec::new());
    let resolve = |pid: u32, _parent: ProcessId, bound: Option<OrderKey>| -> Resolution {
        asked.borrow_mut().push((pid, bound));
        Ok(None)
    };
    for bound in [bound_of(ROOT_TOKEN - 500), None] {
        descendants_with(root(), bound, &parents, resolve, &no_reads());
        assert_eq!(asked.take(), [(200, bound)], "descendants_with");
        children_of_with(root(), bound, &parents, resolve, &no_reads());
        assert_eq!(asked.take(), [(200, bound)], "children_of_with");
    }
}

// The anchor-row rule for a candidate that cannot be read =====

/// The walk's only unreadable candidate in the rows below, and a pid that is no member's child.
const UNREADABLE_PID: RawPid = 200;
const OUTSIDER_PID: RawPid = 4;

/// Run `body` with the anchor reads of stated tables: `keys` the key of each pid that can be opened
/// (a pid absent from it cannot be), `creators` the `(parent pid, creator pid)` its handle names (a
/// parent absent from it cannot be read).
fn with_reads<R>(keys: &[(RawPid, u64)], creators: &[(RawPid, RawPid)], body: impl FnOnce(&AnchorReads<'_>) -> R) -> R {
    with_counted_reads(keys, creators, body).0
}

/// [`with_reads`], and how many reads `body` made.
fn with_counted_reads<R>(
    keys: &[(RawPid, u64)],
    creators: &[(RawPid, RawPid)],
    body: impl FnOnce(&AnchorReads<'_>) -> R,
) -> (R, usize) {
    let keys: HashMap<RawPid, u64> = keys.iter().copied().collect();
    let creators: HashMap<RawPid, RawPid> = creators.iter().copied().collect();
    let reads = std::cell::Cell::new(0);
    let key_of = |pid: RawPid| {
        reads.set(reads.get() + 1);
        keys.get(&pid).map(|&key| OrderKey::for_test(key))
    };
    let creator_of = |parent: ProcessId| {
        reads.set(reads.get() + 1);
        creators.get(&parent.pid()).copied()
    };
    let got = body(&AnchorReads {
        key_of: &key_of,
        creator_of: &creator_of,
    });
    (got, reads.get())
}

/// A resolver that cannot read [`UNREADABLE_PID`] and finds every other pid created just after the root.
fn unreadable_200(pid: RawPid, _parent: ProcessId, _bound: Option<OrderKey>) -> Resolution {
    if pid == UNREADABLE_PID {
        Err(unreadable(pid))
    } else {
        Ok(Some(resolved(pid, ROOT_TOKEN + 1)))
    }
}

/// The unreadable candidate's fate in both filters, given a root of key `root_key`, `rows` as the
/// listing's order, the keys of the pids that can be opened and the root's creator, when its handle
/// reads one: `(members, unassessed)` of each.
fn walk_unreadable(
    root_key: u64,
    rows: &[(RawPid, RawPid)],
    keys: &[(RawPid, u64)],
    root_creator: Option<RawPid>,
) -> [(Vec<RawPid>, Vec<RawPid>); 2] {
    let root = id(ROOT_PID, root_key);
    let creators: Vec<(RawPid, RawPid)> = root_creator.map(|creator| (ROOT_PID, creator)).into_iter().collect();
    let fates = |walk: Walk| (pids_unsorted(&walk), unassessed(&walk));
    with_reads(keys, &creators, |reads| {
        [
            fates(descendants_with(root, bound_of(root_key), rows, unreadable_200, reads)),
            fates(super::children_of_with(
                root,
                bound_of(root_key),
                rows,
                unreadable_200,
                reads,
            )),
        ]
    })
}

/// Both filters' fate for the unreadable candidate must be `expected`.
#[track_caller]
fn assert_fate(fates: [(Vec<RawPid>, Vec<RawPid>); 2], expected: (Vec<RawPid>, Vec<RawPid>), what: &str) {
    for (fate, filter) in fates.into_iter().zip(["descendants", "children"]) {
        assert_eq!(fate, expected, "{filter}: {what}");
    }
}

/// What a walk shows for an unreadable candidate the listing places before an anchor: not a member
/// and not unassessed.
fn dropped() -> (Vec<RawPid>, Vec<RawPid>) {
    (vec![], vec![])
}

/// What it shows for one nothing places: an error.
fn reported() -> (Vec<RawPid>, Vec<RawPid>) {
    (vec![], vec![UNREADABLE_PID])
}

fn pids_unsorted(walk: &Walk) -> Vec<RawPid> {
    walk.members.iter().map(ProcessId::pid).collect()
}

/// An unreadable candidate placed before the row of its parent's pid was created before whoever holds
/// that pid, so it is not the parent's child: dropped as gone, not unassessed. Placed after the row,
/// it stays an error. Only the row's pid (not its key) can drop the candidate.
///
/// Mutants: the row naming the parent's pid is not a stop; the direction is inverted (an error
/// before the parent's row, dropped after it).
#[skuld::test]
fn an_unreadable_candidate_before_its_parents_row_is_not_a_member_and_one_after_it_is_unassessed() {
    let parents_row = (ROOT_PID, OUTSIDER_PID);
    let candidate_row = (UNREADABLE_PID, ROOT_PID);
    let keys = [(ROOT_PID, ROOT_TOKEN)];

    let before = walk_unreadable(ROOT_TOKEN, &[candidate_row, parents_row], &keys, None);
    assert_fate(before, dropped(), "before the parent's row");
    let after = walk_unreadable(ROOT_TOKEN, &[parents_row, candidate_row], &keys, None);
    assert_fate(after, reported(), "after the parent's row");
}

/// A later row with a key older than the parent's, and nothing more, places nothing: the candidate
/// stays an error. So it does when the creator's row, which would be an anchor, is listed before the
/// candidate, not after.
///
/// Mutant: a later row whose key precedes the parent's drops the candidate (the key branch).
#[skuld::test]
fn an_unrelated_later_row_with_an_older_key_does_not_drop_an_unreadable_candidate() {
    const PARENT_KEY: u64 = 20;
    let candidate_row = (UNREADABLE_PID, ROOT_PID);

    let rows = [candidate_row, (400, OUTSIDER_PID)];
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(400, 15)], None),
        reported(),
        "a later row, older than the parent and the creator of nothing",
    );
    // Its creator (key 5) is verified, but is listed before the candidate: no anchor after it.
    let rows = [(OUTSIDER_PID, 0), candidate_row, (400, OUTSIDER_PID)];
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(OUTSIDER_PID, 5), (400, 15)], None),
        reported(),
        "a verified creator row before the candidate",
    );
}

/// A row listed after the candidate that is shown to be a creator is an anchor: its process was in
/// the list before the parent could create anything, so the candidate, listed before it, is not the
/// parent's child. The row (pid 4) is named as the creator of a row (pid 400) whose key is no later
/// than the parent's (20), and its own key precedes that row's.
///
/// Mutants: the creator's key is not compared with its created row's; the created row's key is not
/// compared with the parent's (or compared strictly); a creator that cannot be opened, or a created row
/// that cannot, is read as verified; the creator's pid is not matched against the row's ppid.
#[skuld::test]
fn an_unreadable_candidate_before_a_verified_creator_row_is_not_a_member() {
    const PARENT_KEY: u64 = 20;
    let candidate_row = (UNREADABLE_PID, ROOT_PID);
    let rows = [candidate_row, (OUTSIDER_PID, 0), (400, OUTSIDER_PID)];

    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(OUTSIDER_PID, 5), (400, 15)], None),
        dropped(),
        "the creator precedes what it created, which precedes the parent",
    );
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(OUTSIDER_PID, 5), (400, PARENT_KEY)], None),
        dropped(),
        "what it created is the parent's own age",
    );
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(OUTSIDER_PID, 30), (400, 15)], None),
        reported(),
        "the pid's holder now is newer than what it created: another process",
    );
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(OUTSIDER_PID, 5), (400, 25)], None),
        reported(),
        "what it created is newer than the parent",
    );
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(400, 15)], None),
        reported(),
        "the creator cannot be opened",
    );
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(OUTSIDER_PID, 5)], None),
        reported(),
        "what it created cannot be opened",
    );
    let no_creator_row = [candidate_row, (5, 0), (400, OUTSIDER_PID)];
    assert_fate(
        walk_unreadable(PARENT_KEY, &no_creator_row, &[(OUTSIDER_PID, 5), (400, 15)], None),
        reported(),
        "the creator has no row after the candidate",
    );
}

/// The parent's own creator, read on the parent's handle (a process that has exited but is held has
/// no row, and its creator pid is the one thing that names its creator), is an anchor when its key
/// precedes the parent's. A creator the handle cannot name, or whose holder is newer than the parent,
/// places nothing.
///
/// Mutants: the parent's creator is not an anchor; its key is not compared with the parent's.
#[skuld::test]
fn an_unreadable_candidate_before_its_parents_creator_row_is_not_a_member() {
    const PARENT_KEY: u64 = 20;
    let candidate_row = (UNREADABLE_PID, ROOT_PID);
    let rows = [candidate_row, (300, OUTSIDER_PID)];

    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(300, 10)], Some(300)),
        dropped(),
        "the creator row follows the candidate",
    );
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(300, 30)], Some(300)),
        reported(),
        "the creator's pid is held by a newer process",
    );
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(300, PARENT_KEY)], Some(300)),
        reported(),
        "the creator's pid is held by a process of the parent's own age",
    );
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(300, 10)], None),
        reported(),
        "the parent's creator cannot be read",
    );
    assert_fate(
        walk_unreadable(
            PARENT_KEY,
            &[(300, OUTSIDER_PID), candidate_row],
            &[(300, 10)],
            Some(300),
        ),
        reported(),
        "the creator row precedes the candidate",
    );
}

/// A pid's anchor row is its first: a later row of a pid the listing names twice is no anchor, and
/// a row naming itself as its creator makes no creator of its pid. The candidate sits between the
/// first and the second row of a verified creator (pid 4), so nothing is listed after it that anchors.
///
/// Mutants: a duplicate pid's last row is the anchor row; a row naming itself counts as a creator
/// (not distinguishable from the strict key comparison, which refuses it as well).
#[skuld::test]
fn only_a_pids_first_row_anchors_and_a_row_naming_itself_creates_nothing() {
    const PARENT_KEY: u64 = 20;
    let candidate_row = (UNREADABLE_PID, ROOT_PID);
    let keys = [(OUTSIDER_PID, 5), (400, 15)];

    let rows = [(OUTSIDER_PID, 0), candidate_row, (400, OUTSIDER_PID), (OUTSIDER_PID, 0)];
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &keys, None),
        reported(),
        "the creator's second row is no anchor",
    );
    let rows = [candidate_row, (OUTSIDER_PID, 0), (400, OUTSIDER_PID), (OUTSIDER_PID, 0)];
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &keys, None),
        dropped(),
        "the creator's first row is, after the candidate",
    );
    let rows = [candidate_row, (400, 400)];
    assert_fate(
        walk_unreadable(PARENT_KEY, &rows, &[(400, 15)], None),
        reported(),
        "a row naming itself as its creator",
    );
}

/// The parent is a member: its bound is its own order key, not the root's, so a created row older
/// than the member but newer than the root proves its creator an anchor only against the member's key.
/// Mutant: the root's bound is used for a deeper candidate.
#[skuld::test]
fn an_unreadable_candidate_is_ordered_against_the_member_that_is_its_parent() {
    // root (key 1000) -> member 300 (key 1100, resolved just after the root) -> unreadable 200.
    // Row 500 (key 1080: after the root, before the member) was created by row 400 (key 1050).
    let rows = [(300, ROOT_PID), (UNREADABLE_PID, 300), (400, OUTSIDER_PID), (500, 400)];
    let walk = |keys: &[(RawPid, u64)]| {
        with_reads(keys, &[], |reads| {
            descendants_with(root(), root_bound(), &rows, unreadable_200_under_300, reads)
        })
    };
    let got = walk(&[(400, 1_050), (500, 1_080)]);
    assert_eq!(pids_unsorted(&got), [300]);
    assert!(got.unassessed.is_empty(), "created before its parent: not a member");
    let got = walk(&[(400, 1_050), (500, 1_150)]);
    assert_eq!(unassessed(&got), [UNREADABLE_PID], "row 500 follows the member");
}

/// A resolver that finds 300 created at key 1100 and cannot read [`UNREADABLE_PID`].
fn unreadable_200_under_300(pid: RawPid, _parent: ProcessId, _bound: Option<OrderKey>) -> Resolution {
    match pid {
        UNREADABLE_PID => Err(unreadable(pid)),
        _ => Ok(Some(resolved(pid, 1_100))),
    }
}

/// Where the platform gives no bound (anywhere but Windows) the order of rows is no proof of anything:
/// an unreadable candidate stays an error whatever the rows say. Mutant: the rule applies without a bound.
#[skuld::test]
fn an_unreadable_candidate_is_not_dropped_by_row_order_where_there_is_no_bound() {
    let rows = [(UNREADABLE_PID, ROOT_PID), (ROOT_PID, OUTSIDER_PID)];
    let got = with_reads(&[(ROOT_PID, ROOT_TOKEN)], &[(ROOT_PID, 3)], |reads| {
        descendants_with(root(), None, &rows, unreadable_200, reads)
    });
    assert_eq!(unassessed(&got), [UNREADABLE_PID]);
}

/// A candidate the resolver reads costs no read of a row or of the parent's creator, in either
/// filter. Mutant: every candidate's anchors are looked up.
#[skuld::test]
fn a_candidate_the_resolver_reads_costs_no_anchor_reads() {
    let rows = [(300, ROOT_PID), (400, OUTSIDER_PID)];
    let (got, reads) = with_counted_reads(&[], &[], |reads| {
        descendants_with(root(), root_bound(), &rows, unreadable_200, reads)
    });
    assert_eq!((pids_unsorted(&got), reads), (vec![300], 0), "descendants");
    let (got, reads) = with_counted_reads(&[], &[], |reads| {
        super::children_of_with(root(), root_bound(), &rows, unreadable_200, reads)
    });
    assert_eq!((pids_unsorted(&got), reads), (vec![300], 0), "children");
}

/// A resolver that cannot read two pids under the root.
fn unreadable_two(pid: RawPid, _parent: ProcessId, _bound: Option<OrderKey>) -> Resolution {
    if pid == UNREADABLE_PID || pid == UNREADABLE_PID + 1 {
        Err(unreadable(pid))
    } else {
        Ok(Some(resolved(pid, ROOT_TOKEN + 1)))
    }
}

/// A parent's anchors are looked up once, however many of its candidates cannot be read: the reads
/// of a second candidate under the same parent add none. Both are placed before the anchor.
///
/// Mutant: each unreadable candidate looks the anchors up again.
#[skuld::test]
fn a_parents_anchors_are_looked_up_once_for_all_its_unreadable_candidates() {
    const PARENT_KEY: u64 = 20;
    let keys = [(OUTSIDER_PID, 5), (400, 15)];
    let reads_of = |rows: &[(RawPid, RawPid)], filter: &str| {
        let (walk, reads) = with_counted_reads(&keys, &[], |reads| {
            let (root, bound) = (id(ROOT_PID, PARENT_KEY), bound_of(PARENT_KEY));
            match filter {
                "descendants" => descendants_with(root, bound, rows, unreadable_two, reads),
                _ => super::children_of_with(root, bound, rows, unreadable_two, reads),
            }
        });
        assert_eq!(unassessed(&walk), Vec::<RawPid>::new(), "{filter}: both are placed");
        reads
    };
    let tail = [(OUTSIDER_PID, 0), (400, OUTSIDER_PID)];
    let one = [(UNREADABLE_PID, ROOT_PID), tail[0], tail[1]];
    let two = [
        (UNREADABLE_PID, ROOT_PID),
        (UNREADABLE_PID + 1, ROOT_PID),
        tail[0],
        tail[1],
    ];
    for filter in ["descendants", "children"] {
        assert_eq!(reads_of(&one, filter), reads_of(&two, filter), "{filter}");
    }
}

/// What the live anchor hands the walk as its children's bound: where the platform orders by
/// creation (Windows) the root's order key, elsewhere none, read through `anchor` itself (this
/// process, live) and not stated. Mutants: the anchor hands out a bound off Windows; it hands out
/// none on Windows.
#[skuld::test]
fn the_anchor_hands_out_a_bound_only_on_windows() {
    let proof = super::anchor(&crate::identity::HostKernel, ProcessId::current())
        .expect("this process reads")
        .expect("this process is live");
    assert_eq!(proof.bound.is_some(), crate::identity::ORDER_AFTER_PARENT);
}

/// `resolve_or_drop` is a named discard site: an access-denied descendant must be dropped
/// from the walk as an error naming it, never be silently folded in with a gone pid. The walk's
/// caller reports it ([`super::warn_unassessed`]), so the walk itself logs nothing.
#[cfg(windows)]
#[skuld::test]
fn resolve_or_drop_drops_an_access_denied_pid_as_an_error() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(resolve_or_drop_drops_an_access_denied_pid_as_an_error),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    crate::log_capture::install();
    let denied = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
    assert!(denied.is_running(), "precondition: the subject must be live");
    let mark = crate::log_capture::mark();
    let Err(Error::Unassessable { detail, .. }) =
        super::resolve_or_drop(&crate::identity::HostKernel, denied.pid(), ProcessId::current(), None)
    else {
        panic!("the walk cannot keep what it cannot verify, and an unread pid is not a gone one");
    };
    assert!(
        detail.contains(&format!("pid {} exists but could not be queried", denied.pid())),
        "{detail}"
    );
    assert!(
        !crate::log_capture::contains_since(mark, &format!("treewalk: pid {}", denied.pid())),
        "the walk's caller reports it, not the walk"
    );
    assert!(denied.is_running(), "and dropping it must not have touched it");
}

/// The text of `resolve_or_drop`'s warn for a candidate whose creator-pid query was refused: the
/// cause reaches `unqueryable_read`, which words it, so the warn names the pid and the query, and
/// it does not fall back to "access denied?".
///
/// The failed query itself is not driven through the walk: forcing one needs a hook in production
/// code, and Windows has no `FakeKernel` methods to state it in.
///
/// Mutant: `into_error` drops the creator status.
#[cfg(windows)]
#[skuld::test]
fn a_refused_creator_query_is_worded_with_its_status_in_the_walks_warn_on_windows() {
    let refused = windows::Win32::Foundation::NTSTATUS(0xC000_0004_u32 as i32);
    let cause = crate::identity::UnknownCause::default().with_creator_status(refused);
    let error = crate::identity::unqueryable_read("pid", 7, cause);
    let crate::error::Error::Unassessable { detail, .. } = &error else {
        panic!("a refused creator query is Unassessable");
    };
    assert_eq!(detail, "pid 7 exists but its creator process id query failed");
    // `STATUS_INFO_LENGTH_MISMATCH` as its Win32 code, `ERROR_BAD_LENGTH`.
    assert_eq!(
        crate::error::first_os_code(&error),
        Some(windows::Win32::Foundation::ERROR_BAD_LENGTH.0 as i32)
    );
}

/// The Windows wiring of the walk to the creator read, through `walk_from` with real
/// processes: `x` and `y` are both children of the root (this process). A snapshot that names `x` as
/// `y`'s parent is a stale creator edge: `y`'s own creator is the root, so it is dropped under `x`
/// and kept under the root. `x` is spawned first, so `y`'s key follows `x`'s and the parent-order
/// rule passes the edge: only the creator read drops `y`. (A real edge that breaks the rule names a
/// creator that is not the process's, which the creator read catches first, so the `judged` and
/// bound rows pin that rule.)
/// Mutant: `resolve_or_drop` passes no parent to the read.
#[cfg(windows)]
#[skuld::test]
fn a_real_candidate_is_dropped_under_a_parent_that_is_not_its_creator_on_windows() {
    use crate::identity::HostKernel;
    use crate::test_child::{live_findstr_blocker, release_findstr_unterminated};

    use crate::Recursive;

    let root = ProcessId::current();
    let (x_child, x) = live_findstr_blocker();
    let (y_child, y) = live_findstr_blocker();

    // The root's own row is not read, only the rows that name it as a parent.
    let stale_creator = [(x.pid(), root.pid()), (y.pid(), x.pid())];
    let dropped = super::walk_from(&HostKernel, root, &stale_creator, Recursive::Yes)
        .expect("the root reads")
        .expect("the root is live");
    let genuine = [(x.pid(), root.pid()), (y.pid(), root.pid())];
    let kept = super::walk_from(&HostKernel, root, &genuine, Recursive::Yes)
        .expect("the root reads")
        .expect("the root is live");

    release_findstr_unterminated(x_child);
    release_findstr_unterminated(y_child);
    // A stale creator is dropped as `Gone`, not as unassessed: both of this process's children read.
    assert!(dropped.unassessed.is_empty() && kept.unassessed.is_empty());
    assert_eq!(dropped.members, vec![x]);
    assert_eq!(kept.members, vec![x, y]);
}

/// The Windows wiring of the anchor rows to the live reads, through `walk_from` with real
/// processes. The root `r` is a live child of this process `t`, whose creator is `o` (this test runs
/// in a process of its own, a child of the process that started it). The candidate `u` is a real
/// process this one cannot open, named by a stated row as `r`'s child. Both reads are live and
/// openable here: `r`'s creator is `t`, read on `r`'s handle, and the keys of `t` and `o` are read by
/// pid; both are older than `r`.
///
/// - With only `t`'s row after `u`, the anchor is `r`'s creator: `u`, listed before it, is dropped;
///   listed after it, `u` stays unassessed.
/// - With `t` listed before `u`, and `o`'s row, which names no creator of `r`'s, after it, the anchor
///   is `o`: named as the creator of `t`, older than `t`, which is no later than `r`. `u` is dropped.
///   With `o`'s row before `u` too, nothing follows `u` and `u` stays unassessed.
///
/// Mutants: the creator read of `r` finds nothing (the first case fails); the key read finds nothing
/// (the first and second cases fail).
#[cfg(windows)]
#[skuld::test]
fn an_unreadable_candidate_is_placed_by_the_live_creator_and_key_reads_on_windows() {
    use crate::identity::{HostKernel, Resolved};
    use crate::test_child::{live_findstr_blocker, release_findstr_unterminated};
    use crate::Recursive;

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(
            an_unreadable_candidate_is_placed_by_the_live_creator_and_key_reads_on_windows
        ),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let (r_child, r) = live_findstr_blocker();
    let u = crate::identity::windows_fixture::spawn_unkillable(&done);
    assert_eq!(
        ProcessId::of(u.pid()),
        Resolved::Unknown,
        "precondition: the candidate cannot be opened"
    );
    let t = ProcessId::current().pid();
    let o = ProcessId::current()
        .parent()
        .expect("this process's parent reads")
        .expect("this process has a parent")
        .pid();
    let candidate = (u.pid(), r.pid());
    let fate = |rows: &[(RawPid, RawPid)]| {
        [Recursive::No, Recursive::Yes].map(|depth| {
            let walk = super::walk_from(&HostKernel, r, rows, depth)
                .expect("the root reads")
                .expect("the root is live");
            assert!(walk.members.is_empty(), "the candidate is no member");
            unassessed(&walk)
        })
    };
    let dropped = [Vec::<RawPid>::new(), vec![]];
    let reported = [vec![u.pid()], vec![u.pid()]];

    let creator_row_after = fate(&[candidate, (t, 4)]);
    let creator_row_before = fate(&[(t, 4), candidate]);
    let key_proves_creator = fate(&[(t, o), candidate, (o, 4)]);
    let nothing_after = fate(&[(o, 4), (t, o), candidate]);
    release_findstr_unterminated(r_child);

    assert_eq!(creator_row_after, dropped, "the creator's row follows the candidate");
    assert_eq!(creator_row_before, reported, "the creator's row precedes the candidate");
    assert_eq!(
        key_proves_creator, dropped,
        "a creator shown by a key read follows the candidate"
    );
    assert_eq!(nothing_after, reported, "no anchor follows the candidate");
}

/// A root that exits while its handle is held is walked, and its running child is killed. Windows
/// does not reparent: the child's creator pid is still the root's. Toolhelp does not list an exited
/// process whose handle is held (measured on Windows 11 26100.9711), so the snapshot has no row for
/// the root while the walk's edges, which name it as the child's parent, are intact: a missing root
/// row says nothing about them. The root's order key and creator are read from its own handle, which
/// is held.
///
/// The root is a `cmd.exe` that holds its `more.com` child, blocked on a stdin this test holds: it is
/// released (and exits `0`) only after `hard_kill`, so a kill that did not happen fails the assertion
/// on its exit code instead of hanging the wait.
///
/// Mutant: a root with no row in the snapshot is `Unassessable`, or walks nothing.
#[cfg(windows)]
#[skuld::test]
fn a_root_that_exited_while_its_handle_is_held_is_walked_and_its_child_killed() {
    use std::process::Stdio;

    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    use crate::identity::{windows_close, windows_open_classified, HostKernel, Opened};
    use crate::Recursive;

    // The std `Child` holds the root's process handle until it is dropped, at the end of the row.
    let more = crate::test_child::windows_more();
    let mut shell = crate::test_child::StdChild::spawn(
        std::process::Command::new("cmd.exe")
            .arg("/c")
            .arg(&more)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    );
    let root = ProcessId::of(shell.id()).found().expect("the live root resolves");
    // `more` inherits the root's pipes. It echoes a line as it reads it, so the first byte read
    // back says it exists. Both pipes stay open: `std`'s `wait` would close the stdin, which ends
    // `more`, and a closed stdout would end it too.
    let mut stdin = shell.stdin.take().expect("piped stdin");
    std::io::Write::write_all(&mut stdin, b"x\r\n").expect("feed the child a line");
    let mut first = [0u8; 1];
    let read = std::io::Read::read(shell.stdout.as_mut().expect("piped stdout"), &mut first).expect("read the echo");
    assert_eq!(read, 1, "the root closed its output before its child echoed");
    // The root's children are its console host and its `more`.
    let children = root.children(Recursive::No).expect("the root's children");
    let held = children
        .into_iter()
        .find(|id| crate::identity::windows_fixture::is_more_com(id.pid()))
        .expect("the root has a `more` child")
        .pid();
    let Opened::Found(held_handle) =
        windows_open_classified(held, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)
    else {
        panic!("the child is ours and openable");
    };
    shell.kill().expect("terminate the root");
    shell.wait().expect("the root's exit is recorded");

    let parents = crate::test_child::parents_once_unlisted(root.pid());
    assert!(
        parents.iter().any(|&(pid, ppid)| pid == held && ppid == root.pid()),
        "precondition: the running child must still name the exited root as its creator"
    );

    let children = root.children(Recursive::No).expect("the exited root's children");
    assert!(
        children.iter().any(|id| id.pid() == held),
        "{held} not among {children:?}"
    );
    super::hard_kill(&HostKernel, root, &super::ByIdentity::new(&HostKernel, root))
        .outcome()
        .into_result()
        .expect("an exited root whose handle is held is walked completely");

    // Released only now: a kill that never came ends the child by itself, with code 0, which the
    // assertion below fails.
    drop(stdin);
    // SAFETY: `held_handle` is our live handle with the synchronize right. The wait ends with the
    // kill just asked for, or with the child's release.
    let waited = unsafe { WaitForSingleObject(held_handle, INFINITE) };
    assert_eq!(waited, WAIT_OBJECT_0, "the wait on the child returned {waited:?}");
    let mut code = 0u32;
    // SAFETY: `held_handle` is live with the query right; `code` is a u32.
    unsafe { GetExitCodeProcess(held_handle, &mut code) }.expect("the child's exit code");
    windows_close(held_handle);
    assert_eq!(
        code,
        crate::identity::WINDOWS_TERMINATE_EXIT_CODE,
        "the walk must have terminated the child"
    );
}

/// A walk sends each descendant's kill through the kernel it was given: one `terminate` row per
/// descendant, taken by its kill. The root's kill is the host's (a `ByIdentity` over the host
/// kernel) and ends the root.
///
/// Mutant: `kill_one` asks the host kernel instead of the walk's.
#[cfg(windows)]
#[skuld::test]
fn a_walk_kills_each_descendant_through_its_kernel_on_windows() {
    use std::process::Stdio;

    use crate::identity::{FakeKernel, HostKernel};
    use crate::Recursive;

    let more = crate::test_child::windows_more();
    let mut shell = crate::test_child::StdChild::spawn(
        std::process::Command::new("cmd.exe")
            .arg("/c")
            .arg(&more)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    );
    let root = ProcessId::of(shell.id()).found().expect("the live root resolves");
    // The first byte read back says `more` exists; both pipes stay open so it keeps running.
    let mut stdin = shell.stdin.take().expect("piped stdin");
    std::io::Write::write_all(&mut stdin, b"x\r\n").expect("feed the child a line");
    let mut first = [0u8; 1];
    let read = std::io::Read::read(shell.stdout.as_mut().expect("piped stdout"), &mut first).expect("read the echo");
    assert_eq!(read, 1, "the root closed its output before its child echoed");
    let descendants = root.children(Recursive::Yes).expect("the root's descendants");
    assert!(!descendants.is_empty(), "precondition: the root has descendants");
    let kernel = descendants
        .iter()
        .fold(FakeKernel::new(), |kernel, _| kernel.on_terminate(Ok(())));

    let outcome = super::hard_kill(&kernel, root, &super::ByIdentity::new(&HostKernel, root))
        .outcome()
        .into_result();

    outcome.expect("every descendant's kill was answered");
    assert!(
        kernel.all_rows_taken(),
        "a descendant's kill did not ask the walk's kernel"
    );
}

/// The handle a walk sends a member's kill through is open for the member's exit: it can be waited
/// on once the kill is sent. A handle opened for `PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION`
/// alone cannot (`WaitForSingleObject` answers `ERROR_ACCESS_DENIED`).
///
/// Mutant: the walk opens its member without `SYNCHRONIZE`.
#[cfg(windows)]
#[skuld::test]
fn a_walk_members_handle_can_be_waited_on_after_its_kill() {
    // The blocker's stdin stays open, so only the kill ends it.
    let (_child, _stdin, id) = crate::test_child::live_blocker();
    let os = super::open_by_identity(&crate::identity::HostKernel, id)
        .expect("a live member opens")
        .expect("a live member is not gone");
    // A handle without `SYNCHRONIZE` cannot show that a running member is running: its look fails.
    assert!(
        matches!(os.exited(), Ok(crate::os_process::Exit::Running(_))),
        "a live member's handle is waited on, not refused"
    );
    let outcome = super::KillOutcome::of(os.signal(crate::signal::Sig::Kill));
    assert!(matches!(outcome, super::KillOutcome::Terminated), "{outcome:?}");
    assert!(
        crate::os_process::drive::exited_held(&*os, None).expect("the member's handle can be waited on"),
        "the wait ended on the member's exit"
    );
}

/// `kill_by_identity`-s pre-open Denied arm - the outcome that can leave a process running.
#[cfg(windows)]
#[skuld::test]
fn kill_by_identity_reports_not_attempted_when_the_open_is_denied() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_by_identity_reports_not_attempted_when_the_open_is_denied),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_unkillable(&done);
    let id =
        crate::identity::windows_identity_from_handle_result(&crate::identity::HostKernel, child.handle(), child.pid())
            .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let outcome = super::kill_by_identity(&crate::identity::HostKernel, id);
    assert!(matches!(outcome, super::KillOutcome::NotAttempted(_)), "{outcome:?}");
    assert!(child.is_running(), "a denied open must leave the process running");
}

/// A root the walk may read but not terminate is left running, and `hard_kill` is an error naming it
/// and why: the open succeeds with the rights the process grants, and the kill is refused. Mutant:
/// `hard_kill` drops a `NotAttempted` outcome.
#[cfg(windows)]
#[skuld::test]
fn hard_kill_of_a_root_it_may_read_but_not_terminate_is_an_error_naming_it() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(hard_kill_of_a_root_it_may_read_but_not_terminate_is_an_error_naming_it),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    // Readable by pid, but not terminable: the walk anchors on it, and its kill is refused.
    let child = crate::identity::windows_fixture::spawn_query_only(&done);
    let id =
        crate::identity::windows_identity_from_handle_result(&crate::identity::HostKernel, child.handle(), child.pid())
            .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let kernel = crate::identity::HostKernel;
    match super::hard_kill(&kernel, id, &super::ByIdentity::new(&kernel, id))
        .outcome()
        .into_result()
    {
        Err(super::Unkilled {
            members,
            root: Some(root),
            ..
        }) if members.is_empty() => {
            let crate::error::Error::MemberNotKilled { pid, source, .. } = *root else {
                panic!("expected MemberNotKilled for the root, got {root:?}");
            };
            assert_eq!(pid, child.pid());
            // The open drops the terminate right the process refuses, and the kill is the OS's
            // refusal, with its error.
            assert!(
                matches!(*source, crate::error::Error::Io(_)),
                "a refused kill is the OS's error: {source:?}"
            );
            assert_eq!(
                crate::error::first_os_code(&*source),
                Some(windows::Win32::Foundation::ERROR_ACCESS_DENIED.0 as i32),
                "{source:?}"
            );
        }
        other => panic!("expected MemberNotKilled for the root, got {other:?}"),
    }
    assert!(child.is_running(), "a refused kill must leave the process running");
}

/// A member the OS refuses the signal is left running, and `hard_kill`'s error carries the refusal's
/// OS error, so a caller can tell it from one that could not be read. A setuid-root helper refuses
/// the kill of its caller. Mutant: the refusal is flattened to text.
#[cfg(unix)]
#[skuld::test]
fn hard_kill_of_a_root_that_refuses_the_signal_is_an_error_carrying_the_errno(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    let (child, stdin) = crate::test_privilege::spawn_setuid_blocker();
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let kernel = crate::identity::HostKernel;
    let left = super::hard_kill(&kernel, id, &super::ByIdentity::new(&kernel, id))
        .outcome()
        .into_result()
        .expect_err("the kill is refused");
    assert!(left.members.is_empty(), "the root is the only member the walk left");
    let err = left.root.expect("the root was left");
    // The message names the pid; the OS's own words are the source, each layer said once.
    let os = std::io::Error::from_raw_os_error(libc::EPERM);
    assert_eq!(err.to_string(), format!("pid {} was not killed", child.pid()));
    assert_eq!(
        crate::error::said(&err),
        format!("pid {} was not killed: {}", child.pid(), crate::error::io_said(&os))
    );
    match *err {
        crate::error::Error::MemberNotKilled { pid, source, .. } => {
            assert_eq!(pid, child.pid());
            assert!(
                matches!(*source, crate::error::Error::Io(ref e) if e.raw_os_error() == Some(libc::EPERM)),
                "{source:?}"
            );
        }
        other => panic!("expected MemberNotKilled, got {other:?}"),
    }
    // The helper exits at EOF: nothing killed it.
    drop(stdin);
    assert!(child.wait().expect("the helper exits on EOF").success());
}

/// A descendant the OS refuses the signal is left running by the walk's own loop: the error names it,
/// with the refusal's OS error, and the root, which was killed, is not among what is left. A
/// setuid-root helper under a plain root refuses the kill of its caller.
///
/// Mutants: the loop drops a refused descendant's error; the root is reported left beside it.
#[cfg(unix)]
#[skuld::test]
fn hard_kill_of_a_descendant_that_refuses_the_signal_is_an_error_naming_it_with_the_errno(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    let (child, stdin) = crate::test_privilege::root_over_setuid_blockers(1, |_| {});

    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let kernel = crate::identity::HostKernel;
    let left = super::hard_kill(&kernel, id, &super::ByIdentity::new(&kernel, id))
        .outcome()
        .into_result()
        .expect_err("the helper refuses the kill");

    assert!(left.root.is_none(), "the root was killed: {:?}", left.root);
    assert_eq!(left.members.len(), 1, "{:?}", left.members);
    match &left.members[0] {
        crate::error::Error::MemberNotKilled { pid, source, .. } => {
            assert_ne!(*pid, child.pid(), "the helper, not the root");
            assert!(
                matches!(**source, crate::error::Error::Io(ref e) if e.raw_os_error() == Some(libc::EPERM)),
                "{source:?}"
            );
        }
        other => panic!("expected MemberNotKilled, got {other:?}"),
    }
    // The helper exits at EOF: nothing killed it.
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));
}

/// `Process::kill_tree` of a root that refuses the signal: nothing after the walk kills the root, so
/// it is left, and the error names it with the refusal's OS error.
///
/// Mutant: a root the walk left is dropped from the report as if its kill had ended it.
#[cfg(unix)]
#[skuld::test]
fn process_kill_tree_of_a_root_that_refuses_the_signal_names_the_root(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    let (child, stdin) = crate::test_privilege::spawn_setuid_blocker();
    let process = crate::Process::open_pid(child.pid()).expect("open").expect("running");

    let err = process.kill_tree().expect_err("the root refuses the kill");

    let crate::error::Error::MembersLeft { members, .. } = &err else {
        panic!("expected MembersLeft, got {err:?}");
    };
    let [member] = &members.iter().collect::<Vec<_>>()[..] else {
        panic!("the root is the one member left: {members:?}");
    };
    match &***member {
        crate::error::Error::MemberNotKilled { pid, source, .. } => {
            assert_eq!(*pid, child.pid());
            assert!(
                matches!(&**source, crate::error::Error::Io(e) if e.raw_os_error() == Some(libc::EPERM)),
                "{source:?}"
            );
        }
        other => panic!("expected MemberNotKilled, got {other:?}"),
    }
    drop(stdin);
    assert!(child.wait().expect("the helper exits on EOF").success());
}

/// `Process::kill_tree` of a tree with two members that refuse the signal: the error holds both, each
/// named once with the refusal's OS error, and nothing is warned of one by one.
///
/// Mutants: a member is dropped; one is named twice; the members are warned of as well as returned.
#[cfg(unix)]
#[skuld::test]
fn process_kill_tree_returns_every_refusing_member_and_warns_of_none(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    crate::log_capture::install();
    let (child, stdin) = crate::test_privilege::root_over_setuid_blockers(2, |_| {});
    let process = crate::Process::open_pid(child.pid()).expect("open").expect("running");
    let mark = crate::log_capture::mark();

    let err = process.kill_tree().expect_err("two members refuse the kill");

    let crate::error::Error::MembersLeft { members, .. } = &err else {
        panic!("expected MembersLeft, got {err:?}");
    };
    let mut pids = Vec::new();
    for member in members.iter() {
        let crate::error::Error::MemberNotKilled { pid, .. } = &**member else {
            panic!("expected MemberNotKilled, got {member:?}");
        };
        assert_eq!(crate::error::first_os_code(&**member), Some(libc::EPERM), "{member:?}");
        pids.push(*pid);
    }
    pids.sort_unstable();
    pids.dedup();
    assert_eq!(pids.len(), 2, "each refusing member is named once: {members:?}");
    let warned = crate::log_capture::warns_since(mark, "was not killed");
    assert!(warned.is_empty(), "the members are in the error: {warned:?}");
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));
}

/// `terminate` is best effort: a member that refuses the `SIGTERM` is warned of once, with its pid and
/// the OS's refusal, and the call is `Ok`.
///
/// Mutants: the refusal is not warned of; it is warned of twice.
#[cfg(unix)]
#[skuld::test]
fn terminate_warns_once_of_a_member_that_refuses_the_signal(#[fixture(setuid)] _group: &crate::test_groups::Group) {
    crate::log_capture::install();
    let (child, stdin) = crate::test_privilege::root_over_setuid_blockers(1, |_| {});
    let mark = crate::log_capture::mark();

    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let kernel = crate::identity::HostKernel;
    super::terminate(
        &kernel,
        id,
        &super::ByIdentity::new(&kernel, id),
        crate::containment::TreeStop::default(),
    )
    .0
    .into_tree_result()
    .expect("best effort");

    let os = std::io::Error::from_raw_os_error(libc::EPERM);
    let warned = crate::log_capture::warns_since(mark, "was sent no SIGTERM");
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].starts_with("treewalk: pid "), "{warned:?}");
    assert!(warned[0].contains(&os.to_string()), "{warned:?}");
    drop(stdin);
    child.wait().expect("reap the root");
}

/// `kill_by_identity` must terminate only the process whose START TOKEN matches. A stale
/// identity names a recycled pid, and killing it would kill a stranger.
#[cfg(windows)]
#[skuld::test]
fn kill_by_identity_spares_a_stale_identity_and_kills_a_matching_one() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_by_identity_spares_a_stale_identity_and_kills_a_matching_one),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    // The ACE must grant QUERY_LIMITED: the open needs it to verify the identity, and drops each of
    // SYNCHRONIZE and TERMINATE that the process refuses.
    let (child, stdin) =
        crate::identity::windows_fixture::spawn_restricted_releasable(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let real =
        crate::identity::windows_identity_from_handle_result(&crate::identity::HostKernel, child.handle(), child.pid())
            .expect("the owned handle always yields an identity");
    let stale = real.with_other_value();

    let outcome = super::kill_by_identity(&crate::identity::HostKernel, stale);
    assert!(
        matches!(outcome, super::KillOutcome::AlreadyGone),
        "a stale identity names a process that is gone - nothing to terminate: {outcome:?}"
    );
    assert!(
        child.is_running(),
        "a stale identity must never terminate the pid-s occupant"
    );

    let outcome = super::kill_by_identity(&crate::identity::HostKernel, real);
    assert!(
        matches!(outcome, super::KillOutcome::Terminated),
        "a matching identity must reach TerminateProcess: {outcome:?}"
    );
    // The child reads `stdin` to its end and exits 0, so a kill that sent nothing ends the wait
    // below with that code, not with the kill's `1`.
    drop(stdin);
    child.await_exit();
    assert_eq!(
        child.exit_code(),
        1,
        "a matching identity must terminate the process, not leave it to exit when released"
    );
}

/// A member that exits between `kill_by_identity`'s identity check and its `TerminateProcess`
/// is gone, not a failed kill: Windows refuses `TerminateProcess` on an exited process with
/// `ERROR_ACCESS_DENIED`. Mutant: the error arm warns and answers `NotAttempted` unconditionally.
#[cfg(windows)]
#[skuld::test]
fn kill_by_identity_reports_a_member_that_exits_before_the_terminate_as_gone() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_by_identity_reports_a_member_that_exits_before_the_terminate_as_gone),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    let _watch = crate::log_capture::warn_watch();
    let (child, _stdin) =
        crate::identity::windows_fixture::spawn_restricted_releasable(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let child = std::rc::Rc::new(child);
    let id =
        crate::identity::windows_identity_from_handle_result(&crate::identity::HostKernel, child.handle(), child.pid())
            .expect("the owned handle always yields an identity");
    let exiter = std::rc::Rc::clone(&child);
    super::fault::set_before_terminate(move || exiter.terminate());

    let outcome = super::kill_by_identity(&crate::identity::HostKernel, id);
    assert!(
        matches!(outcome, super::KillOutcome::AlreadyGone),
        "a member that exited before the terminate has nothing left to kill: {outcome:?}"
    );
    assert!(!child.is_running(), "precondition: the hook ended the member");
}

/// A member whose exit is under way but not yet signalled is gone, not a failed kill, and
/// `hard_kill` stays complete.
///
/// Mutant: a refusal is gone only once the process reads signalled, so this one warns and answers
/// `NotAttempted`.
#[cfg(windows)]
#[skuld::test]
fn kill_by_identity_reports_a_member_that_is_exiting_but_not_signalled_as_gone() {
    use std::os::windows::io::AsRawHandle;
    let child = crate::test_child::spawn_more_blocker();
    let id = crate::identity::windows_identity_from_handle_result(
        &crate::identity::HostKernel,
        windows::Win32::Foundation::HANDLE(child.as_raw_handle()),
        child.id(),
    )
    .expect("the owned handle always yields an identity");
    let kernel = crate::identity::refusing_the_next_terminate();
    let outcome = super::kill_by_identity(&kernel, id);

    assert!(
        kernel.all_rows_taken(),
        "the kill reached TerminateProcess to be refused"
    );
    assert!(matches!(outcome, super::KillOutcome::AlreadyGone), "{outcome:?}");
}

/// A walk guards itself by proving its root still holds its pid, so off macOS `kill_tree` and
/// `terminate_tree` walk whatever the root's state says; on macOS they skip a root the handle cannot
/// vouch for (`Unpinned`, `Unknown`) and walk the rest. The root here holds no such pid, so a walk
/// that ran finds no root and kills nothing.
///
/// Mutant: `skipped_walk` skips on `Unknown` or `Reaped` off macOS.
#[cfg(unix)]
#[skuld::test]
fn a_walk_is_skipped_by_the_roots_state_only_on_macos() {
    use crate::containment::dispatch::TreeKillOutcome;
    use crate::containment::TerminateOutcome;
    use crate::signal::RootState;
    use crate::test_support::stated_root::StatedRoot;

    /// A state, and whether macOS cannot vouch for a root in it.
    type Case = (&'static str, fn() -> RootState, bool);
    let states: [Case; 4] = [
        ("unreaped", || RootState::Unreaped, false),
        ("reaped elsewhere", || RootState::Reaped, false),
        (
            "unknown",
            || RootState::Unknown(std::sync::Arc::new(std::io::Error::other("forced"))),
            true,
        ),
        ("unpinned", || RootState::Unpinned, true),
    ];
    for (name, state, untrusted) in states {
        let skipped = untrusted && cfg!(target_os = "macos");
        let root = StatedRoot::with_state(ROOT_PID, state);
        let killed = super::kill_tree(&crate::identity::HostKernel, self::root(), Some(&root)).outcome();
        assert_eq!(
            matches!(killed, TreeKillOutcome::Skipped(_)),
            skipped,
            "kill, {name}: {killed:?}"
        );
        if !skipped {
            assert!(
                matches!(killed, TreeKillOutcome::NoRoot(..)),
                "kill, {name}: {killed:?}"
            );
        }
        let (termed, _) = super::terminate_tree(
            &crate::identity::HostKernel,
            self::root(),
            Some(&root),
            crate::containment::TreeStop::default(),
        );
        assert_eq!(
            matches!(termed, TerminateOutcome::End(_)),
            skipped,
            "terminate, {name}: {termed:?}"
        );
    }
}

/// A kill whose walk was skipped (macOS: the root's number cannot be trusted) is waited for through the
/// kernel the call was given.
///
/// Mutant: the `Skipped` answer waits through the host's kernel, which finds the member gone.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_skipped_kills_wait_reads_through_the_kernel_the_call_was_given() {
    use crate::containment::dispatch::TreeKillOutcome;
    use crate::identity::{FakeKernel, HostKernel, UniqRead};
    use crate::signal::RootState;
    use crate::test_support::stated_root::StatedRoot;

    // A pid above macOS's `PID_MAX`: the host has no such process, so only the row can refuse its open.
    let member = id(999_999, ROOT_TOKEN);
    let kernel = FakeKernel::over(&HostKernel).on_unique_info(member.pid(), UniqRead::Refused(libc::EPERM));
    let owner = StatedRoot::with_state(ROOT_PID, || RootState::Unpinned);

    let (outcome, mut wait) = super::kill_tree(&kernel, root(), Some(&owner)).split();
    assert!(matches!(outcome, TreeKillOutcome::Skipped(_)), "{outcome:?}");
    wait.reaching([member]);
    let err = wait
        .wait()
        .expect_err("the member's open was refused by the stated row");

    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
    assert!(kernel.all_rows_taken(), "the wait read the row");
}

/// The held member's `source` is the first report's own `Arc`.
///
/// Mutant: the held member copies the cause or drops the note.
#[skuld::test]
fn a_member_never_read_is_held_with_its_own_cause() {
    use super::{not_killed, Left};
    use crate::containment::dispatch::Unkilled;
    let code = if cfg!(windows) { 5 } else { 13 };
    let Error::MemberNotKilled { pid, source, .. } = not_killed(
        7,
        Error::Unassessable {
            detail: "pid 7 identity could not be confirmed".into(),
            source: Some(std::sync::Arc::new(Error::Containment {
                detail: "the middle layer".into(),
                source: Some(Error::io_cause(std::io::Error::from_raw_os_error(code))),
            })),
        },
    ) else {
        unreachable!("`not_killed` builds a `MemberNotKilled`");
    };
    let member = Error::MemberNotKilled {
        pid,
        source: std::sync::Arc::clone(&source),
    };
    let first = Unkilled {
        members: vec![member],
        root: None,
        resolved: Vec::new(),
    };

    let held = Left::of(&first);

    let [Left::Unread { pid: 7, source: held }] = held.as_slice() else {
        panic!("never read: {held:?}");
    };
    assert!(
        std::sync::Arc::ptr_eq(held, &source),
        "the held source is the member's own"
    );
    assert_eq!(crate::error::first_os_code(&**held), Some(code), "{held:?}");
}

/// A member the walk never read, held over two later `kill_left` rounds, is reported each time as the
/// first round reported it: the `Report` does not grow a layer per round, and a bare OS error stays an
/// `Error::Io` with its code on the `io::Error`, where a caller matches it.
///
/// Each round's member is the first round's own: its `source` is the same `Arc`.
///
/// Mutants: a round wraps the held cause in another layer; the held cause is rebuilt as another
/// variant, so the code is no longer on the `Error::Io`; a round rebuilds the source from parts, so
/// it is not the first round's.
#[skuld::test]
fn a_member_never_read_is_reported_the_same_over_every_round() {
    use super::{not_killed, with_earlier, Left};
    use crate::containment::dispatch::Unkilled;
    let code = if cfg!(windows) { 5 } else { 13 };
    let bare = || std::io::Error::from_raw_os_error(code);
    let layered = || Error::Containment {
        detail: "the middle layer".into(),
        source: Some(Error::io_cause(crate::error::io_context("w", bare()))),
    };
    for (what, below) in [
        ("a bare OS error", Error::Io(bare())),
        ("layers over an OS error", layered()),
    ] {
        let Error::MemberNotKilled { pid, source, .. } = not_killed(
            7,
            Error::Unassessable {
                detail: "pid 7 identity could not be confirmed".into(),
                source: Some(std::sync::Arc::new(below)),
            },
        ) else {
            unreachable!("`not_killed` builds a `MemberNotKilled`");
        };
        let mut round = Unkilled {
            members: vec![Error::MemberNotKilled {
                pid,
                source: std::sync::Arc::clone(&source),
            }],
            root: None,
            resolved: Vec::new(),
        };
        let first = crate::error::said(&round.members[0]);
        for n in 2..=3 {
            let held = Left::of(&round);
            round = with_earlier(&crate::identity::HostKernel, held, Ok(()))
                .0
                .expect_err("never read, so never shown killed");
            assert_eq!(crate::error::said(&round.members[0]), first, "{what}, round {n}");
            let Error::MemberNotKilled { source: again, .. } = &round.members[0] else {
                panic!("{round:?}");
            };
            assert!(
                std::sync::Arc::ptr_eq(again, &source),
                "{what}, round {n}: the first round's source"
            );
        }
        assert_eq!(crate::error::first_os_code(&round.members[0]), Some(code), "{what}");
        let Error::MemberNotKilled { source, .. } = &round.members[0] else {
            panic!("{round:?}");
        };
        let Error::Unassessable {
            source: Some(cause), ..
        } = &**source
        else {
            panic!("{source:?}");
        };
        if what == "a bare OS error" {
            assert!(
                matches!(&**cause, Error::Io(e) if e.raw_os_error() == Some(code)),
                "{cause:?}"
            );
        }
    }
}

/// A member the walk never read, reported as `Unsupported`, is reported again as `Unsupported`, with
/// its `op` and `platform`: not as `Unassessable`.
///
/// Mutant: the held member is re-reported as `Unassessable` whatever its first error was.
#[skuld::test]
fn a_member_never_read_is_reported_again_as_the_variant_it_was() {
    use super::{not_killed, with_earlier, Left};
    use crate::containment::dispatch::Unkilled;
    let first = Unkilled {
        members: vec![not_killed(
            7,
            Error::Unsupported {
                op: "process open".into(),
                platform: "linux",
                detail: "pidfd_open was refused".into(),
                source: None,
            },
        )],
        root: None,
        resolved: Vec::new(),
    };
    let held = Left::of(&first);

    let again = with_earlier(&crate::identity::HostKernel, held, Ok(()))
        .0
        .expect_err("never read, so never shown killed");

    let Error::MemberNotKilled { pid, source, .. } = &again.members[0] else {
        panic!("{again:?}");
    };
    assert_eq!(*pid, 7);
    assert!(
        matches!(&**source, Error::Unsupported { op, platform: "linux", detail, .. }
            if op == "process open" && detail == "pidfd_open was refused"),
        "{source:?}"
    );
}

/// Reads that find nothing: no row can be shown to be an anchor but the parent's own.
fn no_reads() -> AnchorReads<'static> {
    AnchorReads {
        key_of: &|_| None,
        creator_of: &|_| None,
    }
}
