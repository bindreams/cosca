//! Pure tests for the identity-aware descendant filter. They run on every host
//! (no live processes): synthetic `(pid, ppid)` edges plus a stub token-resolver
//! closure drive `descendants_with` against BOTH `allow_equal` rules.

use super::{descendants_with, Resolution, Walk};
use crate::error::Error;
use crate::identity::{Key, OrderKey, ProcessId, RawPid, UnknownCause};
use std::collections::HashMap;

const ROOT_PID: RawPid = 100;
const ROOT_TOKEN: u64 = 1_000;

fn id(pid: RawPid, token: u64) -> ProcessId {
    ProcessId::from_parts_for_test(pid, Key::for_test(token))
}

/// What the live resolver returns for a process whose identity token and order key agree.
fn resolved(pid: RawPid, token: u64) -> (ProcessId, OrderKey) {
    (id(pid, token), OrderKey::for_test(token))
}

/// Build a resolver from a (pid -> token) table. A pid absent from the table is
/// unresolvable (`Ok(None)`, modelling an already-gone process).
fn resolver(tokens: &HashMap<RawPid, u64>) -> impl Fn(RawPid, ProcessId) -> Resolution + '_ {
    move |pid, _parent| Ok(tokens.get(&pid).map(|&t| resolved(pid, t)))
}

/// What the live resolver returns for a pid whose read was `Unknown`.
fn unreadable(pid: RawPid) -> Error {
    super::unqueryable_read(pid, UnknownCause::default())
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

fn root_key() -> OrderKey {
    OrderKey::for_test(ROOT_TOKEN)
}

// A genuine later child (token > root) is kept under BOTH rules =====

#[skuld::test]
fn keeps_genuine_later_child_under_both_rules() {
    let parents = [(200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN + 5)]);
    for allow_equal in [true, false] {
        let got = descendants_with(root(), root_key(), &parents, allow_equal, false, resolver(&tokens));
        assert_eq!(pids(got), [200], "later child kept (allow_equal={allow_equal})");
    }
}

// Same-tick child (token == root) depends on the rule =====

#[skuld::test]
fn same_tick_child_included_when_allow_equal_true() {
    let parents = [(200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN)]); // equal token
    let got = descendants_with(root(), root_key(), &parents, true, false, resolver(&tokens));
    assert_eq!(pids(got), [200], "same-tick child included with allow_equal=true");
}

#[skuld::test]
fn same_tick_child_excluded_when_allow_equal_false() {
    let parents = [(200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN)]); // equal token
    let got = descendants_with(root(), root_key(), &parents, false, false, resolver(&tokens));
    assert!(
        got.members.is_empty(),
        "same-tick child excluded with allow_equal=false"
    );
}

// Stale-PPID impostor (token < root) is EXCLUDED under BOTH rules =====
// This is the mutation-check case: dropping the order-key guard would WRONGLY
// include pid 200 here (its ppid chains to the root), so this assertion fails if
// the guard is removed.

#[skuld::test]
fn stale_ppid_impostor_excluded_under_both_rules() {
    // pid 200's ppid points at the root pid, but 200 was created BEFORE the root
    // acquired that pid (token < root.token): a recycled-pid impostor.
    let parents = [(200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN - 1)]);
    for allow_equal in [true, false] {
        let got = descendants_with(root(), root_key(), &parents, allow_equal, false, resolver(&tokens));
        assert!(got.members.is_empty(), "impostor excluded (allow_equal={allow_equal})");
    }
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
    let got = descendants_with(root(), root_key(), &parents, true, false, resolver(&tokens));
    assert_eq!(pids(got), [200, 300, 400]);
}

#[skuld::test]
fn impostor_prunes_its_whole_subtree() {
    // 200 is a stale-ppid impostor; its real-looking child 300 must NOT be
    // collected, because 200 was rejected (the subtree under an impostor is
    // unreachable through a genuine chain).
    let parents = [(200, ROOT_PID), (300, 200)];
    let tokens = HashMap::from([
        (200u32, ROOT_TOKEN - 5), // impostor
        (300u32, ROOT_TOKEN + 5), // would-be grandchild
    ]);
    let got = descendants_with(root(), root_key(), &parents, true, false, resolver(&tokens));
    assert!(got.members.is_empty(), "subtree under a rejected impostor is pruned");
}

// The parent-order rule: a candidate must also order after its accepted parent =====

/// The Windows stale-creator edge: 300's ppid names pid 200, but 300 was created after the root and
/// before the process that holds 200 now (200's number changed hands, so the edge is stale). With
/// the rule on, 300 and everything under it are dropped. Mutants (compare against the root's key;
/// rule ignored) keep 300 with the rule on.
#[skuld::test]
fn a_candidate_that_orders_before_its_accepted_parent_is_dropped_with_its_subtree_when_the_rule_is_on() {
    let parents = [(200, ROOT_PID), (300, 200), (400, 300)];
    let tokens = HashMap::from([
        (200u32, ROOT_TOKEN + 10),
        (300u32, ROOT_TOKEN + 5), // after the root, before its accepted parent
        (400u32, ROOT_TOKEN + 20),
    ]);
    for allow_equal in [true, false] {
        let got = descendants_with(root(), root_key(), &parents, allow_equal, true, resolver(&tokens));
        assert_eq!(pids(got), [200], "rule on, allow_equal={allow_equal}");
        let got = descendants_with(root(), root_key(), &parents, allow_equal, false, resolver(&tokens));
        assert_eq!(pids(got), [200, 300, 400], "rule off, allow_equal={allow_equal}");
    }
}

/// Windows runs the walk with its own consts, `ALLOW_EQUAL_ORDER` and `ORDER_AFTER_PARENT`, and
/// the table above is the reused-creator edge: the creator read passes it (the candidate's creator
/// pid is its accepted parent's pid), so only the order rule drops it. Nothing real reaches this
/// edge, as a creator always has the lower sequence number, so the stub states it.
///
/// Mutant (CI runs this row; no other row pins the consts on Windows): `ORDER_AFTER_PARENT` is
/// `false` on Windows, or `walk_from` passes the flags swapped.
#[cfg(windows)]
#[skuld::test]
fn on_windows_a_reused_creator_edge_is_dropped_under_the_production_consts() {
    use super::{ALLOW_EQUAL_ORDER, ORDER_AFTER_PARENT};
    let parents = [(200, ROOT_PID), (300, 200), (400, 300)];
    let tokens = HashMap::from([
        (200u32, ROOT_TOKEN + 10),
        (300u32, ROOT_TOKEN + 5), // after the root, before its accepted parent
        (400u32, ROOT_TOKEN + 20),
    ]);
    let got = descendants_with(
        root(),
        root_key(),
        &parents,
        ALLOW_EQUAL_ORDER,
        ORDER_AFTER_PARENT,
        resolver(&tokens),
    );
    assert_eq!(pids(got), [200]);
}

/// A real chain, each key after its parent's, is kept under every setting.
#[skuld::test]
fn a_chain_whose_keys_each_follow_their_parents_is_kept_under_both_settings() {
    let parents = [(200, ROOT_PID), (300, 200), (400, 300)];
    let tokens = HashMap::from([
        (200u32, ROOT_TOKEN + 1),
        (300u32, ROOT_TOKEN + 2),
        (400u32, ROOT_TOKEN + 3),
    ]);
    for allow_equal in [true, false] {
        for parent_order in [true, false] {
            let got = descendants_with(
                root(),
                root_key(),
                &parents,
                allow_equal,
                parent_order,
                resolver(&tokens),
            );
            assert_eq!(
                pids(got),
                [200, 300, 400],
                "allow_equal={allow_equal}, parent_order={parent_order}"
            );
        }
    }
}

/// The parent comparison takes the OS's `allow_equal`, as the root comparison does: a child whose
/// key equals its accepted parent's is kept only when equality is allowed.
#[skuld::test]
fn a_candidate_whose_key_equals_its_accepted_parents_follows_allow_equal_when_the_rule_is_on() {
    let parents = [(200, ROOT_PID), (300, 200)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN + 10), (300u32, ROOT_TOKEN + 10)]);
    let got = descendants_with(root(), root_key(), &parents, true, true, resolver(&tokens));
    assert_eq!(pids(got), [200, 300], "equal to its parent, allow_equal=true");
    let got = descendants_with(root(), root_key(), &parents, false, true, resolver(&tokens));
    assert_eq!(pids(got), [200], "equal to its parent, allow_equal=false");
}

// A reparented orphan (ppid no longer == root) is honestly missed =====

#[skuld::test]
fn reparented_orphan_is_missed() {
    // 300 was a grandchild, but its parent 200 exited and 300 was reparented to
    // pid 1; its ppid no longer chains to the root, so the walk cannot reach it.
    let parents = [(300, 1)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 9)]);
    let got = descendants_with(root(), root_key(), &parents, true, false, resolver(&tokens));
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
    let got = descendants_with(root(), root_key(), &parents, true, false, resolver(&tokens));
    assert_eq!(pids(got), [200], "root excluded; genuine child kept");
}

// A duplicate edge enumerates the pid only once =====

#[skuld::test]
fn duplicate_edge_yields_pid_once() {
    // A snapshot that lists the same (pid, ppid) edge twice must not enumerate
    // (or later double-kill) the same process twice.
    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN + 1)]);
    let got = descendants_with(root(), root_key(), &parents, true, false, resolver(&tokens));
    assert_eq!(pids(got), [200], "duplicate edge collapses to a single result");
}

// An unresolvable candidate (already gone) is skipped =====

#[skuld::test]
fn unresolvable_candidate_is_skipped() {
    // 200 chains to the root but is absent from the resolver (it exited between
    // snapshot and resolve); it is dropped along with anything under it.
    let parents = [(200, ROOT_PID), (300, 200)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5)]); // 200 missing
    let got = descendants_with(root(), root_key(), &parents, true, false, resolver(&tokens));
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
    let got = descendants_with(root(), root_key(), &parents, true, false, |pid, parent| {
        if pid == 200 {
            Err(unreadable(200))
        } else {
            read(pid, parent)
        }
    });
    assert_eq!(unassessed(&got), [200]);
    assert!(matches!(&got.unassessed[0].1, Error::Unassessable { detail, .. } if detail.contains("pid 200")));
    assert_eq!(pids(got), [400]);
}

/// A snapshot that lists the unreadable pid twice reads it once and counts it once.
#[skuld::test]
fn a_duplicate_edge_to_an_unreadable_candidate_is_one_unassessed_entry() {
    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let got = descendants_with(root(), root_key(), &parents, true, false, |pid, _| Err(unreadable(pid)));
    assert_eq!(unassessed(&got), [200]);
    assert!(got.members.is_empty());
}

#[skuld::test]
fn an_unreadable_direct_child_is_unassessed_in_the_one_level_filter_too() {
    use super::children_of_with;
    let parents = [(200, ROOT_PID), (200, ROOT_PID), (300, ROOT_PID), (400, 200)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5)]);
    let read = resolver(&tokens);
    let got = children_of_with(root(), root_key(), &parents, true, |pid, parent| {
        if pid == 200 {
            Err(unreadable(200))
        } else {
            read(pid, parent)
        }
    });
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
    let first_reads_second_does_not = |pid: RawPid, _parent: ProcessId| {
        reads.set(reads.get() + 1);
        if reads.get() == 1 {
            Ok(Some(resolved(pid, ROOT_TOKEN + 5)))
        } else {
            Err(unreadable(pid))
        }
    };
    let got = children_of_with(root(), root_key(), &parents, true, first_reads_second_does_not);
    assert_eq!((pids(got), reads.get()), (vec![200], 1), "one level");

    reads.set(0);
    let got = descendants_with(root(), root_key(), &parents, true, false, first_reads_second_does_not);
    assert!(got.unassessed.is_empty(), "{:?}", got.unassessed);
    assert_eq!((pids(got), reads.get()), (vec![200], 1), "whole subtree");
}

// One-level child filter keeps only genuine direct children =====

#[skuld::test]
fn children_of_keeps_one_level_genuine_children_only() {
    use super::{children_of_with, ALLOW_EQUAL_ORDER};
    // root 100/tok50; direct child 101/tok60 (genuine, tok>root); grandchild 102 (ppid
    // 101, not one level); impostor 103 ppid 100 tok40 (created before root => excluded).
    let root = id(100, 50);
    let parents = [(101, 100), (102, 101), (103, 100)];
    let resolve = |pid: u32, _parent: ProcessId| -> Resolution {
        Ok(match pid {
            101 => Some(resolved(101, 60)),
            102 => Some(resolved(102, 70)),
            103 => Some(resolved(103, 40)),
            _ => None,
        })
    };
    let got = children_of_with(root, OrderKey::for_test(50), &parents, ALLOW_EQUAL_ORDER, resolve);
    assert_eq!(pids(got), [101]);
}

// children_of_with wires allow_equal into the same-tick boundary =====

#[skuld::test]
fn children_of_same_tick_child_depends_on_allow_equal() {
    use super::children_of_with;
    // Direct child 101 whose token EQUALS the parent's: kept under allow_equal=true,
    // excluded under false — proves children_of_with threads allow_equal to keeps_order.
    let root = id(100, ROOT_TOKEN);
    let parents = [(101, 100)];
    let resolve = |pid: u32, _parent: ProcessId| -> Resolution { Ok((pid == 101).then(|| resolved(101, ROOT_TOKEN))) };
    assert_eq!(
        pids(children_of_with(root, root_key(), &parents, true, resolve)),
        [101],
        "same-tick child included with allow_equal=true"
    );
    assert!(
        children_of_with(root, root_key(), &parents, false, resolve)
            .members
            .is_empty(),
        "same-tick child excluded with allow_equal=false"
    );
}

// A duplicate edge enumerates a direct child only once =====

#[skuld::test]
fn children_of_duplicate_edge_yields_pid_once() {
    use super::children_of_with;
    // A snapshot listing the same (pid, ppid) edge twice must not enumerate (or later
    // double-kill) the same child twice.
    let root = id(100, ROOT_TOKEN);
    let parents = [(101, 100), (101, 100)];
    let resolve =
        |pid: u32, _parent: ProcessId| -> Resolution { Ok((pid == 101).then(|| resolved(101, ROOT_TOKEN + 1))) };
    assert_eq!(
        pids(children_of_with(root, root_key(), &parents, true, resolve)),
        [101],
        "duplicate edge collapses to a single child"
    );
}

// The guard orders by the order key, not by the identity token =====

/// A candidate whose id's token orders after the root's but whose order key orders before it is an
/// impostor: the filters read the key. Mutant: "the filters compare `id.key()`".
#[skuld::test]
fn a_candidate_whose_order_key_precedes_the_roots_is_dropped_even_when_its_id_token_does_not() {
    use super::children_of_with;
    let parents = [(200, ROOT_PID)];
    let resolve = |pid: u32, _parent: ProcessId| -> Resolution {
        Ok((pid == 200).then(|| (id(200, ROOT_TOKEN + 5), OrderKey::for_test(ROOT_TOKEN - 5))))
    };
    for allow_equal in [true, false] {
        assert!(
            descendants_with(root(), root_key(), &parents, allow_equal, false, resolve)
                .members
                .is_empty(),
            "descendants_with dropped by key (allow_equal={allow_equal})"
        );
        assert!(
            children_of_with(root(), root_key(), &parents, allow_equal, resolve)
                .members
                .is_empty(),
            "children_of_with dropped by key (allow_equal={allow_equal})"
        );
    }
}

/// The resolver is told the accepted process the snapshot made each candidate's parent, so a backend
/// can drop a candidate whose parent's number has another holder now. The parent of a grandchild is
/// the id the walk accepted for the child. Mutant: "the resolver is asked the root for every
/// candidate".
#[skuld::test]
fn the_resolver_is_asked_for_each_candidates_accepted_parent() {
    use std::cell::RefCell;

    use super::children_of_with;

    let asked = RefCell::new(Vec::new());
    let resolve = |pid: u32, parent: ProcessId| -> Resolution {
        asked.borrow_mut().push((pid, parent));
        Ok(Some(resolved(pid, ROOT_TOKEN + 1)))
    };
    let parents = [(200, ROOT_PID), (300, 200)];
    descendants_with(root(), root_key(), &parents, true, false, resolve);
    assert_eq!(asked.take(), [(200, root()), (300, id(200, ROOT_TOKEN + 1))]);

    children_of_with(root(), root_key(), &parents, true, resolve);
    assert_eq!(asked.take(), [(200, root())]);
}

/// The anchor side of the same rule: candidates are compared against the `root_key` argument, not
/// against the root id's token. Here the root's token is `ROOT_TOKEN` but its key is lower
/// (a candidate between them is kept) or higher (a candidate between them is dropped).
/// Mutant: "the filters compare against `root.key()`".
#[skuld::test]
fn candidates_are_compared_against_the_roots_order_key_not_its_id_token() {
    use super::children_of_with;
    let parents = [(200, ROOT_PID)];
    for (root_key, candidate_key, kept) in [
        (ROOT_TOKEN - 500, ROOT_TOKEN - 300, true),
        (ROOT_TOKEN + 500, ROOT_TOKEN + 300, false),
    ] {
        let resolve = |pid: u32, _parent: ProcessId| -> Resolution {
            Ok((pid == 200).then(|| (id(200, candidate_key), OrderKey::for_test(candidate_key))))
        };
        for allow_equal in [true, false] {
            let want: &[RawPid] = if kept { &[200] } else { &[] };
            let got = descendants_with(
                root(),
                OrderKey::for_test(root_key),
                &parents,
                allow_equal,
                false,
                resolve,
            );
            assert_eq!(
                pids(got),
                want,
                "descendants_with: root_key {root_key}, candidate {candidate_key} (allow_equal={allow_equal})"
            );
            let got = children_of_with(root(), OrderKey::for_test(root_key), &parents, allow_equal, resolve);
            assert_eq!(
                pids(got),
                want,
                "children_of_with: root_key {root_key}, candidate {candidate_key} (allow_equal={allow_equal})"
            );
        }
    }
}

/// `resolve_or_drop` is a named discard site: an access-denied descendant must be dropped
/// from the walk AND leave a warn behind, never be silently folded in with a gone pid.
#[cfg(windows)]
#[skuld::test]
fn resolve_or_drop_drops_an_access_denied_pid_and_warns() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(resolve_or_drop_drops_an_access_denied_pid_and_warns),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    crate::log_capture::install();
    let denied = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
    assert!(denied.is_running(), "precondition: the subject must be live");
    let mark = crate::log_capture::mark();
    assert!(
        super::resolve_or_drop(&crate::identity::HostKernel, denied.pid(), ProcessId::current()).is_err(),
        "the walk cannot keep what it cannot verify, and an unread pid is not a gone one"
    );
    assert!(crate::log_capture::contains_since(
        mark,
        &format!("treewalk: pid {} exists but could not be queried", denied.pid())
    ));
    assert!(denied.is_running(), "and dropping it must not have touched it");
}

/// The text of `resolve_or_drop`'s warn for a candidate whose creator-pid query was refused: the
/// cause reaches `unqueryable_read`, which words it, so the warn names the pid and the `NTSTATUS`
/// and does not fall back to "access denied?".
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
    let crate::error::Error::Unassessable { detail, .. } = super::unqueryable_read(7, cause) else {
        panic!("a refused creator query is Unassessable");
    };
    assert_eq!(
        detail,
        "pid 7 exists but its creator process id query failed: NTSTATUS 0xc0000004"
    );
}

/// The Windows wiring of the walk to the creator read, through `walk_from` with real
/// processes: `x` and `y` are both children of the root (this process). A snapshot that names `x` as
/// `y`'s parent is a stale creator edge: `y`'s own creator is the root, so it is dropped under `x`
/// and kept under the root. `x` is spawned first, so `y`'s key follows `x`'s and the parent-order
/// rule passes the edge: only the creator read drops `y`. (A real edge that breaks the rule names a
/// creator that is not the process's, which the creator read catches first, so the stub rows pin
/// that rule.)
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
    let stale_creator = [(root.pid(), 0), (x.pid(), root.pid()), (y.pid(), x.pid())];
    let dropped = super::walk_from(&HostKernel, root, &stale_creator, Recursive::Yes)
        .expect("the root reads")
        .expect("the root is live");
    let genuine = [(root.pid(), 0), (x.pid(), root.pid()), (y.pid(), root.pid())];
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

/// A root that exits while its handle is held is walked, and its running child is killed. Windows
/// does not reparent: the child's creator pid is still the root's. Toolhelp does not list an exited
/// process whose handle is held (measured on Windows 11 26100.9711), so the snapshot has no row for
/// the root while the walk's edges, which name it as the child's parent, are intact: a missing root
/// row says nothing about them. The root's order key and creator are read from its own handle, which
/// is held.
///
/// The root is a `cmd.exe` that holds its `ping` child, and the child ends by itself after 30
/// seconds: a kill that did not happen fails the assertion on its exit code, and a failed row leaves
/// the child running for that long at most.
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
    let mut shell = crate::test_spawn::spawn(
        std::process::Command::new("cmd.exe")
            .args(["/c", "ping.exe", "-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null()),
    )
    .expect("spawn the root");
    let root = ProcessId::of(shell.id()).found().expect("the live root resolves");
    // The root's children are its console host and its `ping`: wait for the `ping`.
    let ping = loop {
        assert!(
            shell.try_wait().expect("poll the root").is_none(),
            "the root exited before its child was listed"
        );
        let children = root.children(Recursive::No).expect("the root's children");
        let is_ping = |id: &ProcessId| {
            crate::identity::windows_fixture::image_file_name(id.pid()).is_some_and(|image| {
                std::path::Path::new(&image)
                    .file_name()
                    .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe"))
            })
        };
        if let Some(ping) = children.into_iter().find(is_ping) {
            break ping.pid();
        }
        std::thread::yield_now();
    };
    let Opened::Found(ping_handle) =
        windows_open_classified(ping, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)
    else {
        panic!("the child is ours and openable");
    };
    shell.kill().expect("terminate the root");
    shell.wait().expect("the root's exit is recorded");

    let parents = crate::containment::enumerate::process_parents(&HostKernel).expect("the process snapshot");
    assert!(
        !parents.iter().any(|&(pid, _)| pid == root.pid()),
        "precondition: Toolhelp must not list the exited root whose handle is held"
    );
    assert!(
        parents.iter().any(|&(pid, ppid)| pid == ping && ppid == root.pid()),
        "precondition: the running child must still name the exited root as its creator"
    );

    let children = root.children(Recursive::No).expect("the exited root's children");
    assert!(
        children.iter().any(|id| id.pid() == ping),
        "{ping} not among {children:?}"
    );
    assert!(
        super::hard_kill(&HostKernel, root).expect("an exited root whose handle is held is walked"),
        "the walk is complete"
    );

    // SAFETY: `ping_handle` is our live handle with the synchronize right. The wait ends with the
    // kill just asked for, or with the child's own exit.
    let waited = unsafe { WaitForSingleObject(ping_handle, INFINITE) };
    assert_eq!(waited, WAIT_OBJECT_0, "the wait on the child returned {waited:?}");
    let mut code = 0u32;
    // SAFETY: `ping_handle` is live with the query right; `code` is a u32.
    unsafe { GetExitCodeProcess(ping_handle, &mut code) }.expect("the child's exit code");
    windows_close(ping_handle);
    assert_eq!(
        code,
        crate::identity::WINDOWS_TERMINATE_EXIT_CODE,
        "the walk must have terminated the child"
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
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    assert_eq!(super::kill_by_identity(id), super::KillOutcome::NotAttempted);
    assert!(child.is_running(), "a denied open must leave the process running");
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
    // The ACE must grant QUERY_LIMITED as well as TERMINATE: kill_by_identity opens for
    // both, and a combined-mask OpenProcess fails entirely if ANY requested bit is ungranted.
    let (child, stdin) =
        crate::identity::windows_fixture::spawn_restricted_releasable(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let real = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let stale = real.with_other_value();

    assert_eq!(
        super::kill_by_identity(stale),
        super::KillOutcome::AlreadyGone,
        "a stale identity names a process that is gone - nothing to terminate"
    );
    assert!(
        child.is_running(),
        "a stale identity must never terminate the pid-s occupant"
    );

    assert_eq!(
        super::kill_by_identity(real),
        super::KillOutcome::Terminated,
        "a matching identity must reach TerminateProcess"
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
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let exiter = std::rc::Rc::clone(&child);
    super::fault::set_before_terminate(move || exiter.terminate());

    assert_eq!(
        super::kill_by_identity(id),
        super::KillOutcome::AlreadyGone,
        "a member that exited before the terminate has nothing left to kill"
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
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "more"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn cmd /C more");
    let id = crate::identity::windows_identity_from_handle(
        windows::Win32::Foundation::HANDLE(child.as_raw_handle()),
        child.id(),
    )
    .expect("the owned handle always yields an identity");
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let outcome = super::kill_by_identity(id);
    // The seam sent no terminate: end the fixture before asserting.
    child.kill().expect("end the fixture");
    child.wait().expect("reap the fixture");

    assert_eq!(outcome, super::KillOutcome::AlreadyGone);
}
