//! Pure tests for the identity-aware descendant filter. They run on every host
//! (no live processes): synthetic `(pid, ppid)` edges plus a stub token-resolver
//! closure drive `descendants_with` against BOTH `allow_equal` rules.

use super::descendants_with;
use crate::identity::{ProcessId, RawPid};
use std::collections::HashMap;

const ROOT_PID: RawPid = 100;
const ROOT_TOKEN: u64 = 1_000;

fn id(pid: RawPid, token: u64) -> ProcessId {
    ProcessId::from_parts_for_test(pid, token)
}

/// Build a resolver from a (pid -> token) table. A pid absent from the table is
/// unresolvable (returns `None`, modelling an already-gone process).
fn resolver(tokens: &HashMap<RawPid, u64>) -> impl Fn(RawPid) -> Option<ProcessId> + '_ {
    move |pid| tokens.get(&pid).map(|&t| id(pid, t))
}

/// Collect the result pids into a sorted Vec for order-independent comparison.
fn pids(mut v: Vec<ProcessId>) -> Vec<RawPid> {
    v.sort_by_key(|i| i.pid());
    v.into_iter().map(|i| i.pid()).collect()
}

fn root() -> ProcessId {
    id(ROOT_PID, ROOT_TOKEN)
}

// A genuine later child (token > root) is kept under BOTH rules =====

#[test]
fn keeps_genuine_later_child_under_both_rules() {
    let parents = [(200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN + 5)]);
    for allow_equal in [true, false] {
        let got = descendants_with(root(), &parents, allow_equal, resolver(&tokens));
        assert_eq!(pids(got), [200], "later child kept (allow_equal={allow_equal})");
    }
}

// Same-tick child (token == root) depends on the rule =====

#[test]
fn same_tick_child_included_when_allow_equal_true() {
    let parents = [(200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN)]); // equal token
    let got = descendants_with(root(), &parents, true, resolver(&tokens));
    assert_eq!(pids(got), [200], "same-tick child included with allow_equal=true");
}

#[test]
fn same_tick_child_excluded_when_allow_equal_false() {
    let parents = [(200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN)]); // equal token
    let got = descendants_with(root(), &parents, false, resolver(&tokens));
    assert!(got.is_empty(), "same-tick child excluded with allow_equal=false");
}

// Stale-PPID impostor (token < root) is EXCLUDED under BOTH rules =====
// This is the mutation-check case: dropping the token guard would WRONGLY
// include pid 200 here (its ppid chains to the root), so this assertion fails if
// the guard is removed.

#[test]
fn stale_ppid_impostor_excluded_under_both_rules() {
    // pid 200's ppid points at the root pid, but 200 was created BEFORE the root
    // acquired that pid (token < root.token): a recycled-pid impostor.
    let parents = [(200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN - 1)]);
    for allow_equal in [true, false] {
        let got = descendants_with(root(), &parents, allow_equal, resolver(&tokens));
        assert!(got.is_empty(), "impostor excluded (allow_equal={allow_equal})");
    }
}

// Deep trees recurse =====

#[test]
fn recurses_into_deep_tree() {
    // root(100) -> 200 -> 300 -> 400, all created after the root.
    let parents = [(200, ROOT_PID), (300, 200), (400, 300)];
    let tokens = HashMap::from([
        (200u32, ROOT_TOKEN + 1),
        (300u32, ROOT_TOKEN + 2),
        (400u32, ROOT_TOKEN + 3),
    ]);
    let got = descendants_with(root(), &parents, true, resolver(&tokens));
    assert_eq!(pids(got), [200, 300, 400]);
}

#[test]
fn impostor_prunes_its_whole_subtree() {
    // 200 is a stale-ppid impostor; its real-looking child 300 must NOT be
    // collected, because 200 was rejected (the subtree under an impostor is
    // unreachable through a genuine chain).
    let parents = [(200, ROOT_PID), (300, 200)];
    let tokens = HashMap::from([
        (200u32, ROOT_TOKEN - 5), // impostor
        (300u32, ROOT_TOKEN + 5), // would-be grandchild
    ]);
    let got = descendants_with(root(), &parents, true, resolver(&tokens));
    assert!(got.is_empty(), "subtree under a rejected impostor is pruned");
}

// A reparented orphan (ppid no longer == root) is honestly missed =====

#[test]
fn reparented_orphan_is_missed() {
    // 300 was a grandchild, but its parent 200 exited and 300 was reparented to
    // pid 1; its ppid no longer chains to the root, so the walk cannot reach it.
    let parents = [(300, 1)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 9)]);
    let got = descendants_with(root(), &parents, true, resolver(&tokens));
    assert!(got.is_empty(), "reparented orphan is honestly missed (documented)");
}

// The root itself is never included =====

#[test]
fn root_is_never_included() {
    // An edge naming the root as its own child would be degenerate; ensure the
    // root pid never appears in the descendant set even if such an edge exists.
    let parents = [(ROOT_PID, ROOT_PID), (200, ROOT_PID)];
    let tokens = HashMap::from([(ROOT_PID, ROOT_TOKEN), (200u32, ROOT_TOKEN + 1)]);
    let got = descendants_with(root(), &parents, true, resolver(&tokens));
    assert_eq!(pids(got), [200], "root excluded; genuine child kept");
}

// A duplicate edge enumerates the pid only once =====

#[test]
fn duplicate_edge_yields_pid_once() {
    // A snapshot that lists the same (pid, ppid) edge twice must not enumerate
    // (or later double-kill) the same process twice.
    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN + 1)]);
    let got = descendants_with(root(), &parents, true, resolver(&tokens));
    assert_eq!(pids(got), [200], "duplicate edge collapses to a single result");
}

// An unresolvable candidate (already gone) is skipped =====

#[test]
fn unresolvable_candidate_is_skipped() {
    // 200 chains to the root but is absent from the resolver (it exited between
    // snapshot and resolve); it is dropped along with anything under it.
    let parents = [(200, ROOT_PID), (300, 200)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5)]); // 200 missing
    let got = descendants_with(root(), &parents, true, resolver(&tokens));
    assert!(got.is_empty(), "gone candidate and its subtree are skipped");
}
