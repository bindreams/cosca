//! The ppid join: `join_edges`, `process_parents`, and `ppid_of`'s failure branches.

use crate::identity::Resolved;

use super::super::{join_edges, ppid_of, process_parents, push_denied_sample, DENIED_SAMPLE_CAP};

/// The `pid <= 0` filter, pinned deterministically with a synthetic pid list rather than a
/// live one: depending on a live run to happen to contain pid 0 (a kernel-internal fact
/// this filter's correctness should not hinge on to be exercised) would let the test pass
/// vacuously on a host/kernel where it's absent. `getpid()` is a real, live pid guaranteed
/// to resolve (`proc_pidinfo` on SELF is always permitted), so it proves the non-positive
/// entries are what's filtered, not that every entry is.
#[test]
fn join_edges_filters_non_positive_pids() {
    let me = std::process::id() as libc::c_int;
    // Read before and after, same reasoning as `parents_contains_this_process_edge`:
    // nothing holds this process's real parent fixed across the call.
    let parent_before = std::os::unix::process::parent_id();
    let (out, denied, sample) = join_edges(&[0, -1, me]).expect("edge buffer");
    let parent_after = std::os::unix::process::parent_id();
    assert_eq!(denied, 0, "0 and -1 must not be counted as denied ppid lookups");
    assert!(
        sample.is_empty(),
        "nothing was attempted-and-denied, so nothing should be sampled"
    );
    assert_eq!(out.len(), 1, "only the real pid should produce an edge");
    let (pid, ppid) = out[0];
    assert_eq!(pid, me as u32, "the filtered edge must be for the real pid");
    assert!(
        ppid == parent_before || ppid == parent_after,
        "edge's ppid ({ppid}) matched neither parent read ({parent_before}, {parent_after})"
    );
}

/// A `Gone` pid (one that can never resolve because it's beyond `PID_MAX`) is a legitimate
/// exclusion, not a denial: it must produce no edge and must NOT be counted in `denied`, no
/// matter how many are batched together.
#[test]
fn join_edges_does_not_count_gone_pids_as_denied() {
    let unresolvable = vec![libc::c_int::MAX; 8];
    let (out, denied, sample) = join_edges(&unresolvable).expect("edge buffer");
    assert!(out.is_empty(), "none of these pids can resolve to an edge");
    assert_eq!(denied, 0, "a pid that is simply gone must not be counted as denied");
    assert!(
        sample.is_empty(),
        "a Gone pid must not be sampled either — only Unknown is"
    );
}

/// The denied-sample cap, pinned directly against [`push_denied_sample`] rather than through
/// a live `join_edges` call: there is no deterministic way to force `Resolved::Unknown` from
/// a real `ppid_of` call (see `snapshot`'s doc), so this is the only way to exercise the cap
/// at all. Pushing `DENIED_SAMPLE_CAP + 2` entries must still keep exactly the first
/// `DENIED_SAMPLE_CAP` of them — capped, not merely bounded by coincidence, and not silently
/// replacing earlier entries with later ones.
#[test]
fn push_denied_sample_caps_at_the_limit() {
    let mut sample = Vec::new();
    for pid in 0..(DENIED_SAMPLE_CAP as libc::c_int + 2) {
        push_denied_sample(&mut sample, pid);
    }
    assert_eq!(
        sample.len(),
        DENIED_SAMPLE_CAP,
        "the sample must be capped, not grow with every push"
    );
    assert_eq!(
        sample,
        (0..DENIED_SAMPLE_CAP as libc::c_int).collect::<Vec<_>>(),
        "a capped sample must keep the FIRST N pushes, not the last"
    );
}

/// The delivered `(pid, ppid)` snapshot carries this test process's own edge.
///
/// This is the only edge that can be asserted unconditionally: `proc_pidinfo` on SELF is
/// always permitted, so `ppid_of(getpid())` cannot be denied. A broader assertion — every
/// same-uid pid in `all_pids()` has an edge — would be flaky, because a same-uid process
/// that exits between the two calls is a legitimate ESRCH drop. The EPERM gap that bounds
/// this layer is pinned separately, in `ppid_of_resolves_a_different_users_process_via_the_sysctl_fallback`.
///
/// `parent_id()` is read both before and after `process_parents()`, and either is accepted:
/// nothing holds this process's real parent fixed across the call, so a single read compared
/// for exact equality would be a race against reparenting (rare, but a real TOCTOU, not a
/// hypothetical one) rather than a pin on the join.
#[test]
fn parents_contains_this_process_edge() {
    let me = std::process::id();
    let parent_before = std::os::unix::process::parent_id();
    let parents = process_parents().expect("the process snapshot");
    let parent_after = std::os::unix::process::parent_id();
    assert!(
        parents.contains(&(me, parent_before)) || parents.contains(&(me, parent_after)),
        "own edge missing from a {}-edge snapshot (parent read as {parent_before} before, \
         {parent_after} after)",
        parents.len()
    );
}

/// The EPERM gap the module docs traced is now CLOSED for this case: pid 1 (launchd) is
/// guaranteed to exist and, outside a root process, guaranteed to be owned by a different
/// (root) user - a deterministic trigger for the sysctl fallback without spawning a
/// cross-uid process. Its real ppid is 0 (the kernel) on every macOS version - the one case
/// `identity::macos::trusted_ppid`'s "`e_ppid == 0` is never trusted" rule exempts by pid
/// rather than discards (see that function's doc).
///
/// The precondition assertion is load-bearing, not decoration: the whole point of this test
/// is that the FALLBACK resolves pid 1, but whether the fallback is even reached depends
/// entirely on the runner's privilege - root's `proc_pidinfo(1, ..)` succeeds outright, so a
/// privileged run (a root run on a dev VM, or a root CI container — this file only ever builds
/// for macOS, so never the Linux cgroup lane) would satisfy `Found(0)` via the PRIMARY path alone
/// and never exercise the fallback at all, leaving this test green while silently testing
/// nothing. Asserting non-root up front makes that case fail loudly instead.
#[test]
fn ppid_of_resolves_a_different_users_process_via_the_sysctl_fallback() {
    // SAFETY: geteuid takes no arguments and cannot fail.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "this test's claim only holds if proc_pidinfo(1, ..) is actually denied, forcing the \
         sysctl fallback - re-run as a non-root user"
    );
    assert_eq!(
        ppid_of(1),
        Resolved::Found(0),
        "pid 1 (launchd)'s parent is the kernel (ppid 0), resolvable via the sysctl fallback"
    );
}

/// The OTHER cause of `ppid_of`'s non-`Found` branch: `Gone`, a pid that does not exist.
/// Triggered deterministically: XNU caps real pids at `PID_MAX` (99999), so `libc::c_int::MAX`
/// can never be live.
#[test]
fn ppid_of_reports_gone_for_an_unallocatable_pid() {
    assert_eq!(
        ppid_of(libc::c_int::MAX),
        Resolved::Gone,
        "a pid beyond PID_MAX can never resolve to a ppid, and is not a denial"
    );
}

/// A failed `proc_listallpids` is `Unassessable` naming the call, not an empty snapshot a tree
/// walk would read as "no descendants". Mutant: "`process_parents` reads `all_pids()`" (a failure
/// becomes an empty list).
#[test]
fn a_failed_pid_listing_is_unassessable_not_an_empty_snapshot() {
    super::super::force_blind_snapshot_for_next_call(true);
    match process_parents() {
        Err(crate::error::Error::Unassessable { detail, source }) => {
            assert!(detail.contains("proc_listallpids"), "{detail}");
            assert!(source.is_some());
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}

/// A pid denied its ppid read leaves its subtree out of the edges, and a walk over them would skip
/// it: `process_parents` is `Unassessable` naming the denied count and a sample. Mutant: "`denied >
/// 0` still returns `Ok`".
#[test]
fn a_denied_ppid_read_is_unassessable_naming_the_count_and_a_sample() {
    let me = std::process::id() as libc::c_int;
    let _forced = super::super::fault::force_denied(&[me]);
    match process_parents() {
        Err(crate::error::Error::Unassessable { detail, source }) => {
            assert!(detail.contains("1 of "), "{detail}");
            assert!(detail.contains(&format!("sample: [{me}]")), "{detail}");
            assert!(source.is_none());
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}

/// `snapshot` keeps its own policy for the same denial: the fd-marker sweep folds the count into
/// its `incomplete` accounting, so it gets the edges it could read and the count. Mutant:
/// "`snapshot` fails like `process_parents`".
#[test]
fn snapshot_reports_a_denied_ppid_read_as_a_count_not_an_error() {
    let me = std::process::id() as libc::c_int;
    let _forced = super::super::fault::force_denied(&[me]);
    let (pids, edges, denied) = super::super::snapshot();
    assert_eq!(denied, 1);
    assert!(pids.contains(&(me as u32)));
    assert!(!edges.iter().any(|&(pid, _)| pid == me as u32));
}

/// A failed edge allocation is `Unassessable`, not an empty tree. Mutant: "`join_edges`' failure is
/// an empty snapshot".
#[test]
fn a_failed_edge_allocation_is_unassessable_not_an_empty_snapshot() {
    let _forced = super::super::fault::force_join_alloc_failure();
    match process_parents() {
        Err(crate::error::Error::Unassessable { detail, source }) => {
            assert!(detail.contains("edge buffer"), "{detail}");
            assert!(source.is_some());
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}

/// `snapshot`'s blind-pass arm: a failed join is an empty table and a zero count, which the
/// fd-marker sweep reads as an incomplete pass. Mutant: "a failed join returns the pid list".
#[test]
fn snapshot_is_an_empty_blind_pass_when_the_edge_allocation_fails() {
    let _forced = super::super::fault::force_join_alloc_failure();
    assert_eq!(super::super::snapshot(), (Vec::new(), Vec::new(), 0));
}
