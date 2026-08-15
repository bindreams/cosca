//! The ppid join: `join_ppids`, `process_parents`, and `ppid_of`'s failure branches.

use super::super::{join_ppids, ppid_of, process_parents, DROP_SAMPLE_CAP};

/// The `pid <= 0` filter, pinned deterministically with a synthetic pid list rather than a
/// live one: depending on a live run to happen to contain pid 0 (a kernel-internal fact
/// this filter's correctness should not hinge on to be exercised) would let the test pass
/// vacuously on a host/kernel where it's absent. `getpid()` is a real, live pid guaranteed
/// to resolve (`proc_pidinfo` on SELF is always permitted), so it proves the non-positive
/// entries are what's filtered, not that every entry is.
#[test]
fn join_ppids_filters_non_positive_pids() {
    let me = std::process::id() as libc::c_int;
    // Read before and after, same reasoning as `parents_contains_this_process_edge`:
    // nothing holds this process's real parent fixed across the call.
    let parent_before = std::os::unix::process::parent_id();
    let (out, dropped, sample) = join_ppids(&[0, -1, me]);
    let parent_after = std::os::unix::process::parent_id();
    assert_eq!(dropped, 0, "0 and -1 must not be counted as failed ppid lookups");
    assert!(
        sample.is_empty(),
        "nothing was attempted-and-failed, so nothing should be sampled"
    );
    assert_eq!(out.len(), 1, "only the real pid should produce an edge");
    let (pid, ppid) = out[0];
    assert_eq!(pid, me as u32, "the filtered edge must be for the real pid");
    assert!(
        ppid == parent_before || ppid == parent_after,
        "edge's ppid ({ppid}) matched neither parent read ({parent_before}, {parent_after})"
    );
}

/// The drop sample truncates at `DROP_SAMPLE_CAP`, not off-by-one and not unbounded: more
/// than `DROP_SAMPLE_CAP` copies of a pid that can never resolve (see
/// `ppid_of_returns_none_for_an_unallocatable_pid`) must still count every one as dropped
/// while the sample itself stays capped.
#[test]
fn join_ppids_caps_the_drop_sample() {
    let unresolvable = vec![libc::c_int::MAX; DROP_SAMPLE_CAP + 2];
    let (out, dropped, sample) = join_ppids(&unresolvable);
    assert!(out.is_empty(), "none of these pids can resolve to an edge");
    assert_eq!(
        dropped,
        DROP_SAMPLE_CAP + 2,
        "every attempted lookup must be counted as dropped"
    );
    assert_eq!(
        sample.len(),
        DROP_SAMPLE_CAP,
        "the sample must be capped, not grow with the drop count"
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
    let parents = process_parents();
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
/// privileged run (`sudo cargo test`, a root CI container) would satisfy `Some(0)` via the
/// PRIMARY path alone and never exercise the fallback at all, leaving this test green while
/// silently testing nothing. Asserting non-root up front makes that case fail loudly instead.
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
        Some(0),
        "pid 1 (launchd)'s parent is the kernel (ppid 0), resolvable via the sysctl fallback"
    );
}

/// The OTHER cause of `ppid_of`'s `None` branch: ESRCH, a pid that does not exist. Triggered
/// deterministically: XNU caps real pids at `PID_MAX` (99999), so `libc::c_int::MAX` can
/// never be live.
#[test]
fn ppid_of_returns_none_for_an_unallocatable_pid() {
    assert!(
        ppid_of(libc::c_int::MAX).is_none(),
        "a pid beyond PID_MAX can never resolve to a ppid"
    );
}
