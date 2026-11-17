//! The ppid join: `join_edges`, `process_parents`, and `ppid_of`'s failure branches.

use crate::identity::{FakeKernel, HostKernel, Resolved};

use super::super::{join_edges, ppid_of, process_parents, push_denied_sample, snapshot, DENIED_SAMPLE_CAP};

/// The `pid <= 0` filter, pinned deterministically with a synthetic pid list rather than a
/// live one: depending on a live run to happen to contain pid 0 (a kernel-internal fact
/// this filter's correctness should not hinge on to be exercised) would let the test pass
/// vacuously on a host/kernel where it's absent. `getpid()` is a real, live pid guaranteed
/// to resolve (`proc_pidinfo` on SELF is always permitted), so it proves the non-positive
/// entries are what's filtered, not that every entry is.
#[skuld::test]
fn join_edges_filters_non_positive_pids() {
    let me = std::process::id() as libc::c_int;
    // Read before and after, same reasoning as `parents_contains_this_process_edge`:
    // nothing holds this process's real parent fixed across the call.
    let parent_before = std::os::unix::process::parent_id();
    let (out, denied, sample) = join_edges(&HostKernel, &[0, -1, me]);
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
#[skuld::test]
fn join_edges_does_not_count_gone_pids_as_denied() {
    let unresolvable = vec![libc::c_int::MAX; 8];
    let (out, denied, sample) = join_edges(&HostKernel, &unresolvable);
    assert!(out.is_empty(), "none of these pids can resolve to an edge");
    assert_eq!(denied, 0, "a pid that is simply gone must not be counted as denied");
    assert!(
        sample.is_empty(),
        "a Gone pid must not be sampled either — only Unknown is"
    );
}

/// The denied-sample cap, pinned against [`push_denied_sample`]: `DENIED_SAMPLE_CAP + 2` pushes keep
/// exactly the first `DENIED_SAMPLE_CAP`, not a later window.
#[skuld::test]
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
/// same-uid pid in the listing has an edge — would be flaky, because a same-uid process
/// that exits between the two calls is a legitimate ESRCH drop. The EPERM gap that bounds
/// this layer is pinned separately, in `ppid_of_resolves_a_different_users_process_via_the_sysctl_fallback`.
///
/// `parent_id()` is read both before and after `process_parents()`, and either is accepted:
/// nothing holds this process's real parent fixed across the call, so a single read compared
/// for exact equality would be a race against reparenting (rare, but a real TOCTOU, not a
/// hypothetical one) rather than a pin on the join.
#[skuld::test]
fn parents_contains_this_process_edge() {
    let me = std::process::id();
    let parent_before = std::os::unix::process::parent_id();
    let parents = process_parents(&HostKernel).expect("the process snapshot");
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
/// cross-uid process. Its real ppid is 0 (the kernel) on every macOS version - a case
/// `identity::macos::trusted_ppid`'s "`e_ppid == 0` is never trusted" rule exempts by pid
/// (with pid 0's) rather than discards (see that function's doc).
///
/// The precondition assertion is load-bearing, not decoration: the whole point of this test
/// is that the FALLBACK resolves pid 1, but whether the fallback is even reached depends
/// entirely on the runner's privilege - root's `proc_pidinfo(1, ..)` succeeds outright, so a
/// privileged run (a root run on a dev VM, or a root CI container — this file only ever builds
/// for macOS, so never the Linux cgroup lane) would satisfy `Found(0)` via the PRIMARY path alone
/// and never exercise the fallback at all, leaving this test green while silently testing
/// nothing. Asserting non-root up front makes that case fail loudly instead.
#[skuld::test]
fn ppid_of_resolves_a_different_users_process_via_the_sysctl_fallback() {
    // SAFETY: geteuid takes no arguments and cannot fail.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "this test's claim only holds if proc_pidinfo(1, ..) is actually denied, forcing the \
         sysctl fallback - re-run as a non-root user"
    );
    assert_eq!(
        ppid_of(&HostKernel, 1),
        Resolved::Found(0),
        "pid 1 (launchd)'s parent is the kernel (ppid 0), resolvable via the sysctl fallback"
    );
}

/// The OTHER cause of `ppid_of`'s non-`Found` branch: `Gone`, a pid that does not exist.
/// Triggered deterministically: XNU caps real pids at `PID_MAX` (99999), so `libc::c_int::MAX`
/// can never be live.
#[skuld::test]
fn ppid_of_reports_gone_for_an_unallocatable_pid() {
    assert_eq!(
        ppid_of(&HostKernel, libc::c_int::MAX),
        Resolved::Gone,
        "a pid beyond PID_MAX can never resolve to a ppid, and is not a denial"
    );
}

/// A failed `proc_listallpids` is `Unassessable` naming the call, not an empty snapshot a tree
/// walk would read as "no descendants". Mutants: "a failure becomes an empty list";
/// "`process_parents` lists through the host's kernel" (the row is left, and the listing succeeds).
#[skuld::test]
fn a_failed_pid_listing_is_unassessable_not_an_empty_snapshot() {
    let kernel = FakeKernel::over(&HostKernel).on_pids(Err(libc::EIO));
    match process_parents(&kernel) {
        Err(crate::error::Error::Unassessable { detail, source }) => {
            assert!(detail.contains("proc_listallpids"), "{detail}");
            assert!(source.is_some());
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    assert!(kernel.all_rows_taken());
}

/// A pid denied its ppid read leaves its subtree out of the edges, and a walk over them would skip
/// it: `process_parents` is `Unassessable` naming the denied count and a sample. Mutants: "`denied >
/// 0` still returns `Ok`"; "a persistent refusal is retried" (a second read reaches the host's,
/// which resolves it).
#[skuld::test]
fn a_denied_ppid_read_is_unassessable_naming_the_count_and_a_sample() {
    let me = std::process::id() as libc::c_int;
    match process_parents(&FakeKernel::over(&HostKernel).on_record_refused(me as u32)) {
        Err(crate::error::Error::Unassessable { detail, source }) => {
            assert!(detail.contains("1 of "), "{detail}");
            assert!(detail.contains(&format!("sample: [{me}]")), "{detail}");
            assert!(source.is_none());
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}

/// `snapshot` keeps its own policy for the same denial: it returns the edges it could read and the
/// count. Mutant: "`snapshot` fails like `process_parents`".
#[skuld::test]
fn snapshot_reports_a_denied_ppid_read_as_a_count_not_an_error() {
    let me = std::process::id() as libc::c_int;
    let (pids, edges, denied) = snapshot(&FakeKernel::over(&HostKernel).on_record_refused(me as u32));
    assert_eq!(denied, 1);
    assert!(pids.contains(&(me as u32)));
    assert!(!edges.iter().any(|&(pid, _)| pid == me as u32));
}

/// A failed listing is an empty table and a zero count, which the fd-marker sweep reads as an
/// incomplete pass. Mutants: "a failed listing returns the host's"; "a failed listing is a list of
/// no edges and a count of the pids".
#[skuld::test]
fn snapshot_is_an_empty_blind_pass_when_the_listing_fails() {
    let kernel = FakeKernel::over(&HostKernel).on_pids(Err(libc::EIO));
    assert_eq!(snapshot(&kernel), (Vec::new(), Vec::new(), 0));
    assert!(kernel.all_rows_taken());
}

/// `process_parents` and `snapshot` join the pids the kernel lists, and only those: a non-positive pid
/// is dropped, and each edge is the parent that a stated row gives a listed pid. The kernel has no
/// other row, so a read of any other pid panics. Mutants: the listing is read from the host (the row is
/// left, and the host's pids have no rows); a non-positive pid is joined.
#[skuld::test]
fn the_snapshot_joins_the_list_the_kernel_states() {
    use crate::identity::Kernel;
    let me = std::process::id() as libc::c_int;
    let Ok(record) = HostKernel.bsd_info(me as u32) else {
        panic!("this process has a record");
    };
    let with_parent = |ppid| {
        let mut record = record;
        record.pbi_ppid = ppid;
        Ok(record)
    };
    let listing = [0, -1, 100, 200];
    let stated = || {
        FakeKernel::new()
            .on_pids(Ok(&listing))
            .on_bsd_info(100, with_parent(7))
            .on_bsd_info(200, with_parent(100))
    };

    let kernel = stated();
    assert_eq!(
        process_parents(&kernel).expect("the stated listing"),
        [(100, 7), (200, 100)]
    );
    assert!(kernel.all_rows_taken());

    let kernel = stated();
    assert_eq!(snapshot(&kernel), (vec![100, 200], vec![(100, 7), (200, 100)], 0));
    assert!(kernel.all_rows_taken());
}

/// `fork()` in progress is transient: it resolves inside the read, so it is neither a denial nor
/// an error. Mutant: "transient counted as denied".
#[skuld::test]
fn a_fork_in_progress_resolves_and_is_not_counted_as_denied() {
    use crate::identity::Kernel;
    let me = std::process::id() as libc::c_int;
    let Ok(record) = HostKernel.bsd_info(me as u32) else {
        panic!("this process has a record");
    };
    let with_parent = |ppid| {
        let mut record = record;
        record.pbi_ppid = ppid;
        Ok(record)
    };
    // The record states parent `0` twice, then `1`, and the kernel has no other row: a fourth read
    // would panic.
    let kernel = FakeKernel::new()
        .on_bsd_info(me as u32, with_parent(0))
        .on_bsd_info(me as u32, with_parent(0))
        .on_bsd_info(me as u32, with_parent(1));
    let (edges, denied, _) = join_edges(&kernel, &[me]);
    assert_eq!(denied, 0);
    assert_eq!(edges, [(me as u32, 1)]);
}
