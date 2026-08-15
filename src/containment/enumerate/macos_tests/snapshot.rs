//! Completeness of the macOS host snapshot, pinned against two independent sources.

use super::super::snapshot;

/// The pid list must be complete, not merely non-empty. The oracle is `proc_listallpids`'
/// own sizing return, read here independently of the code under test: the kernel's own count
/// of what it is about to hand over. A units mistake (treating that return as bytes) yields
/// roughly a quarter of the table and fails this immediately.
#[test]
fn the_pid_list_is_at_least_as_large_as_the_kernels_own_sizing_return() {
    // SAFETY: the sizing form of proc_listallpids takes a null buffer.
    let needed = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    assert!(needed > 0, "the sizing call must report a positive count");
    let (pids, _, _) = snapshot();
    // The sizing call over-reports headroom, and some process churn between THIS test's own
    // sizing call and `snapshot()`'s internal one is normal — neither is a fixed quantity this
    // test can derive in advance, so equality is wrong and an unexplained additive constant
    // would be a guess. What IS derivable: the specific units bug this guards against (bytes
    // read as a pid count) undercounts by roughly 4x — far past any plausible slop-plus-churn
    // margin — so a factor-of-2 tolerance robustly catches that bug class without pinning an
    // unjustified absolute number. The companion test below (against `ps`) is the stronger,
    // precise completeness check; this one exists to catch the units mistake specifically,
    // cheaply and without depending on `ps`.
    assert!(
        pids.len() * 2 >= needed as usize,
        "the pid list ({}) is far short of the kernel's own sizing return ({needed}) — \
         consistent with a units mistake (bytes read as a pid count), which undercounts by \
         roughly 4x",
        pids.len()
    );
}

/// Two pids that provably exist for the whole test must both be present.
#[test]
fn the_pid_list_contains_launchd_and_this_process() {
    let (pids, _, _) = snapshot();
    assert!(pids.contains(&1), "launchd must be in the pid list");
    assert!(
        pids.contains(&std::process::id()),
        "the running test process must be in the pid list"
    );
}

/// `ps` is an independent implementation of "list every pid". Every pid it reports that is
/// STILL alive when we look must be in ours — a pid that exited in between is legitimately
/// absent, and re-resolving its identity (rather than a timed re-check) distinguishes the two.
///
/// `.output()` forks+execs `/bin/ps`, so it takes production's `spawn_lock()` for the same
/// reason every fdmarker test that spawns does: an unlocked fork here is a bystander that could
/// transiently inherit another test's still-open marker write end, exactly the fork-bystander
/// window `spawn_lock()` exists to close host-wide within this process.
#[test]
fn every_still_live_pid_that_ps_reports_is_in_the_snapshot() {
    let _serialize = crate::child::spawn::spawn_lock();
    let out = std::process::Command::new("/bin/ps")
        .args(["-Ao", "pid="])
        .output()
        .expect("run ps");
    let ps_pids: Vec<u32> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    assert!(!ps_pids.is_empty(), "ps reported no processes; the oracle is broken");
    let (pids, _, _) = snapshot();
    let set: std::collections::HashSet<u32> = pids.into_iter().collect();
    for pid in ps_pids {
        if set.contains(&pid) {
            continue;
        }
        // Not in our list: it must be because it has since exited.
        let gone = matches!(crate::identity::ProcessId::of(pid), crate::identity::Resolved::Gone);
        assert!(gone, "pid {pid} is live and reported by ps but missing from the snapshot");
    }
}

/// The ppid pairs are a subset of the pid list: every edge names a pid the sweep will visit.
#[test]
fn every_ppid_edge_names_a_pid_from_the_same_snapshot() {
    let (pids, parents, _) = snapshot();
    let set: std::collections::HashSet<u32> = pids.into_iter().collect();
    for (pid, _) in &parents {
        assert!(set.contains(pid), "pid {pid} has a ppid edge but is not in the pid list");
    }
}
