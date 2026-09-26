// Exercises the ACTUAL shared classifier both Drop impls call (crate::child::
// is_teardown_mechanism_failure), not a hand-copied duplicate — a future edit to the real
// condition is caught here automatically. Cannot force a REAL Containment through a live
// Drop without root (same constraint as the rest of this plan), so this drives the
// classifier directly with constructed Error values. Both Unassessable shapes are exercised
// because they classify oppositely: `source: None` (an ordinary "member unconfirmed" outcome
// from group::decide) is NOT a mechanism failure; `source: Some(_)` (group::state's listing
// itself failed) IS one.
#[test]
fn teardown_mechanism_failure_excludes_containment_and_per_member_unassessable() {
    use crate::child::is_teardown_mechanism_failure;
    assert!(!is_teardown_mechanism_failure(&crate::error::Error::Containment {
        detail: "refused".into()
    }));
    assert!(!is_teardown_mechanism_failure(&crate::error::Error::Unassessable {
        detail: "unknown".into(),
        source: None
    }));
    assert!(is_teardown_mechanism_failure(&crate::error::Error::Io(
        std::io::Error::other("mechanism failure")
    )));
}

#[test]
fn teardown_mechanism_failure_includes_listing_failure_unassessable() {
    use crate::child::is_teardown_mechanism_failure;
    assert!(is_teardown_mechanism_failure(&crate::error::Error::Unassessable {
        detail: "process group 372 could not be listed after SIGKILL".into(),
        source: Some(std::io::Error::other("sysctl KERN_PROC_PGRP failed"))
    }));
}

// #194 follow-up: a disarmed-but-killed drop's leaf can still block waiting for a drain (this
// handle's own `kill_tree()`/`hard_kill()` already fired) — that wait must run on a reaper
// thread, not whichever thread called `drop`, exactly like the armed path's own kill-then-wait.
//
// A real delegated cgroup needs root/CI, but `CgroupLeaf::for_test_at`'s directory operations run
// for real against the kernel's own errnos on any Linux host without one (see its own doc and
// `containment::cgroup::leaf_tests`, which tests `CgroupLeaf::drop` this same way) — no root
// needed here either. `Child` is built as a struct literal, not through `spawn`: this module is a
// descendant of `crate::tokio::child`, so its private fields are reachable, the same way
// `reaper_tests`'s `bare_job` builds a `ReapJob` by hand.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_disarmed_killed_drop_routes_its_drain_wait_through_the_reaper_pool() {
    use std::sync::mpsc;

    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::containment::Attached;
    use crate::identity::ProcessId;

    use super::reaper::test_probe::{arm, DropProbe, ReapOutcome};
    use super::{Child, OsResources, ProcSource};

    // Not populated, so the leaf's own drain wait (wherever it runs) returns at once instead of
    // blocking on an inotify event nothing would ever fire.
    let fake = FakeLeaf::new("cosca-async-disarmed-killed-routing", false);
    let leaf = entered_leaf_at(fake.leaf.clone());
    leaf.disarm();
    leaf.hard_kill().expect("kill the tree");
    assert!(
        leaf.disarmed_kill_may_block_drop(),
        "test setup: this leaf must be the one Drop routes off the calling thread"
    );

    // A real, short-lived child this handle owns, never awaited — mirroring an ordinary drop and
    // `reaper_tests::bare_job`'s own fixture.
    let proc = {
        let _guard = crate::child::spawn::spawn_lock();
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", "__cosca_no_such_test__"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child that exits")
    };
    let pid = proc.id().expect("a freshly spawned child has a pid");

    let child = Child {
        os: OsResources {
            proc: Some(ProcSource::Tokio(proc)),
            attached: Attached::Cgroup(leaf),
            pipes: Default::default(),
            owned_std: Default::default(),
        },
        id: ProcessId::from_parts_for_test(pid, 0),
        kill_on_drop: false,
        containment: crate::containment::Containment::CgroupV2,
        graceful: crate::graceful::GracefulMechanism::Process,
        elevation: None,
    };

    let (entered_tx, entered) = mpsc::channel();
    let (started_tx, started) = mpsc::channel();
    let (gate_tx, gate_rx) = mpsc::channel();
    let (outcome_tx, outcome) = mpsc::channel();
    arm(DropProbe {
        entered: entered_tx,
        started: started_tx,
        gate: gate_rx,
        outcome: outcome_tx,
    });
    drop(gate_tx); // never held: nothing here needs the teardown parked open

    drop(child);

    let dropping = entered
        .recv()
        .expect("a disarmed, already-killed drop must reach the reaper handoff");
    assert_eq!(
        dropping,
        std::thread::current().id(),
        "#[tokio::test] is current-thread"
    );
    let executing = started.recv().expect("a worker must take the job");
    assert_ne!(
        executing, dropping,
        "the drain wait must run on a reaper thread, never the thread that called drop"
    );
    assert!(
        matches!(outcome.recv(), Ok(ReapOutcome::Reaped(_))),
        "the job must complete via the reaper pool"
    );
}

/// Sibling of the routing test above: a disarmed leaf that was NEVER killed has nothing to wait
/// for, so its drop must NOT engage the reaper handoff at all — an armed probe must be left
/// untouched for whatever later drop it was meant for.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_disarmed_never_killed_drop_does_not_route_through_the_reaper_pool() {
    use std::sync::mpsc;

    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::containment::Attached;
    use crate::identity::ProcessId;

    use super::reaper::test_probe::{arm, DropProbe};
    use super::{Child, OsResources, ProcSource};

    let fake = FakeLeaf::new("cosca-async-disarmed-never-killed-routing", false);
    let leaf = entered_leaf_at(fake.leaf.clone());
    leaf.disarm();
    assert!(
        !leaf.disarmed_kill_may_block_drop(),
        "test setup: this leaf must be the one Drop leaves alone"
    );

    let proc = {
        let _guard = crate::child::spawn::spawn_lock();
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", "__cosca_no_such_test__"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child that exits")
    };
    let pid = proc.id().expect("a freshly spawned child has a pid");

    let child = Child {
        os: OsResources {
            proc: Some(ProcSource::Tokio(proc)),
            attached: Attached::Cgroup(leaf),
            pipes: Default::default(),
            owned_std: Default::default(),
        },
        id: ProcessId::from_parts_for_test(pid, 0),
        kill_on_drop: false,
        containment: crate::containment::Containment::CgroupV2,
        graceful: crate::graceful::GracefulMechanism::Process,
        elevation: None,
    };

    let (entered_tx, entered) = mpsc::channel();
    let (started_tx, _started) = mpsc::channel();
    let (_gate_tx, gate_rx) = mpsc::channel();
    let (outcome_tx, outcome) = mpsc::channel();
    arm(DropProbe {
        entered: entered_tx,
        started: started_tx,
        gate: gate_rx,
        outcome: outcome_tx,
    });

    drop(child);

    // Never taken: the sender is still parked in the thread-local, so an untouched probe reads
    // `Empty`, not `Disconnected` — `Disconnected` would mean something DID take and drop it.
    assert!(
        matches!(entered.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "a disarmed, never-killed drop must never touch the reaper probe"
    );
    assert!(
        matches!(outcome.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "no job may have been submitted for a drop with nothing to wait for"
    );
    // `proc` dropped in place along with `child.os`: unsignalled and never awaited, exactly like
    // `Command::kill_on_drop(false)` on a plain tokio child, which the runtime's own orphan
    // handling reaps in the background — nothing further to release here.
}
