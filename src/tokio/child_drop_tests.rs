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

/// Regression test for adversarial round-3 finding 5: the ARMED `kill_on_drop` path's own
/// `start_kill`-failure early return used to drop `os` — and so `os.attached` — inline, on
/// whichever thread called `drop`. The tree-level `hard_kill` a few lines above it runs
/// unconditionally, before `start_kill` is even attempted, so a `Cgroup` leaf is armed or
/// already killed by the time this early return is reached regardless of whether `start_kill`
/// (a separate, root-specific kill) then succeeds — its own `Drop` can still block waiting for a
/// drain. This forces `start_kill` to fail via the same seam `child_wait_tests` uses, then
/// asserts the release still runs on a reaper thread, not the dropping one.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failed_start_kill_still_routes_an_armed_leafs_release_through_the_reaper_pool() {
    use std::sync::mpsc;

    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::containment::Attached;
    use crate::identity::ProcessId;

    use super::reaper::test_probe::{arm, DropProbe, ReapOutcome};
    use super::{Child, OsResources, ProcSource};

    let fake = FakeLeaf::new("cosca-async-failed-startkill-routing", false);
    let leaf = entered_leaf_at(fake.leaf.clone());
    assert!(
        leaf.drop_may_block(),
        "test setup: a freshly entered, still-armed leaf must be one Drop routes off the \
         calling thread"
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
        kill_on_drop: true,
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
    drop(gate_tx);

    super::reaper::fault::set_force_kill_failure(true);
    drop(child);

    let dropping = entered.recv().expect("the armed path must reach the reaper handoff");
    assert_eq!(
        dropping,
        std::thread::current().id(),
        "#[tokio::test] is current-thread"
    );
    let executing = started.recv().expect("a worker must take the job");
    assert_ne!(
        executing, dropping,
        "an armed leaf's release must run on a reaper thread, never the thread that called drop, \
         even though this handle's own start_kill failed for the root"
    );
    assert!(
        matches!(outcome.recv(), Ok(ReapOutcome::Reaped(_))),
        "the job must complete via the reaper pool"
    );
}

/// Sibling of the test above: the root already reaped (`os.proc: None`) by the time `drop` runs
/// is the OTHER early return in the armed path — it must route the same way, for the same
/// reason: the tree-level `hard_kill` a few lines above already leaves the leaf armed or killed.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_already_reaped_root_still_routes_an_armed_leafs_release_through_the_reaper_pool() {
    use std::sync::mpsc;

    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::containment::Attached;
    use crate::identity::ProcessId;

    use super::reaper::test_probe::{arm, DropProbe, ReapOutcome};
    use super::{Child, OsResources};

    let fake = FakeLeaf::new("cosca-async-already-reaped-routing", false);
    let leaf = entered_leaf_at(fake.leaf.clone());
    assert!(
        leaf.drop_may_block(),
        "test setup: a freshly entered, still-armed leaf must be one Drop routes off the \
         calling thread"
    );

    let child = Child {
        os: OsResources {
            proc: None,
            attached: Attached::Cgroup(leaf),
            pipes: Default::default(),
            owned_std: Default::default(),
        },
        id: ProcessId::from_parts_for_test(std::process::id(), 0),
        kill_on_drop: true,
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
    drop(gate_tx);

    drop(child);

    let dropping = entered.recv().expect("the armed path must reach the reaper handoff");
    assert_eq!(
        dropping,
        std::thread::current().id(),
        "#[tokio::test] is current-thread"
    );
    let executing = started.recv().expect("a worker must take the job");
    assert_ne!(
        executing, dropping,
        "an armed leaf's release must run on a reaper thread, never the thread that called drop, \
         even though the root was already reaped"
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

/// Async twin of `child_tests.rs`'s
/// `dropping_an_armed_fdmarker_child_calls_hard_kill_exactly_once` — see that test's doc for the
/// full hazard. `Child::drop` (tokio, `kill_on_drop` true, the default) sweeps the contained tree
/// itself via its own explicit `self.os.attached.hard_kill()` call, then hands the root's reap off
/// to the reaper pool (`reaper::submit`). Once that job's `run_teardown` reaps the root and drops
/// `os` (dropping `os.attached`, an `Attached::FdMarker` on macOS), `Drop for Marker` runs — before
/// this fix, still armed, firing `hard_kill` a SECOND, unconditional time, exactly like the sync
/// twin.
///
/// Uses the real `reaper::test_probe` handoff (not a sleep) to wait until `run_teardown` has
/// dropped `os` on the reaper thread — `run_teardown` sends `outcome` strictly AFTER `drop(os)` —
/// before inspecting the marker's call count.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn dropping_an_armed_fdmarker_child_calls_hard_kill_exactly_once() {
    use std::sync::mpsc;

    use super::reaper::test_probe::{arm, DropProbe, ReapOutcome};

    let mut cmd = crate::tokio::Command::new();
    cmd.executable("/usr/bin/true");
    cmd.arg("true"); // argv[0]; `executable` alone selects the loaded image, not argv
    cmd.contain_with(crate::ContainMode::Strongest);
    let child = cmd.spawn().expect("spawn a contained macOS root");
    // Keyed on this marker's own dedicated, never-reused hard-kill-count key — NOT its real OS
    // pipe handle, which this process's own kernel can reissue to an unrelated, concurrently
    // spawned marker once this one's read end is dropped, before this assertion even runs. See
    // `fault::HARD_KILL_CALLS`'s own doc for the false failure that caused, measured.
    let key = child
        .test_marker_hard_kill_key()
        .expect("Strongest attaches FdMarker on macOS");

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

    drop(child); // kill_on_drop defaults to true: this is the armed path under test.

    entered
        .recv()
        .expect("an armed, not-yet-reaped drop must reach the reaper handoff");
    started.recv().expect("a worker must take the job");
    assert!(
        matches!(outcome.recv(), Ok(ReapOutcome::Reaped(_))),
        "the job must complete via the reaper pool"
    );

    assert_eq!(
        crate::containment::fdmarker::fault::take_hard_kill_calls(key),
        1,
        "Child::drop's own explicit hard_kill must be the ONLY sweep of this tree; a second \
         (from an armed Drop for Marker still running after the reaper thread's drop(os) already \
         tore the tree down) unconditionally re-fires killpg on a pgid that may since have been \
         recycled"
    );
}
