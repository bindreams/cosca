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
    let proc = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", "__cosca_no_such_test__"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn a child that exits");
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

    super::reaper::test_probe::assert_consumed();
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

    let proc = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", "__cosca_no_such_test__"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn a child that exits");
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

/// Async twin of the sync `drop_warns_instead_of_asserting_on_a_real_teardown_mechanism_failure`
/// (`child_tests.rs`): a failed `cgroup.kill` write reached during `Child::drop`'s OWN teardown
/// is a real OS outcome: Drop must warn and return normally.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn drop_warns_instead_of_asserting_on_a_real_teardown_mechanism_failure() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-drop-kill-fail-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill a directory");
    crate::child::spawn::fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });

    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sleep", "30"]);
    // The override is consumed by this spawn; `kill_on_drop` defaults to true. The tree-kill call
    // in Drop runs synchronously on the dropping thread, before any reaper-pool hand-off, so no
    // probe is needed to observe it.
    let mut child = cmd.spawn().expect("spawn");

    // Pin that the forced failure is the mechanism class this test claims (a raw `EISDIR` from
    // the `cgroup.kill` write, surfaced as `Error::Io`), so it cannot go vacuous if the forcing
    // stops reaching the kill.
    let forced = child
        .kill_tree()
        .expect_err("the forced cgroup.kill failure must surface from kill_tree");
    assert!(
        matches!(&forced, crate::error::Error::Io(io) if io.raw_os_error() == Some(libc::EISDIR)),
        "the forced failure must be a mechanism-class Error::Io(EISDIR), got {forced:?}"
    );

    let mark = crate::log_capture::mark();
    // A same-text record from ANOTHER thread, fixed before the drop by the join: the thread-filtered
    // scan below must not count it (a concurrent test's identical record would look the same).
    let marker = "Child::drop: contained-tree teardown did not fully succeed";
    std::thread::spawn(move || log::warn!("{marker}: from another thread"))
        .join()
        .expect("emit from another thread");
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(child)));
    assert!(
        unwound.is_ok(),
        "Child::drop must not panic on a real teardown-mechanism failure: {unwound:?}"
    );

    // `Drop` logs on the dropping thread (the tree kill runs there before any reaper hand-off),
    // so the current-thread scan sees exactly its record.
    let records = crate::log_capture::records_since_on_current_thread(mark, marker);
    assert_eq!(
        records.iter().map(|(level, _)| *level).collect::<Vec<_>>(),
        [log::Level::Warn],
        "a real teardown-mechanism failure during Drop must be logged at warn, got {records:?}"
    );
}
