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
        reaped_via_public_wait: false,
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

/// Round-4 finding D2 proposed routing the disarmed branch's `is_reaped()` (root already reaped)
/// case off-thread too, matching the ARMED path's own already-reaped early return (round-3
/// finding 5). Applying it broke a real-kernel CI check,
/// `linux_cgroup_v2_async_kill_on_drop_false_kill_tree_still_waits_for_the_leaf_to_drain`
/// (`tests/tokio_io.rs`), which explicitly forbids sleeps or polling in the test and relies on
/// `drop(child)` itself not returning until the leaf's drain — and so its `rmdir` — is done: with
/// no public way to wait for an async hand-off's completion, routing this off-thread makes that
/// property unprovable from outside the crate, not merely differently-timed. This test proves the
/// INLINE behavior — that `os.attached` (and so the leaf) drops on the calling thread here,
/// synchronously, exactly as the real-kernel check needs — using the reaper pool's own probe to
/// prove the NEGATIVE: the handoff this leaf's `disarmed_kill_may_block_drop()` would otherwise
/// qualify it for never happens once the root is already reaped.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_disarmed_killed_drop_with_an_already_reaped_root_releases_inline_not_through_the_reaper_pool() {
    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::containment::Attached;
    use crate::identity::ProcessId;

    use super::{Child, OsResources, ProcSource};

    let fake = FakeLeaf::new("cosca-async-disarmed-killed-reaped-root-inline", false);
    // A REAL, non-empty tmpfs directory stands in for the leaf: without this hook, even a
    // correct (unpopulated) removal would fail with a genuine `ENOTEMPTY`, since `cgroup.kill`
    // and the `cgroup.events` symlink are real filesystem entries here, unlike a real cgroupfs
    // leaf's own kernel-provided files.
    let (leaf_path, events) = (fake.leaf.clone(), fake.events.clone());
    fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&leaf_path, &events));
    let leaf = entered_leaf_at(fake.leaf.clone());
    leaf.disarm();
    leaf.hard_kill().expect("kill the tree");
    assert!(
        leaf.disarmed_kill_may_block_drop(),
        "test setup: this leaf must be one `disarmed_kill_may_block_drop()` reports true for, so \
         the already-reaped check below is what actually keeps it off the reaper pool"
    );

    let mut proc = {
        let _guard = crate::child::spawn::spawn_lock();
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", "__cosca_no_such_test__"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child that exits")
    };
    let pid = proc.id().expect("a freshly spawned child has a pid");
    // Reap it through tokio's own `wait` BEFORE it is ever handed to `Child` — this is what
    // `ProcSource::is_reaped()` actually reads (`tokio::process::Child::id()` going `None`), the
    // same state an explicit `kill_tree()` + `wait().await` leaves behind in the real scenario.
    proc.wait().await.expect("reap the child through tokio's own wait");

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

    drop(child);

    // Checked immediately, with no wait of any kind: the whole point is that `drop` itself does
    // not return until this is already true. (This is the same "real-kernel regression check,
    // not a deterministic proof" tradeoff `tests/tokio_io.rs`'s own twin documents — a wrongly
    // async release would most likely still leave the leaf present here, but is not GUARANTEED
    // to; the deterministic proof is the reaper pool's own probe elsewhere in this file, showing
    // it engages for a STILL-RUNNING root and not for this already-reaped one.)
    assert!(
        !fake.leaf.exists(),
        "an already-reaped root's release must remove the leaf inline, synchronously, before \
         `drop` returns — matching the real-kernel CI check that has no other way to observe it"
    );
    fault::take_rmdir_hook();
}

/// Regression test for round-4 finding D3: the disarmed branch's own `reaper::submit` call, when
/// it DID route (root not yet reaped), submitted `skip_wait: false` — asking the reaper pool to
/// `wait_and_reap` the root — with no confirmed signal actually sent TO THE ROOT backing that
/// wait: this branch's own leaf-level `killed` flag only proves a `cgroup.kill` WRITE succeeded,
/// which misses a process that migrated out of the leaf (a `sudo -i` into a different session
/// scope, say) before the kill fired. `ReapJob::skip_wait`'s own invariant is that its wait is
/// only ever bounded by a signal the SENDER knows reached the root — violating it here parks a
/// reaper-pool worker for the root's entire remaining lifetime, and with only 2 workers, two such
/// drops wedge every kill-on-drop reap in the process.
///
/// A `FakeLeaf`'s `cgroup.kill` is a plain file, so writing to it (the same `leaf.hard_kill()`
/// call the other tests here make) never touches the REAL child either — reproducing the "missed
/// by the kill" case exactly, without needing a real session escape. The child is left genuinely
/// RUNNING (blocked on its own stdin) through the drop and the probe: an already-exited child
/// (this test's first version) cannot distinguish `skip_wait: false` actually reaping it from
/// tokio's own background orphan-queue reaper picking it up once `os.proc` is simply dropped —
/// both leave nothing for this test's own `waitpid` to find, for unrelated reasons, so that
/// version passed and failed for the wrong reason either way.
///
/// Waits on `outcome` with a plain, untimed `recv()`: the reaper pool is our own code, so syncing
/// on it with a wall clock is forbidden — a regression that parks the worker genuinely hangs, and
/// nextest's own `slow-timeout` for this test (`.config/nextest.toml`) is the failure bound
/// surfaced to a human instead.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_disarmed_killed_drop_whose_kill_missed_the_root_does_not_park_a_reaper_worker_on_it() {
    use std::sync::mpsc;

    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::containment::Attached;
    use crate::identity::ProcessId;

    use super::reaper::test_probe::{arm, DropProbe, ReapOutcome};
    use super::{Child, OsResources, ProcSource};

    let fake = FakeLeaf::new("cosca-async-disarmed-killed-missed-root-routing", false);
    let leaf = entered_leaf_at(fake.leaf.clone());
    leaf.disarm();
    leaf.hard_kill()
        .expect("kill the (fake) tree — never reaches the real child below");
    assert!(
        leaf.disarmed_kill_may_block_drop(),
        "test setup: this leaf must be the one Drop routes off the calling thread"
    );

    let (proc, stdin) = {
        let _guard = crate::child::spawn::spawn_lock();
        let mut proc = ::tokio::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child blocked on stdin");
        let stdin = proc.stdin.take().expect("piped stdin");
        (proc, stdin)
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
    drop(gate_tx);

    drop(child);

    let dropping = entered
        .recv()
        .expect("a disarmed, already-killed drop must reach the reaper handoff");
    let executing = started.recv().expect("a worker must take the job");
    assert_ne!(
        executing, dropping,
        "the release must run on a reaper thread, never the dropping one"
    );
    let result = outcome.recv();

    // Only reached once `outcome` actually reports: a real regression parks the worker in
    // `wait_and_reap` on this still-blocked child forever, which nextest's own `slow-timeout` for
    // this test bounds by terminating the process — the same OS-level teardown that ends the
    // child too, so nothing here needs to unblock it by hand in that case. Not asserted further
    // in the ordinary case either: once `os.proc` is dropped it is tokio's own orphan queue that
    // may reap it, racing harmlessly with whatever else in this shared test binary next triggers
    // a `SIGCHLD` sweep — the same best-effort cleanup `Unreaped::leak` documents elsewhere, not
    // this test's concern.
    drop(stdin);

    assert!(
        matches!(result, Ok(ReapOutcome::Reaped(_))),
        "the release must complete without parking a reaper-pool worker waiting for a root this \
         leaf's kill never actually signalled, got {result:?}"
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
        reaped_via_public_wait: false,
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
        reaped_via_public_wait: false,
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

/// Async twin of `leaf_tests::an_armed_leaf_retries_cgroup_kill_after_its_own_failed_attempt` —
/// round-4's "add an async F2 test" finding: mutant M14 (reverting `child.rs:876`'s
/// `disarm_after_own_sweep()` back to a blanket `disarm()`) survived in both lanes because no
/// async test drove this specific path. `Child::drop`'s own tree-level `hard_kill`, fired
/// unconditionally near its top, is forced to fail for real (`EACCES`) — since round-4 also
/// removed the `debug_assert` that used to make this panic in debug builds, this now runs in
/// every build. If `disarm_after_own_sweep` regresses to `disarm()`, the leaf lands disarmed and
/// never-killed instead of staying armed, and its own `Drop` never retries the write at all.
///
/// Unlike the sync twin, this leaf's own `Drop` runs on a reaper-pool thread, not this test's own
/// — so the sync twin's `rmdir`/drain-block hooks (thread-local, per `cgroup/fault.rs`) cannot be
/// reused here as written; they would simply never fire on that other thread and this test would
/// hang or silently no-op. Two things sidestep that instead, both already thread-independent by
/// design: no `rmdir` hook is installed at all, so the leaf's `rmdir_leaf()` falls through to a
/// REAL `rmdir` on the real (non-empty) fake leaf directory, which fails with a real, unrecognized
/// errno on ANY thread — read by the Drop logic the same as a genuinely occupied leaf, forcing the
/// kill-it branch regardless of who calls it; and `set_next_kill_thread_hook` (already a global,
/// path-keyed registry — see its own doc — built for exactly this async, cross-thread case) reports
/// the real retried write, whichever thread performs it, and is used here to flip the fake leaf's
/// `populated` bit so the drain that follows completes.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_armed_async_leaf_retries_cgroup_kill_after_its_own_failed_attempt() {
    use std::sync::mpsc;

    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::containment::Attached;
    use crate::identity::ProcessId;

    use super::reaper::test_probe::{arm, DropProbe, ReapOutcome};
    use super::{Child, OsResources, ProcSource};

    let fake = FakeLeaf::new("cosca-async-armed-kill-retry-leaf", true);
    let events = fake.events.clone();
    let (retried_tx, retried) = mpsc::channel();
    fault::set_next_kill_thread_hook(
        &fake.leaf,
        Box::new(move |_thread| {
            FakeLeaf::set_populated(&events, false);
            let _ = retried_tx.send(());
        }),
    );

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

    fault::set_force_kill_write_failure(true);
    drop(child);

    let _dropping = entered.recv().expect("the armed path must reach the reaper handoff");
    let _executing = started.recv().expect("a worker must take the job");
    // No timeout: syncing on our own reaper pool with a wall clock is forbidden. nextest's own
    // `slow-timeout` for this test (`.config/nextest.toml`) is the human-facing failure bound if
    // this ever genuinely hangs.
    let result = outcome.recv();
    assert!(
        matches!(result, Ok(ReapOutcome::Reaped(_))),
        "the job must complete via the reaper pool, got {result:?}"
    );

    assert!(
        !fault::take_force_kill_write_failure(),
        "one-shot: the forced failure must already have been consumed by Child::drop's own \
         hard_kill call"
    );
    assert!(
        retried.try_recv().is_ok(),
        "an armed leaf's own Drop must retry cgroup.kill after its own earlier attempt \
         (Child::drop's own sweep) failed — no retried write was ever observed"
    );
    // Not asserted further: with no `rmdir` hook installed (thread-local, and so unusable here —
    // see the doc above), the retried rmdir this leaf's own Drop makes after the drain ALSO hits
    // the real, non-empty fake directory and fails the same way the first one did, so the leaf is
    // left behind (logged, not asserted) rather than actually removed. That is a limitation of
    // this fixture reused across a thread hop, not a claim about production behavior: the retry
    // write itself — this test's actual subject, and M14's actual effect — is what `retried`
    // proves, unconditionally of whether the directory removal that follows can succeed here.
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
        reaped_via_public_wait: false,
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
