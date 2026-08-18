//! Probe-based coverage of the drop handoff and the reaper pool. These are unit tests because
//! the probe is `#[cfg(test)]`: an integration test has no edge to wait on.
//!
//! **Gate-holding budget.** The pool behind `submit` is process-global and shared with every
//! other test in this binary, so no test may reason about its worker count or its idleness. A
//! worker of it is held *indefinitely* only behind a held probe gate, and probes are private to
//! this module, so the budget is local: at most `REAPER_POOL_THREADS - 1` tests here may hold a
//! gate on the global pool concurrently. Currently exactly one does
//! (`drop_signals_the_root_and_returns_before_the_reap`); the pool-shape tests hold their gates
//! on their own [`private_pool`]s instead. Every other drop in the binary occupies a global
//! worker only for a killed child's prompt exit.

use std::sync::mpsc;
use std::thread::ThreadId;

use super::test_probe::{arm, DropProbe, ReapOutcome};
// Windows has no zombie, and a pid outlives its last handle by an asynchronous kernel rundown
// that nothing in user mode signals. So identity-after-teardown is a Unix-only property, as the
// `#[cfg(unix)]` `async_drop_leaves_no_zombie` this coverage came from already recorded.
#[cfg(unix)]
use crate::identity::{ProcessId, Resolved};
use crate::test_child::spawn_async_blocker;

/// Failure bound on an external kernel event — a killed child's exit — surfaced through the
/// named `expect`/`panic!` below. Not a synchronisation device: the edge is the socket's EOF.
const CHILD_EXIT_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

/// The four ends a test keeps: the dropping thread's id, the executing worker's id, the gate
/// release, and the outcome.
struct ProbeEnds {
    entered: mpsc::Receiver<ThreadId>,
    started: mpsc::Receiver<ThreadId>,
    gate: mpsc::Sender<()>,
    outcome: mpsc::Receiver<ReapOutcome>,
}

fn probe_pair() -> (DropProbe, ProbeEnds) {
    let (entered_tx, entered) = mpsc::channel();
    let (started_tx, started) = mpsc::channel();
    let (gate, gate_rx) = mpsc::channel();
    let (outcome_tx, outcome) = mpsc::channel();
    (
        DropProbe {
            entered: entered_tx,
            started: started_tx,
            gate: gate_rx,
            outcome: outcome_tx,
        },
        ProbeEnds {
            entered,
            started,
            gate,
            outcome,
        },
    )
}

/// A pool of this test's own, so its worker count and idleness are facts the test may reason
/// about — which the process-global one never is. Leaked: a published pool's sender must never
/// drop, or its workers would exit on the disconnect.
fn private_pool(bound: usize) -> &'static super::LazyPool {
    Box::leak(Box::new(super::LazyPool::new(bound)))
}

/// A job built by hand around a bare `::tokio::process::Child` that exits of its own accord —
/// NOT by emptying a `cosca` handle, whose own `Drop` would then hit `PROC_TAKEN` and panic the
/// test. The teardown never kills, so the child's own exit is what ends the wait.
fn bare_job(origin: ThreadId, probe: Option<DropProbe>) -> super::ReapJob {
    let proc = {
        // The same lock every cosca-originated spawn in this binary takes: a macOS fork landing
        // while another test's fd-marker write end is open would transiently inherit it.
        let _guard = crate::child::spawn::spawn_lock();
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", "__cosca_no_such_test__"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child that exits")
    };
    let pid = proc.id().expect("a freshly spawned child has a pid");
    super::ReapJob {
        proc: super::super::ProcSource::Tokio(proc),
        attached: crate::containment::Attached::None,
        pipes: Default::default(),
        owned_std: Default::default(),
        pid,
        origin,
        probe,
    }
}

/// The ends of `count` jobs submitted to `pool`, each gated by this test.
fn submit_gated(pool: &'static super::LazyPool, count: usize) -> Vec<ProbeEnds> {
    let origin = std::thread::current().id();
    (0..count)
        .map(|_| {
            let (probe, ends) = probe_pair();
            super::submit_to(pool, bare_job(origin, Some(probe)));
            ends
        })
        .collect()
}

/// Release one gated job and take its reap — how a test hands its worker back.
fn release_and_reap(ends: ProbeEnds) {
    let ProbeEnds { gate, outcome, .. } = ends;
    drop(gate);
    assert!(
        matches!(outcome.recv(), Ok(ReapOutcome::Reaped(_))),
        "a released job must reap"
    );
}

/// Arm a probe for the next `Child::drop` on this thread and keep its ends.
fn arm_probe() -> ProbeEnds {
    let (probe, ends) = probe_pair();
    arm(probe);
    ends
}

#[tokio::test]
async fn drop_signals_the_root_and_returns_before_the_reap() {
    use std::io::Read as _;
    let ends = arm_probe();
    let (child, mut sock) = spawn_async_blocker();
    #[cfg(unix)]
    let id = child.id();
    drop(child);

    // Guard: `Drop` reached the handoff at all. Without it an early return would leave every
    // assertion below observing nothing and passing vacuously.
    let dropping = ends.entered.recv().expect("Drop must reach the handoff");
    assert_eq!(
        dropping,
        std::thread::current().id(),
        "#[tokio::test] is current-thread"
    );

    // The root was SIGNALLED on the dropping thread and has exited: its control socket is shut.
    // The gate is still held, so no worker can have done this.
    sock.set_read_timeout(Some(CHILD_EXIT_BOUND))
        .expect("bound the killed child's exit");
    let mut buf = [0u8; 1];
    match sock.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("root not signalled on the dropping thread before Drop returned: {other:?}"),
    }

    // `Drop` returned before the teardown. Race-free rather than merely not-yet-observed: we
    // still hold the gate SENDER, so a teardown on a worker CANNOT have reported, while an
    // inlined one provably reported before `drop` returned. This is the whole discriminator on
    // Windows, where the identity comparison below cannot tell the two worlds apart.
    assert!(
        matches!(ends.outcome.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "Drop must return before the teardown runs"
    );
    // Unix sharpens it: the child has exited but is still an unreaped zombie, so its identity
    // resolves. Reuse-immune — the comparison is pid + start token.
    #[cfg(unix)]
    assert_eq!(
        ProcessId::of(id.pid()),
        Resolved::Found(id),
        "the exited child must still be an unreaped zombie while the teardown is gated"
    );

    drop(ends.gate);
    assert!(
        matches!(ends.outcome.recv(), Ok(ReapOutcome::Reaped(_))),
        "the released teardown must reap"
    );
    #[cfg(unix)]
    assert_ne!(
        ProcessId::of(id.pid()),
        Resolved::Found(id),
        "after the teardown the child's identity must be gone"
    );
}

#[tokio::test]
async fn drop_reaps_on_a_worker_thread() {
    let ends = arm_probe();
    let (child, _sock) = spawn_async_blocker();
    #[cfg(unix)]
    let id = child.id();
    drop(child);

    let dropping = ends.entered.recv().expect("Drop must reach the handoff");
    drop(ends.gate);
    let outcome = ends.outcome.recv().expect("the teardown must report an outcome");
    // Thread ids FIRST: an inlined teardown is the failure under test, and asserting the
    // identity first would fail it for an incidental reason instead.
    match outcome {
        ReapOutcome::Reaped(executing) => assert_ne!(
            executing, dropping,
            "the reap must run on a worker thread, not the dropping thread"
        ),
        other => panic!("expected Reaped, got {other:?}"),
    }
    // The no-zombie property, sequenced after a real edge rather than after a blocking `Drop`.
    // A zombie still resolves to `Found(id)` (Linux `/proc` persists); a reaped pid resolves to
    // `Gone` or, if recycled, a DIFFERENT identity — so a recycled pid never false-passes.
    #[cfg(unix)]
    assert_ne!(
        ProcessId::of(id.pid()),
        Resolved::Found(id),
        "the teardown must fully reap the child (no lingering process or zombie at its identity)"
    );
}

#[tokio::test]
async fn teardown_reports_the_executing_thread_not_the_origin() {
    let (probe, ends) = probe_pair();
    drop(ends.gate); // a dropped sender is a release, so the teardown never blocks
    let origin = std::thread::current().id();
    let job = bare_job(origin, Some(probe));

    // `h.thread().id()` is a value the TEST holds without asking the executing thread, and it
    // differs from `origin` — so an implementation reporting `job.origin` fails here. Calling
    // `run_teardown` synchronously and comparing against `thread::current().id()` would be two
    // evaluations of one expression and could not fail.
    let h = std::thread::spawn(move || super::run_teardown(job));
    let executing = h.thread().id();
    h.join().expect("the teardown thread must not panic");

    assert_ne!(executing, origin, "the teardown must run off the origin thread");
    assert_eq!(
        ends.outcome.recv().expect("the teardown must report an outcome"),
        ReapOutcome::Reaped(executing),
        "the reported thread must be the EXECUTING one, not the job's origin"
    );
}

#[tokio::test]
async fn each_wedged_job_occupies_its_own_worker_and_the_extra_job_queues() {
    let bound = super::REAPER_POOL_THREADS;
    let pool = private_pool(bound);
    let mut ends = submit_gated(pool, bound + 1);
    let extra = ends.pop().expect("bound + 1 jobs were submitted");

    // Every one of the first `bound` jobs is picked up: each wedged job occupies its OWN worker.
    // A pool that failed to publish releases in hand instead, dropping this sender unsent — an
    // immediate, loud `Err`.
    let workers: Vec<ThreadId> = ends
        .iter()
        .map(|e| {
            e.started
                .recv()
                .expect("each of the first `bound` jobs must be taken by a worker of its own")
        })
        .collect();
    // Race-free: every worker is wedged on a gate THIS test holds, so none can take the extra.
    assert!(
        matches!(extra.started.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "with every worker wedged, the extra job must queue rather than run"
    );

    // Free exactly one worker; the queue drains onto it and no other.
    let first = ends.remove(0);
    drop(first.gate);
    assert_eq!(
        first.outcome.recv().expect("the released job must report an outcome"),
        ReapOutcome::Reaped(workers[0]),
        "the released job reaps on the worker that took it"
    );
    assert_eq!(
        extra
            .started
            .recv()
            .expect("the queued job must be taken once a worker frees up"),
        workers[0],
        "the freed worker is the one that drains the queue"
    );

    release_and_reap(extra);
    for e in ends {
        release_and_reap(e);
    }
}

/// The positive control that makes the published width falsifiable with no mutation at all: it
/// runs at a width DIFFERENT from the constant, so hardcoding either the spawn loop or the
/// predicate to `REAPER_POOL_THREADS` makes this pool abandon and the first `started.recv()` errs.
/// Hardcoding BOTH — the only way a wider-than-bound pool can exist — publishes four workers, and
/// the queued job then starts on one of the two THIS test never gated.
#[tokio::test]
async fn pool_width_follows_its_bound() {
    const BOUND: usize = 2;
    let pool = private_pool(BOUND);
    let mut ends = submit_gated(pool, BOUND + 1);
    let extra = ends.pop().expect("BOUND + 1 jobs were submitted");

    let workers: Vec<ThreadId> = ends
        .iter()
        .map(|e| e.started.recv().expect("a pool of BOUND must take BOUND jobs at once"))
        .collect();
    // Race-free: both workers are wedged on gates THIS test holds.
    assert!(
        matches!(extra.started.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "a pool of BOUND must not take a BOUND + 1'th job"
    );

    // Free exactly one worker and see which one takes the queue. Blocking, so it is an edge in
    // BOTH worlds: a wider pool has already handed the job to a worker this test never gated, and
    // reports that thread instead — where the `Empty` above only catches it by timing.
    let first = ends.remove(0);
    drop(first.gate);
    assert!(
        matches!(first.outcome.recv(), Ok(ReapOutcome::Reaped(_))),
        "the released job must reap"
    );
    assert_eq!(
        extra
            .started
            .recv()
            .expect("the queued job must be taken once a worker frees up"),
        workers[0],
        "a pool of BOUND has no third worker to take the queued job"
    );

    release_and_reap(extra);
    for e in ends {
        release_and_reap(e);
    }
}
