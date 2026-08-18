//! Probe-based coverage of the drop handoff. These are unit tests because the probe is
//! `#[cfg(test)]`: an integration test has no edge to wait on.

use std::sync::mpsc;

use super::fault;
use super::test_probe::{arm, DropProbe, ReapOutcome};
use super::{run_teardown, ReapJob};
// Windows has no zombie, and a pid outlives its last handle by an asynchronous kernel rundown
// that nothing in user mode signals (measured on an idle box: 0-14 `OpenProcess` probes of
// slack). So identity-after-teardown is a Unix-only property, as the `#[cfg(unix)]`
// `async_drop_leaves_no_zombie` this coverage came from already recorded.
#[cfg(unix)]
use crate::identity::{ProcessId, Resolved};
use crate::test_child::spawn_async_blocker;

/// The three ends a test keeps: the dropping thread's id, the gate release, and the outcome.
struct ProbeEnds {
    entered: mpsc::Receiver<std::thread::ThreadId>,
    gate: mpsc::Sender<()>,
    outcome: mpsc::Receiver<ReapOutcome>,
}

fn arm_probe() -> ProbeEnds {
    let (entered_tx, entered) = mpsc::channel();
    let (gate, gate_rx) = mpsc::channel();
    let (outcome_tx, outcome) = mpsc::channel();
    arm(DropProbe {
        entered: entered_tx,
        gate: gate_rx,
        outcome: outcome_tx,
    });
    ProbeEnds { entered, gate, outcome }
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
    // Were the signal to move onto the worker, this read would block forever behind the held
    // gate and the job timeout is the failure signal — the convention
    // `async_drop_tears_down_a_contained_tree` already uses.
    let mut buf = [0u8; 1];
    match sock.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("root not signalled on the dropping thread: {other:?}"),
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
    // Unix-only, keeping the gate its source test carried: Windows has no zombie, and the
    // outcome above already implies the backend was released, because it is sent only after the
    // job's four resources are dropped.
    #[cfg(unix)]
    assert_ne!(
        ProcessId::of(id.pid()),
        Resolved::Found(id),
        "the teardown must fully reap the child (no lingering process or zombie at its identity)"
    );
}

#[tokio::test]
async fn teardown_reports_the_executing_thread_not_the_origin() {
    // Built by hand around a bare `::tokio::process::Child`, NOT by emptying a `cosca` handle —
    // an emptied handle would hit `PROC_TAKEN` in its own `Drop` and panic the test.
    let mut cmd = ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"));
    cmd.args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let proc = cmd.spawn().expect("spawn a child that exits");
    let pid = proc.id().expect("a freshly spawned child has a pid");

    let (entered, _entered_rx) = mpsc::channel();
    let (gate_tx, gate) = mpsc::channel();
    let (outcome, outcome_rx) = mpsc::channel();
    drop(gate_tx); // a dropped sender is a release, so the worker never blocks
    let origin = std::thread::current().id();
    let job = ReapJob {
        proc: super::super::ProcSource::Tokio(proc),
        attached: crate::containment::Attached::None,
        pipes: Default::default(),
        owned_std: Default::default(),
        pid,
        origin,
        probe: Some(DropProbe { entered, gate, outcome }),
        force_panic: false,
    };

    // `h.thread().id()` is a value the TEST holds without asking the executing thread, and it
    // differs from `origin` — so an implementation reporting `job.origin` fails here. Calling
    // `run_teardown` synchronously and comparing against `thread::current().id()` would be two
    // evaluations of one expression and could not fail.
    let h = std::thread::spawn(move || run_teardown(job));
    let executing = h.thread().id();
    h.join().expect("the teardown thread must not panic");

    assert_ne!(executing, origin, "the teardown must run off the origin thread");
    assert_eq!(
        outcome_rx.recv().expect("the teardown must report an outcome"),
        ReapOutcome::Reaped(executing),
        "the reported thread must be the EXECUTING one, not the job's origin"
    );
}

#[tokio::test]
async fn no_reaper_available_releases_the_job_in_hand() {
    let ends = arm_probe();
    let (child, _sock) = spawn_async_blocker();
    fault::set_force_no_reaper(true);
    drop(child);

    ends.entered.recv().expect("Drop must reach the handoff");
    // Release the gate: the release path never gates, but a broken world that submitted the job
    // would otherwise wedge the worker behind it instead of failing the assertion below.
    drop(ends.gate);
    assert_eq!(
        ends.outcome.recv().expect("the release path must report an outcome"),
        ReapOutcome::Released,
        "with no reaper available the job must be released in hand, not reaped"
    );
    assert!(
        !fault::take_force_no_reaper(),
        "the fault must have been consumed — a flag nothing read cannot pass this test"
    );
}

#[tokio::test]
async fn teardown_panic_is_caught_and_reported() {
    let ends = arm_probe();
    let (child, _sock) = spawn_async_blocker();
    fault::set_force_teardown_panic(true);
    drop(child);

    ends.entered.recv().expect("Drop must reach the handoff");
    drop(ends.gate);
    assert_eq!(
        ends.outcome
            .recv()
            .expect("without catch_unwind the worker unwinds and no outcome ever arrives"),
        ReapOutcome::Panicked,
        "a panicking teardown must be caught and reported"
    );
    assert!(
        !fault::take_force_teardown_panic(),
        "the fault must have been consumed at submit time"
    );
}

#[tokio::test]
async fn unkillable_root_is_not_submitted() {
    use std::io::{Read as _, Write as _};
    let ends = arm_probe();
    let (child, mut sock) = spawn_async_blocker();
    let id = child.id();
    fault::set_force_kill_failure(true);
    drop(child);

    ends.entered.recv().expect("Drop must reach the handoff");
    // Nothing is submitted, so nothing gates; releasing anyway keeps a broken world that DID
    // submit from wedging the worker instead of failing the assertion below.
    drop(ends.gate);
    // The probe's outcome sender drops with the job that was never built: a submitted job would
    // report `Reaped(_)` here and park a pool slot on a child nobody can kill.
    assert!(
        ends.outcome.recv().is_err(),
        "a child whose kill failed must not be submitted"
    );
    assert!(!fault::take_force_kill_failure(), "the fault must have been consumed");
    // Race-free: the fault REPLACED the kill, so nothing was ever signalled.
    assert_eq!(
        id.is_alive(),
        crate::identity::Liveness::Alive,
        "an unkillable root must be left running"
    );

    // Release it so it exits. Its reaping is left to the runtime's orphan handling — the
    // documented behaviour of this path — so the assertion is on the EXIT, not the reap.
    sock.write_all(b"x").expect("release the unsignalled child");
    let mut buf = [0u8; 1];
    match sock.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("released child did not exit: {other:?}"),
    }
}
