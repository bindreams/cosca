//! Probe-based coverage of the drop handoff and the reaper pool. These are unit tests because
//! the probe is `#[cfg(test)]`: an integration test has no edge to wait on.
//!
//! **Gate-holding budget.** The pool behind `submit` is process-global and shared with every
//! other test in this binary, so no test may reason about its worker count or its idleness. A
//! worker is held *indefinitely* only behind a held probe gate, and probes are private to this
//! module, so the budget is local: at most `REAPER_POOL_THREADS - 1` tests here may hold a gate
//! concurrently. Currently exactly one does
//! (`drop_signals_the_root_and_returns_before_the_reap`). Every other drop in the binary occupies
//! a worker only for a killed child's prompt exit.

use std::sync::mpsc;

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

/// The three ends a test keeps: the dropping thread's id, the gate release, and the outcome.
struct ProbeEnds {
    entered: mpsc::Receiver<std::thread::ThreadId>,
    gate: mpsc::Sender<()>,
    outcome: mpsc::Receiver<ReapOutcome>,
}

fn probe_pair() -> (DropProbe, ProbeEnds) {
    let (entered_tx, entered) = mpsc::channel();
    let (gate, gate_rx) = mpsc::channel();
    let (outcome_tx, outcome) = mpsc::channel();
    (
        DropProbe {
            entered: entered_tx,
            gate: gate_rx,
            outcome: outcome_tx,
        },
        ProbeEnds { entered, gate, outcome },
    )
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
