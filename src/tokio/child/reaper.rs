//! The wait-and-reap half of the async [`Child`](super::Child)'s teardown.
//!
//! `Drop` issues every signal on the dropping thread and hands what remains here, so the wait —
//! and only the wait — runs on a reaper thread.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use crate::containment::Attached;
use crate::stdio::Fd;

/// Everything `Drop` hands over: the process backend plus every field that holds an OS resource
/// and drops after it today, so the release order survives the handoff.
pub(crate) struct ReapJob {
    pub(crate) proc: super::ProcSource,
    pub(crate) attached: Attached,
    pub(crate) pipes: super::FdPipes,
    pub(crate) owned_std: BTreeMap<Fd, crate::tokio::stdio::OwnedStd>,
    pub(crate) pid: u32,
    /// The thread `Drop` ran on. `run_teardown` gates only when it is executing elsewhere.
    #[cfg(test)]
    pub(crate) origin: std::thread::ThreadId,
    #[cfg(test)]
    pub(crate) probe: Option<test_probe::DropProbe>,
    /// Seeded panic in the wait region. Sampled at submit time on the dropping thread — a
    /// thread-local armed by the test is invisible on a worker.
    #[cfg(test)]
    pub(crate) force_panic: bool,
    /// Seeded panic in the release region. Set directly on a hand-built job, so it needs no
    /// thread-local of its own.
    #[cfg(test)]
    pub(crate) force_release_panic: bool,
}

/// A wedged child occupies one worker and no other; the rest keep draining the shared queue. Not
/// a throughput device — an ordinary reap waits microseconds on an already-killed child.
const REAPER_POOL_THREADS: usize = 4;

/// A published pool: the sending half of the one queue its workers share.
struct Pool {
    tx: crossbeam_channel::Sender<ReapJob>,
}

impl Pool {
    /// Hand the job to whichever worker takes it next.
    fn dispatch(&self, job: ReapJob) {
        let backlog = self.tx.len();
        if backlog > 0 {
            // Fires on healthy bursts too — this is a depth reading, not a fault. No decision
            // reads it.
            log::debug!(
                "child {} queued behind {backlog} reaps (pool width {REAPER_POOL_THREADS})",
                job.pid
            );
        }
        if let Err(e) = self.tx.send(job) {
            // Unreachable: a published pool's sender lives in a `static` and never drops.
            debug_assert!(false, "a published reaper pool's channel cannot disconnect");
            release(e.into_inner());
        }
    }
}

/// The pool behind a `submit`, started on first use.
struct LazyPool {
    bound: usize,
    cell: OnceLock<Pool>,
    init: Mutex<()>,
    /// Init attempts that reached their spawn loop. Observability only — no decision reads it.
    #[cfg(test)]
    inits: std::sync::atomic::AtomicUsize,
}

impl LazyPool {
    const fn new(bound: usize) -> LazyPool {
        LazyPool {
            bound,
            cell: OnceLock::new(),
            init: Mutex::new(()),
            #[cfg(test)]
            inits: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The pool, starting it on first use. **Publishes iff `started == bound`**; any other
    /// outcome abandons, and `None` tells the caller to release the job in hand and leaves the
    /// cell empty so the next submit retries.
    ///
    /// The guard covers only the re-check, the channel, the spawns and the publish decision —
    /// exclusivity is the whole point of keeping the spawns inside it. Joining abandoned workers
    /// and every log call happen after it drops, so no dropping thread convoys behind another's
    /// join or behind a consumer's `Log` impl.
    fn get(&self) -> Option<&Pool> {
        if let Some(pool) = self.cell.get() {
            return Some(pool);
        }
        // Handed out of the critical section (see above).
        let mut abandoned: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let mut failures: Vec<std::io::Error> = Vec::new();
        let mut published = false;
        {
            let guard = match self.init.lock() {
                Ok(guard) => guard,
                // The guarded state is a single once-only `cell.set` taken as the last step, so
                // it is consistent by construction.
                Err(poisoned) => {
                    debug_assert!(false, "the reaper init lock cannot be poisoned");
                    poisoned.into_inner()
                }
            };
            if self.cell.get().is_none() {
                #[cfg(test)]
                self.inits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Consumed here, on the submitting thread this init runs on.
                #[cfg(test)]
                let mut forced = fault::take_force_spawn_failures();
                let (tx, rx) = crossbeam_channel::unbounded::<ReapJob>();
                let mut started = 0usize;
                for _ in 0..self.bound {
                    #[cfg(test)]
                    if forced > 0 {
                        forced -= 1;
                        failures.push(std::io::Error::other("forced reaper spawn failure (test seam)"));
                        continue;
                    }
                    let rx = rx.clone();
                    match std::thread::Builder::new()
                        .name("cosca-reaper".to_owned())
                        .spawn(move || work(rx))
                    {
                        Ok(handle) => {
                            started += 1;
                            abandoned.push(handle);
                        }
                        Err(e) => failures.push(e),
                    }
                }
                // The single publication predicate. On any other outcome `tx` and `rx` drop with
                // this block, disconnecting the queue, so the started workers exit and the joins
                // below are bounded.
                if started == self.bound {
                    match self.cell.set(Pool { tx }) {
                        // A published pool's workers are immortal: drop the handles, never join.
                        Ok(()) => {
                            abandoned.clear();
                            published = true;
                        }
                        Err(_) => debug_assert!(false, "the reaper cell was set past its own in-lock re-check"),
                    }
                }
            }
            drop(guard);
        }
        for handle in abandoned {
            let _ = handle.join();
        }
        for e in failures {
            log::error!("starting a reaper thread failed: {e}");
        }
        if published {
            log::debug!("reaper pool started ({} threads)", self.bound);
        }
        self.cell.get()
    }
}

/// A reaper worker. Immortal once its pool is published: [`run_teardown`] cannot unwind, and the
/// only exit is the queue's disconnect — the pre-publication abandon edge, since a published
/// pool's sender lives in a `static`.
fn work(rx: crossbeam_channel::Receiver<ReapJob>) {
    while let Ok(job) = rx.recv() {
        // Defense in depth against a future edit breaking `run_teardown`'s no-unwind contract:
        // loud, never a silent absorb.
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_teardown(job))).is_err() {
            debug_assert!(false, "run_teardown unwound despite its no-unwind contract");
            let _ = std::panic::catch_unwind(|| {
                log::error!("a reaper teardown unwound despite its no-unwind contract");
            });
        }
    }
}

fn submit_to(lazy: &LazyPool, job: ReapJob) {
    // Sampled HERE, on the submitting thread: the region it models runs on a worker, where a
    // thread-local armed by the test is invisible.
    #[cfg(test)]
    let job = ReapJob {
        force_panic: fault::take_force_teardown_panic(),
        ..job
    };
    match lazy.get() {
        Some(pool) => pool.dispatch(job),
        None => release(job),
    }
}

/// Hand `job` to the process-global reaper pool, starting it if this is the first kill-on-drop
/// drop of the process.
pub(crate) fn submit(job: ReapJob) {
    static GLOBAL: LazyPool = LazyPool::new(REAPER_POOL_THREADS);
    submit_to(&GLOBAL, job);
}

/// Degraded mode: the pool could not start at full width. The root is already signalled, so the
/// remaining cost is the reap — handed to tokio's orphan handling (a no-op on Windows, which has
/// nothing to reap). `error`, not `warn`: the crate is knowingly giving up its own guarantee.
fn release(job: ReapJob) {
    log::error!(
        "no reaper thread is available; child {} is left to the runtime's orphan handling (it is \
         already signalled)",
        job.pid
    );
    #[cfg(test)]
    let probe = job.probe;
    drop(job.proc);
    drop(job.attached);
    drop(job.pipes);
    drop(job.owned_std);
    #[cfg(test)]
    if let Some(p) = probe {
        let _ = p.outcome.send(test_probe::ReapOutcome::Released);
    }
}

/// Wait for the root's exit, reap it, then release the job's resources in `Child`'s own field
/// order. **Never kills:** the signal was already issued on the dropping thread, and a second
/// kill can fail (Windows denies terminating an already-exiting process), which every
/// kill-then-wait path reads as "do not wait" — silently losing the reap.
///
/// **Never unwinds.** Two `catch_unwind` regions — the wait, then the release — with glue that is
/// only moves, matches and further `catch_unwind` calls. Every log call sits inside a region,
/// because a consumer's `Log` impl is untrusted.
pub(crate) fn run_teardown(job: ReapJob) {
    #[cfg(test)]
    let origin = job.origin;
    #[cfg(test)]
    let probe = job.probe;
    #[cfg(test)]
    let force_panic = job.force_panic;
    #[cfg(test)]
    let force_release_panic = job.force_release_panic;
    let mut proc = job.proc;
    let attached = job.attached;
    let pipes = job.pipes;
    let owned_std = job.owned_std;
    let pid = job.pid;

    // `proc` is BORROWED into this region, never moved: an unwind must not destroy a resource
    // whose release the region below owns and orders.
    let waited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[cfg(test)]
        if let Some(p) = probe.as_ref() {
            let _ = p.started.send(std::thread::current().id());
        }
        // Executing elsewhere ⇒ a test may hold the teardown until it has observed the
        // not-yet-reaped state. On the dropping thread the teardown was inlined, so skipping the
        // gate lets that broken world fail an assertion instead of deadlocking.
        #[cfg(test)]
        if std::thread::current().id() != origin {
            if let Some(p) = probe.as_ref() {
                let _ = p.gate.recv(); // a dropped sender is also a release
            }
        }
        #[cfg(test)]
        if force_panic {
            panic!("forced teardown panic (test seam)");
        }
        proc.wait_and_reap(pid);
    }));

    let released = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if waited.is_err() {
            log::error!("reaping child {pid} panicked; releasing its resources anyway");
        }
        #[cfg(test)]
        if force_release_panic {
            panic!("forced release-region panic (test seam)");
        }
        // `Child`'s declaration order — `proc` first, so the pid stays pinned for the whole wait
        // and every other release stays ordered after the reap.
        drop(proc);
        drop(attached);
        drop(pipes);
        drop(owned_std);
        #[cfg(test)]
        if let Some(p) = probe {
            let _ = p.outcome.send(if waited.is_err() {
                test_probe::ReapOutcome::Panicked
            } else {
                test_probe::ReapOutcome::Reaped(std::thread::current().id())
            });
        }
    }));
    if released.is_err() {
        // Wrapped for the same reason the other log calls are: an untrusted `Log` impl must not
        // be the thing that finally unwinds this function.
        let _ = std::panic::catch_unwind(|| {
            log::error!("releasing child {pid}'s resources panicked; its wait had already completed");
        });
    }
}

/// Fault seams for the off-nominal paths. Take-semantics, matching `crate::wait::fault`.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    thread_local! {
        static FORCE_SPAWN_FAILURES: Cell<usize> = const { Cell::new(0) };
        static FORCE_TEARDOWN_PANIC: Cell<bool> = const { Cell::new(false) };
        static FORCE_KILL_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Fail the first `n` `Builder::spawn` attempts of the NEXT init entered from THIS thread.
    /// Init runs on the submitting thread, so the thread-local is visible where it is read.
    pub(crate) fn set_force_spawn_failures(n: usize) {
        FORCE_SPAWN_FAILURES.with(|f| f.set(n));
    }
    pub(crate) fn take_force_spawn_failures() -> usize {
        FORCE_SPAWN_FAILURES.with(|f| f.replace(0))
    }

    /// Force the NEXT teardown to panic in its wait region. Sampled at submit time into
    /// [`ReapJob::force_panic`](super::ReapJob::force_panic), because the region it models runs
    /// on a worker.
    pub(crate) fn set_force_teardown_panic(on: bool) {
        FORCE_TEARDOWN_PANIC.with(|f| f.set(on));
    }
    pub(crate) fn take_force_teardown_panic() -> bool {
        FORCE_TEARDOWN_PANIC.with(|f| f.replace(false))
    }

    /// Force the NEXT root `start_kill` in `Drop` on THIS thread to report failure. It REPLACES
    /// the kill rather than masking its result, so the child really is left unsignalled.
    pub(crate) fn set_force_kill_failure(on: bool) {
        FORCE_KILL_FAILURE.with(|f| f.set(on));
    }
    pub(crate) fn take_force_kill_failure() -> bool {
        FORCE_KILL_FAILURE.with(|f| f.replace(false))
    }
}

/// Observation seam for the drop handoff. `#[cfg(test)]`, not `#[doc(hidden)] pub`: nothing
/// test-only reaches a downstream build, so no gate can ever block in a consumer's `Drop`.
///
/// A held [`DropProbe::gate`] parks one worker of the process-global pool indefinitely, and the
/// pool is shared with every other test in the binary — see `reaper_tests`' header for the
/// budget that keeps.
#[cfg(test)]
pub(crate) mod test_probe {
    use std::cell::RefCell;

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum ReapOutcome {
        Reaped(std::thread::ThreadId),
        Released,
        Panicked,
    }

    pub(crate) struct DropProbe {
        /// The dropping thread's id, sent from `Drop` before the handoff.
        pub(crate) entered: std::sync::mpsc::Sender<std::thread::ThreadId>,
        /// The executing thread's id, sent by the teardown before it gates: "a worker took this
        /// job". A released job never sends it, so the receiver's `Err` is the negative edge.
        pub(crate) started: std::sync::mpsc::Sender<std::thread::ThreadId>,
        /// Held teardowns wait here; a dropped sender releases them.
        pub(crate) gate: std::sync::mpsc::Receiver<()>,
        pub(crate) outcome: std::sync::mpsc::Sender<ReapOutcome>,
    }

    thread_local! {
        static PROBE: RefCell<Option<DropProbe>> = const { RefCell::new(None) };
    }

    /// Arm a probe for the NEXT `Child::drop` on THIS thread (take-semantics, matching
    /// `crate::wait::fault`).
    pub(crate) fn arm(probe: DropProbe) {
        PROBE.with(|p| *p.borrow_mut() = Some(probe));
    }

    pub(crate) fn take() -> Option<DropProbe> {
        PROBE.with(|p| p.borrow_mut().take())
    }
}

#[cfg(test)]
#[path = "reaper_tests.rs"]
mod reaper_tests;
