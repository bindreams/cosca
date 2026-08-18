//! The wait-and-reap half of the async [`Child`](super::Child)'s teardown.
//!
//! `Drop` signals the tree and the root on the dropping thread, then hands what remains to a
//! bounded pool of reaper threads.
//!
//! The job carries the process backend and every field whose release must stay ordered after the
//! reap, not a bare pid: the backend pins the pid for the whole wait, and a bare pid would let
//! the runtime's orphan queue reap it and let the OS recycle it onto another of our children —
//! under our own `waitid`.
//!
//! Workers are immortal. The loop ends only on disconnect, which cannot happen (both channel ends
//! live in the pool), and the whole job body runs inside `catch_unwind`, so a panic cannot end it
//! either. Nothing decrements the slot count on exit, so were a worker to die anyway the pool
//! would narrow permanently — but no job is stranded by that, because a submitter only ever sends
//! against a token a live worker published.
//!
//! Degraded mode is a knowing trade, not an oversight: when the OS refuses a thread the
//! alternatives are blocking the dropping thread (reinstating the defect at the worst moment) or
//! holding pinned pids in our own queue indefinitely. The child goes to the runtime's orphan
//! handling instead, which is best-effort — the one place this module uses the mechanism it
//! otherwise rejects. Reaching the bound is NOT this case: there the workers exist and are
//! working, so the job queues.
//!
//! Process exit with jobs still queued is benign: the root is already signalled by then, so the
//! worst case is a zombie the OS reaps when the process exits.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

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
    /// Sampled on the dropping thread — see `fault::set_force_teardown_panic`.
    #[cfg(test)]
    pub(crate) force_panic: bool,
}

/// The pool's bulkhead width: a wedged job occupies one worker and no other, so up to this many
/// independently wedged children can be in flight before a further one has to wait. Not a
/// throughput device — an ordinary reap waits microseconds on an already-killed child.
const REAPER_POOL_THREADS: usize = 4;

/// What [`Pool::start_worker`] managed to do about the absence of an idle worker.
enum WorkerStart {
    /// A worker was started; it owes its starter one receive.
    Started,
    /// Every slot is taken and none is idle. The job queues — see [`Pool::dispatch`].
    AtBound,
    /// The OS refused the thread. Degraded mode.
    SpawnFailed,
}

/// A bounded set of reaper threads over one MPMC queue.
///
/// **The queue's invariant:** every job sent is backed by a receive no other job can take — either
/// an idle token claimed from a parked worker, or the first receive owed by a worker this submit
/// just started. A worker holds no token while it runs a job, so a wedged one is never sent to.
/// The single exception is the at-bound path, which queues deliberately.
struct Pool {
    tx: crossbeam_channel::Sender<ReapJob>,
    rx: crossbeam_channel::Receiver<ReapJob>,
    /// Workers parked in `recv` that no submitter has claimed. **Published by the worker itself**,
    /// so a thread that failed to start cannot contribute one — which is what makes this a
    /// liveness signal rather than a proxy for one.
    idle: AtomicUsize,
    /// Slots taken by a started-or-starting thread. The CAP, and only the cap: a reservation here
    /// never authorises a send.
    spawned: AtomicUsize,
    bound: usize,
}

impl Pool {
    fn new(bound: usize) -> Pool {
        let (tx, rx) = crossbeam_channel::unbounded();
        Pool {
            tx,
            rx,
            idle: AtomicUsize::new(0),
            spawned: AtomicUsize::new(0),
            bound,
        }
    }

    /// Take one idle token, or report that no parked worker is available. An unbounded CAS retry,
    /// not a budget.
    fn claim_idle(&self) -> bool {
        self.idle
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
    }

    fn start_worker(&'static self, force_spawn_failure: bool) -> WorkerStart {
        let reserved = self
            .spawned
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.bound).then_some(n + 1)
            })
            .is_ok();
        if !reserved {
            return WorkerStart::AtBound;
        }
        // The seam sits on the spawn itself, so the branch a real thread exhaustion takes is the
        // branch under test. A constant `false` outside test builds.
        let spawned = if force_spawn_failure {
            Err(std::io::Error::other("forced thread-spawn failure (test seam)"))
        } else {
            std::thread::Builder::new()
                .name("cosca-reaper".to_string())
                .spawn(move || self.work())
                .map(|_| ())
        };
        match spawned {
            Ok(()) => WorkerStart::Started,
            Err(e) => {
                // Roll the slot back. No job was sent — the caller still holds it — so nothing is
                // stranded, and no concurrent submitter was told a worker exists.
                self.spawned.fetch_sub(1, Ordering::AcqRel);
                log::error!("spawning a reaper thread failed: {e}");
                WorkerStart::SpawnFailed
            }
        }
    }

    fn work(&'static self) {
        // The first receive is owed to the thread that started this worker, so no token is
        // published for it; every later park publishes one.
        let mut publish = false;
        loop {
            if publish {
                self.idle.fetch_add(1, Ordering::Release);
            }
            publish = true;
            match self.rx.recv() {
                // The guard the module header promises: a panic anywhere in the job.
                Ok(job) => {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_teardown(job)));
                }
                Err(_) => break,
            }
        }
        debug_assert!(false, "reaper channel disconnected");
    }

    /// Hand the job to a worker. **Identity-preserving:** the job stays in hand until a receive is
    /// secured for it, and is never enqueued speculatively and never dequeued — with a shared FIFO
    /// what you dequeue is not what you enqueued, so a thread recovering "a" job would release
    /// another thread's child and report it on the wrong probe.
    fn dispatch(&'static self, job: ReapJob) {
        #[cfg(test)]
        let job = {
            let mut job = job;
            job.force_panic = fault::take_force_teardown_panic(); // sampled here — see `fault`
            job
        };
        #[cfg(test)]
        let force_spawn_failure = fault::take_force_spawn_failure();
        #[cfg(not(test))]
        let force_spawn_failure = false;

        if !self.claim_idle() {
            match self.start_worker(force_spawn_failure) {
                WorkerStart::Started => {}
                WorkerStart::AtBound => {
                    // Queue rather than release. Every worker being busy is the ordinary shape of
                    // a burst of short-lived children, each finishing in microseconds; and if they
                    // are instead all wedged, the runtime's orphan handling could not reap this
                    // child either, so releasing would trade a delay for a leak.
                    log::debug!(
                        "reaper pool at its bound ({}); child {} waits for a worker",
                        self.bound,
                        job.pid
                    );
                }
                WorkerStart::SpawnFailed => {
                    release(job);
                    return;
                }
            }
        }
        if let Err(e) = self.tx.send(job) {
            // Unreachable: both ends live in the pool, which outlives the process. Even so,
            // recover the job rather than dropping it unordered.
            debug_assert!(false, "the reaper channel cannot disconnect");
            release(e.into_inner());
        }
    }
}

fn pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(|| Pool::new(REAPER_POOL_THREADS))
}

pub(crate) fn submit(job: ReapJob) {
    pool().dispatch(job);
}

/// Degraded mode — see the module header for why this is the least bad option. `error`, not
/// `warn`: the crate is knowingly giving up its own guarantee.
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
pub(crate) fn run_teardown(job: ReapJob) {
    #[cfg(test)]
    let origin = job.origin;
    #[cfg(test)]
    let probe = job.probe;
    #[cfg(test)]
    let force_panic = job.force_panic;
    let mut proc = job.proc;
    let attached = job.attached;
    let pipes = job.pipes;
    let owned_std = job.owned_std;
    let pid = job.pid;

    #[cfg(test)]
    if let Some(p) = probe.as_ref() {
        let _ = p.started.send(std::thread::current().id());
    }

    // Executing elsewhere ⇒ the test may hold the teardown until it has observed the
    // not-yet-reaped state. Executing on the dropping thread means the teardown was inlined, so
    // skipping the gate lets that broken world fail on an assertion instead of deadlocking.
    #[cfg(test)]
    if std::thread::current().id() != origin {
        if let Some(p) = probe.as_ref() {
            let _ = p.gate.recv(); // a dropped sender is also a release
        }
    }

    // `proc` is BORROWED into this inner region, never moved, so a panic in the wait cannot
    // destroy a resource whose release the code below still owns and orders. The worker wraps the
    // whole call as well, which is what keeps the loop alive.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[cfg(test)]
        if force_panic {
            panic!("forced teardown panic (test seam)");
        }
        proc.wait_and_reap(pid);
    }));
    if outcome.is_err() {
        log::error!("reaping child {pid} panicked; releasing its resources anyway");
    }

    // `Child`'s declaration order — `proc` first, so the pid stays pinned for the whole wait and
    // every other release stays ordered after the reap.
    drop(proc);
    drop(attached);
    drop(pipes);
    drop(owned_std);

    #[cfg(test)]
    if let Some(p) = probe {
        let _ = p.outcome.send(if outcome.is_err() {
            test_probe::ReapOutcome::Panicked
        } else {
            test_probe::ReapOutcome::Reaped(std::thread::current().id())
        });
    }
}

/// Guaranteed synchronous teardown for the spawn error paths: kill the child, then block until
/// it has exited. `done_ok` says whether an already-`Done` child is legal here: `true` for a
/// caller whose child the user may have `wait()`ed, `false` for the spawn-error path (the child
/// was never awaited).
/// **Invariant:** no `wait()` future for this child is in flight when this runs.
pub(crate) fn reap_now(child: &mut ::tokio::process::Child, pid: u32, done_ok: bool) {
    // `start_kill` bounds the wait below — it MUST run in release (NOT inside `debug_assert!`,
    // whose argument is stripped in release). A no-op on an already-exited child.
    let killed = child.start_kill();
    debug_assert!(killed.is_ok(), "start_kill of an owned child should not fail");
    // A failed start_kill means this is not a live process to wait on (ESRCH = already exited;
    // EPERM is impossible for our own child) — skip, so a kill failure can never turn the bounded
    // exit-wait into an unbounded block. tokio's field-drop reaps any leftover zombie.
    if killed.is_err() {
        return;
    }
    wait_and_reap(child, pid, done_ok);
}

/// The wait-then-reap half of [`reap_now`], with no kill of its own. On Unix we wait with
/// `WNOWAIT` (NOT reaping), so tokio's own `Child` field-drop reaps the zombie synchronously in
/// its drop (its `try_wait` returns `Ok(Some)`, not a park-dependent orphan enqueue). We only
/// wait while tokio still owns the child (`id().is_some()`), which pins the pid; once tokio is
/// `Done` (a prior `wait()` reaped it), the pid may be recycled and we must not wait on it.
pub(crate) fn wait_and_reap(child: &mut ::tokio::process::Child, pid: u32, done_ok: bool) {
    // tokio `Done` ⇒ already reaped, pid possibly recycled ⇒ nothing to do (the recycled-pid wait
    // hazard the sync side avoids by holding a handle).
    if child.id().is_none() {
        debug_assert!(
            done_ok,
            "wait_and_reap found an already-reaped child where one was impossible"
        );
        return;
    }
    #[cfg(unix)]
    {
        // `nix` doesn't expose `waitid` on macOS (0.31 configures it out), so call `libc::waitid`
        // directly (WEXITED | WNOWAIT: block until exit without reaping) — portable across every Unix
        // target and the identical syscall.
        debug_assert!(pid <= i32::MAX as u32, "pid {pid} exceeds i32::MAX");
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: a well-formed `waitid` call; `info` is a valid, owned, zeroed `siginfo_t` the
            // kernel fills in. WNOWAIT leaves the child reapable for tokio's in-drop reap.
            let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // id() was Some above (tokio un-reaped ⇒ pid pinned), so no ECHILD / other errno should
            // occur — a debug tripwire, with a safe release `break`.
            debug_assert!(false, "waitid in wait_and_reap failed unexpectedly: {err}");
            break;
        }
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
        let _ = pid;
        let h = child.raw_handle().expect("tokio owns the handle while id() is Some");
        // SAFETY: tokio owns and (on its field-drop) closes the handle; we only wait on it.
        // INFINITE is bounded by the kill the caller already issued.
        let waited = unsafe { WaitForSingleObject(HANDLE(h), INFINITE) };
        debug_assert!(
            waited == WAIT_OBJECT_0,
            "wait_and_reap did not observe the child's exit: {waited:?}"
        );
    }
}

/// Fault seams for the three off-nominal paths. Take-semantics, matching `crate::wait::fault`.
/// Each is CONSUMED on the dropping thread; only the panic flag's effect is deferred, by riding
/// in the job.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    thread_local! {
        static FORCE_SPAWN_FAILURE: Cell<bool> = const { Cell::new(false) };
        static FORCE_TEARDOWN_PANIC: Cell<bool> = const { Cell::new(false) };
        static FORCE_KILL_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Force the NEXT reaper-thread spawn on THIS thread to fail. Sits on the `Builder::spawn`
    /// call itself, so the branch a real thread exhaustion takes is the branch under test — the
    /// slot reservation, its rollback and the release are all genuinely executed. A test drives
    /// it through a pool of its own, where "no worker is idle" is a fact rather than a fake.
    pub(crate) fn set_force_spawn_failure(on: bool) {
        FORCE_SPAWN_FAILURE.with(|f| f.set(on));
    }
    pub(crate) fn take_force_spawn_failure() -> bool {
        FORCE_SPAWN_FAILURE.with(|f| f.replace(false))
    }

    /// Force the NEXT teardown to panic. Sampled at DISPATCH time into `ReapJob::force_panic`:
    /// the region it models runs on a worker, where a thread-local armed on the test thread is
    /// invisible.
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
        /// The executing worker's id, sent on entry to the teardown and BEFORE the gate — the
        /// only way to observe which worker a job occupies while it is still wedged on it.
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
