//! The wait-and-reap half of the async [`Child`](super::Child)'s teardown.
//!
//! `Drop` signals the tree and the root on the dropping thread, then hands what remains to a
//! bounded pool of reaper threads.

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
    /// Sampled at submit time on the dropping thread — a thread-local armed by the test is
    /// invisible on a worker.
    #[cfg(test)]
    pub(crate) force_panic: bool,
}

/// A wedged child occupies one worker and no other; the rest keep servicing their own jobs. Not
/// a throughput device — an ordinary reap waits microseconds on an already-killed child.
const REAPER_POOL_THREADS: usize = 4;

/// Reserved worker slots. Monotone: a reserved slot is released only when the spawn itself
/// fails, and a started worker never exits.
static LIVE: AtomicUsize = AtomicUsize::new(0);

type Queue = (crossbeam_channel::Sender<ReapJob>, crossbeam_channel::Receiver<ReapJob>);

/// Both ends live here for the process's life, so the channel can never disconnect.
fn queue() -> &'static Queue {
    static QUEUE: OnceLock<Queue> = OnceLock::new();
    QUEUE.get_or_init(crossbeam_channel::unbounded)
}

fn worker(rx: crossbeam_channel::Receiver<ReapJob>) {
    for job in rx {
        run_teardown(job);
    }
    debug_assert!(false, "reaper channel disconnected");
}

/// ONE spawn attempt — no loop, no retry budget. The bound is on live workers; the retry is one
/// attempt per submit while there are none.
fn ensure_worker() -> bool {
    let live = LIVE.load(Ordering::Acquire);
    // Grow only when there is nobody at all, or when the queue is already backing up. A burst of
    // short-lived children is serviced by one worker without creating threads for it.
    if live < REAPER_POOL_THREADS && (live == 0 || !queue().0.is_empty()) {
        // Reserve before spawning, so concurrent submits cannot overshoot the bound.
        if LIVE.fetch_add(1, Ordering::AcqRel) < REAPER_POOL_THREADS {
            let rx = queue().1.clone();
            if let Err(e) = std::thread::Builder::new()
                .name("cosca-reaper".to_string())
                .spawn(move || worker(rx))
            {
                LIVE.fetch_sub(1, Ordering::AcqRel);
                log::error!("spawning a reaper thread failed: {e}");
            }
        } else {
            LIVE.fetch_sub(1, Ordering::AcqRel);
        }
    }
    LIVE.load(Ordering::Acquire) > 0
}

/// Hand the job to a worker. **Identity-preserving:** the job stays in hand until a worker is
/// known to exist, and is never enqueued speculatively — with a shared FIFO, what you dequeue is
/// not what you enqueued, so a thread recovering "a" job would release another thread's child and
/// report it on the wrong probe.
pub(crate) fn submit(job: ReapJob) {
    if !ensure_worker() {
        release(job);
        return;
    }
    if let Err(e) = queue().0.send(job) {
        // Unreachable: the receiver lives in a `static` for the process's life. Even so, recover
        // the job rather than dropping it unordered.
        debug_assert!(false, "the reaper channel cannot disconnect");
        release(e.into_inner());
    }
}

/// Degraded mode: no worker exists and the spawn failed. The root is already signalled, so the
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

    // Executing elsewhere ⇒ the test may hold the teardown until it has observed the
    // not-yet-reaped state. Executing on the dropping thread means the teardown was inlined, so
    // skipping the gate lets that broken world fail on an assertion instead of deadlocking.
    #[cfg(test)]
    if std::thread::current().id() != origin {
        if let Some(p) = probe.as_ref() {
            let _ = p.gate.recv(); // a dropped sender is also a release
        }
    }

    // `proc` is BORROWED into the region, never moved: an unwind must not destroy a resource
    // whose release the outer code still owns and orders.
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
