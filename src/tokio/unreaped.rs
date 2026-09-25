//! The async mirror of [`cosca::Unreaped`](crate::Unreaped): a child a failed
//! [`cosca::tokio::Command::spawn`](crate::tokio::Command::spawn) could not kill, handed back.

use std::process::ExitStatus;

use crate::child::unreaped::{Held, Retained};

/// A child a failed spawn created but could not kill — a setuid child refuses the kill with
/// `EPERM` — handed back to the caller in
/// [`cosca::tokio::Error::Unreaped`](crate::tokio::Error). cosca keeps no background
/// thread to reap it: the caller does, in its own scope.
///
/// [`wait`](Unreaped::wait) waits for the child's exit without blocking the runtime, on the handle
/// it holds — tokio's own child; on Linux a pidfd, on macOS a kqueue filter on its pid, on Windows
/// its process handle — then reaps it. It takes
/// `&mut self`, so a cancelled `wait` — the losing arm of a `select!` — leaves the caller still
/// holding the child. [`leak`](Unreaped::leak) gives the child up without waiting for it.
///
/// **Its `Drop` blocks** the thread it runs on until the child exits, then reaps it, so it never
/// lingers as a zombie. Don't let it drop implicitly on a runtime thread: `wait().await` it, move
/// it to [`spawn_blocking`](::tokio::task::spawn_blocking), or `leak()` it.
///
/// On Unix a `wait` can see the child exit before it is reapable: macOS reports the exit before
/// the zombie exists, and a tracer holds a traced child until it releases it. The child then moves
/// to a blocking-pool task that waits until it is reapable and reaps it. That wait is bounded by
/// the exit, which has happened, and by the tracer's release. A `wait` cancelled meanwhile leaves
/// the task holding the child: the next `wait` takes its result, `Drop` blocks until the task has
/// finished, and `leak` lets it finish and disarms what the child retained.
///
/// If the runtime shuts down before that task ever runs, it is dropped unrun, still `NotStarted`.
/// `wait` and `Drop` tell that apart from a real report by reclaiming the child back from
/// `NotStarted` directly: `wait` returns an error ("the blocking reap never ran") with the child
/// still held and unreaped for a later `wait`, `leak`, or `Drop`; `Drop` reclaims it the same way
/// and waits for it synchronously instead of hanging on a task that will never report.
///
/// A successful reap moves what it retained to a second, similar blocking-pool task — see
/// [`reaped`](Unreaped::reaped) — whose own claim slot ([`RetainedDrain`]) this holds in
/// `draining`. That move, and the `wait` awaiting it, sets `status` first: a cancelled `wait`
/// never loses the exit status to the drain it queued, only re-awaits that drain on its next call
/// before returning the status it already has. `leak` and `Drop` read `draining` the same way they
/// read `blocking` — `Drop` blocks on it, `leak` disarms an unclaimed one.
#[must_use = "an unkillable child must be waited for or explicitly leaked"]
pub struct Unreaped {
    /// `None` once reaped or leaked, so `Drop` does nothing more. Boxed, so an
    /// [`Error`](crate::error::Error) that carries it stays small.
    held: Option<Box<Held>>,
    /// Released after the child's reap. `None` once a successful reap has moved it to `draining`.
    retained: Option<Box<Retained>>,
    pid: u32,
    /// The status of a child `wait` reaped, returned again by a later `wait`. Set before
    /// `retained` moves to `draining` (see [`reaped`](Unreaped::reaped)), so a cancelled `wait`
    /// never loses it.
    status: Option<ExitStatus>,
    /// Why a wait released the child for uncertain ownership, reported by a later `wait`.
    released: Option<String>,
    /// A blocking-pool task that owns the child — and what it retains — while it waits for the
    /// child to become reapable and reaps it: what it reports, and the signal that it has. A
    /// cancelled `wait` leaves both here for the next one, and `leak` and `Drop` read them too.
    #[cfg(unix)]
    blocking: Option<(std::sync::Arc<BlockingReap>, ::tokio::sync::oneshot::Receiver<()>)>,
    /// A blocking-pool task dropping what a successful reap retained — see
    /// [`reaped`](Unreaped::reaped). A cancelled `wait` leaves it here for the next one to
    /// re-await; `leak` and `Drop` read it too. Cross-platform: a successful reap on Windows moves
    /// its retained job object here exactly as a Unix reap moves its cgroup leaf.
    draining: Option<(std::sync::Arc<RetainedDrain>, ::tokio::sync::oneshot::Receiver<()>)>,
    /// Run as `Drop` starts to block on a blocking reap or a drain, for a test. `draining` itself
    /// is cross-platform, but every test that sets this hook still drives a real Unix child
    /// through `libc::waitid`; gated to match, so an unused-on-Windows test seam does not fail a
    /// Windows `-D warnings` build. Widen this (and its call in the `draining` arm of `Drop`) back
    /// to `#[cfg(test)]` once a Windows test needs it.
    #[cfg(all(test, unix))]
    before_blocking_drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

/// What a blocking reap reports to its holder, and the condition `Drop` blocks on until it has.
#[cfg(unix)]
struct BlockingReap {
    state: std::sync::Mutex<ReapState>,
    finished: std::sync::Condvar,
}

#[cfg(unix)]
enum ReapState {
    /// The task has not yet claimed the child: still queued for a blocking-pool thread, or
    /// dropped (a runtime shutdown) before it ever ran. Reclaimable directly, without waiting for
    /// a thread that a saturated pool may never free: see `reclaim_before_start`.
    NotStarted(Box<Held>, Option<Box<Retained>>),
    /// The task has claimed the child and is running (or, having panicked mid-run, is about to
    /// report `None` from its own `Drop`).
    Running,
    /// The child and what it retained, handed back, and how the reap went: `None` if the task
    /// claimed the child, then ended without finishing — it panicked after claiming it.
    Finished(
        Box<Held>,
        Option<Box<Retained>>,
        Option<std::io::Result<Option<ExitStatus>>>,
    ),
    /// `leak` gave the child up while the task held it: the task disarms what it retained.
    Leaked,
    /// The holder took what the task handed back, or reclaimed it directly.
    Taken,
}

#[cfg(unix)]
impl BlockingReap {
    fn state(&self) -> std::sync::MutexGuard<'_, ReapState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Block until the task has finished, and take what it handed back. Only correct to call once
    /// the task has claimed the child (state is no longer `NotStarted`): a task still queued may
    /// be behind the very thread that would call this — calling it too early panics (this
    /// `debug_assert`, or `take_reap`'s own `unreachable!` past it in release) rather than
    /// deadlocking, since the state stays `NotStarted`, never reaching `Running` — check
    /// `reclaim_before_start` first.
    fn take_blocking(&self) -> ReapState {
        let mut state = self.state();
        debug_assert!(
            !matches!(*state, ReapState::NotStarted(..)),
            "take_blocking on a task that has not claimed the child would wait on pool scheduling"
        );
        while matches!(*state, ReapState::Running) {
            state = self
                .finished
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        std::mem::replace(&mut *state, ReapState::Taken)
    }

    /// Take the child back directly, without waiting for the task, if it has not yet claimed it —
    /// still queued, or dropped unrun. The task, if it later runs anyway, finds the child already
    /// gone and does nothing (see `ReapTask::run`).
    #[cfg(unix)]
    fn reclaim_before_start(&self) -> Option<(Box<Held>, Option<Box<Retained>>)> {
        let mut state = self.state();
        if !matches!(*state, ReapState::NotStarted(..)) {
            return None;
        }
        let ReapState::NotStarted(held, retained) = std::mem::replace(&mut *state, ReapState::Taken) else {
            unreachable!("checked above")
        };
        Some((held, retained))
    }
}

/// The blocking-pool task's hold on the child. Whether it runs or is dropped unrun, it reports to
/// the holder exactly once — but only once it has claimed the child from `NotStarted`; a task
/// beaten to the claim by a direct reclaim does nothing at all.
#[cfg(unix)]
struct ReapTask {
    shared: std::sync::Arc<BlockingReap>,
    /// `Some` only once `run` has claimed the child from `NotStarted`, until it reports.
    held: Option<Box<Held>>,
    retained: Option<Box<Retained>>,
    signal: Option<::tokio::sync::oneshot::Sender<()>>,
    /// Run once, right after `claim` succeeds (state is now `Running`, on this task's own
    /// blocking-pool thread), for a test. Lets a test gate the task there, so it can call `leak`
    /// while state is deterministically `Running` — proving the `Running -> Leaked` arm without
    /// racing the task's own progress to `Finished`.
    #[cfg(test)]
    after_claim: Option<Box<dyn FnOnce() + Send + Sync>>,
}

#[cfg(unix)]
impl ReapTask {
    fn run(mut self) {
        if !self.claim() {
            // Reclaimed directly before this task was scheduled: nothing to do.
            return;
        }
        #[cfg(test)]
        if let Some(hook) = self.after_claim.take() {
            hook();
        }
        let held = self.held.as_mut().expect("claimed above");
        let reaped = crate::child::unreaped::block_until_reapable(held.pid()).and_then(|()| held.try_reap());
        self.report(Some(reaped));
    }

    /// Atomically take the child from `NotStarted`, transitioning to `Running`. `false` if a
    /// direct reclaim already took it.
    fn claim(&mut self) -> bool {
        let mut state = self.shared.state();
        match std::mem::replace(&mut *state, ReapState::Running) {
            ReapState::NotStarted(held, retained) => {
                self.held = Some(held);
                self.retained = retained;
                true
            }
            other => {
                *state = other;
                false
            }
        }
    }

    fn report(&mut self, reaped: Option<std::io::Result<Option<ExitStatus>>>) {
        let held = self.held.take().expect("reported once, after claiming");
        let retained = self.retained.take();
        let mut state = self.shared.state();
        match *state {
            ReapState::Running => *state = ReapState::Finished(held, retained, reaped),
            // Given up: the reap, if it ran, is done, and nothing the child leads is killed.
            ReapState::Leaked => {
                (*held).release();
                if let Some(retained) = retained {
                    retained.attached.disarm();
                }
            }
            ReapState::NotStarted(..) | ReapState::Finished(..) | ReapState::Taken => {
                unreachable!("a blocking reap reports once, after claiming")
            }
        }
        drop(state);
        self.shared.finished.notify_all();
        if let Some(signal) = self.signal.take() {
            // The holder may have stopped listening: it leaked or dropped the child.
            let _ = signal.send(());
        }
    }
}

#[cfg(unix)]
impl Drop for ReapTask {
    fn drop(&mut self) {
        // `held` is `Some` only once `claim` succeeded and before `report` runs: a task never
        // scheduled, or beaten to the claim by a direct reclaim, has nothing to report.
        if self.held.is_some() {
            self.report(None);
        }
    }
}

/// What a retained-drain task reports to its holder, and the condition `Drop` blocks on until it
/// has. The cross-platform twin of `BlockingReap`, for the second blocking-pool task a successful
/// reap moves what it retained to (see [`Unreaped::reaped`]) rather than dropping it inline on
/// whatever thread `wait` runs on, which may be a runtime worker.
struct RetainedDrain {
    state: std::sync::Mutex<DrainState>,
    finished: std::sync::Condvar,
}

enum DrainState {
    /// The task has not yet claimed what it must drop: still queued for a blocking-pool thread, or
    /// dropped (a runtime shutdown) before it ever ran. Reclaimable directly, without waiting for a
    /// thread that a saturated pool may never free: see `reclaim_before_start`.
    NotStarted(Box<Retained>),
    /// The task has claimed it, and by that same claim has committed to kill-through (see
    /// `DrainTask::claim`): running the real teardown, unbounded on a Linux cgroup drain (see
    /// `Retained`'s doc). `leak` arriving this late can no longer change anything — only
    /// `NotStarted` still can, by reclaiming directly (see `Unreaped::leak`).
    Committed,
    /// The task has finished: dropped what it retained, killing through it. Nothing is handed back
    /// — unlike `ReapTask`, which only ever defers the drop to whoever later takes `Finished`, this
    /// task performs it itself; see `DrainTask::finish`.
    Finished,
    /// The holder took it back directly (before the task ever claimed it), or the task's report was
    /// observed.
    Taken,
}

impl RetainedDrain {
    fn state(&self) -> std::sync::MutexGuard<'_, DrainState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Block until the task has finished dropping what it retained — the real kill-through, since a
    /// claim already commits to that (see `DrainState`'s doc) — for `Drop`. Only correct to call once
    /// the task has claimed it (state is no longer `NotStarted`): a task still queued may be behind
    /// the very thread that would call this — calling it too early panics (this `debug_assert`)
    /// rather than deadlocking, since the state stays `NotStarted`, never reaching `Committed` —
    /// check `reclaim_before_start` first.
    fn take_blocking(&self) {
        let mut state = self.state();
        debug_assert!(
            !matches!(*state, DrainState::NotStarted(..)),
            "take_blocking on a task that has not claimed what it must drop would wait on pool scheduling"
        );
        while matches!(*state, DrainState::Committed) {
            state = self
                .finished
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *state = DrainState::Taken;
    }

    /// Take what must be dropped back directly, without waiting for the task, if it has not yet
    /// claimed it — still queued, or dropped unrun. The task, if it later runs anyway, finds it
    /// already gone and does nothing (see `DrainTask::run`).
    fn reclaim_before_start(&self) -> Option<Box<Retained>> {
        let mut state = self.state();
        if !matches!(*state, DrainState::NotStarted(..)) {
            return None;
        }
        let DrainState::NotStarted(retained) = std::mem::replace(&mut *state, DrainState::Taken) else {
            unreachable!("checked above")
        };
        Some(retained)
    }
}

/// The blocking-pool task's hold on what a successful reap retained. Whether it runs or is dropped
/// unrun, it reports to the holder exactly once — but only once it has claimed it from
/// `NotStarted`; a task beaten to the claim by a direct reclaim does nothing at all.
struct DrainTask {
    shared: std::sync::Arc<RetainedDrain>,
    /// `Some` only once `run` has claimed it from `NotStarted`, until `finish` takes it.
    retained: Option<Box<Retained>>,
    signal: Option<::tokio::sync::oneshot::Sender<()>>,
    /// Run once, right after `claim` succeeds (state is now `Committed`, on this task's own
    /// blocking-pool thread), for a test. Lets a test gate the task there, so it can call `leak`,
    /// or observe `Drop` blocking on a genuinely still-running drain, deterministically rather than
    /// racing the task's own progress to `Finished`.
    #[cfg(test)]
    after_claim: Option<Box<dyn FnOnce() + Send + Sync>>,
    /// Run once, right before `finish` drops what it retained — the real kill-through — for a
    /// test. Cross-platform, unlike `crate::containment::cgroup::fault::set_next_kill_thread_hook`,
    /// which reaches this same moment only on a Linux cgroup leaf, from inside its `cgroup.kill`
    /// write; this reaches it for every `Attached` kind, on every platform.
    #[cfg(test)]
    before_drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl DrainTask {
    fn run(mut self) {
        if !self.claim() {
            // Reclaimed directly before this task was scheduled: nothing to do.
            return;
        }
        #[cfg(test)]
        if let Some(hook) = self.after_claim.take() {
            hook();
        }
        self.finish();
    }

    /// Atomically take what must be dropped from `NotStarted`, transitioning straight to
    /// `Committed`: claiming and committing to kill-through are the same step (see `DrainState`'s
    /// doc) — there is no window left between them for `leak`, racing in, to still change anything
    /// (see `Unreaped::leak`). `false` if a direct reclaim already took it.
    fn claim(&mut self) -> bool {
        let mut state = self.shared.state();
        match std::mem::replace(&mut *state, DrainState::Committed) {
            DrainState::NotStarted(retained) => {
                self.retained = Some(retained);
                true
            }
            other => {
                *state = other;
                false
            }
        }
    }

    /// Run the real teardown — the containment teardown proper, unbounded on a Linux cgroup drain
    /// (see `Retained`'s doc) — and only THEN settle the state to `Finished` and notify.
    ///
    /// Unlike `ReapTask::report`, which only ever hands its result back for a later consumer to
    /// drop, this task performs the drop itself: notifying any earlier — before the drop, as an
    /// initial version of this did — would tell a waiter (`wait`'s `await_draining`, or `Drop`'s
    /// `take_blocking`) the teardown is done while it is, in fact, still running on this thread.
    /// That earlier ordering is what let `wait` observe a cgroup leaf's `cgroup.kill` not yet
    /// written right after a successful reap — caught by
    /// `probe_tokio_wait_returns_only_after_the_retained_drop_ran` in `leaf_tests.rs`, and by this
    /// module's own `wait_returns_only_after_the_retained_drop_ran` on every platform. A panic
    /// mid-drop cannot hang either waiter regardless of this ordering: `catch_unwind` below always
    /// reaches the settle-and-notify step that follows it.
    fn finish(&mut self) {
        let retained = self.retained.take().expect("claimed above, reported once");
        #[cfg(test)]
        if let Some(hook) = self.before_drop.take() {
            hook();
        }
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(retained))).is_err() {
            // A consumer's `Log` impl is untrusted: keep its own panic from unwinding out of a
            // blocking-pool task, the same as `crate::tokio::child::reaper`'s teardown does.
            let _ = std::panic::catch_unwind(|| {
                log::warn!("releasing what a reaped child retained panicked on the blocking pool");
            });
        }
        let mut state = self.shared.state();
        *state = DrainState::Finished;
        drop(state);
        self.shared.finished.notify_all();
        if let Some(signal) = self.signal.take() {
            // The holder may have stopped listening: it leaked or dropped the child.
            let _ = signal.send(());
        }
    }
}

impl Drop for DrainTask {
    fn drop(&mut self) {
        // `retained` is `Some` only once `claim` succeeded and before `finish` runs: a task never
        // scheduled, or beaten to the claim by a direct reclaim, has nothing to report. `run`'s own
        // structure — claim, then finish, with no fallible code between — makes this `if` false in
        // practice; it stays, the same as `ReapTask`'s twin above, because assuming that instead of
        // checking it would silently skip the real kill-through rather than run it.
        if self.retained.is_some() {
            self.finish();
        }
    }
}

/// Why an async wait did not reap: the child's ownership became uncertain, so it must be released;
/// or its exit cannot be awaited without blocking, and the caller keeps it.
enum Failed {
    /// On Unix, a genuine `ECHILD` (see `crate::child::unreaped::releases_ownership`). On Windows
    /// a held handle always pins its process, so nothing in production code constructs this here
    /// — only the `set_force_uncertain` test seam does, cross-platform, for a shared test.
    #[cfg_attr(windows, allow(dead_code))]
    Uncertain(std::io::Error),
    Unawaitable(std::io::Error),
    /// Its exit is certain, but it is not reapable yet: see `Unreaped::wait`'s blocking reap.
    #[cfg(unix)]
    NotYetReapable,
}

impl Unreaped {
    /// Hold `held`, which its one check did not find exited or reaped elsewhere.
    #[cfg(test)]
    pub(crate) fn new(held: Held) -> Unreaped {
        Unreaped::with_retained(held, None)
    }

    /// Hold `held`, which its one check did not find exited or reaped elsewhere, and `retained`
    /// until its reap. A raw Windows handle is held by the async backend, so `wait` can await it.
    pub(crate) fn with_retained(held: Held, retained: Option<Retained>) -> Unreaped {
        let held = awaitable(held);
        Unreaped {
            pid: held.pid(),
            held: Some(Box::new(held)),
            retained: retained.map(Box::new),
            status: None,
            released: None,
            #[cfg(unix)]
            blocking: None,
            draining: None,
            #[cfg(all(test, unix))]
            before_blocking_drop: None,
        }
    }

    /// The async mirror of a child the sync teardown handed back.
    pub(crate) fn from_sync(child: crate::Unreaped) -> Unreaped {
        let (held, retained) = child.into_parts();
        Unreaped::with_retained(held, retained)
    }

    /// The child's process id. It stays this child's until the child is reaped.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for the child to exit, then reap it and return its status; a later call returns the
    /// same status. Cancel-safe: dropping the future before it completes leaves the child held.
    /// Needs the runtime's IO driver.
    ///
    /// Only a wait that finds the child's ownership uncertain — something else reaped it —
    /// releases it. Any other failure — an exit watch that could not be set up, a runtime shutting
    /// down, a Linux kernel with no pidfd for it — says nothing about the child: the caller keeps
    /// it, to wait again or drop on a blocking thread.
    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.status {
            // A previous, cancelled wait may have left what the child retained still draining: a
            // `wait` that returns `Ok` re-awaits it first (see `await_draining`), so it is never
            // left merely queued to settle. That is not the same as fully settled, though: if the
            // blocking pool's runtime shut down before the task ever claimed what it must drop,
            // `await_draining` reclaims it back into `self.retained` unsettled, still armed, for a
            // later `Drop` or `leak` to settle instead (M1: `leak` must still disarm it there).
            self.await_draining().await;
            return Ok(status);
        }
        #[cfg(unix)]
        if self.blocking.is_none() {
            // `leak` consumes the handle, so a missing child was released by an earlier wait.
            let Some(held) = self.held.as_mut() else {
                return Err(self.released_error());
            };
            match wait_on(held).await {
                Ok(status) => {
                    let status = self.reaped(status);
                    self.await_draining().await;
                    return Ok(status);
                }
                Err(Failed::Unawaitable(e)) => return Err(e),
                Err(Failed::Uncertain(e)) => return Err(self.release(e)),
                // The child — and what it retains — moves to a blocking-pool task, which waits
                // for it to become reapable and reaps it. That wait is bounded by the exit, which
                // has happened, and by any tracer's release, not by this process, so it never runs
                // on a runtime worker. The task owns the child, so no wait there is keyed on a pid
                // the holder could reap and free.
                Err(Failed::NotYetReapable) => {
                    let held = self.held.take().expect("checked above");
                    let retained = self.retained.take();
                    self.spawn_blocking_reap(held, retained);
                }
            }
        }
        #[cfg(unix)]
        if let Some((_, finished)) = self.blocking.as_mut() {
            // Cancel-safe: a dropped wait leaves the receiver here, and the task keeps the child.
            // The task reports before it signals, or drops the sender; either ends this await.
            let _ = finished.await;
            let (shared, _) = self.blocking.take().expect("awaited above");
            // The task may never have claimed the child at all: a runtime shutting down drops a
            // still-queued task without running it, which drops `finished`'s sender too, so the
            // `await` above resolves the same way a real report does. Only `reclaim_before_start`
            // tells the two apart; `take_blocking` past this point would panic instead — its own
            // `debug_assert` in a debug build, or `take_reap`'s `unreachable!` past it in release.
            if let Some((held, retained)) = shared.reclaim_before_start() {
                self.held = Some(held);
                self.retained = retained;
                return Err(std::io::Error::other("the blocking reap never ran"));
            }
            let taken = shared.take_blocking();
            return self.take_reap(taken).await;
        }
        #[cfg(windows)]
        {
            let Some(held) = self.held.as_mut() else {
                return Err(self.released_error());
            };
            return match wait_on(held).await {
                Ok(status) => {
                    let status = self.reaped(status);
                    self.await_draining().await;
                    Ok(status)
                }
                Err(Failed::Uncertain(e)) => Err(self.release(e)),
                Err(Failed::Unawaitable(e)) => Err(e),
            };
        }
        #[cfg(unix)]
        unreachable!("a wait either finishes, or hands its child to a blocking reap it then awaits")
    }

    /// Hand `held` (and `retained`) to a fresh blocking-pool task that waits for it to become
    /// reapable and reaps it, recording the new task in `self.blocking`.
    #[cfg(unix)]
    fn spawn_blocking_reap(&mut self, held: Box<Held>, retained: Option<Box<Retained>>) {
        let shared = std::sync::Arc::new(BlockingReap {
            state: std::sync::Mutex::new(ReapState::NotStarted(held, retained)),
            finished: std::sync::Condvar::new(),
        });
        let (signal, finished) = ::tokio::sync::oneshot::channel();
        let task = ReapTask {
            shared: shared.clone(),
            held: None,
            retained: None,
            signal: Some(signal),
            #[cfg(test)]
            after_claim: fault::take_after_claim(),
        };
        // The task reports through `shared`, run or not, so its handle is not needed.
        drop(::tokio::task::spawn_blocking(move || task.run()));
        self.blocking = Some((shared, finished));
    }

    /// Take back what a finished blocking reap handed back, and settle the child as its reap went.
    #[cfg(unix)]
    async fn take_reap(&mut self, taken: ReapState) -> std::io::Result<ExitStatus> {
        let ReapState::Finished(held, retained, reaped) = taken else {
            unreachable!("only a leak stops a blocking reap from handing the child back, and it consumes the holder")
        };
        self.held = Some(held);
        self.retained = retained;
        match reaped {
            Some(Ok(Some(status))) => {
                let status = self.reaped(status);
                self.await_draining().await;
                Ok(status)
            }
            // Reapable, yet `try_wait` found no exit waiting for it: not something else reaping
            // it first (tokio's own `try_wait` reports a foreign reap as `ECHILD`, not `Ok(None)`
            // — see `crate::child::unreaped`'s module doc), so the child is kept, unreaped, not
            // released: releasing here would zombie-leak it.
            Some(Ok(None)) => Err(std::io::Error::other(
                "the child was reapable, yet its reap found no exit waiting for it",
            )),
            Some(Err(e)) if crate::child::unreaped::releases_ownership(&e) => Err(self.release(e)),
            Some(Err(e)) => Err(e),
            // It claimed the child, then ended without finishing — it panicked mid-reap: the
            // child is held, unreaped.
            None => Err(std::io::Error::other("the blocking reap ended without reaping")),
        }
    }

    /// The same settling `take_reap` does, but synchronous, for `Drop`: a successful reap drops
    /// what it retained inline rather than moving it to the blocking pool. `Drop` is already
    /// documented as blocking the thread it runs on until the child exits, unlike `wait`'s
    /// non-blocking contract, so dropping inline here is no new hazard — only `wait`'s `reaped`
    /// needs the blocking-pool move.
    #[cfg(unix)]
    fn take_reap_sync(&mut self, taken: ReapState) -> std::io::Result<ExitStatus> {
        let ReapState::Finished(held, retained, reaped) = taken else {
            unreachable!("only a leak stops a blocking reap from handing the child back, and it consumes the holder")
        };
        self.held = Some(held);
        self.retained = retained;
        match reaped {
            Some(Ok(Some(status))) => {
                self.held = None;
                self.retained = None;
                self.status = Some(status);
                Ok(status)
            }
            Some(Ok(None)) => Err(std::io::Error::other(
                "the child was reapable, yet its reap found no exit waiting for it",
            )),
            Some(Err(e)) if crate::child::unreaped::releases_ownership(&e) => Err(self.release(e)),
            Some(Err(e)) => Err(e),
            None => Err(std::io::Error::other("the blocking reap ended without reaping")),
        }
    }

    /// Record a reaped child's status, and hand what it retained to a fresh blocking-pool task that
    /// drops it (`spawn_drain`, recorded in `self.draining`). It is left armed until then: its own
    /// teardown belongs after the root's reap (see `Retained`'s doc), so it still kills through a
    /// failed spawn's grandchildren left behind — only a released or leaked child disarms it. An
    /// armed `CgroupLeaf` still occupied drops through `cgroup.kill` and a drain wait, and that wait
    /// is NOT bounded: a member stuck in uninterruptible I/O, or one moved into the leaf after the
    /// kill, can wedge it (see `crate::tokio::child::reaper`'s own doc on the same hazard). So the
    /// drop never runs inline here, on whatever thread called `wait` — which may be a runtime
    /// worker: `spawn_drain` moves it to the blocking pool instead.
    ///
    /// Synchronous, and so trivially cancel-safe: unlike the task it queues, `reaped` itself has no
    /// await point. `status` is set here, before that task is even queued, so a `wait` dropped
    /// while awaiting the drain (`await_draining`) never loses it — a later `wait` returns it
    /// directly, re-awaiting the same drain first.
    fn reaped(&mut self, status: ExitStatus) -> ExitStatus {
        self.held = None;
        self.status = Some(status);
        if let Some(retained) = self.retained.take() {
            self.spawn_drain(retained);
        }
        status
    }

    /// Hand `retained` to a fresh blocking-pool task that drops it (see `reaped`'s doc), recording
    /// the new task in `self.draining`.
    fn spawn_drain(&mut self, retained: Box<Retained>) {
        let shared = std::sync::Arc::new(RetainedDrain {
            state: std::sync::Mutex::new(DrainState::NotStarted(retained)),
            finished: std::sync::Condvar::new(),
        });
        let (signal, finished) = ::tokio::sync::oneshot::channel();
        let task = DrainTask {
            shared: shared.clone(),
            retained: None,
            signal: Some(signal),
            #[cfg(test)]
            after_claim: fault::take_after_drain_claim(),
            #[cfg(test)]
            before_drop: fault::take_before_drain_drop(),
        };
        // The task reports through `shared`, run or not, so its handle is not needed.
        drop(::tokio::task::spawn_blocking(move || task.run()));
        self.draining = Some((shared, finished));
    }

    /// Re-await a drain a previous, cancelled `wait` left running, or one `reaped` just queued
    /// above; a no-op once there is none left to await.
    ///
    /// Awaits through `self.draining.as_mut()`, only taking it out once the await has resolved —
    /// same as `wait`'s own handling of `self.blocking` — so a `wait` cancelled while this itself is
    /// pending leaves `self.draining` right where it was, for the next `wait` (or `Drop`, or `leak`)
    /// to find, rather than dropping it here, unrestored, inside this future's own discarded state.
    ///
    /// If the task never ran at all — a runtime shut down before it was ever scheduled — its
    /// `Arc<RetainedDrain>` is still holding what it would have dropped, `NotStarted`. Simply
    /// letting `self.draining`'s clone of that `Arc` fall out of scope here could make THIS call —
    /// on whatever thread called `wait`, which may be a runtime worker — the one that runs the
    /// drop, if it happens to be the last reference: the exact inline-on-a-runtime-thread hazard
    /// `spawn_drain` exists to avoid. So this reclaims it back into `self.retained` instead, same as
    /// a direct reclaim anywhere else in this module, deferring the drop to `Drop`'s fallback, which
    /// is already documented as safe to block on.
    async fn await_draining(&mut self) {
        let Some((_, finished)) = self.draining.as_mut() else {
            return;
        };
        let _ = finished.await;
        let (shared, _) = self.draining.take().expect("awaited above");
        if let Some(retained) = shared.reclaim_before_start() {
            self.retained = Some(retained);
        }
    }

    /// Release a child whose ownership became uncertain, and return why, as a later `wait` will.
    fn release(&mut self, e: std::io::Error) -> std::io::Error {
        if let Some(held) = self.held.take() {
            (*held).release_uncertain();
        }
        self.released = Some(e.to_string());
        if let Some(retained) = self.retained.take() {
            retained.attached.disarm();
        }
        e
    }

    /// A later wait's error once the child was released.
    fn released_error(&self) -> std::io::Error {
        std::io::Error::other(format!(
            "released: ownership uncertain (reaped elsewhere): {}",
            self.released.as_deref().unwrap_or("an earlier wait released it")
        ))
    }

    /// Block until the blocking reap has finished, without taking its result, for a test.
    ///
    /// Waits through `NotStarted` too: unlike `take_blocking` (production code, which must not
    /// block on a task that may still be queued behind a saturated pool — see its doc), this is a
    /// test helper for a pool with nothing else queued, so the wait is bounded by the task actually
    /// running. `report` is the only notifier, firing once as the task moves straight to
    /// `Finished`; waiting through `NotStarted` (rather than only `Running`, which the task may
    /// never be observed in between one `lock()` and the next) still wakes exactly there.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn block_until_blocking_reap_finished(&self) {
        let (shared, _) = self.blocking.as_ref().expect("a blocking reap holds the child");
        let mut state = shared.state();
        while matches!(*state, ReapState::Running | ReapState::NotStarted(..)) {
            state = shared
                .finished
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Run `hook` as `Drop` starts to block on a blocking reap or a drain, for a test.
    #[cfg(all(test, unix))]
    pub(crate) fn before_blocking_drop(&mut self, hook: Box<dyn FnOnce() + Send + Sync>) {
        self.before_blocking_drop = Some(hook);
    }

    /// Whether a blocking-pool task holds the child, for a test.
    #[cfg(all(test, unix))]
    pub(crate) fn hands_child_to_blocking_task(&self) -> bool {
        self.blocking.is_some() && self.held.is_none()
    }

    /// Whether a blocking-pool task holds what a reap retained, still draining it, for a test.
    /// Every current caller also drives a real Unix child (`libc::waitid`); gated to match `Drop`'s
    /// `before_blocking_drop` seam above, for the same Windows `-D warnings` reason.
    #[cfg(all(test, unix))]
    pub(crate) fn hands_retained_to_draining_task(&self) -> bool {
        self.draining.is_some() && self.retained.is_none()
    }

    /// Give the child up without waiting for it: it runs on, and nothing of cosca's reaps it. A
    /// tokio child goes to tokio's process-global orphan queue, whose reap is best-effort: it runs
    /// only when a live runtime sees a later `SIGCHLD`, and otherwise the child stays a zombie (see
    /// `crate::child::unreaped`'s **Releasing**). Logged at `warn`.
    ///
    /// Nothing the child leads is killed. A cgroup v2 leaf it still occupies is left in place, and
    /// cosca never removes it — not even once the tree has exited: the empty `cosca-*` leaf stays
    /// until the owner of the delegated parent cgroup removes it.
    ///
    /// Leaking a child a cancelled `wait` left with its blocking-pool task does not stop that task:
    /// the child has exited, and the task still reaps it, then disarms what it retained instead of
    /// releasing it. The same does NOT hold for a child a cancelled `wait` already reaped, whose
    /// retained drain a blocking-pool task still has running: a drain already claimed has, by that
    /// same claim, committed to kill-through (see `DrainState`'s doc), and is not recalled — `leak`
    /// disarms it only if it has not yet been claimed; otherwise it returns while the kill-through
    /// it can no longer stop keeps running.
    pub fn leak(mut self) {
        if let Some((shared, _)) = self.draining.take() {
            match shared.reclaim_before_start() {
                // Never claimed by the task: disarm directly, rather than leave it queued behind a
                // blocking pool that may never schedule it.
                Some(retained) => {
                    retained.attached.disarm();
                    log::warn!(
                        "leaking unkillable child {}: disarming what it retained rather than killing \
                         through it, before its drain ran",
                        self.pid
                    );
                }
                // Already claimed: committed to kill-through by that same claim (see `DrainState`'s
                // doc) — a drain already claimed is not recalled. `leak` returns while it runs,
                // rather than wait for a blocking pool that may be saturated.
                None => {
                    log::warn!(
                        "leaking unkillable child {}: a drain already claimed what it retained and \
                         is killing through it on the blocking pool; leak returns without waiting \
                         for it",
                        self.pid
                    );
                }
            }
            return;
        }
        #[cfg(unix)]
        if let Some((shared, _)) = self.blocking.take() {
            let mut state = shared.state();
            match std::mem::replace(&mut *state, ReapState::Taken) {
                // Never claimed by the task: reclaim directly, rather than leave it queued
                // behind a blocking pool that may never schedule it.
                ReapState::NotStarted(held, retained) => {
                    drop(state);
                    (*held).release();
                    if let Some(retained) = retained {
                        retained.attached.disarm();
                    }
                    log::warn!("leaking unkillable child {}, unreaped", self.pid);
                    return;
                }
                ReapState::Running => {
                    *state = ReapState::Leaked;
                    log::warn!(
                        "leaking unkillable child {}: its blocking reap is still waiting for it to become \
                         reapable, and will release what it retained (disarmed, not killed through) once \
                         it finishes",
                        self.pid
                    );
                    return;
                }
                // Finished, unawaited: settle it here, as a leak — nothing the child leads is killed.
                ReapState::Finished(held, retained, reaped) => {
                    drop(state);
                    if let Some(retained) = retained {
                        retained.attached.disarm();
                    }
                    match reaped {
                        Some(Ok(Some(_))) => {
                            (*held).release();
                            log::warn!(
                                "leaking unkillable child {}, already reaped by its blocking reap",
                                self.pid
                            );
                        }
                        Some(Err(e)) if crate::child::unreaped::releases_ownership(&e) => {
                            (*held).release_uncertain();
                            log::warn!(
                                "leaking unkillable child {}, released: something else reaped it",
                                self.pid
                            );
                        }
                        // `Ok(None)` here is reapable yet unreaped, not a foreign reap (only
                        // `ECHILD` reports that — see `crate::child::unreaped`'s module doc):
                        // releasing it would zombie-leak the child, so it is kept, unreaped.
                        Some(Ok(None)) | Some(Err(_)) | None => {
                            (*held).release();
                            log::warn!("leaking unkillable child {}, unreaped", self.pid);
                        }
                    }
                    return;
                }
                ReapState::Leaked | ReapState::Taken => unreachable!("a holder leaks once"),
            }
        }
        // These are independent: a cancelled wait can leave `retained` reclaimed here (see
        // `await_draining`'s doc, above) with `held` already `None` from an earlier successful
        // reap. Disarm whichever is present — M1: `held`'s absence must not skip `retained`'s.
        let held = self.held.take();
        let retained = self.retained.take();
        if held.is_some() || retained.is_some() {
            if let Some(held) = held {
                (*held).release();
            }
            if let Some(retained) = retained {
                retained.attached.disarm();
            }
            log::warn!("leaking unkillable child {}, unreaped", self.pid);
        }
    }
}

/// `held` in the form an async wait can watch without blocking: on Windows a raw or std child's
/// process handle goes to the async raw backend; on Linux a std child is held by a pidfd opened on
/// its pid — its own unreaped child's, so the pidfd is its own — and std's `Child`, which reaps
/// nothing on drop, is let go. A child for which none opens stays as it was: its wait says so, and
/// its holder keeps it.
fn awaitable(held: Held) -> Held {
    match held {
        #[cfg(windows)]
        Held::Raw(child) => {
            let (proc, pid) = child.into_parts();
            Held::RawAsync(crate::tokio::spawn::windows_raw::RawAsyncChild::new(proc, pid))
        }
        #[cfg(windows)]
        Held::Std(child) => {
            let pid = child.id();
            Held::RawAsync(crate::tokio::spawn::windows_raw::RawAsyncChild::new(
                std::os::windows::io::OwnedHandle::from(child),
                pid,
            ))
        }
        #[cfg(target_os = "linux")]
        Held::Std(child) => {
            let pid = child.id();
            let pidfd = rustix::process::Pid::from_raw(pid as i32)
                .and_then(|p| rustix::process::pidfd_open(p, rustix::process::PidfdFlags::empty()).ok());
            match pidfd {
                Some(pidfd) => {
                    drop(child);
                    Held::Bare {
                        pid,
                        pidfd: Some(pidfd),
                    }
                }
                None => Held::Std(child),
            }
        }
        other => other,
    }
}

/// Await `held`'s exit on the handle it owns, and reap it. Borrows it, so a cancelled wait leaves
/// it with its holder.
async fn wait_on(held: &mut Held) -> Result<ExitStatus, Failed> {
    #[cfg(test)]
    if fault::take_force_uncertain() {
        return Err(Failed::Uncertain(std::io::Error::other(
            "forced uncertain ownership (test seam)",
        )));
    }
    if let Held::Tokio(child) = held {
        return child.wait().await.map_err(classify_tokio_wait);
    }
    #[cfg(all(test, unix))]
    if fault::take_force_not_yet_reapable() {
        return Err(Failed::NotYetReapable);
    }
    watch_exit(held).await.map_err(Failed::Unawaitable)?;
    let reaped = held.try_reap().map_err(reap_failed)?;
    // The exit is certain, but the watch may have fired before the child became reapable (macOS's
    // `NOTE_EXIT` precedes the zombie, and a tracer holds a traced child until it releases it).
    // Not yet reapable is never uncertain ownership: the caller reaps it on the blocking pool.
    #[cfg(unix)]
    if reaped.is_none() {
        return Err(Failed::NotYetReapable);
    }
    // Reapable, yet not reaped. On Unix this is unreachable: the `NotYetReapable` branch above
    // already returns before here. On Windows this is the same condition `tokio_wait_blocking`
    // guards against on the sync side (see `crate::child::unreaped`'s module doc): not a
    // confirmed foreign reap, so the child is kept, not released.
    reaped.ok_or_else(|| {
        Failed::Unawaitable(std::io::Error::other(
            "the child's exit watch reported an exit it had not made",
        ))
    })
}

/// A failed reap after an exit watch, classified by `crate::child::unreaped::releases_ownership`.
/// On Windows the held handle still names its process, so the caller keeps it either way.
fn reap_failed(e: std::io::Error) -> Failed {
    #[cfg(unix)]
    {
        if crate::child::unreaped::releases_ownership(&e) {
            Failed::Uncertain(e)
        } else {
            Failed::Unawaitable(e)
        }
    }
    #[cfg(windows)]
    {
        Failed::Unawaitable(e)
    }
}

/// A failed wait of tokio's own child. On Unix only `ECHILD` — something else reaped it — makes
/// its ownership uncertain; anything else (a runtime whose driver is gone) leaves it ours. On
/// Windows the process handle names it whatever happens, so nothing does.
fn classify_tokio_wait(e: std::io::Error) -> Failed {
    #[cfg(unix)]
    if crate::child::unreaped::releases_ownership(&e) {
        return Failed::Uncertain(e);
    }
    Failed::Unawaitable(e)
}

/// Await `held`'s exit without reaping it, on the handle it owns: a pidfd on Linux, a kqueue filter
/// on its pid — its own unreaped child's, so the pid names it — on macOS, the process handle on
/// Windows. A failure here is the watch's, not the child's: the caller keeps it.
async fn watch_exit(held: &mut Held) -> std::io::Result<()> {
    #[cfg(test)]
    if fault::take_force_watch_failure() {
        return Err(std::io::Error::other("forced exit-watch failure (test seam)"));
    }
    let watched = match held {
        #[cfg(target_os = "linux")]
        Held::Bare { pidfd: Some(pidfd), .. } => crate::tokio::wait::pidfd_exit(pidfd).await,
        #[cfg(target_os = "macos")]
        Held::Std(child) => crate::tokio::wait::pid_exit(child.id()).await,
        #[cfg(windows)]
        Held::RawAsync(child) => child.wait().await.map(drop),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this child's exit cannot be awaited without blocking; drop it on a blocking thread",
            ))
        }
    };
    watched.map_err(crate::child::unreaped::error_to_io)
}

impl Drop for Unreaped {
    /// Blocks until the child exits, then reaps it. A failed wait is logged at `warn`, and always
    /// releases the child: on Unix only the manner depends on
    /// `crate::child::unreaped::releases_ownership`; on Windows the held handle always pins its
    /// process, so it is released the same single way either way. A child a cancelled `wait` left
    /// with its blocking-pool task is waited for there: this blocks until that task has reaped it,
    /// or — if the task never ran at all (a runtime shut down before it was scheduled) — reclaims
    /// the child directly and waits for it here instead, the same as a fresh `Unreaped` would.
    ///
    /// The same holds for a child a cancelled `wait` already reaped, whose retained drain a
    /// blocking-pool task still has running (see `RetainedDrain`): this blocks until that task's own
    /// drop has run, or — if it never claimed it at all — drops it directly, right here.
    fn drop(&mut self) {
        if let Some((shared, _)) = self.draining.take() {
            // Fires once Drop commits to this drain, before either arm below runs: firing it only
            // in the `take_blocking` arm would leave a hook meant to unblock the other arm's direct
            // drop stranded, the same reasoning as the reap branch below.
            #[cfg(all(test, unix))]
            if let Some(hook) = self.before_blocking_drop.take() {
                hook();
            }
            match shared.reclaim_before_start() {
                // Not yet claimed by the task: drop it directly (killing through), instead of
                // blocking on pool scheduling that a saturated pool may never grant. `Drop` is
                // documented as safe to block on the child's own exit, and this is no different.
                Some(retained) => drop(retained),
                // Claimed by the task: by that claim, it has already committed to kill-through (see
                // `DrainState`'s doc) — block until its own drop has actually run, rather than return
                // while it is still running on another thread.
                None => shared.take_blocking(),
            }
            return;
        }
        #[cfg(unix)]
        if let Some((shared, _)) = self.blocking.take() {
            // Fires once Drop commits to blocking on this reap, before either arm below actually
            // blocks: a direct reclaim still blocks right after, on `held.wait()` further down.
            // Firing it only in the `take_blocking` arm would leave that direct wait blocked
            // forever on whatever the hook was meant to release.
            #[cfg(test)]
            if let Some(hook) = self.before_blocking_drop.take() {
                hook();
            }
            // Not yet claimed by the task: reclaim it directly, instead of blocking on pool
            // scheduling that a saturated pool — even one whose only thread is this very
            // drop's own — may never grant. `Drop` is documented as safe to block on the
            // child's own exit, so the synchronous wait below picks it up from here.
            if let Some((held, retained)) = shared.reclaim_before_start() {
                self.held = Some(held);
                self.retained = retained;
            } else {
                let taken = shared.take_blocking();
                match self.take_reap_sync(taken) {
                    Ok(_) => return,
                    Err(e) if self.held.is_none() => {
                        log::warn!("unkillable child {} was released unreaped: {e}", self.pid);
                        return;
                    }
                    // Still held, unreaped: waited for below.
                    Err(_) => {}
                }
            }
        }
        // Only the fallback synchronous wait just below, or just above, can still leave
        // `retained` to settle here: `reaped`, `release` and `leak` all take it themselves.
        let mut failed = false;
        if let Some(held) = self.held.take() {
            let mut held = *held;
            let waited = held.wait();
            if let Err(e) = &waited {
                failed = true;
                log::warn!(
                    "waiting for unkillable child {} failed ({e}); it stays unreaped",
                    self.pid
                );
            }
            #[cfg(unix)]
            crate::child::unreaped::settle_after_wait(held, &waited);
            #[cfg(windows)]
            drop(held);
        }
        if let Some(retained) = self.retained.take() {
            // See `reaped`: a successful reap leaves what it retained armed.
            if failed {
                retained.attached.disarm();
            }
        }
    }
}

impl std::fmt::Debug for Unreaped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unreaped")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

/// Test-only seams.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    use std::cell::RefCell;
    thread_local! {
        static FORCE_WATCH_FAILURE: Cell<bool> = const { Cell::new(false) };
        static FORCE_NOT_YET_REAPABLE: Cell<bool> = const { Cell::new(false) };
        static FORCE_UNCERTAIN: Cell<bool> = const { Cell::new(false) };
        #[cfg(unix)]
        static AFTER_CLAIM: RefCell<Option<Box<dyn FnOnce() + Send + Sync>>> = const { RefCell::new(None) };
        static AFTER_DRAIN_CLAIM: RefCell<Option<Box<dyn FnOnce() + Send + Sync>>> = const { RefCell::new(None) };
        static BEFORE_DRAIN_DROP: RefCell<Option<Box<dyn FnOnce() + Send + Sync>>> = const { RefCell::new(None) };
    }
    /// Run `hook` once a `ReapTask` spawned next — by `spawn_blocking_reap`, sampled here on the
    /// submitting thread, before the task moves to the blocking pool — has claimed the child
    /// (state `Running`), right on the task's own blocking-pool thread.
    #[cfg(unix)]
    pub(crate) fn set_after_claim(hook: Box<dyn FnOnce() + Send + Sync>) {
        AFTER_CLAIM.with(|f| *f.borrow_mut() = Some(hook));
    }
    #[cfg(unix)]
    pub(crate) fn take_after_claim() -> Option<Box<dyn FnOnce() + Send + Sync>> {
        AFTER_CLAIM.with(|f| f.borrow_mut().take())
    }
    /// Run `hook` once a `DrainTask` spawned next — by `spawn_drain`, sampled here on the
    /// submitting thread, before the task moves to the blocking pool — has claimed what it must
    /// drop (state `Committed`), right on the task's own blocking-pool thread, having thereby
    /// committed to kill-through (see `DrainState`'s doc: claiming and committing are the same
    /// step).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // its callers are Linux cgroup tests
    pub(crate) fn set_after_drain_claim(hook: Box<dyn FnOnce() + Send + Sync>) {
        AFTER_DRAIN_CLAIM.with(|f| *f.borrow_mut() = Some(hook));
    }
    pub(crate) fn take_after_drain_claim() -> Option<Box<dyn FnOnce() + Send + Sync>> {
        AFTER_DRAIN_CLAIM.with(|f| f.borrow_mut().take())
    }
    /// Run `hook` once a `DrainTask` spawned next reaches `finish`, right before it drops what it
    /// retained — the real kill-through — on the task's own blocking-pool thread. Cross-platform,
    /// unlike `crate::containment::cgroup::fault::set_next_kill_thread_hook`, which reaches this
    /// same moment only on a Linux cgroup leaf, from inside its `cgroup.kill` write: this reaches
    /// it for every `Attached` kind, on every platform.
    pub(crate) fn set_before_drain_drop(hook: Box<dyn FnOnce() + Send + Sync>) {
        BEFORE_DRAIN_DROP.with(|f| *f.borrow_mut() = Some(hook));
    }
    pub(crate) fn take_before_drain_drop() -> Option<Box<dyn FnOnce() + Send + Sync>> {
        BEFORE_DRAIN_DROP.with(|f| f.borrow_mut().take())
    }
    /// Make the next wait on this thread find the child's ownership uncertain, as `ECHILD` does.
    #[cfg_attr(windows, allow(dead_code))] // its one caller is a Unix test
    pub(crate) fn set_force_uncertain() {
        FORCE_UNCERTAIN.with(|f| f.set(true));
    }
    pub(crate) fn take_force_uncertain() -> bool {
        FORCE_UNCERTAIN.with(|f| f.replace(false))
    }
    /// Make the next wait on this thread skip its exit watch and find the child not yet reapable,
    /// as one right after macOS's `NOTE_EXIT`, before the zombie exists, does — so it goes to the
    /// blocking reap at once, whether or not the child has exited.
    #[cfg_attr(windows, allow(dead_code))] // its one caller is a Unix test
    pub(crate) fn set_force_not_yet_reapable() {
        FORCE_NOT_YET_REAPABLE.with(|f| f.set(true));
    }
    #[cfg_attr(windows, allow(dead_code))] // read only on Unix
    pub(crate) fn take_force_not_yet_reapable() -> bool {
        FORCE_NOT_YET_REAPABLE.with(|f| f.replace(false))
    }
    /// Make the next exit watch an `Unreaped` sets up on this thread fail, as one whose pidfd
    /// cannot be duplicated does.
    pub(crate) fn set_force_watch_failure() {
        FORCE_WATCH_FAILURE.with(|f| f.set(true));
    }
    pub(crate) fn take_force_watch_failure() -> bool {
        FORCE_WATCH_FAILURE.with(|f| f.replace(false))
    }
}

#[cfg(test)]
#[path = "unreaped_tests.rs"]
mod unreaped_tests;
