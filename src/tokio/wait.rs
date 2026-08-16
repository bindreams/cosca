//! Reactor-native, non-reaping async grace-wait. Linux: the identity-verified pidfd is
//! registered with the reactor (`AsyncFd`); macOS: a kqueue `EVFILT_PROC|NOTE_EXIT` filter is
//! armed and its kqueue fd registered; Windows has no pollable process handle, so a
//! `spawn_blocking` watcher waits on the process handle AND a cancel event that a drop-guard
//! signals — a dropped grace-wait releases its watcher promptly on every platform. The grace
//! bound (`tokio::time::timeout` on Unix, the kernel wait's timeout on Windows) is a failure
//! bound on a genuine external event: the child's exit. Unix needs the runtime's IO + time
//! drivers (tokio panics otherwise) — documented on the public graceful methods.

use std::time::Duration;

use crate::error::Error;
use crate::identity::ProcessId;

/// Resolve when the process exits — UNBOUNDED, non-reaping, signal-free, identity-verified
/// (a stale/recycled id reports exited immediately). Cancellable: dropping the future
/// deregisters the watch on Unix; on Windows the drop-guard's cancel event releases the
/// blocking watcher promptly.
#[cfg(unix)]
pub(crate) async fn wait_exit(id: ProcessId) -> Result<(), Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    exit_watch(id).await
}

/// `Ok(true)` = the process exited within `grace`; `Ok(false)` = still alive at the deadline.
/// Non-reaping and signal-free; identity-verified (a stale/recycled id reports exited).
/// `Duration::ZERO` performs the sync backend's one-shot non-blocking probe.
#[cfg(unix)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    if grace.is_zero() {
        // Delegates to the sync ZERO probe (bounded-instant, safe from async); consumes the
        // fault seam there.
        return crate::wait::block_until_exit(id, Some(Duration::ZERO));
    }
    match ::tokio::time::timeout(grace, wait_exit(id)).await {
        Ok(watch) => watch.map(|()| true),
        Err(_elapsed) => Ok(false),
    }
}

#[cfg(windows)]
async fn blocking_watch(id: ProcessId, grace: Option<Duration>) -> Result<bool, Error> {
    /// Signals the cancel event on drop (harmless after completion) so the blocking watcher
    /// returns promptly instead of parking out the grace, and `Runtime::drop` — which joins
    /// blocking tasks — does not stall.
    struct SignalOnDrop(std::sync::Arc<std::os::windows::io::OwnedHandle>);
    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            crate::wait::backend::signal_cancel(&self.0);
        }
    }
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event()?);
    let _guard = SignalOnDrop(cancel.clone());
    let joined = ::tokio::task::spawn_blocking(move || {
        let result = crate::wait::backend::block_until_exit_or_cancel(id, grace, &cancel);
        #[cfg(test)]
        fault_observer::notify_released();
        result
    })
    .await;
    match joined {
        Ok(result) => result,
        // block_until_exit_or_cancel does not panic — a panic here is a bug, not an I/O
        // condition; propagate it instead of masking it as an error.
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Keep the shutdown-cancelled discriminator visible instead of folding it into an
        // opaque error indistinguishable from a real wait failure. The final arm is
        // presently unreachable (panic and cancelled are tokio's only variants today) and
        // exists for type-system conservatism: a future variant surfaces as an Err, never a
        // false success — with a debug tripwire, mirroring the unexpected-wait-verdict arm.
        Err(e) if e.is_cancelled() => Err(Error::Io(std::io::Error::other(
            "grace-wait watcher cancelled (runtime shutting down)",
        ))),
        Err(e) => {
            debug_assert!(false, "unknown JoinError variant: {e:?}");
            Err(Error::Io(std::io::Error::other(e)))
        }
    }
}

/// `Ok(true)` = the process exited within `grace`; `Ok(false)` = still alive at the deadline.
/// Non-reaping and signal-free; identity-verified (a stale/recycled id reports exited).
/// `Duration::ZERO` performs the sync backend's one-shot non-blocking probe.
///
/// **Windows:** Graces >= ~49.7 days (`INFINITE - 1` ms) are silently clamped to that cap —
/// a platform limit. A debug_assert surfaces this clamping in tests. On production, the clamp
/// is silent; a use case needing a genuinely unbounded watch composes `wait()` (unbounded,
/// cancellable) with its own escalation instead of a grace.
#[cfg(windows)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    blocking_watch(id, Some(grace)).await
}

/// Resolve when the process exits — UNBOUNDED, non-reaping, signal-free, identity-verified
/// (a stale/recycled id reports exited immediately). Cancellable: dropping the future
/// deregisters the watch on Unix; on Windows the drop-guard's cancel event releases the
/// blocking watcher promptly.
#[cfg(windows)]
pub(crate) async fn wait_exit(id: ProcessId) -> Result<(), Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    // An unbounded watch (`None` => INFINITE) has no timeout path, and cancel-at-drop never
    // RESOLVES the future (it is gone) — so a resolved watch means exit. If that contract
    // ever broke, re-watching — not returning — preserves the postcondition (the Unix
    // exit_watch's false-positive re-await idiom); the debug_assert trips it in tests.
    loop {
        let exited = blocking_watch(id, None).await?;
        debug_assert!(exited, "an unbounded watch resolved without an exit");
        if exited {
            return Ok(());
        }
        log::warn!("unbounded watch for {id:?} resolved without an exit; re-watching");
    }
}

/// Deliberate test scaffolding (the `wait::fault` pattern): signals when the blocking
/// watcher RETURNS, so a test can prove drop-release with a plain `recv()` — the
/// no-time-sync alternative to observing teardown timing. Absent from non-test builds.
#[cfg(all(test, windows))]
pub(crate) mod fault_observer {
    use std::sync::mpsc::Sender;
    use std::sync::Mutex;
    static RELEASE_TX: Mutex<Option<Sender<()>>> = Mutex::new(None);
    pub(crate) fn install_release_observer(tx: Sender<()>) {
        *RELEASE_TX.lock().unwrap() = Some(tx);
    }
    pub(crate) fn notify_released() {
        if let Some(tx) = RELEASE_TX.lock().unwrap().as_ref() {
            let _ = tx.send(());
        }
    }
}

/// Resolve when the process exits (no internal timeout — the caller bounds it).
#[cfg(target_os = "linux")]
async fn exit_watch(id: ProcessId) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    let Some(pidfd) = crate::wait::backend::open_verified(id, "its exit cannot be observed")? else {
        return Ok(());
    };
    // The pidfd becomes readable (POLLIN) when the task becomes a zombie; POLLHUP once
    // reaped. Either readiness is terminal. A registration failure here (reactor at
    // capacity, etc.) is a genuine I/O error; a MISSING IO driver panics inside tokio
    // instead (documented on the graceful methods).
    let afd = AsyncFd::with_interest(pidfd, Interest::READABLE | Interest::ERROR).map_err(Error::Io)?;
    // ready() may complete with an empty/unclassified set (tokio's documented false
    // positive) — the same re-await discipline as the macOS watch_readable loop.
    loop {
        let mut guard = afd
            .ready(Interest::READABLE | Interest::ERROR)
            .await
            .map_err(Error::Io)?;
        match classify_pidfd_ready(guard.ready()) {
            Some(verdict) => return verdict,
            None => guard.clear_ready(), // false-positive wake — re-await
        }
    }
}

/// Map a pidfd readiness to the watch verdict; `None` = unclassified readiness (tokio's
/// documented `ready()` false positive) — re-await: never a false "exited" (which would skip
/// escalation on a live child) and never a false watch failure (which would force-kill a
/// gracefully-exiting child). Factored out so the POLLERR branch and the readiness contract
/// are unit-testable with synthetic `Ready` values — a real pidfd cannot be made to surface
/// POLLERR on demand.
#[cfg(target_os = "linux")]
fn classify_pidfd_ready(ready: ::tokio::io::Ready) -> Option<Result<(), Error>> {
    // Mirror the sync backend: POLLERR is an error; POLLIN (zombie) / POLLHUP (reaped) = exited.
    if ready.is_error() {
        return Some(Err(Error::Io(std::io::Error::other("pidfd poll returned POLLERR"))));
    }
    if ready.is_readable() || ready.is_read_closed() {
        return Some(Ok(()));
    }
    None
}

/// Resolve when the process exits (no internal timeout — the caller bounds it).
#[cfg(target_os = "macos")]
async fn exit_watch(id: ProcessId) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    let Some(kq) = crate::wait::backend::arm_proc_exit(id)? else {
        return Ok(());
    };
    let afd = AsyncFd::with_interest(KqueueFd(kq), Interest::READABLE).map_err(Error::Io)?;
    watch_readable(&afd, crate::wait::backend::drain_proc_exit).await
}

/// `AsyncFd` requires `AsRawFd`; nix's `Kqueue` exposes only `AsFd` — delegate.
#[cfg(target_os = "macos")]
struct KqueueFd(nix::sys::event::Kqueue);
#[cfg(target_os = "macos")]
impl std::os::fd::AsRawFd for KqueueFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsFd;
        self.0.as_fd().as_raw_fd()
    }
}

/// The readiness/drain loop, parameterized over the drain so the re-await cycle is testable
/// against the REAL `AsyncFd` (see `wait_tests`). Exit is concluded only on a drained event;
/// `clear_ready` only after an EMPTY drain — mio's edge-triggered (`EV_CLEAR`) would-block
/// contract.
///
/// `drain` returning `Ok(None)` is what `clear_ready` treats as "empty" — this loop has no way
/// to verify that itself, since the closure's return type carries no more than "done" or "not
/// done". The invariant holds for both current callers because NEITHER `Ok(None)` case ever
/// consumes bytes: `drain_proc_exit`'s only non-`None` outcome is `NOTE_EXIT`, with no draining
/// concept at all, and `marker_eof::drain_kqueue`'s caller here (`wait_tree_drained_inner`)
/// always arms with `unbounded_wait: true`, under which `interpret_read_event` itself never
/// drains (see `marker_eof`'s module doc — an unbounded wait cannot drain on a sustained
/// writer's behalf without spinning). A future `drain` closure that DOES consume bytes on a
/// non-`None`-but-also-non-terminal path would violate this silently; `watch_readable` cannot
/// detect that on its own, so any such closure owns re-verifying this invariant itself.
#[cfg(target_os = "macos")]
async fn watch_readable<F>(afd: &::tokio::io::unix::AsyncFd<KqueueFd>, mut drain: F) -> Result<(), Error>
where
    F: FnMut(&nix::sys::event::Kqueue) -> Result<Option<()>, Error>,
{
    loop {
        let mut guard = afd.readable().await.map_err(Error::Io)?;
        match drain(&afd.get_ref().0)? {
            Some(()) => return Ok(()),
            None => guard.clear_ready(), // no exit drained — re-await
        }
    }
}

/// Resolve when every holder of the containment marker's write end has exited — genuinely
/// poll-free, reactor-native, and with no internal deadline at all.
///
/// **Unlike `block_until_drained`, this future has no deadline parameter.** Below `NOTE_LOWAT`'s
/// clamp it never wakes except on `EV_EOF`. At or past the clamp (a member sustaining writes ≥
/// the pipe's buffer capacity) this primitive does NOT drain on the writer's behalf, unlike the
/// sync form's bounded case — see `marker_eof`'s module doc for why an unbounded wait cannot
/// honestly offer both zero CPU and forward progress for a sustained writer, and why this
/// primitive, having no deadline to bound the alternative, chooses zero CPU: the writer's own
/// `write()` call blocks against the full pipe (the marker fd's documented misuse contract —
/// `fdmarker`'s module doc), and this future stays genuinely asleep until that descriptor
/// closes. A caller that wants such a writer to make forward progress toward closing the
/// descriptor cannot get that from this primitive; a caller that merely wants a time bound on
/// the wait itself can still layer one externally (e.g. `tokio::time::timeout`, the same
/// pattern `grace_wait` already uses over `wait_exit` in this file) — that bounds the CALLER's
/// patience, not the writer's blocked state.
///
/// Exited is not reaped: this says nothing about statuses. A caller wanting a status waits on
/// the root as well.
///
/// The marker's own kqueue is what gets registered with the reactor, not the marker
/// descriptor: a knote is keyed on `(kqueue, fd, filter)`, so a second waiter registering the
/// same descriptor directly would take over the first's registration and park it forever —
/// each call arms its OWN private kqueue (`marker_eof::arm`).
///
#[cfg(target_os = "macos")]
pub(crate) async fn wait_tree_drained(read_end: std::os::fd::BorrowedFd<'_>) -> Result<(), Error> {
    wait_tree_drained_inner(read_end, None).await
}

/// Deadline-bounded, [`TreeDrain`](crate::containment::TreeDrain)-returning wrapper over
/// [`wait_tree_drained`] — the macOS arm of `tokio::Child::wait_tree`/`wait_tree_timeout`.
/// `Duration::ZERO` delegates to the sync backend's one-shot, non-blocking probe (safe to call
/// directly from async code), matching `grace_wait`'s identical `Duration::ZERO` delegation to
/// `block_until_exit`.
#[cfg(target_os = "macos")]
pub(crate) async fn wait_tree_deadline(
    read_end: std::os::fd::BorrowedFd<'_>,
    deadline: Option<Option<std::time::Instant>>,
) -> Result<crate::containment::TreeDrain, Error> {
    use crate::containment::TreeDrain;
    match crate::wait::remaining(deadline) {
        None => {
            wait_tree_drained(read_end).await?;
            Ok(TreeDrain::AllMembersExited)
        }
        Some(d) if d.is_zero() => crate::containment::marker_eof::probe(read_end),
        Some(d) => match ::tokio::time::timeout(d, wait_tree_drained(read_end)).await {
            Ok(res) => res.map(|()| TreeDrain::AllMembersExited),
            Err(_elapsed) => Ok(TreeDrain::MembersRemain),
        },
    }
}

/// Test-only entry point that reports the instant its kqueue is armed, on a channel the
/// CALLER owns — no shared/global observer state, so concurrently-running tests (this file
/// has four) cannot steal each other's notification.
#[cfg(all(test, target_os = "macos"))]
pub(crate) async fn wait_tree_drained_for_test(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: std::sync::mpsc::Sender<()>,
) -> Result<(), Error> {
    wait_tree_drained_inner(read_end, Some(armed)).await
}

#[cfg(target_os = "macos")]
async fn wait_tree_drained_inner(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: Option<std::sync::mpsc::Sender<()>>,
) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    // Unbounded: this future has no deadline parameter at all (see the doc comment above).
    let kq = crate::containment::marker_eof::arm(read_end, true)?;
    if let Some(tx) = armed {
        let _ = tx.send(());
    }
    let afd = AsyncFd::with_interest(KqueueFd(kq), Interest::READABLE).map_err(Error::Io)?;
    watch_readable(&afd, move |kq| {
        crate::containment::marker_eof::drain_kqueue(kq, read_end, true).map(|d| d.map(|_| ()))
    })
    .await
}

/// Resolve when every process in the cgroup v2 leaf has EXITED (not reaped), observed via
/// `cgroup.events`'s `populated` key over a reactor-registered `AsyncFd` (`EPOLLPRI`, tokio's
/// `Interest::PRIORITY`) — genuinely reactor-native, no polling interval anywhere, and
/// cancellable (dropping the future deregisters the fd, same as every other Unix watch in this
/// file). Mirrors `CgroupLeaf::wait_drained`'s sync loop exactly, including read-before-arm: the
/// file is read BEFORE every `ready()` await, not only after, so a transition that already
/// happened is observed on the read rather than requiring a fresh edge that may never fire
/// again. `deadline` follows the crate's watch convention; each round awaits readiness for
/// exactly the caller's own remaining time (`tokio::time::timeout`), never an invented interval.
#[cfg(target_os = "linux")]
async fn cgroup_wait_tree_drained(
    leaf: &crate::containment::cgroup::CgroupLeaf,
    deadline: Option<Option<std::time::Instant>>,
) -> Result<crate::containment::TreeDrain, Error> {
    use std::io::{Read, Seek, SeekFrom};

    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;

    use crate::containment::TreeDrain;

    use crate::containment::cgroup::removed_after_drain;

    let file = match std::fs::File::open(leaf.events_path()) {
        Ok(f) => f,
        Err(e) if removed_after_drain(&e) => return Ok(TreeDrain::AllMembersExited),
        Err(e) => return Err(Error::Io(e)),
    };
    let mut afd = AsyncFd::with_interest(file, Interest::PRIORITY).map_err(Error::Io)?;
    let mut buf = String::new();
    loop {
        buf.clear();
        // Mirrors `CgroupLeaf::wait_drained`'s own leaf-removal race handling exactly (see its
        // doc): `rmdir` on this leaf — `Drop`'s own retry, or an external cgroup manager's
        // cleanup of an already-empty leaf — can land between this loop's own `ready()` wakeup
        // and its next read, and observing that removal is itself proof every member had
        // already exited (rmdir cannot precede full drain), not a failure.
        {
            let f = afd.get_mut();
            if let Err(e) = f.seek(SeekFrom::Start(0)) {
                return if removed_after_drain(&e) {
                    Ok(TreeDrain::AllMembersExited)
                } else {
                    Err(Error::Io(e))
                };
            }
            if let Err(e) = f.read_to_string(&mut buf) {
                return if removed_after_drain(&e) {
                    Ok(TreeDrain::AllMembersExited)
                } else {
                    Err(Error::Io(e))
                };
            }
        }
        match crate::containment::cgroup::parse_populated(&buf) {
            Some(false) => return Ok(TreeDrain::AllMembersExited),
            Some(true) => {}
            None => {
                return Err(Error::Io(std::io::Error::other(
                    "cgroup.events has no 'populated' field — unexpected kernel format",
                )))
            }
        }
        let remaining = crate::wait::remaining(deadline);
        if remaining == Some(std::time::Duration::ZERO) {
            return Ok(TreeDrain::MembersRemain);
        }
        let mut ready = match remaining {
            None => afd.ready(Interest::PRIORITY).await.map_err(Error::Io)?,
            Some(d) => match ::tokio::time::timeout(d, afd.ready(Interest::PRIORITY)).await {
                Ok(r) => r.map_err(Error::Io)?,
                Err(_elapsed) => return Ok(TreeDrain::MembersRemain),
            },
        };
        // A regular file has no "would block" concept to drain — any readiness means a
        // transition fired (possibly stale by the time we re-read, which the loop's own
        // re-read handles); clear and re-await.
        ready.clear_ready();
    }
}

/// Resolve when every process in the Windows job has EXITED (not reaped), or until `deadline`.
/// Job objects expose no pollable handle, so — unlike the Linux/macOS arms in this file — this
/// is NOT reactor-native: it hands the sync `JobHandle::wait_drained` loop to `spawn_blocking`,
/// releasing the blocking thread promptly on drop via the same cancel-event idiom
/// `blocking_watch` uses for `grace_wait`. Only the raw `HANDLE` value (`Copy`, `Send`) crosses
/// into the blocking closure — `JobHandle` itself is never moved there — because the closure
/// must be `'static` while `JobHandle` is only borrowed. This is sound because the caller
/// (`wait_tree_drained`, transitively `tokio::Child::wait_tree`/`wait_tree_timeout`) holds
/// `&Child` — and so `&JobHandle` — across this entire `.await`, so the job handle cannot be
/// closed while the blocking task runs.
#[cfg(windows)]
async fn job_wait_tree_drained(
    job: &crate::containment::windows::JobHandle,
    deadline: Option<Option<std::time::Instant>>,
) -> Result<crate::containment::TreeDrain, Error> {
    use windows::Win32::Foundation::HANDLE;

    // Duration::ZERO delegates to the sync one-shot probe — no thread-pool hop needed for a
    // call that cannot block (mirrors grace_wait's identical delegation).
    if crate::wait::remaining(deadline) == Some(std::time::Duration::ZERO) {
        return job.wait_drained(deadline, None);
    }
    let Some(raw_job) = job.as_handle() else {
        // Mirrors `JobHandle::wait_drained`'s own early return exactly (this function only
        // reaches here once that method's Duration::ZERO delegation above has already been
        // ruled out): the job handle was already consumed, so there is no live handle left to
        // re-enumerate or open member handles from, and `TerminateJobObject`/`CloseHandle` are
        // not documented as synchronous with member process teardown. Reporting
        // `AllMembersExited` here would be a guess, not a live-checked verdict — see that
        // method's doc and inline comment for the full justification.
        return Err(Error::Unassessable {
            detail: "the job handle was already closed (kill_tree()/hard_kill(), or the Child \
                     was dropped) before this drain check ran; whether every member has \
                     actually finished exiting can no longer be observed"
                .into(),
            source: None,
        });
    };

    /// Signals the cancel event on drop (harmless after completion) so the blocking watcher
    /// releases promptly instead of parking out the deadline, and `Runtime::drop` — which
    /// joins blocking tasks — does not stall. Identical idiom to `blocking_watch`'s guard.
    struct SignalOnDrop(std::sync::Arc<std::os::windows::io::OwnedHandle>);
    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            crate::wait::backend::signal_cancel(&self.0);
        }
    }
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event()?);
    let _guard = SignalOnDrop(cancel.clone());
    // SAFETY: `cancel`'s OwnedHandle is kept alive by the Arc clone captured in the
    // spawn_blocking closure below (and by `_guard`/`cancel` here) for the whole wait.
    let cancel_raw = HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&*cancel));
    let cancel_for_blocking = cancel.clone();

    /// `HANDLE`'s raw pointer is `!Send` by default; a job or event handle is sound to use
    /// from another thread (the kernel serialises handle operations) — the same justification
    /// as `JobHandle`'s own `unsafe impl Send`.
    struct SendHandles {
        job: HANDLE,
        cancel: HANDLE,
    }
    unsafe impl Send for SendHandles {}
    let handles = SendHandles {
        job: raw_job,
        cancel: cancel_raw,
    };

    let joined = ::tokio::task::spawn_blocking(move || {
        let handles = handles;
        let result = crate::containment::windows::wait_drained_raw(handles.job, deadline, Some(handles.cancel));
        drop(cancel_for_blocking); // keep the handle alive for the full blocking call, explicitly
        result
    })
    .await;
    match joined {
        Ok(result) => result,
        // wait_drained_raw does not panic — a panic here is a bug, not an I/O condition;
        // propagate it instead of masking it as an error.
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) if e.is_cancelled() => Err(Error::Io(std::io::Error::other(
            "tree-drain watcher cancelled (runtime shutting down)",
        ))),
        Err(e) => {
            debug_assert!(false, "unknown JoinError variant: {e:?}");
            Err(Error::Io(std::io::Error::other(e)))
        }
    }
}

/// Async equivalent of `Attached::wait_drained`, dispatched by mechanism. Linux and macOS are
/// genuinely reactor-native (`AsyncFd`); Windows hands its sync loop to `spawn_blocking` with a
/// cancel event (job objects have no pollable handle). Every other mechanism delegates to the
/// sync `Attached::wait_drained`, whose non-drainable arm returns `Unsupported` immediately —
/// never blocking — so calling it directly here (no `spawn_blocking`) is safe.
pub(crate) async fn wait_tree_drained_dispatch(
    attached: &crate::containment::Attached,
    deadline: Option<Option<std::time::Instant>>,
) -> Result<crate::containment::TreeDrain, Error> {
    match attached {
        #[cfg(target_os = "linux")]
        crate::containment::Attached::Cgroup(leaf) => cgroup_wait_tree_drained(leaf, deadline).await,
        #[cfg(windows)]
        crate::containment::Attached::JobObject(job) => job_wait_tree_drained(job, deadline).await,
        #[cfg(target_os = "macos")]
        crate::containment::Attached::FdMarker(m) => wait_tree_deadline(m.read_end(), deadline).await,
        other => other.wait_drained(deadline),
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
