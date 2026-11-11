//! A tree's own kernel edge for "no member runs" ([`DrainEdge`]), and the per-OS drivers that await
//! it. The drivers use the async waits' primitives (`crate::tokio::wait`'s clock, its armed
//! deadline and its readiness loop), which know nothing of a tree.

use std::time::Instant;

use crate::containment::TreeDrain;
use crate::error::Error;

/// A tree's own kernel edge for "every member has exited", borrowed from the tree that owns the
/// resource it watches for the child's whole life (a marker's read end must, to keep its pipe's
/// identity from being reissued). Both waits report the [`TreeDrain`] verdict.
pub(crate) enum DrainEdge<'a> {
    /// The leaf's own watch of `cgroup.events`.
    #[cfg(target_os = "linux")]
    Cgroup(&'a crate::containment::cgroup::CgroupLeaf),
    /// The job's live process list.
    #[cfg(windows)]
    Job(&'a crate::containment::windows::JobHandle),
    /// The marker pipe's read end, which reads EOF once the last holder of the write end is gone.
    #[cfg(target_os = "macos")]
    Marker(&'a crate::containment::fdmarker::Marker),
}

impl DrainEdge<'_> {
    /// Block until every member of the tree has EXITED (not reaped), or until `deadline` (`None`: for
    /// ever): `MembersRemain` at expiry.
    pub(crate) fn wait(&self, deadline: Option<Instant>) -> Result<TreeDrain, Error> {
        match self {
            #[cfg(target_os = "linux")]
            DrainEdge::Cgroup(leaf) => leaf.wait_drained(deadline),
            #[cfg(windows)]
            DrainEdge::Job(job) => job.wait_drained(deadline, None),
            #[cfg(target_os = "macos")]
            DrainEdge::Marker(m) => m.wait_drained(deadline),
        }
    }

    /// [`wait`](Self::wait), awaited, with no thread blocked: macOS is reactor-native (`AsyncFd`);
    /// Linux awaits a broadcast from the pump thread its leaf owns (an `event_listener` future, no
    /// reactor registration); Windows hands its sync loop to `spawn_blocking` with a cancel event (job
    /// objects have no pollable handle). `deadline` is on tokio's clock
    /// ([`deadline_from`](crate::tokio::wait::deadline_from)).
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_async(&self, deadline: Option<Instant>) -> Result<TreeDrain, Error> {
        match self {
            #[cfg(target_os = "linux")]
            DrainEdge::Cgroup(leaf) => cgroup_wait_tree_drained(leaf, deadline).await,
            #[cfg(windows)]
            DrainEdge::Job(job) => job_wait_tree_drained(job, deadline).await,
            #[cfg(target_os = "macos")]
            DrainEdge::Marker(m) => {
                // Mirrors `Marker::wait_drained`'s own preamble exactly: a reissued read-end fd
                // would falsely deliver `EV_EOF` instantly here just as readily as it would there,
                // so this path must not skip the check just because it reads the raw fd directly
                // instead of going through `Marker::wait_drained`.
                m.check_read_end_still_valid()?;
                debug_assert_ne!(
                    crate::containment::marker_eof::write_end_check(m.read_end()),
                    crate::containment::marker_eof::WriteEndCheck::HeldByUs,
                    "the supervisor still holds a copy of the marker write end - the tree-drain edge can never fire"
                );
                wait_tree_deadline(m.read_end(), deadline).await
            }
        }
    }
}

// The per-OS drivers -----

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
/// the wait itself can still bound it with a deadline instant (see [`crate::tokio::drive`] for
/// the deadline; outside the crate, `tokio::time::timeout_at`) — that bounds the CALLER's
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
#[cfg(all(feature = "tokio", target_os = "macos"))]
pub(crate) async fn wait_tree_drained(read_end: std::os::fd::BorrowedFd<'_>) -> Result<(), Error> {
    wait_tree_drained_watched(read_end, None).await
}

/// Deadline-bounded, [`TreeDrain`]-returning wrapper over [`wait_tree_drained_inner`] — the macOS
/// arm of `tokio::Child::wait_tree`/`wait_tree_timeout`. `Duration::ZERO` delegates to the sync
/// backend's one-shot, non-blocking probe (safe to call directly from async code).
///
/// The bounded arm (`Some(d)`) arms with `unbounded_wait: false` — computed the same way the
/// sync backend's `block_until_drained` does (`crate::wait::remaining(deadline).is_none()`,
/// `false` whenever a real deadline governs this call) — NOT via [`wait_tree_drained`], which is
/// always unbounded by construction (see its own doc). Arming unbounded here would be a real,
/// observable divergence from the sync twin: `refuse_if_write_end_held` would refuse an
/// `Unassessable` write-end scan that a bounded caller should tolerate (its own deadline caps
/// the risk), and `interpret_read_event` would stop draining a sustained writer at the low-water
/// clamp, so a bounded wait could only ever expire into `MembersRemain` where the sync call
/// drains through to the real edge. [`arm_at`](crate::tokio::wait::arm_at) still supplies the
/// actual bound, armed with the caller's deadline instant; this only fixes what the ARMED kqueue
/// itself is told.
#[cfg(all(feature = "tokio", target_os = "macos"))]
pub(crate) async fn wait_tree_deadline(
    read_end: std::os::fd::BorrowedFd<'_>,
    deadline: Option<Instant>,
) -> Result<TreeDrain, Error> {
    use crate::tokio::wait::{arm_at, tokio_now};
    match deadline {
        None => {
            wait_tree_drained(read_end).await?;
            Ok(TreeDrain::AllMarkersClosed)
        }
        Some(at) => {
            if crate::wait::remaining_at(deadline, tokio_now()) == Some(std::time::Duration::ZERO) {
                return crate::containment::marker_eof::probe(read_end);
            }
            match arm_at(at, wait_tree_drained_inner(read_end, false, None)).await {
                Some(res) => res.map(|()| TreeDrain::AllMarkersClosed),
                // One final probe, so an EOF already pending is not missed.
                None => crate::containment::marker_eof::probe(read_end),
            }
        }
    }
}

/// Test seam: fires every time [`wait_tree_drained_inner`]'s watch loop gets
/// `DrainOutcome::Declined` (a genuine non-EOF event, retrieved and interpreted, that did not
/// resolve the wait; its bytes were discarded when `suppress_drain` is false and left buffered
/// when true). Never `Spurious`. A `#[cfg(test)]` thread-local installed by an RAII guard, so no
/// production signature carries it. It relies on a current-thread runtime: the future is polled on
/// the installing thread.
#[cfg(all(test, feature = "tokio", target_os = "macos"))]
pub(crate) mod declined_hook {
    use std::cell::RefCell;

    use ::tokio::sync::mpsc::UnboundedSender;

    thread_local! {
        static DECLINED: RefCell<Option<UnboundedSender<()>>> = const { RefCell::new(None) };
    }

    /// Fire this thread's installed hook, if any. Called only from
    /// [`super::wait_tree_drained_inner`]'s `DrainOutcome::Declined` arm.
    pub(crate) fn notify() {
        DECLINED.with(|d| {
            if let Some(tx) = d.borrow().as_ref() {
                let sent = tx.send(());
                debug_assert!(sent.is_ok(), "declined_hook receiver dropped before the hook fired");
            }
        });
    }

    /// RAII installer: clears the hook on `Drop`, including during unwinding.
    #[must_use]
    pub(crate) struct DeclinedGuard {
        _private: (),
    }

    impl DeclinedGuard {
        pub(crate) fn install(tx: UnboundedSender<()>) -> Self {
            DECLINED.with(|d| {
                let mut slot = d.borrow_mut();
                debug_assert!(slot.is_none(), "a declined_hook is already installed on this thread");
                *slot = Some(tx);
            });
            Self { _private: () }
        }
    }

    impl Drop for DeclinedGuard {
        fn drop(&mut self) {
            DECLINED.with(|d| {
                let prev = d.borrow_mut().take();
                debug_assert!(
                    prev.is_some(),
                    "declined_hook slot was cleared before its guard dropped"
                );
            });
        }
    }
}

/// Test-only entry point that reports the instant its kqueue is armed, on a channel the
/// CALLER owns — no shared/global observer state, so concurrently-running tests (this file
/// has four) cannot steal each other's notification.
#[cfg(all(test, feature = "tokio", target_os = "macos"))]
pub(crate) async fn wait_tree_drained_for_test(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: std::sync::mpsc::Sender<std::os::fd::RawFd>,
) -> Result<(), Error> {
    wait_tree_drained_watched(read_end, Some(armed)).await
}

/// The ONE call site for [`wait_tree_drained`]'s own "always unbounded" choice — shared with
/// [`wait_tree_drained_for_test`] so a mutant on that literal breaks both identically. A test
/// that instead called `wait_tree_drained_inner` with its OWN independent `true` would not
/// notice a mutant that changed only the production caller's.
#[cfg(all(feature = "tokio", target_os = "macos"))]
async fn wait_tree_drained_watched(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: Option<std::sync::mpsc::Sender<std::os::fd::RawFd>>,
) -> Result<(), Error> {
    wait_tree_drained_inner(read_end, true, armed).await
}

/// `unbounded_wait` must be the SAME expression the sync backend's `block_until_drained` uses
/// (`crate::wait::remaining(deadline).is_none()`) for whichever deadline the caller is honoring
/// — threaded through to both `arm` and `drain_kqueue` (see [`wait_tree_deadline`]'s own doc for
/// why arming this wrong is a real, observable divergence, not a cosmetic one).
///
/// `armed`, if given, receives the raw fd of the kqueue this call just armed (test-only; see
/// [`wait_tree_drained_for_test`]). That fd is valid only while this future is alive.
/// `DrainOutcome::Declined` fires [`declined_hook::notify`] in test builds only.
#[cfg(all(feature = "tokio", target_os = "macos"))]
async fn wait_tree_drained_inner(
    read_end: std::os::fd::BorrowedFd<'_>,
    unbounded_wait: bool,
    armed: Option<std::sync::mpsc::Sender<std::os::fd::RawFd>>,
) -> Result<(), Error> {
    use std::os::fd::AsRawFd;

    use crate::containment::marker_eof::DrainOutcome;
    use crate::tokio::wait::watch_readable;
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    let kq = crate::containment::marker_eof::arm(read_end, unbounded_wait)?;
    if let Some(tx) = armed {
        let sent = tx.send(kq.as_raw_fd());
        debug_assert!(
            sent.is_ok(),
            "the `armed` receiver was dropped before the kqueue was armed"
        );
    }
    let afd = AsyncFd::with_interest(kq, Interest::READABLE).map_err(Error::Io)?;
    watch_readable(&afd, move |kq| {
        match crate::containment::marker_eof::drain_kqueue(kq, read_end, unbounded_wait)? {
            DrainOutcome::Drained(_) => Ok(Some(())),
            DrainOutcome::Declined => {
                #[cfg(test)]
                declined_hook::notify();
                Ok(None)
            }
            DrainOutcome::Spurious => Ok(None),
        }
    })
    .await
}

/// Resolve when every process in the cgroup v2 leaf has EXITED (not reaped), or until `deadline`.
/// The async twin of `CgroupLeaf::wait_drained`, taking the same `CgroupLeaf::drain_step`s and
/// awaiting each broadcast where the sync wait blocks on it. It never touches the watch itself, so
/// a future dropped, or never polled again, holds nothing another wait needs. Each round awaits
/// for exactly the caller's own remaining time; no interval anywhere.
#[cfg(all(feature = "tokio", target_os = "linux"))]
pub(crate) async fn cgroup_wait_tree_drained(
    leaf: &crate::containment::cgroup::CgroupLeaf,
    deadline: Option<Instant>,
) -> Result<TreeDrain, Error> {
    use crate::containment::cgroup::DrainStep;
    use crate::tokio::wait::{arm_at, tokio_now};

    loop {
        match leaf.drain_step_on(deadline, tokio_now)? {
            DrainStep::Done(drain) => return Ok(drain),
            DrainStep::Block {
                listener,
                deadline: None,
            } => {
                #[cfg(test)]
                crate::tokio::wait::armed_deadline_seam::notify(
                    crate::tokio::wait::armed_deadline_seam::Armed::Unbounded,
                );
                listener.await
            }
            // The timeout is looked at by the next step, which reads the leaf once more.
            DrainStep::Block {
                listener,
                deadline: Some(at),
            } => {
                let _ = arm_at(at, listener).await;
            }
        }
    }
}

/// Resolve when every process in the Windows job has EXITED (not reaped), or until `deadline`.
/// Job objects expose no pollable handle, so — unlike the macOS arm, on the reactor, and the Linux
/// arm, awaiting its leaf's pump — this hands the sync `JobHandle::wait_drained` loop to `spawn_blocking`,
/// releasing the blocking thread promptly on drop via the same cancel-event idiom
/// [`cancellable_blocking`](crate::tokio::wait::cancellable_blocking) uses for the process wait.
///
/// **Handle ownership across cancellation.** [`cancellable_blocking`](crate::tokio::wait::cancellable_blocking)
/// gets away with borrowing nothing at all — a process wait clones the process handle into the
/// closure. A job object has no such re-openable identity, so this function instead duplicates the
/// live job `HANDLE` into one the spawned task owns outright (`DuplicateHandle`, closed by the
/// closure itself on every exit path, panic included) before ever spawning. This matters because
/// dropping THIS future only cancels the `.await` — it does not join the blocking task, which keeps
/// running detached. A caller cancelling the `wait_tree`/`wait_tree_timeout` future (via `select!`,
/// an outer `timeout()`, or simply not polling it again) can therefore race `JobHandle::hard_kill`/
/// `Drop` closing the ORIGINAL handle while the detached task is still mid-syscall on it. A
/// borrowed raw `HANDLE` would then alias a handle value the kernel is free to recycle onto an
/// unrelated object the moment it is closed; the duplicate has its own independent lifetime,
/// closed only by the task that owns it, and is never touched by `JobHandle` at all — so no
/// such aliasing is possible regardless of what the caller does with the `Child` after
/// cancelling.
#[cfg(all(feature = "tokio", windows))]
async fn job_wait_tree_drained(
    job: &crate::containment::windows::JobHandle,
    deadline: Option<Instant>,
) -> Result<TreeDrain, Error> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    // The kernel wait runs on the real clock, not tokio's.
    let deadline = crate::tokio::wait::to_real_clock(deadline);
    // Duration::ZERO delegates to the sync one-shot probe — no thread-pool hop needed for a
    // call that cannot block.
    if crate::wait::remaining(deadline) == Some(std::time::Duration::ZERO) {
        return job.wait_drained(deadline, None);
    }
    /// An independently-owned duplicate of the job handle, held only by the spawned blocking
    /// task and closed by it on every exit path, panic included — see this function's own doc
    /// for why a borrowed handle is not safe to hand across the cancellation boundary here.
    /// Closing a job handle only fires `KILL_ON_JOB_CLOSE` if it is the LAST open handle to
    /// that job (Win32 semantics); `JobHandle`'s own, separate handle is unaffected either way.
    struct OwnedJobDup(HANDLE);
    impl Drop for OwnedJobDup {
        fn drop(&mut self) {
            // SAFETY: `self.0` is this struct's own `DuplicateHandle`-created handle, never
            // shared or aliased anywhere else.
            unsafe {
                _ = CloseHandle(self.0);
            }
        }
    }

    // Duplicate INSIDE the closure, so the lock is still held when `DuplicateHandle` reads the
    // handle. Returning the handle out of `with_handle` first would release the guard before
    // the call — leaving the load-then-use gap this is meant to close — and Windows recycles a
    // closed handle's value onto unrelated kernel objects.
    let Some(dup) = job
        .with_handle(crate::containment::windows::duplicate_job)
        .transpose()?
    else {
        // Mirrors `JobHandle::wait_drained`'s own early return exactly (this function only
        // reaches here once that method's Duration::ZERO delegation above has already been
        // ruled out) — see `consumed_job_handle_error`'s own doc for the full justification.
        return Err(crate::containment::windows::consumed_job_handle_error());
    };
    let job_dup = OwnedJobDup(dup);

    /// Signals the cancel event on drop (harmless after completion) so the blocking watcher
    /// releases promptly instead of parking out the deadline, and `Runtime::drop` — which
    /// joins blocking tasks — does not stall. Identical idiom to `cancellable_blocking`'s guard.
    struct SignalOnDrop(std::sync::Arc<std::os::windows::io::OwnedHandle>);
    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            crate::os_process::windows::cancel::signal_cancel(&self.0);
        }
    }
    let cancel = std::sync::Arc::new(crate::os_process::windows::cancel::new_cancel_event()?);
    let _guard = SignalOnDrop(cancel.clone());
    // SAFETY: `cancel`'s OwnedHandle is kept alive by the Arc clone captured in the
    // spawn_blocking closure below (and by `_guard`/`cancel` here) for the whole wait.
    let cancel_raw = HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&*cancel));
    let cancel_for_blocking = cancel.clone();

    /// `HANDLE`'s raw pointer is `!Send` by default; a job or event handle (owned or borrowed
    /// for the task's own full lifetime) is sound to use and close from another thread — the
    /// kernel serialises handle operations — the same justification as `JobHandle`'s own
    /// `unsafe impl Send`.
    struct SendHandles {
        job: OwnedJobDup,
        cancel: HANDLE,
    }
    unsafe impl Send for SendHandles {}
    let handles = SendHandles {
        job: job_dup,
        cancel: cancel_raw,
    };

    let joined = ::tokio::task::spawn_blocking(move || {
        let handles = handles;
        let result = crate::containment::windows::wait_drained_raw(handles.job.0, deadline, Some(handles.cancel));
        drop(cancel_for_blocking); // keep the handle alive for the full blocking call, explicitly
        result
        // `handles.job` (`OwnedJobDup`) drops here on every path, including an early return
        // from `wait_drained_raw` above, closing our duplicate independently of `JobHandle`.
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
