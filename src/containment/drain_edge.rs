//! A tree's own kernel edge for "no member runs" ([`DrainEdge`]), and the per-OS drivers that await
//! it. The drivers use the async waits' primitives (`crate::tokio::wait`'s clock, its armed
//! deadline and its readiness loop), which know nothing of a tree.

use std::time::Instant;

use crate::containment::TreeDrain;
use crate::error::Error;

#[cfg(all(feature = "tokio", windows))]
#[path = "drain_edge/job_dup.rs"]
mod job_dup;

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
                // Same reissued-fd check as `Marker::wait_drained`: a reissued read-end fd would
                // deliver a false `EV_EOF`.
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

/// Resolve when every holder of the marker's write end has exited: poll-free, no internal deadline.
/// It never drains a sustained writer on its behalf (see `marker_eof`'s module doc); bound the
/// caller's patience with a deadline instant.
///
/// Exited is not reaped: this says nothing about statuses. A caller wanting a status waits on
/// the root as well.
///
/// The marker's own kqueue is what gets registered with the reactor, not the marker
/// descriptor: a knote is keyed on `(kqueue, fd, filter)`, so a second waiter registering the
/// same descriptor directly would take over the first's registration and park it forever —
/// each call arms its OWN private kqueue (`marker_eof::arm`).
#[cfg(all(feature = "tokio", target_os = "macos"))]
pub(crate) async fn wait_tree_drained(read_end: std::os::fd::BorrowedFd<'_>) -> Result<(), Error> {
    wait_tree_drained_watched(read_end, None).await
}

/// Deadline-bounded, [`TreeDrain`]-returning wrapper over [`wait_tree_drained_inner`] — the macOS
/// arm of `tokio::Child::wait_tree`/`wait_tree_timeout`. `Duration::ZERO` delegates to the sync
/// backend's one-shot, non-blocking probe (safe to call directly from async code).
///
/// The bounded arm arms with `unbounded_wait: false`, as the sync `block_until_drained` does for a
/// real deadline; `wait_tree_drained` is always unbounded.
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
/// [`wait_tree_drained_for_test`].
#[cfg(all(feature = "tokio", target_os = "macos"))]
async fn wait_tree_drained_watched(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: Option<std::sync::mpsc::Sender<std::os::fd::RawFd>>,
) -> Result<(), Error> {
    wait_tree_drained_inner(read_end, true, armed).await
}

/// `unbounded_wait` must be the SAME expression the sync backend's `block_until_drained` uses
/// (`crate::wait::remaining(deadline).is_none()`) for whichever deadline the caller is honoring,
/// threaded through to both `arm` and `drain_kqueue`.
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

#[cfg(all(feature = "tokio", windows))]
use job_dup::OwnedJobDup;

/// Resolve when every process in the Windows job has EXITED (not reaped), or until `deadline`.
/// Job objects expose no pollable handle, so — unlike the macOS arm, on the reactor, and the Linux
/// arm, awaiting its leaf's pump — this hands the sync `JobHandle::wait_drained` loop to `spawn_blocking`,
/// releasing the blocking thread promptly on drop via the same cancel-event idiom
/// [`cancellable_blocking`](crate::tokio::wait::cancellable_blocking) uses for the process wait.
///
/// Dropping this future does not join the blocking task, so the task owns a `DuplicateHandle` copy
/// of the job handle (closed on every exit path, panic included) rather than borrowing one the
/// `Child` may close, and the kernel recycle, once the borrow ends.
#[cfg(all(feature = "tokio", windows))]
async fn job_wait_tree_drained(
    job: &crate::containment::windows::JobHandle,
    deadline: Option<Instant>,
) -> Result<TreeDrain, Error> {
    use windows::Win32::Foundation::HANDLE;

    // The kernel wait runs on the real clock, not tokio's.
    let deadline = crate::tokio::wait::to_real_clock(deadline);
    // Duration::ZERO delegates to the sync one-shot probe — no thread-pool hop needed for a
    // call that cannot block.
    if crate::wait::remaining(deadline) == Some(std::time::Duration::ZERO) {
        return job.wait_drained(deadline, None);
    }
    let job_dup = OwnedJobDup::new(job.handle())?;

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
        let result =
            crate::containment::windows::wait_drained_raw(handles.job.handle(), deadline, Some(handles.cancel));
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
