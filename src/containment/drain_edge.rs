//! A tree's own kernel edge for "no member runs" ([`DrainEdge`]), and the per-OS drivers that await
//! it. The drivers use the async waits' primitives (`crate::tokio::wait`'s clock, its armed
//! deadline and its readiness loop), which know nothing of a tree.

use std::time::Instant;

use crate::containment::tree_kill::Settled;
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
        self.wait_past(deadline, &Settled::default())
    }

    /// [`wait`](Self::wait) for a caller that has already waited for the members `settled`, each of which
    /// exited or failed in a way it reported. Only a Job's edge, which confirms an empty listing from a
    /// system snapshot of its members, has anything to skip: it neither waits for them nor reports them
    /// again.
    pub(crate) fn wait_past(&self, deadline: Option<Instant>, settled: &Settled) -> Result<TreeDrain, Error> {
        #[cfg(not(windows))]
        let _ = settled;
        match self {
            #[cfg(target_os = "linux")]
            DrainEdge::Cgroup(leaf) => leaf.wait_drained(deadline),
            #[cfg(windows)]
            DrainEdge::Job(job) => job.wait_drained_past(deadline, settled),
            #[cfg(target_os = "macos")]
            DrainEdge::Marker(m) => m.wait_drained(deadline),
        }
    }

    /// [`wait`](Self::wait), awaited, with no thread blocked: macOS is reactor-native (`AsyncFd`);
    /// Linux awaits a broadcast from the pump thread its leaf owns (an `event_listener` future, no
    /// reactor registration); Windows awaits registered waits on the job's members (job objects
    /// have no pollable handle). `deadline` is on tokio's clock
    /// ([`deadline_from`](crate::tokio::wait::deadline_from)).
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_async(&self, deadline: Option<Instant>) -> Result<TreeDrain, Error> {
        self.wait_async_past(deadline, &Settled::default()).await
    }

    /// [`wait_past`](Self::wait_past), awaited.
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_async_past(
        &self,
        deadline: Option<Instant>,
        settled: &Settled,
    ) -> Result<TreeDrain, Error> {
        #[cfg(not(windows))]
        let _ = settled;
        match self {
            #[cfg(target_os = "linux")]
            DrainEdge::Cgroup(leaf) => cgroup_wait_tree_drained(leaf, deadline).await,
            #[cfg(windows)]
            DrainEdge::Job(job) => job_wait_tree_drained(job, deadline, settled).await,
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

/// The members of `job` a system snapshot names ([`unsignalled_members_of`]), found on tokio's
/// blocking pool: the scan opens every process on the system, which a runtime thread must not do.
/// The task owns a duplicate of the job's handle, because it can outlive the future that asked for
/// it. The scan is bounded work that waits for no exit, as the pool is for.
#[cfg(all(feature = "tokio", windows))]
async fn snapshot_members_on_pool(
    job: &crate::containment::windows::JobHandle,
) -> Result<Vec<crate::containment::windows::Found>, Error> {
    use crate::containment::windows::unsignalled_members_of;
    use std::os::windows::io::AsHandle as _;

    let held = job.handle().try_clone_to_owned().map_err(|e| Error::Unassessable {
        detail: "the job's handle could not be duplicated for the snapshot of its members".to_owned(),
        source: Some(Error::io_cause(e)),
    })?;
    crate::tokio::wait::on_blocking_pool("the snapshot of a job's members", move || {
        unsignalled_members_of(held.as_handle())
    })
    .await
    .map_err(|unjoined| {
        let (crate::tokio::wait::Unjoined::NotRun(cause) | crate::tokio::wait::Unjoined::Unknown(cause)) = unjoined;
        Error::Unassessable {
            detail: "the snapshot of the job's members did not run, so their exit cannot be observed".to_owned(),
            source: Some(std::sync::Arc::new(cause)),
        }
    })?
}

/// Resolve when every process in the Windows job has EXITED (not reaped), or until `deadline`.
/// Job objects expose no pollable handle, so — unlike the macOS arm, on the reactor, and the Linux
/// arm, awaiting its leaf's pump — this runs the sync wait's own rounds
/// ([`JobHandle::drain_round`](crate::containment::windows::JobHandle::drain_round)) and awaits each
/// round's member handles as registered waits where the sync wait blocks on them. The deadline is
/// the registrations' own timeout (see [`registered_wait`](crate::os_process::windows::registered_wait));
/// dropping the future unregisters the round's waits.
///
/// An empty listing is confirmed from a system snapshot, as the sync wait's `confirm_drained` does:
/// each job member it names, except those `settled`, is awaited in turn through the by-identity wait
/// a kill's wait uses. It is the sync wait's own [`ConfirmWalk`]; the two differ only in how a member
/// is waited for.
///
/// The round's own work (a listing and up to 63 opens) runs on the polling thread: it waits for no
/// exit and is bounded. The snapshot of an empty listing, with one open per process on the system,
/// runs on the blocking pool ([`snapshot_members_on_pool`]). Every round reaches an
/// await, so a future that is dropped between rounds is not starved by rounds that find every
/// member gone.
#[cfg(all(feature = "tokio", windows))]
async fn job_wait_tree_drained(
    job: &crate::containment::windows::JobHandle,
    deadline: Option<Instant>,
    settled: &Settled,
) -> Result<TreeDrain, Error> {
    use crate::containment::tree_kill::wait_for_member_async;
    use crate::containment::windows::{ConfirmStep, ConfirmWalk, Ended, Round};
    use crate::identity::HostKernel;
    use crate::os_process::windows::registered_wait::{wait_any, Woke};

    // The registered waits run on the real clock, not tokio's.
    let deadline = crate::tokio::wait::to_real_clock(deadline);
    loop {
        // A round that starts past the deadline is the last, as in the sync wait.
        let last_round = deadline.is_some_and(|at| crate::wait::now() >= at);
        let round = match job.drain_round(last_round)? {
            Round::Watch(watch) => {
                let ended = if last_round {
                    watch.poll()?
                } else {
                    match wait_any(watch.handles(), deadline).await.map_err(Error::Io)? {
                        Woke::Signalled => Ended::Signalled,
                        // The deadline passed first. One look at the handles, as the sync wait's
                        // zero-ms wait is: a member that exited as it passed is seen, and the last
                        // round lists.
                        Woke::TimedOut => watch.poll()?,
                    }
                };
                match ended {
                    Ended::Deadline => return Ok(TreeDrain::MembersRemain),
                    Ended::Signalled => job.after_signalled(&watch)?,
                }
            }
            round => round,
        };
        match round {
            Round::Answer(drain) => return Ok(drain),
            // The sync wait's `confirm_drained`: the same walk, each member awaited through the same
            // by-identity wait a kill's wait uses.
            Round::Confirm => {
                let Some(count) = job.count_to_confirm()? else {
                    return Ok(TreeDrain::AllMembersExited);
                };
                let mut walk = ConfirmWalk::new(job, count, snapshot_members_on_pool(job).await, settled);
                loop {
                    match walk.next() {
                        ConfirmStep::Wait(id) => {
                            walk.waited(id, wait_for_member_async(&HostKernel, id, deadline).await)
                        }
                        ConfirmStep::Done(answer) => return answer,
                    }
                }
            }
            Round::List | Round::Watch(_) => {}
        }
        // A signal that was already waiting at registration resolves without a pending poll, and a
        // round that found every member gone reached no suspension at all: yield before listing
        // again.
        ::tokio::task::yield_now().await;
    }
}
