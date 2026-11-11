//! What a contained tree is made of: the contract every way of naming a tree meets ([`Contains`]),
//! the closed set of them ([`Mechanism`]), and what a mechanism hands out: the tree's own drain edge
//! ([`DrainEdge`]) and the end of its resource ([`Release`]).

use std::fmt;
use std::time::Instant;

use crate::containment::dispatch::TreeKillOutcome;
use crate::containment::{Containment, Root, TerminateOutcome, TreeDrain};
use crate::error::Error;

/// One way the OS names a process tree. Implemented by the mechanism types (`CgroupLeaf`, `JobHandle`,
/// `Group`, `Marker`, `Walker`) and by the test fake; a [`Tree`](crate::containment::Tree) holds one
/// as a [`Mechanism`] and asks it nothing about which it is.
pub(crate) trait Contains: fmt::Debug {
    /// Kill every member it names. Never waits. `root` is the root a mechanism that names its tree by
    /// the root's pid looks at, right before each send by the number, and decides what to send by
    /// it: the outcome says what it did not send, and why ([`Skip`](crate::containment::Skip)).
    /// Every other mechanism ignores it.
    ///
    /// What `Ok` says depends on how the mechanism names the tree:
    ///
    /// - A cgroup leaf and a Job Object name it in the kernel: `Ok` says the kernel killed every
    ///   member, however it was spawned.
    /// - A process group or session, and an fd marker, name it by a number or a pipe: `Ok` says every
    ///   member they list or find holding it was reached. A member outside it (one that left the
    ///   group, or on Linux one `hidepid` hides) is not.
    /// - A tree walk names it by parentage: `Ok` says every descendant of the root at the walk's
    ///   snapshot was killed. A process already reparented away from the root (an orphan), or one the
    ///   snapshot did not list, is not a descendant to it and is not killed. A descendant it left
    ///   running is an [`Error::MemberNotKilled`].
    fn send_kill(&self, root: Option<&dyn Root>) -> TreeKillOutcome;

    /// The cooperative signal to every member it names, as [`send_kill`](Self::send_kill) decides it
    /// from `root`: `SIGTERM`, or `CTRL_BREAK` to the root's group `pid` on Windows. Signal-only.
    fn send_terminate(&self, pid: u32, root: Option<&dyn Root>) -> TerminateOutcome;

    /// The tree's own kernel edge for "no member runs" (a cgroup's `populated`, a job's process
    /// list, a marker pipe's EOF); `None` for a group, a session and a walk.
    fn drain_edge(&self) -> Option<DrainEdge<'_>>;

    /// What [`Child::containment`](crate::Child::containment) reports.
    fn kind(&self) -> Containment;

    /// Neutralize the resource's own kill on drop (`detach`, `kill_on_drop(false)`): a Job Object's
    /// `KILL_ON_JOB_CLOSE`, a cgroup leaf's `Drop` kill. `Ok` where there is none; only a Job's can
    /// fail (the OS refuses `SetInformationJobObject`), and the resource is then still armed.
    fn disarm(&self) -> std::io::Result<()>;

    /// Whether a kill sent through it would reach `pid` (which `pidfd` names, when there is one)
    /// whatever its credentials: only a cgroup's `cgroup.kill` does, and only while `pid` is in it. A
    /// signal to a group or to walked members is subject to the kernel's permission check, so it is
    /// `false` for every other mechanism. `pid` must be this process's unreaped child, so its number
    /// is not reused.
    #[cfg(unix)]
    fn would_reach(&self, pid: u32, pidfd: Option<std::os::fd::BorrowedFd<'_>>) -> std::io::Result<bool>;

    /// The end of the resource it owns, which the caller's wait over the [`Release`] completes: a cgroup
    /// leaf is killed through, drained and removed, a Job Object is closed. The mechanisms that own
    /// nothing a wait ends have nothing to wait on.
    #[must_use = "the resource is released only by its wait"]
    #[cfg_attr(
        not(any(unix, feature = "tokio")),
        allow(dead_code, reason = "only a Unix teardown and an awaited one release a tree")
    )]
    fn release(self) -> Release
    where
        Self: Sized;
}

/// The closed set of mechanisms a [`Tree`](crate::containment::Tree) is contained by, each variant
/// cfg'd as its mechanism is. Only `impl Contains for Mechanism` and the tree's `_for_test`
/// accessors match on it; everything else goes through [`Contains`].
pub(crate) enum Mechanism {
    /// Linux cgroup v2 leaf + `cgroup.kill`.
    #[cfg(target_os = "linux")]
    Cgroup(crate::containment::cgroup::CgroupLeaf),
    /// Windows Job Object + `KILL_ON_JOB_CLOSE`.
    #[cfg(windows)]
    Job(crate::containment::windows::JobHandle),
    /// A Unix process group or session, named by the root's pid.
    #[cfg(unix)]
    Group(crate::containment::unix::Group),
    /// macOS inherited-fd marker: membership survives `setsid`, `setpgid`, reparenting and `exec`.
    /// Owns the supervisor's read end of the marker pipe, which keeps the pipe's kernel identity
    /// from being re-issued, plus, when the mode created one, the pgid.
    #[cfg(target_os = "macos")]
    Marker(crate::containment::fdmarker::Marker),
    /// Identity-aware tree-walk teardown (cross-platform): the root's identity is re-enumerated and
    /// killed by identity at teardown. The universal fallback, and selectable on every OS.
    Walk(crate::containment::treewalk::Walker),
    /// A table of stated answers, for the tests of what consumes a tree.
    #[cfg(test)]
    Fake(crate::containment::fake::FakeContains),
}

impl fmt::Debug for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.fmt(f),
            #[cfg(windows)]
            Mechanism::Job(m) => m.fmt(f),
            #[cfg(unix)]
            Mechanism::Group(m) => m.fmt(f),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.fmt(f),
            Mechanism::Walk(m) => m.fmt(f),
            #[cfg(test)]
            Mechanism::Fake(m) => m.fmt(f),
        }
    }
}

impl Contains for Mechanism {
    fn send_kill(&self, root: Option<&dyn Root>) -> TreeKillOutcome {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.send_kill(root),
            #[cfg(windows)]
            Mechanism::Job(m) => m.send_kill(root),
            #[cfg(unix)]
            Mechanism::Group(m) => m.send_kill(root),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.send_kill(root),
            Mechanism::Walk(m) => m.send_kill(root),
            #[cfg(test)]
            Mechanism::Fake(m) => m.send_kill(root),
        }
    }

    fn send_terminate(&self, pid: u32, root: Option<&dyn Root>) -> TerminateOutcome {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.send_terminate(pid, root),
            #[cfg(windows)]
            Mechanism::Job(m) => m.send_terminate(pid, root),
            #[cfg(unix)]
            Mechanism::Group(m) => m.send_terminate(pid, root),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.send_terminate(pid, root),
            Mechanism::Walk(m) => m.send_terminate(pid, root),
            #[cfg(test)]
            Mechanism::Fake(m) => m.send_terminate(pid, root),
        }
    }

    fn drain_edge(&self) -> Option<DrainEdge<'_>> {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.drain_edge(),
            #[cfg(windows)]
            Mechanism::Job(m) => m.drain_edge(),
            #[cfg(unix)]
            Mechanism::Group(m) => m.drain_edge(),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.drain_edge(),
            Mechanism::Walk(m) => m.drain_edge(),
            #[cfg(test)]
            Mechanism::Fake(m) => m.drain_edge(),
        }
    }

    fn kind(&self) -> Containment {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.kind(),
            #[cfg(windows)]
            Mechanism::Job(m) => m.kind(),
            #[cfg(unix)]
            Mechanism::Group(m) => m.kind(),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.kind(),
            Mechanism::Walk(m) => m.kind(),
            #[cfg(test)]
            Mechanism::Fake(m) => m.kind(),
        }
    }

    fn disarm(&self) -> std::io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => Contains::disarm(m),
            #[cfg(windows)]
            Mechanism::Job(m) => Contains::disarm(m),
            #[cfg(unix)]
            Mechanism::Group(m) => m.disarm(),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.disarm(),
            Mechanism::Walk(m) => m.disarm(),
            #[cfg(test)]
            Mechanism::Fake(m) => m.disarm(),
        }
    }

    #[cfg(unix)]
    fn would_reach(&self, pid: u32, pidfd: Option<std::os::fd::BorrowedFd<'_>>) -> std::io::Result<bool> {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.would_reach(pid, pidfd),
            Mechanism::Group(m) => m.would_reach(pid, pidfd),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.would_reach(pid, pidfd),
            Mechanism::Walk(m) => m.would_reach(pid, pidfd),
            #[cfg(test)]
            Mechanism::Fake(m) => m.would_reach(pid, pidfd),
        }
    }

    fn release(self) -> Release {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.release(),
            #[cfg(windows)]
            Mechanism::Job(m) => m.release(),
            #[cfg(unix)]
            Mechanism::Group(m) => m.release(),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.release(),
            Mechanism::Walk(m) => m.release(),
            #[cfg(test)]
            Mechanism::Fake(m) => m.release(),
        }
    }
}

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
            DrainEdge::Cgroup(leaf) => crate::tokio::wait::cgroup_wait_tree_drained(leaf, deadline).await,
            #[cfg(windows)]
            DrainEdge::Job(job) => crate::tokio::wait::job_wait_tree_drained(job, deadline).await,
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
                crate::tokio::wait::wait_tree_deadline(m.read_end(), deadline).await
            }
        }
    }
}

/// What places an elevation front once its leaf is gone: the leaf's subtree, or why it could not be
/// read. Linux only; elsewhere there is no leaf to read.
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "only a Unix teardown looks at an elevation front")
)]
pub(crate) struct FrontReach(
    #[cfg(target_os = "linux")] pub(crate) std::io::Result<Option<crate::containment::cgroup::Subtree>>,
);

/// The end of a mechanism's resource, which [`wait`](Self::wait) completes by dropping it: a cgroup
/// leaf is killed through, drained and removed; a Job Object is closed. It carries what places an
/// elevation front once the leaf is gone, read before the first step, which may remove the leaf.
#[must_use = "the resource is released only by its wait"]
#[cfg_attr(
    not(any(unix, feature = "tokio")),
    allow(dead_code, reason = "only a Unix teardown and an awaited one release a tree")
)]
pub(crate) struct Release {
    reach: FrontReach,
    held: Held,
}

/// The resource a [`Release`] owns until its wait drops it.
#[cfg_attr(
    not(any(unix, feature = "tokio")),
    allow(dead_code, reason = "only a Unix teardown and an awaited one release a tree")
)]
enum Held {
    Nothing,
    #[cfg(target_os = "linux")]
    Leaf(crate::containment::cgroup::CgroupLeaf),
    #[cfg(windows)]
    Job(crate::containment::windows::JobHandle),
}

#[cfg_attr(
    not(any(unix, feature = "tokio")),
    allow(dead_code, reason = "only a Unix teardown and an awaited one release a tree")
)]
impl Release {
    /// The release of a mechanism that owns nothing a wait ends.
    pub(crate) fn nothing() -> Release {
        Release {
            #[cfg(target_os = "linux")]
            reach: FrontReach(Ok(None)),
            #[cfg(not(target_os = "linux"))]
            reach: FrontReach(),
            held: Held::Nothing,
        }
    }

    /// The release of a cgroup leaf: its subtree is read now, before any step of its teardown.
    #[cfg(target_os = "linux")]
    pub(crate) fn leaf(leaf: crate::containment::cgroup::CgroupLeaf) -> Release {
        Release {
            reach: FrontReach(leaf.subtree().map(Some)),
            held: Held::Leaf(leaf),
        }
    }

    /// The release of a Job Object, which its close ends (and kills through, unless it is disarmed).
    #[cfg(windows)]
    pub(crate) fn job(job: crate::containment::windows::JobHandle) -> Release {
        Release {
            reach: FrontReach(),
            held: Held::Job(job),
        }
    }

    /// Drop the resource: a cgroup leaf is killed through if it is armed and occupied, drained
    /// (blocking, warned past the leaf's threshold) and removed. After [`wait_async`](Self::wait_async)
    /// it finds nothing left to wait for. Answers what places an elevation front.
    pub(crate) fn wait(self) -> FrontReach {
        match self.held {
            Held::Nothing => {}
            #[cfg(target_os = "linux")]
            Held::Leaf(leaf) => drop(leaf),
            #[cfg(windows)]
            Held::Job(job) => drop(job),
        }
        self.reach
    }

    /// The steps of [`wait`](Self::wait) that can be awaited instead of blocked on: a leaf's first
    /// step, the one its drop takes first
    /// ([`CgroupLeaf::remove_else_kill`](crate::containment::cgroup::CgroupLeaf::remove_else_kill)),
    /// then the drain a landed kill bounds, so that the drop in `wait` finds it drained. A drain that
    /// cannot be watched is left to `wait`. The resource stays held, so a future dropped mid-await
    /// leaves the whole of it to `wait`.
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_async(&mut self) {
        #[cfg(target_os = "linux")]
        if let Held::Leaf(leaf) = &self.held {
            // The leaf's drop makes this step again and reports what remains. A leaf that is occupied
            // is the expected failure; one already gone is proof of a drain. Any other failure
            // (EACCES, EIO) is the environment's, so it is logged, never asserted.
            if let Err(e) = leaf.remove_else_kill() {
                let occupied = matches!(e.raw_os_error(), Some(libc::EBUSY | libc::ENOTEMPTY));
                if !occupied && !crate::containment::cgroup::removed_after_drain(&e) {
                    log::debug!(
                        "cgroup leaf {}: its first rmdir failed ({report})",
                        leaf.path().display(),
                        report = crate::error::Report(&e)
                    );
                }
            }
            if !leaf.kill_landed() {
                return;
            }
            if let Err(e) = crate::tokio::wait::cgroup_wait_tree_drained(leaf, None).await {
                log::debug!(
                    "cgroup leaf {}: its leaf's drain cannot be watched ({report}); the teardown waits for it on this thread, blocking",
                    leaf.path().display(),
                    report = crate::error::Report(&e)
                );
            }
        }
    }
}
