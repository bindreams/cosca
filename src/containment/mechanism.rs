//! What a contained tree is made of: the contract every way of naming a tree meets ([`Contains`]),
//! the closed set of them ([`Mechanism`]), and what a mechanism hands out: the end of its resource
//! ([`Release`]). Its drain edge is [`DrainEdge`](crate::containment::drain_edge::DrainEdge).

use std::fmt;

use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::containment::drain_edge::DrainEdge;
use crate::containment::treewalk::Left;
use crate::containment::{Containment, Root, TerminateOutcome};

/// [`Contains::kill_left`] of every mechanism but a tree walk: `result` as it is, with nothing held.
/// Only a tree walk leaves the root alone (the root's own death then settles it), so a result with
/// the root left is a walk's.
pub(crate) fn nothing_held(result: Result<(), Unkilled>) -> (Result<(), Unkilled>, Vec<Left>) {
    debug_assert!(
        !matches!(&result, Err(left) if left.root.is_some()),
        "only a tree walk leaves the root alone"
    );
    (result, Vec::new())
}

/// One way the OS names a process tree. Implemented by the mechanism types (`CgroupLeaf`, `JobHandle`,
/// `Group`, `Marker`, `Walker`) and by the test fake; a [`Tree`](crate::containment::Tree) holds one
/// as a [`Mechanism`] and asks it nothing about which it is.
pub(crate) trait Contains: fmt::Debug {
    /// Kill every member it names. Never waits. `root` is read right before each send by a mechanism
    /// that names its tree by the root's pid, which decides from it what to send; the outcome says
    /// what was skipped and why ([`Skip`](crate::containment::Skip)). Others ignore it.
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
    ///   running is an [`Error::MemberNotKilled`](crate::error::Error::MemberNotKilled).
    fn send_kill(&self, root: Option<&dyn Root>) -> TreeKillOutcome;

    /// What a kill's `result` comes to once the members an earlier kill left (`left`, which only a
    /// tree walk holds) are answered, and the members it leaves now: the tree's settlement calls it
    /// for every kill, under its one lock ([`TreeKilled::settle`](crate::containment::TreeKilled::settle)).
    /// A tree walk's root death reparents a member out of every later walk, so it kills again the
    /// members whose identity it read ([`with_earlier`](crate::containment::treewalk::with_earlier)).
    /// Every other mechanism hands `result` back, with nothing held ([`nothing_held`]).
    fn kill_left(&self, result: Result<(), Unkilled>, left: Vec<Left>) -> (Result<(), Unkilled>, Vec<Left>);

    /// The cooperative signal to every member it names, as [`send_kill`](Self::send_kill) decides it
    /// from `root`: `SIGTERM`, or `CTRL_BREAK` to the root's group `pid` on Windows. Signal-only.
    fn send_terminate(&self, pid: u32, root: Option<&dyn Root>) -> TerminateOutcome;

    /// The tree's own kernel edge for "no member runs" (a cgroup's `populated`, a job's process
    /// list, a marker pipe's EOF); `None` for a group, a session and a walk.
    fn drain_edge(&self) -> Option<DrainEdge<'_>>;

    /// What [`Child::containment`](crate::Child::containment) reports.
    fn kind(&self) -> Containment;

    /// What names the tree in a message about its teardown: a cgroup leaf its path (a kill returns
    /// the kernel's error unwrapped, so the error does not name it), every other mechanism what it is.
    #[cfg(unix)]
    fn subject(&self) -> String;

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

    /// Whether a kill through it has landed and reached `child` (see
    /// [`Reach`](crate::child::owned::teardown::Reach)): only then does the child's exit follow, so
    /// only then may it be waited for. `false` for every mechanism whose kill is subject to the kernel's
    /// permission check; an error where the child cannot be placed.
    #[cfg(unix)]
    fn reached(&self, child: &crate::child::owned::OwnedChild) -> std::io::Result<bool>;

    /// The end of the resource it owns, which the caller's wait over the [`Release`] completes: a cgroup
    /// leaf is killed through, drained and removed. The mechanisms that own nothing a wait ends have
    /// nothing to wait on. A Job Object is not released: it closes as its `Child` drops.
    #[cfg(unix)]
    #[must_use = "the resource is released only by its wait"]
    fn release(self) -> Release
    where
        Self: Sized;

    /// The steps of [`release`](Self::release) that a caller can await instead of block on, taken with
    /// the resource left where it is: only a cgroup leaf has any. `None` for every other mechanism.
    #[cfg(all(feature = "tokio", target_os = "linux"))]
    fn awaitable_release(&self) -> Option<AwaitableRelease<'_>>;
}

/// The awaitable steps of a mechanism's release ([`Contains::awaitable_release`]): a cgroup leaf's
/// first step and its drain (see
/// [`CgroupLeaf::step_and_await_drain`](crate::containment::cgroup::CgroupLeaf::step_and_await_drain)).
#[cfg(all(feature = "tokio", target_os = "linux"))]
pub(crate) struct AwaitableRelease<'a> {
    leaf: &'a crate::containment::cgroup::CgroupLeaf,
}

#[cfg(all(feature = "tokio", target_os = "linux"))]
impl<'a> AwaitableRelease<'a> {
    pub(crate) fn of_leaf(leaf: &'a crate::containment::cgroup::CgroupLeaf) -> AwaitableRelease<'a> {
        AwaitableRelease { leaf }
    }

    /// Take the steps. A future dropped mid-await leaves the rest to the resource's release. `child`
    /// names it in debug lines.
    pub(crate) async fn wait(&self, child: u32) {
        self.leaf.step_and_await_drain(child).await;
    }
}

/// The closed set of mechanisms a [`Tree`](crate::containment::Tree) is contained by, each variant
/// cfg'd as its mechanism is. Only `impl Contains for Mechanism` and the tree's `_for_test`
/// accessors match on it; everything else goes through [`Contains`].
#[derive(Debug)]
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

    fn kill_left(&self, result: Result<(), Unkilled>, left: Vec<Left>) -> (Result<(), Unkilled>, Vec<Left>) {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.kill_left(result, left),
            #[cfg(windows)]
            Mechanism::Job(m) => m.kill_left(result, left),
            #[cfg(unix)]
            Mechanism::Group(m) => m.kill_left(result, left),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.kill_left(result, left),
            Mechanism::Walk(m) => m.kill_left(result, left),
            #[cfg(test)]
            Mechanism::Fake(m) => m.kill_left(result, left),
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

    #[cfg(unix)]
    fn subject(&self) -> String {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.subject(),
            Mechanism::Group(m) => m.subject(),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.subject(),
            Mechanism::Walk(m) => m.subject(),
            #[cfg(test)]
            Mechanism::Fake(m) => m.subject(),
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

    #[cfg(unix)]
    fn reached(&self, child: &crate::child::owned::OwnedChild) -> std::io::Result<bool> {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.reached(child),
            Mechanism::Group(m) => m.reached(child),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.reached(child),
            Mechanism::Walk(m) => m.reached(child),
            #[cfg(test)]
            Mechanism::Fake(m) => m.reached(child),
        }
    }

    #[cfg(unix)]
    fn release(self) -> Release {
        match self {
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup(m) => m.release(),
            Mechanism::Group(m) => m.release(),
            #[cfg(target_os = "macos")]
            Mechanism::Marker(m) => m.release(),
            Mechanism::Walk(m) => m.release(),
            #[cfg(test)]
            Mechanism::Fake(m) => m.release(),
        }
    }

    #[cfg(all(feature = "tokio", target_os = "linux"))]
    fn awaitable_release(&self) -> Option<AwaitableRelease<'_>> {
        match self {
            Mechanism::Cgroup(m) => m.awaitable_release(),
            Mechanism::Group(m) => m.awaitable_release(),
            Mechanism::Walk(m) => m.awaitable_release(),
            #[cfg(test)]
            Mechanism::Fake(m) => m.awaitable_release(),
        }
    }
}

/// What places an elevation front once its leaf is gone: the leaf's subtree, or why it could not be
/// read. Linux only; elsewhere there is no leaf to read.
#[cfg(unix)]
pub(crate) struct FrontReach(
    #[cfg(target_os = "linux")] pub(crate) std::io::Result<Option<crate::containment::cgroup::Subtree>>,
);

/// The end of a mechanism's resource, which [`wait`](Self::wait) completes by dropping it: a cgroup
/// leaf is killed through, drained and removed. [`front_reach`](Self::front_reach) reads what places
/// an elevation front before that, since the first step may remove the leaf.
#[cfg(unix)]
#[must_use = "the resource is released only by its wait"]
pub(crate) struct Release {
    held: Held,
}

/// The resource a [`Release`] owns until its wait drops it.
#[cfg(unix)]
enum Held {
    Nothing,
    #[cfg(target_os = "linux")]
    Leaf(crate::containment::cgroup::CgroupLeaf),
}

#[cfg(unix)]
impl Release {
    /// The release of a mechanism that owns nothing a wait ends.
    pub(crate) fn nothing() -> Release {
        Release { held: Held::Nothing }
    }

    /// The release of a cgroup leaf.
    #[cfg(target_os = "linux")]
    pub(crate) fn leaf(leaf: crate::containment::cgroup::CgroupLeaf) -> Release {
        Release { held: Held::Leaf(leaf) }
    }

    /// What places an elevation front once the resource is gone, read now: only a caller that looks
    /// at a front asks, and it asks before the first step of the teardown.
    pub(crate) fn front_reach(&self) -> FrontReach {
        match &self.held {
            Held::Nothing => {
                #[cfg(target_os = "linux")]
                {
                    FrontReach(Ok(None))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    FrontReach()
                }
            }
            #[cfg(target_os = "linux")]
            Held::Leaf(leaf) => FrontReach(leaf.subtree().map(Some)),
        }
    }

    /// Drop the resource: a cgroup leaf is killed through if it is armed and occupied, drained
    /// (blocking, warned past the leaf's threshold) and removed. After [`wait_async`](Self::wait_async)
    /// it finds nothing left to wait for. It has no deadline: no caller needs one yet.
    pub(crate) fn wait(self) {
        match self.held {
            Held::Nothing => {}
            #[cfg(target_os = "linux")]
            Held::Leaf(leaf) => drop(leaf),
        }
    }

    /// The awaitable steps of [`wait`](Self::wait) (see
    /// [`CgroupLeaf::step_and_await_drain`](crate::containment::cgroup::CgroupLeaf::step_and_await_drain));
    /// a future dropped mid-await leaves the rest to `wait`. `child` names it in debug lines.
    #[cfg(feature = "tokio")]
    #[cfg_attr(
        not(target_os = "linux"),
        allow(unused_variables, reason = "only a Linux cgroup leaf has steps to await")
    )]
    pub(crate) async fn wait_async(&self, child: u32) {
        #[cfg(target_os = "linux")]
        if let Held::Leaf(leaf) = &self.held {
            leaf.step_and_await_drain(child).await;
        }
    }
}
