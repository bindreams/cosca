//! The tree a [`Child`](crate::Child) owns: none, a nested member's (delegated), or contained by one
//! mechanism, with where that tree stands after the kills that settled it. Everything the child does to
//! its tree goes through [`Tree`], which asks its mechanism only through [`Contains`].

#[cfg(unix)]
use crate::containment::dispatch::{SettleOutcome, Unsettled};
use crate::containment::dispatch::{SweepFailure, TreeKillOutcome, TreeKilled};
use crate::containment::drain_edge::DrainEdge;
#[cfg(unix)]
use crate::containment::mechanism::Release;
use crate::containment::mechanism::{Contains, Mechanism};
use crate::containment::{Containment, Root, TerminateOutcome};
use crate::error::Error;

/// Owns the OS containment resource for a spawned child. `killed` is where the tree stands after the
/// kills and drops that settled it ([`TreeKilled`]); it is the handle's, whatever it holds, and
/// outlives the mechanism's [`release`](Self::release).
#[derive(Debug, Default)]
pub(crate) struct Tree {
    holder: Holder,
    killed: TreeKilled,
    /// What the tree was when its mechanism was released, which no longer holds it: the tree still
    /// reports and settles as it was. `None` for a tree never released.
    released_as: Option<Containment>,
}

/// What holds the tree.
#[derive(Debug, Default)]
#[allow(
    clippy::large_enum_variant,
    reason = "one per child, held inline: a leaf is the largest mechanism, and boxing it would add an allocation to every contained spawn"
)]
enum Holder {
    /// Uncontained: lone-process semantics. Also what a released tree holds.
    #[default]
    None,
    /// A nested containment member: it joined an ancestor's group/job and owns no teardown mechanism
    /// of its own (the outermost root tears the tree down). Distinct from `None` (genuinely
    /// uncontained) so `_tree` ops can error honestly.
    Delegated,
    /// Contained by this mechanism.
    Contained(Mechanism),
}

impl Tree {
    /// An uncontained tree, never settled.
    pub(crate) fn none() -> Tree {
        Tree::default()
    }

    /// A nested member's tree, never settled.
    pub(crate) fn delegated() -> Tree {
        Tree {
            holder: Holder::Delegated,
            ..Tree::default()
        }
    }

    /// A tree contained by `mechanism`, never settled.
    pub(crate) fn contained(mechanism: Mechanism) -> Tree {
        Tree {
            holder: Holder::Contained(mechanism),
            ..Tree::default()
        }
    }

    /// The teardown mechanism this tree achieved (queried via `Child::containment()`): the one source
    /// of it, and the same after the mechanism's [`release`](Self::release).
    pub(crate) fn containment(&self) -> Containment {
        match &self.holder {
            Holder::None => self.released_as.unwrap_or(Containment::None),
            Holder::Delegated => Containment::Delegated,
            Holder::Contained(mechanism) => mechanism.kind(),
        }
    }

    /// Guard for the `_tree` operations (single-sourced with the async `Child`): they act on the
    /// containment group's teardown mechanism, so a child that holds none has no tree to act on.
    pub(crate) fn require_contained(&self) -> Result<(), Error> {
        let contained = matches!(self.holder, Holder::Contained(_));
        if self.released_as.is_none() {
            debug_assert_eq!(
                self.containment().can_teardown(),
                contained,
                "`can_teardown` disagrees with the holder of {:?}",
                self.containment()
            );
        }
        if contained {
            return Ok(());
        }
        Err(Error::Unsupported {
            op: "tree teardown (kill_tree / terminate_tree)".into(),
            platform: std::env::consts::OS,
            detail: "this child holds no actionable tree-teardown mechanism (uncontained, \
                     or a nested member of an ancestor's containment group). Use kill() for a \
                     lone process, or tear down the tree via the outermost .contain()ed handle."
                .into(),
            source: None,
        })
    }

    /// The tree's own drain edge, for `wait_tree`/`wait_tree_timeout` and a graceful shutdown's grace
    /// (single-sourced with the async `Child`): only a mechanism with a real kernel edge can answer
    /// "has the whole tree exited" without polling. `None` for everything else (an uncontained child,
    /// a nested `Delegated` member, or a teardown-only mechanism like a process group or a walk).
    pub(crate) fn drain_edge(&self) -> Option<DrainEdge<'_>> {
        let edge = match &self.holder {
            Holder::Contained(mechanism) => mechanism.drain_edge(),
            Holder::None | Holder::Delegated => None,
        };
        if self.released_as.is_none() {
            debug_assert_eq!(
                self.containment().can_observe_drain(),
                edge.is_some(),
                "`can_observe_drain` disagrees with the drain edge of {:?}",
                self.containment()
            );
        }
        edge
    }

    /// What a call that needs the tree's drain edge answers when it has none.
    fn no_drain_edge(&self) -> Error {
        Error::Unsupported {
            op: "wait for the contained tree to drain (wait_tree / wait_tree_timeout)".into(),
            platform: std::env::consts::OS,
            detail: format!(
                "this child's containment mechanism ({containment}) exposes no kernel edge for \
                 tree drain — only cgroup v2, a Windows job object, and the macOS fd marker do. \
                 Use kill_tree()/terminate_tree() for teardown, or wait() to watch the root alone.",
                containment = self.containment()
            ),
            source: None,
        }
    }

    /// Block until every member has exited, or until `deadline`, through the tree's drain edge
    /// ([`DrainEdge::wait`]); `Unsupported` where it has none.
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<crate::containment::TreeDrain, Error> {
        self.drain_edge().ok_or_else(|| self.no_drain_edge())?.wait(deadline)
    }

    /// [`wait_drained`](Self::wait_drained), awaited ([`DrainEdge::wait_async`]).
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_drained_async(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<crate::containment::TreeDrain, Error> {
        self.drain_edge()
            .ok_or_else(|| self.no_drain_edge())?
            .wait_async(deadline)
            .await
    }

    /// Hard-kill the contained tree (best-effort; a member that is already gone is success), as the
    /// mechanism's [`send_kill`](Contains::send_kill) decides it from `root`. A tree that is none or
    /// delegated has nothing to kill.
    pub(crate) fn kill(&self, root: Option<&dyn Root>) -> TreeKillOutcome {
        match &self.holder {
            Holder::None | Holder::Delegated => {
                debug_assert!(self.released_as.is_none(), "a send on a released tree");
                TreeKillOutcome::Ran(Ok(()))
            }
            Holder::Contained(mechanism) => mechanism.send_kill(root),
        }
    }

    /// [`kill`](Self::kill) for a caller with no root to kill after it, settled and reported as
    /// [`settle_for_kill_tree`](Self::settle_for_kill_tree) does, with the root not ended. `caller`
    /// names the call in the warns of the members it left besides the first.
    #[cfg(unix)]
    pub(crate) fn kill_settled(&self, caller: &str, root: Option<&dyn Root>) -> Result<(), Error> {
        self.settle_for_kill_tree(caller, self.kill(root), false)
    }

    /// Send the graceful termination signal to the tree (signal-only), as [`kill`](Self::kill) decides
    /// it from `root`: the outcome says what went out, or what was skipped and what the caller does
    /// about it.
    pub(crate) fn terminate(&self, pid: u32, root: Option<&dyn Root>) -> TerminateOutcome {
        match &self.holder {
            Holder::None | Holder::Delegated => {
                debug_assert!(false, "Tree::terminate on a tree that is not contained");
                TerminateOutcome::Sent {
                    result: Err(Error::Unsupported {
                        op: "terminate on a non-actionable mechanism".into(),
                        platform: std::env::consts::OS,
                        detail: "internal invariant: a non-actionable mechanism reached terminate".into(),
                        source: None,
                    }),
                    earlier: Some("the SIGTERM"),
                }
            }
            Holder::Contained(mechanism) => mechanism.send_terminate(pid, root),
        }
    }

    /// Whether a kill sent through the mechanism would reach `pid` whatever its credentials (see
    /// [`Contains::would_reach`]): `false` for a tree that is none or delegated.
    #[cfg(unix)]
    pub(crate) fn would_reach(&self, pid: u32, pidfd: Option<std::os::fd::BorrowedFd<'_>>) -> std::io::Result<bool> {
        match &self.holder {
            Holder::None | Holder::Delegated => {
                debug_assert!(self.released_as.is_none(), "a send on a released tree");
                Ok(false)
            }
            Holder::Contained(mechanism) => mechanism.would_reach(pid, pidfd),
        }
    }

    /// Apply a handle's `kill_on_drop` decision to the containment resource, once its spawn is
    /// committed.
    ///
    /// `Child::drop` returning early on `kill_on_drop == false` skips only ITS teardown. The
    /// resource is a field of that handle and drops with it regardless — and a `CgroupLeaf`'s
    /// `Drop` fires `cgroup.kill` over an occupied leaf, a Job Object's close fires
    /// `KILL_ON_JOB_CLOSE`. So the opt-out has to reach the resource as well, which is what
    /// [`disarm`](Self::disarm) is for.
    ///
    /// Called as spawn hands the handle over, not earlier (a later spawn failure must still tear the
    /// tree down) and not in `Drop` (a supervisor exiting without destructors still has its Job
    /// closed by the OS, and `KILL_ON_JOB_CLOSE` is the kill).
    ///
    /// # Errors
    ///
    /// The refusal of the disarm (Windows: `SetInformationJobObject`), when the handle opted out
    /// of `kill_on_drop`: the resource is then still armed, and the caller must not hand the child
    /// over as one cosca no longer kills.
    pub(crate) fn honor_kill_on_drop(&self, kill_on_drop: bool) -> std::io::Result<()> {
        if kill_on_drop {
            Ok(())
        } else {
            self.disarm()
        }
    }

    /// Neutralize teardown so `detach()` leaves the tree running (see [`Contains::disarm`]). A tree
    /// that is none or delegated owns nothing to neutralize.
    pub(crate) fn disarm(&self) -> std::io::Result<()> {
        match &self.holder {
            Holder::None | Holder::Delegated => {
                debug_assert!(self.released_as.is_none(), "a send on a released tree");
                Ok(())
            }
            Holder::Contained(mechanism) => mechanism.disarm(),
        }
    }

    /// The end of the tree's resource (see [`Contains::release`]): the mechanism leaves the tree and
    /// its [`Release`] owns it until its wait. What the kills left stays the tree's ([`TreeKilled`]),
    /// and so does what it was ([`containment`](Self::containment)), so a settle after the release is
    /// over the real state, with nothing held.
    #[cfg(unix)]
    #[must_use = "the resource is released only by its wait"]
    pub(crate) fn release(&mut self) -> Release {
        self.released_as = Some(self.containment());
        match std::mem::take(&mut self.holder) {
            Holder::None | Holder::Delegated => Release::nothing(),
            Holder::Contained(mechanism) => mechanism.release(),
        }
    }

    /// [`CgroupLeaf::step_and_await_drain`](crate::containment::cgroup::CgroupLeaf::step_and_await_drain)
    /// with the leaf left in the tree; a no-op for any other tree.
    #[cfg(all(feature = "tokio", target_os = "linux"))]
    pub(crate) async fn step_leaf_and_await_drain(&self, child: u32) {
        if let Holder::Contained(Mechanism::Cgroup(leaf)) = &self.holder {
            leaf.step_and_await_drain(child).await;
        }
    }

    /// What names this mechanism's tree in a message about its teardown (see [`Contains::subject`]).
    #[cfg(unix)]
    pub(crate) fn teardown_subject(&self) -> String {
        match &self.holder {
            Holder::None => "None".to_owned(),
            Holder::Delegated => "Delegated".to_owned(),
            Holder::Contained(mechanism) => mechanism.subject(),
        }
    }

    /// Whether this handle already killed the tree completely, as the settlement left it.
    #[cfg(unix)]
    pub(crate) fn is_killed(&self) -> bool {
        self.killed.is_set()
    }

    /// The tree's settlement ([`TreeKilled`]) and whether the tree is a walk's, whose held members
    /// are the walk's own state, for `f`.
    fn settling<R>(&self, f: impl FnOnce(&TreeKilled, bool) -> R) -> R {
        f(&self.killed, self.containment() == Containment::TreeWalk)
    }

    /// What a tree kill's `outcome` comes to once the root's own handle has had its say
    /// ([`TreeKilled::settle`]). Only a Unix cleanup reads the answer itself.
    #[cfg(unix)]
    pub(crate) fn settle(
        &self,
        outcome: impl Into<TreeKillOutcome>,
        root_ended: bool,
    ) -> Result<SettleOutcome, Unsettled> {
        self.settling(|killed, walk| killed.settle(walk, outcome, root_ended))
    }

    /// [`settle`](Self::settle) for a `kill_tree` call, which reports: the error names the first member
    /// left, and each other is warned of here, once. `caller` names the call in those warns.
    pub(crate) fn settle_for_kill_tree(
        &self,
        caller: &str,
        outcome: impl Into<TreeKillOutcome>,
        root_ended: bool,
    ) -> Result<(), Error> {
        self.settling(|killed, walk| killed.settle_for_kill_tree(caller, walk, outcome, root_ended))
    }

    /// `outcome` for a `kill_tree` that goes on to the root's backstop (see
    /// [`TreeKilled::unless_unwalked`]).
    pub(crate) fn unless_unwalked(
        &self,
        caller: &str,
        outcome: TreeKillOutcome,
    ) -> Result<TreeKillOutcome, SweepFailure> {
        self.settling(|killed, walk| killed.unless_unwalked(caller, walk, outcome))
    }

    /// [`settle`](Self::settle) for a drop: the text of its warn when the tree is not settled, worded
    /// here and only when it will be logged.
    pub(crate) fn settle_for_drop(&self, outcome: impl Into<TreeKillOutcome>, root_ended: bool) -> Option<String> {
        self.settling(|killed, walk| killed.settle_for_drop(walk, outcome, root_ended))
    }
}

/// Whether the tree kill of this mechanism reached the child ([`Contains::reached`]): `false` for a
/// tree that is none or delegated.
#[cfg(unix)]
impl crate::child::owned::teardown::Reach for Tree {
    fn reached(&self, child: &crate::child::owned::OwnedChild) -> std::io::Result<bool> {
        match &self.holder {
            Holder::None | Holder::Delegated => Ok(false),
            Holder::Contained(mechanism) => mechanism.reached(child),
        }
    }
}

// Test accessors -----
//
// The `pub` accessors of `Child` that integration tests reach forward to them.

#[cfg(windows)]
impl Tree {
    /// Whether `pid` is inside this tree's Job Object (see
    /// [`job_contains_pid`](crate::containment::windows::job_contains_pid)). `false` for any other
    /// tree.
    pub(crate) fn job_contains_for_test(&self, pid: u32) -> bool {
        match self.job_for_test() {
            Some(job) => crate::containment::windows::job_contains_pid(job, pid),
            None => false,
        }
    }

    /// Whether this tree's Job Object kills its members when its last handle closes. `false` for any
    /// other tree. Panics, naming the cause, when the query fails or the job handle is closed.
    pub(crate) fn job_kills_on_close_for_test(&self) -> bool {
        match self.job_for_test() {
            Some(job) => crate::containment::windows::job_kills_on_close(job),
            None => false,
        }
    }

    /// The Job Object of this tree, if it is contained by one.
    pub(crate) fn job_for_test(&self) -> Option<&crate::containment::windows::JobHandle> {
        match &self.holder {
            Holder::Contained(Mechanism::Job(job)) => Some(job),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
impl Tree {
    /// The cgroup leaf of this tree, if it is contained by one.
    #[cfg(test)]
    pub(crate) fn cgroup_leaf_for_test(&self) -> Option<&crate::containment::cgroup::CgroupLeaf> {
        match &self.holder {
            Holder::Contained(Mechanism::Cgroup(leaf)) => Some(leaf),
            _ => None,
        }
    }
}

#[cfg(all(test, unix))]
impl Tree {
    /// Whether this tree signals a process group named by the root's pid: a process group, and a
    /// macOS fd marker whose mode made a group.
    pub(crate) fn signals_a_group_for_test(&self) -> bool {
        match &self.holder {
            Holder::Contained(Mechanism::Group(_)) => true,
            #[cfg(target_os = "macos")]
            Holder::Contained(Mechanism::Marker(m)) => m.pgid().is_some(),
            _ => false,
        }
    }

    /// The root a tree walk walks from; `None` for any other tree.
    pub(crate) fn walk_root_for_test(&self) -> Option<crate::identity::ProcessId> {
        match &self.holder {
            Holder::Contained(Mechanism::Walk(walk)) => Some(walk.root()),
            _ => None,
        }
    }
}

#[cfg(target_os = "macos")]
impl Tree {
    /// The fd-marker descriptor's number in the child, so this crate's OWN integration tests
    /// (`tests/*.rs`, which cannot name a `pub(crate)` item) can be TOLD the exact number rather than
    /// inferring it from ambient process state. `None` for any tree not contained by a marker.
    pub(crate) fn marker_fd_for_test(&self) -> Option<i32> {
        match &self.holder {
            Holder::Contained(Mechanism::Marker(m)) => Some(m.own_fd()),
            _ => None,
        }
    }

    /// The marker pipe's kernel identity, for tests that must sweep this tree.
    #[cfg(test)]
    pub(crate) fn marker_handle_for_test(&self) -> Option<u64> {
        match &self.holder {
            Holder::Contained(Mechanism::Marker(m)) => Some(m.handle()),
            _ => None,
        }
    }

    /// The root an fd marker's ppid-walk channel starts from.
    #[cfg(test)]
    pub(crate) fn marker_root_for_test(&self) -> Option<crate::identity::ProcessId> {
        match &self.holder {
            Holder::Contained(Mechanism::Marker(m)) => m.root(),
            _ => None,
        }
    }

    /// Force the fd marker's process-group id, so a test can drive `containment::unix::signal_group`'s
    /// real `pgid <= 0` guard through the real `kill_tree`/`terminate_tree`/`Drop` path. Panics for a
    /// tree not contained by a marker: a misuse of this seam, not a case to silently no-op past.
    #[cfg(test)]
    pub(crate) fn force_marker_pgid_for_test(&mut self, pgid: i32) {
        match &mut self.holder {
            Holder::Contained(Mechanism::Marker(m)) => m.force_pgid_for_test(pgid),
            other => panic!("force_marker_pgid_for_test called on a tree no marker contains: {other:?}"),
        }
    }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tree_tests;
