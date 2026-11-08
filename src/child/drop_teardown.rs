//! The teardown of a [`Child`] handle: what [`Drop`] does, and what the run-to-completion helpers do
//! to a child that failed after its spawn. One policy, whichever way it waits: it splits at its one
//! wait, as [`OwnedChild::begin_tear_down`] does. The first half ([`Child::begin_tear_down`]) never
//! blocks, and answers the teardown's [`Remains`] or the pending [`DropWait`]. The second half
//! reports and, with the policy's warn, blocks ([`DropWait::settle`]) or, for the async `Child`,
//! awaits ([`Child::tear_down_awaiting`]).

use crate::child::owned::teardown::{BeginOutcome, Disposition, Kill, Remains, TeardownOutcome, TeardownWait};
#[cfg(unix)]
use crate::child::owned::teardown::{FrontLook, FrontWait};
use crate::child::owned::unreaped::Unreaped;
use crate::child::Child;
use crate::containment::dispatch::{TeardownCaller, TreeKillOutcome};

impl Child {
    /// What [`Drop`] does, now, for a caller that owns the child and fails after its spawn: it says
    /// what became of the child. With [`Disposition::HandBack`], a child whose teardown could not
    /// end it, a refused kill or an elevation front (which is sent none), is given back too if it
    /// still runs.
    ///
    /// Only a `kill_on_drop(false)` child is left whatever `disposition` says. The containment is
    /// torn down as `self` drops, before this returns. On Windows a refused root kill gets the
    /// single look.
    pub(crate) fn tear_down_or_hand_back(
        mut self,
        disposition: Disposition,
    ) -> (crate::error::ChildFate, Option<Unreaped>) {
        if !self.kill_on_drop {
            return (self.fate_of_a_disarmed_child(), None);
        }
        self.kill_on_drop = false;
        let torn = self.tear_down(TeardownCaller::FailedRun, disposition);
        (torn.fate, disposition.hands_back(&torn).then(|| self.into_unreaped()))
    }

    /// [`tear_down_or_hand_back`](Self::tear_down_or_hand_back) for an `async fn`: the root's wait
    /// and the leaf's drain are awaited, with no warn (the warn is about a blocked thread).
    /// Dropped mid-teardown, the future settles as the drop does.
    #[cfg(feature = "tokio")]
    pub(crate) async fn tear_down_or_hand_back_awaiting(
        mut self,
        disposition: Disposition,
    ) -> (crate::error::ChildFate, Option<Unreaped>) {
        if !self.kill_on_drop {
            return (self.fate_of_a_disarmed_child(), None);
        }
        // Before the waits, so the handle's own drop does nothing more if this future is dropped.
        self.kill_on_drop = false;
        let torn = self.tear_down_awaiting(TeardownCaller::FailedRun, disposition).await;
        (torn.fate, disposition.hands_back(&torn).then(|| self.into_unreaped()))
    }

    /// What became of a child whose teardown a `kill_on_drop(false)` leaves.
    fn fate_of_a_disarmed_child(&self) -> crate::error::ChildFate {
        if self.proc.is_reaped() {
            crate::error::ChildFate::Reaped
        } else {
            crate::error::ChildFate::Running { id: self.id }
        }
    }

    /// The root, as an [`Unreaped`]. `self` has already torn its containment down by dropping.
    pub(super) fn into_unreaped(mut self) -> Unreaped {
        debug_assert!(!self.kill_on_drop, "a handed-back child is no longer killed on drop");
        let root = self.proc.take().expect("a child handed back still holds its root");
        Unreaped::new(root, self.id, self.front.is_some(), self.policy.unreaped_drop)
    }

    /// The kill-on-drop teardown, answering what became of the child. `caller` prefixes the event's
    /// warn, and `disposition` words it for a child that still runs after a refused kill, and for an
    /// elevation front left running. The clause has been said: the warn, or a debug line, has said
    /// it, so what is left is the [`Remains`].
    pub(crate) fn tear_down(&mut self, caller: TeardownCaller, disposition: Disposition) -> Remains {
        match self.begin_tear_down(caller, disposition) {
            BeginOutcome::Done(remains) => remains,
            BeginOutcome::Wait(wait) => wait.settle(self),
        }
    }

    /// [`tear_down`](Self::tear_down) awaited, as [`tear_down_or_hand_back_awaiting`] has it.
    ///
    /// [`tear_down_or_hand_back_awaiting`]: Self::tear_down_or_hand_back_awaiting
    #[cfg(feature = "tokio")]
    pub(crate) async fn tear_down_awaiting(&mut self, caller: TeardownCaller, disposition: Disposition) -> Remains {
        let remains = match self.begin_tear_down(caller, disposition) {
            BeginOutcome::Done(remains) => remains,
            BeginOutcome::Wait(wait) => {
                let mut settling = Settling {
                    child: self,
                    wait: Some(wait),
                };
                // The wait stays in `settling` while it is awaited, for the drop of this future to
                // settle.
                let torn = settling
                    .wait
                    .as_mut()
                    .expect("held until it is settled")
                    .settle_async(&mut *settling.child)
                    .await;
                let wait = settling.wait.take().expect("held until it is settled");
                let remains = wait.parts.finish(settling.child, torn);
                drop(settling);
                remains
            }
        };
        // The root is reaped and the event reported: what is left is the leaf's drain, which its kill
        // bounds. Dropped here, the leaf drops in place, which waits for it on this thread.
        #[cfg(target_os = "linux")]
        self.step_leaf_and_await_drain().await;
        remains
    }

    /// The awaited teardown's part of the leaf's teardown: the leaf's first step, the one its drop
    /// takes first ([`CgroupLeaf::remove_else_kill`](crate::containment::cgroup::CgroupLeaf::remove_else_kill)),
    /// then the drain a landed kill bounds, so the leaf's drop finds it drained. A drain that cannot
    /// be watched is left to the drop.
    #[cfg(all(feature = "tokio", target_os = "linux"))]
    async fn step_leaf_and_await_drain(&self) {
        let crate::containment::Attached::Cgroup(leaf) = &self.attached else {
            return;
        };
        _ = leaf.remove_else_kill();
        if !self.attached.cgroup_kill_landed() {
            return;
        }
        if let Err(e) = crate::tokio::wait::cgroup_wait_tree_drained(leaf, None).await {
            log::debug!(
                "child {}: its leaf's drain cannot be watched ({e}); the teardown waits for it on this thread, blocking",
                self.pid()
            );
        }
    }

    /// The first half of [`tear_down`](Self::tear_down), which never blocks: the signals, and what
    /// can be settled without waiting. Nothing that names the tree by the root's number runs once
    /// the root is reaped, or when its handle cannot say: the handle's own answer (`RootState`), or
    /// the number no longer reading as this root. Each send by the group's number checks the root
    /// again, as for [`kill_tree`](Child::kill_tree). On Linux 6.9+ a process group is decided by the
    /// root's pidfd ([`Attached::hard_kill_for_drop`](crate::containment::Attached::hard_kill_for_drop)).
    /// An unreaped root stays a zombie, pinning its number, until its teardown settles.
    pub(crate) fn begin_tear_down(
        &mut self,
        caller: TeardownCaller,
        disposition: Disposition,
    ) -> BeginOutcome<Remains, DropWait> {
        // Hard-kill the contained tree (if any) — on Linux cgroup.kill reaches an elevated
        // subtree — then tear the direct child down. The dispatcher preserves the Unix
        // kill-before-wait order and NEVER blocks on an unkillable elevated child.
        #[cfg(unix)]
        {
            self.begin_drop_unix(caller, disposition)
        }
        #[cfg(not(unix))]
        {
            let tree = self.attached.hard_kill(&crate::containment::GroupRoot::none());
            let parts = DropParts {
                caller,
                tree: Some(tree),
            };
            let begun = self.proc.begin_tear_down(
                self.id,
                Kill {
                    disposition,
                    tree: None,
                },
                self.policy.teardown_warn_after,
            );
            self.begun(parts, begun)
        }
    }

    /// What `begun`, the first half of a root's teardown, comes to: the teardown's end, or its wait.
    fn begun(
        &mut self,
        parts: DropParts,
        begun: BeginOutcome<TeardownOutcome, TeardownWait>,
    ) -> BeginOutcome<Remains, DropWait> {
        match begun {
            BeginOutcome::Done(torn) => BeginOutcome::Done(parts.finish(self, torn)),
            BeginOutcome::Wait(wait) => BeginOutcome::Wait(DropWait {
                parts,
                wait: RootWait::Root(wait),
            }),
        }
    }
}

#[cfg(unix)]
impl Child {
    /// [`begin_tear_down`](Self::begin_tear_down) on Unix, with one report of the event.
    fn begin_drop_unix(&mut self, caller: TeardownCaller, disposition: Disposition) -> BeginOutcome<Remains, DropWait> {
        use crate::child::owned::teardown::Reach;
        use crate::error::ChildFate;

        // A live elevation front gets no signal of its own: outside a cgroup it is sent nothing and
        // stays running and unreaped, named by the warn; a `HandBack` caller then takes it. The
        // gate comes first, so the look at the root is right before the kill it decides.
        let gate = self.kill_gate();
        let view =
            crate::containment::DropView::read(caller, self.pid(), self.id, || self.proc.state(), &self.tree_killed);
        let cgroup_only = match gate {
            crate::elevation::front::Gate::Closed(unkillable) => {
                // The leaf stays armed: its teardown kills what it holds, a front among it if it is
                // in it. Run now, not at field drop, so the look at the front comes after it.
                let parts = DropParts {
                    view,
                    skipped: None,
                    tree: None,
                    disposition,
                };
                return self.begin_leaf_and_front(unkillable.to_string(), parts);
            }
            gate => matches!(gate, crate::elevation::front::Gate::CgroupOnly),
        };
        // The hold names the root's group. The handle owns the child outright here, so no reap
        // can land; it is dropped before anything below locks the child.
        let held = self.proc.hold(self.pid());
        let kill = self.attached.hard_kill_for_drop(&view, &held.group());
        drop(held);
        // A live member refused, or couldn't be confirmed — visible, not silently
        // discarded, on the RAII teardown path most callers actually hit. A mechanism
        // failure (e.g. `EACCES`/`EIO` on `cgroup.kill`) is a real OS outcome, so it is
        // reported, never asserted on.
        let skipped = kill.left_undone(&view);
        // A reaped root is neither killed nor waited for: its number may name another child by now.
        // Neither is a root this process does not pin (macOS: launchd holds its zombie). Its fate is
        // `Reaped` by this handle's own reap, else `Gone`: nothing was signalled, so a root someone
        // else reaped or launchd holds is `Gone`, as the classifier has it.
        if view.leaves_root_alone() {
            let torn = TeardownOutcome::collected(if self.proc.is_reaped() {
                ChildFate::Reaped
            } else {
                ChildFate::Gone
            });
            let parts = DropParts {
                view,
                skipped,
                tree: Some(kill),
                disposition,
            };
            return BeginOutcome::Done(parts.finish(self, torn));
        }
        if cgroup_only {
            let not_reached = match kill.incomplete() {
                None => self.cgroup_kill_reached().err().map(|e| e.to_string()),
                failure => failure,
            };
            let parts = DropParts {
                view,
                skipped,
                tree: Some(kill),
                disposition,
            };
            return match not_reached {
                // The cgroup kill ended it: reap it, sending nothing. The reap is the front's.
                None => {
                    let wait = self.proc.begin_reap_after_tree_kill(
                        None,
                        crate::elevation::front::front_named(Some(self.pid())),
                        disposition,
                        self.policy.teardown_warn_after,
                    );
                    BeginOutcome::Wait(DropWait {
                        parts,
                        wait: RootWait::Root(wait),
                    })
                }
                // Never waited for. A kill that failed is final: the armed leaf writes no
                // other. The front is looked at once the leaf is torn down.
                Some(why) => self.begin_leaf_and_front(why, parts),
            };
        }
        // The tree kill above may have reached the root: if the root's own kill is refused,
        // that kill is what ends it.
        let begun = {
            let reach = kill.completed().then_some(&self.attached as &dyn Reach);
            self.proc.begin_tear_down(
                self.id,
                Kill {
                    disposition,
                    tree: reach,
                },
                self.policy.teardown_warn_after,
            )
        };
        let parts = DropParts {
            view,
            skipped,
            tree: Some(kill),
            disposition,
        };
        self.begun(parts, begun)
    }

    /// A drop's end for an elevation front it cannot be sure its cgroup kill reached: its leaf is
    /// torn down (killed through unless a kill was made, whose failure is final; drained; removed),
    /// and then the front is looked at. The leaf's drain is the first of the teardown's waits, so
    /// the first half only names it ([`RootWait::Leaf`]) and blocks on nothing. `why` is why the
    /// front is not killed.
    fn begin_leaf_and_front(&mut self, why: String, parts: DropParts) -> BeginOutcome<Remains, DropWait> {
        BeginOutcome::Wait(DropWait {
            parts,
            wait: RootWait::Leaf { why },
        })
    }

    /// The second half of [`begin_leaf_and_front`](Self::begin_leaf_and_front): the leaf is dropped,
    /// which kills through it, waits for it to drain and removes it, and then the front is looked at
    /// ([`look_at_front_after_leaf`](Self::look_at_front_after_leaf)).
    fn tear_leaf_down_then_look_at_front(&mut self) -> BeginOutcome<FrontLook, FrontWait> {
        let reach = self.front_reach();
        drop(std::mem::take(&mut self.attached));
        self.look_at_front_after_leaf(reach)
    }

    /// The leaf's subtree, read while the leaf exists, since it places the front once the leaf is
    /// gone. Read before the leaf's first step, which may remove it.
    fn front_reach(&self) -> FrontReach {
        #[cfg(target_os = "linux")]
        {
            match &self.attached {
                crate::containment::Attached::Cgroup(leaf) => FrontReach(leaf.subtree().map(Some)),
                _ => FrontReach(Ok(None)),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            FrontReach
        }
    }

    /// The look at the front, once the leaf is gone, through
    /// [`begin_look_at_front`](OwnedChild::begin_look_at_front), which waits for it only if its place
    /// says the kill reached it. A front is never killed through [`tear_down`](OwnedChild::tear_down):
    /// that would orphan its program. How the look went is worded by [`word_front`].
    #[cfg_attr(
        not(target_os = "linux"),
        allow(unused_variables, reason = "only a Linux cgroup leaf has a subtree")
    )]
    fn look_at_front_after_leaf(&mut self, reach: FrontReach) -> BeginOutcome<FrontLook, FrontWait> {
        use crate::child::owned::teardown::Reach;

        #[cfg(target_os = "linux")]
        let subtree;
        #[cfg(target_os = "linux")]
        let reach = match reach.0 {
            Ok(read) => {
                subtree = read;
                Ok(subtree.as_ref().map(|subtree| subtree as &dyn Reach))
            }
            Err(e) => Err(e),
        };
        #[cfg(not(target_os = "linux"))]
        let reach: Result<Option<&dyn Reach>, std::io::Error> = Ok(None);
        self.proc
            .begin_look_at_front(self.id, reach, self.policy.teardown_warn_after)
    }
}

/// What places a front once its leaf is gone: the leaf's subtree, or why it could not be read.
#[cfg(target_os = "linux")]
struct FrontReach(std::io::Result<Option<crate::containment::cgroup::Subtree>>);
#[cfg(all(unix, not(target_os = "linux")))]
struct FrontReach;

/// What a teardown's report needs once its wait is over: the kill's outcome and the root's view.
struct DropParts {
    /// The look at the root.
    #[cfg(unix)]
    view: crate::containment::DropView,
    /// What the tree kill skipped ([`TreeKillOutcome::left_undone`]).
    #[cfg(unix)]
    skipped: Option<String>,
    /// Who tore the child down: it names itself in the report. On Unix the root view holds it.
    #[cfg(not(unix))]
    caller: TeardownCaller,
    /// What the tree kill did, settled for the report only once the root's kill is known
    /// ([`Attached::settle_for_drop`](crate::containment::Attached::settle_for_drop)). `None`: no tree
    /// kill ran (a closed front's gate), so there is nothing to settle and nothing to mark.
    tree: Option<TreeKillOutcome>,
    /// How the look at an elevation front words a child that still runs.
    #[cfg(unix)]
    disposition: Disposition,
}

impl DropParts {
    /// The teardown's one report, once the root's `torn` is known: what became of the child.
    #[cfg(unix)]
    fn finish(self, child: &mut Child, torn: TeardownOutcome) -> Remains {
        let DropParts {
            view,
            skipped,
            tree,
            disposition: _,
        } = self;
        let mut report = crate::child::drop_report::DropReport::new(&view);
        report.skipped = skipped;
        let remains = report.fold_clause(torn);
        if let Some(kill) = tree {
            report.tree = child
                .attached
                .settle_for_drop(&child.tree_killed, kill, remains.fate.not_running());
        }
        report.emit(&child.reported);
        remains
    }

    /// The teardown's one report, once the root's `torn` is known: what became of the child.
    #[cfg(not(unix))]
    fn finish(self, child: &mut Child, torn: TeardownOutcome) -> Remains {
        let (warn, remains) = torn.take_warn(self.caller.label());
        let mut left = Vec::new();
        if let Some(tree) = self.tree {
            left.extend(
                child
                    .attached
                    .settle_for_drop(&child.tree_killed, tree, remains.fate.not_running()),
            );
        }
        left.extend(warn);
        if !left.is_empty() {
            log::warn!("{}: {}", self.caller.label(), left.join("; "));
        }
        remains
    }
}

/// The one wait of a handle's teardown, with what its second half needs: the root's reap, or the
/// leaf's teardown and the look at an elevation front that a kill sent elsewhere is ending.
#[must_use = "a pending wait that is dropped leaves the child unreaped"]
pub(crate) struct DropWait {
    parts: DropParts,
    wait: RootWait,
}

enum RootWait {
    Root(TeardownWait),
    /// The leaf is still held: its teardown, then the look at the front, are to come. `why` is why
    /// the front was not killed.
    #[cfg(unix)]
    Leaf {
        why: String,
    },
    /// The look at the front is under way, as an awaited teardown leaves it; `why` is why the front
    /// was not killed.
    #[cfg(all(unix, feature = "tokio"))]
    Front {
        wait: FrontWait,
        why: String,
    },
}

impl DropWait {
    /// Blocks until the root has exited and been reaped, warning once past the policy's threshold,
    /// then reports and says what became of the child.
    pub(crate) fn settle(self, child: &mut Child) -> Remains {
        let DropWait { parts, wait } = self;
        let torn = match wait {
            RootWait::Root(wait) => wait.settle(&child.proc),
            #[cfg(unix)]
            RootWait::Leaf { why } => match child.tear_leaf_down_then_look_at_front() {
                BeginOutcome::Done(look) => word_front(child.proc.pid(), &why, parts.disposition, look),
                BeginOutcome::Wait(wait) => {
                    word_front(child.proc.pid(), &why, parts.disposition, wait.settle(&child.proc))
                }
            },
            #[cfg(all(unix, feature = "tokio"))]
            RootWait::Front { wait, why } => {
                word_front(child.proc.pid(), &why, parts.disposition, wait.settle(&child.proc))
            }
        };
        parts.finish(child, torn)
    }
}

impl DropWait {
    /// [`settle`](Self::settle)'s wait, awaited, with no warn: the caller still holds the wait if
    /// its future is dropped, and then settles it blocking. The wait moves on as it is awaited
    /// (the leaf's teardown over, the look at the front under way), so a drop settles what is left.
    #[cfg(feature = "tokio")]
    async fn settle_async(&mut self, child: &mut Child) -> TeardownOutcome {
        #[cfg(unix)]
        if let RootWait::Leaf { why } = &self.wait {
            let why = why.clone();
            // The subtree is read before the leaf's first step, which may remove it. The leaf is
            // killed through and its drain awaited, so dropping it waits for nothing.
            let reach = child.front_reach();
            #[cfg(target_os = "linux")]
            child.step_leaf_and_await_drain().await;
            drop(std::mem::take(&mut child.attached));
            match child.look_at_front_after_leaf(reach) {
                BeginOutcome::Done(look) => return word_front(child.proc.pid(), &why, self.parts.disposition, look),
                BeginOutcome::Wait(wait) => self.wait = RootWait::Front { wait, why },
            }
        }
        match &self.wait {
            RootWait::Root(wait) => wait.settle_async(&mut child.proc).await,
            #[cfg(unix)]
            RootWait::Leaf { .. } => unreachable!("the leaf's teardown is over"),
            #[cfg(unix)]
            RootWait::Front { wait, why } => {
                let look = wait.settle_async(&mut child.proc).await;
                word_front(child.proc.pid(), why, self.parts.disposition, look)
            }
        }
    }
}

/// A teardown whose wait is being awaited. Dropped with the wait unfinished (its future was), it
/// settles it as the drop would, blocking, with the policy's warn. While unwinding it gives the
/// child up unreaped and warns with its pid, as an [`Unreaped`]'s drop does.
#[cfg(feature = "tokio")]
struct Settling<'a> {
    child: &'a mut Child,
    wait: Option<DropWait>,
}

#[cfg(feature = "tokio")]
impl Drop for Settling<'_> {
    fn drop(&mut self) {
        if let Some(wait) = self.wait.take() {
            if std::thread::panicking() {
                log::warn!(
                    "{} was given up unreaped: its teardown was dropped while the thread is panicking",
                    crate::os_process::child_named(self.child.proc.pid())
                );
            } else {
                _ = wait.settle(self.child);
            }
        }
    }
}

/// Words how a look at the elevation front `pid` (`None`: not known) went, as the outcome of its
/// teardown: the front's [`Settlement`](crate::child::lifecycle::Settlement) words one it looked at,
/// and a warn the others. `why` is why the caller did not kill the front. A front seen running (left
/// running, or with its place or its leaf's subtree unreadable) is worded as handed back if
/// `disposition` says the caller hands it back, and as left otherwise; no other look depends on it.
#[cfg(unix)]
pub(super) fn word_front(
    pid: impl Into<Option<u32>>,
    why: &dyn std::fmt::Display,
    disposition: Disposition,
    look: FrontLook,
) -> TeardownOutcome {
    use crate::child::owned::teardown::LookOutcome;

    let front = crate::elevation::front::front_named(pid.into());
    let FrontLook { fate, look } = look;
    // A front seen running whose reach cannot be read: it is not known whether the cgroup kill ended it.
    let unreadable = |cause: String| match disposition {
        Disposition::Leave => {
            format!("{front} is left unreaped: {cause}, so it is not known whether the cgroup kill ended it")
        }
        Disposition::HandBack => format!(
            "{front} is running and unreaped: {cause}, so it is not known whether the cgroup kill \
             ended it{}",
            Disposition::HandBack.suffix(true)
        ),
    };
    // A front seen running is still this process's.
    let left = |warn: String| TeardownOutcome::left_uncollected(fate, warn);
    match look {
        LookOutcome::Ended(settlement) => {
            TeardownOutcome::new(fate, settlement.wording(&front, None, Some(disposition)))
        }
        LookOutcome::LeftRunning => left(match disposition {
            Disposition::Leave => format!(
                "{front} is left running and unreaped: {why}, and a kill of the front would orphan \
                 the elevated program"
            ),
            Disposition::HandBack => format!(
                "{front} is running and unreaped: {why}, and a kill of the front would orphan \
                 the elevated program{}",
                Disposition::HandBack.suffix(true)
            ),
        }),
        LookOutcome::PlaceUnreadable(e) => left(unreadable(format!("where it is cannot be read ({e})"))),
        LookOutcome::SubtreeUnreadable(e) => left(unreadable(format!("its leaf's subtree cannot be read ({e})"))),
    }
}
