//! Per-OS containment dispatch (two-phase: prepare before spawn, attach after).

use crate::containment::mechanism::Mechanism;
use crate::containment::{ContainMode, ContainRequest, Nesting, Skip, Tree};
use crate::error::Error;
#[cfg(unix)]
use crate::signal::RootState;

/// The pre-spawn containment decision produced by `prepare` (env-marker root
/// detection plus per-OS pre-spawn setup).
pub(crate) struct Prepared {
    pub mode: Option<ContainMode>,
    pub is_root: bool,
    /// Pre-created cgroup leaf (Linux only). `Some` means the child must be
    /// placed in the cgroup by the in-child placement step; `None` means fall back
    /// to the process-group mechanism.
    #[cfg(target_os = "linux")]
    pub cgroup_leaf: Option<crate::containment::cgroup::CgroupLeaf>,
    /// The marker pipe for a contained macOS root. `None` for a nested member, an
    /// uncontained or elevation-derived spawn, or a failed install (which degrades to the
    /// process group).
    #[cfg(target_os = "macos")]
    pub marker: Option<crate::containment::fdmarker::PreparedMarker>,
    /// The cooperative-signal mechanism implied by the creation-flag word this spawn passed to
    /// `CreateProcessW`. Set by whichever backend chose that word, so the derivation reads what
    /// the OS was actually given.
    #[cfg(windows)]
    pub graceful: crate::graceful::GracefulMechanism,
    /// Whether the child is created suspended and `attach` must leave it so (see
    /// [`Command::spawn_suspended`](crate::Command::spawn_suspended)).
    #[cfg(windows)]
    pub frozen: bool,
}

/// A child the spawn has just forked, as the spawn holds it: its pid, and the pidfd the handshake
/// gave it from before `exec`. The pidfd names the child whoever reaps it and whoever takes its
/// number, so everything about the child's exit asks it, and the pid only labels.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChildHandle<'a> {
    pub(crate) pid: u32,
    pub(crate) pidfd: std::os::fd::BorrowedFd<'a>,
}

/// Linux 6.9+: `SIGKILL`, through a root's pidfd, the root's process group while the group has a
/// member. `pid` only labels the log. `Err` is the kernel's refusal of the kill, with the group's
/// members possibly left running: `EINVAL` when it refuses the flag (expected below 6.9), in which
/// case nothing is sent, as the group's number may name another group.
#[cfg(target_os = "linux")]
pub(crate) fn kill_group_through_pidfd(
    pidfd: std::os::fd::BorrowedFd<'_>,
    pid: Option<u32>,
) -> Result<(), nix::errno::Errno> {
    use nix::errno::Errno;
    let named = crate::child::spawn::named(pid);
    match crate::containment::unix::pidfd_signal_group(pidfd, nix::sys::signal::Signal::SIGKILL) {
        Ok(()) => log::debug!("spawn teardown: sent SIGKILL to the process group of {named} through its pidfd"),
        Err(Errno::ESRCH) => log::debug!("spawn teardown: the process group of {named} has no member left"),
        Err(e) => return Err(e),
    }
    Ok(())
}

impl Prepared {
    /// The cooperative-signal mechanism for a child spawned from this decision. The `cfg` lives
    /// here, once, so no spawn path carries one for it: every non-Windows child cosca owns can
    /// be sent an identity-bound `SIGTERM`, whatever its containment.
    pub(crate) fn graceful_mechanism(&self) -> crate::graceful::GracefulMechanism {
        #[cfg(windows)]
        return self.graceful;
        #[cfg(not(windows))]
        return crate::graceful::GracefulMechanism::Process;
    }

    /// End the placement exchange of a spawn that failed while the caller still holds its child:
    /// take the verdict, as `attach` would, so the leaf answers only for the tree and
    /// never for the child the caller will reap. Nothing is taken without a leaf, or once the
    /// verdict is taken. A child the leaf does not hold is only logged: the leaf answers for the
    /// tree either way.
    pub(crate) fn settle_verdict(&mut self, #[cfg(target_os = "linux")] child: ChildHandle<'_>) {
        #[cfg(target_os = "linux")]
        if let Some(leaf) = self.cgroup_leaf.as_mut().filter(|leaf| leaf.holds_verdict_to_take()) {
            if let Err(e) = leaf.take_placement(child) {
                log::debug!(
                    "cgroup v2: a failed spawn's child is not placed in its leaf: {report}",
                    report = crate::error::Report(&e)
                );
            }
        }
    }

    /// Whether the root's process group is its containment: the root is a Session or process-group
    /// root, and no cgroup leaf took it, as `attach` would decide. On Linux the leaf's verdict is
    /// taken first ([`settle_verdict`](Self::settle_verdict)).
    #[cfg(unix)]
    pub(crate) fn group_is_containment(&self) -> bool {
        #[cfg(target_os = "linux")]
        let taken_by_a_leaf = self.cgroup_leaf.as_ref().is_some_and(|leaf| leaf.child_entered());
        #[cfg(not(target_os = "linux"))]
        let taken_by_a_leaf = false;
        self.is_root && !taken_by_a_leaf && matches!(self.mode, Some(mode) if !matches!(mode, ContainMode::TreeWalk))
    }

    /// Linux 6.9+: `SIGKILL`, through `child`'s pidfd, the process group of a spawn that failed
    /// before its attach, while the group has a member. The pidfd names the group exactly, whoever
    /// reaped the root. Only a root whose group is its containment is sent it: a Session root, or a
    /// process-group root with no cgroup leaf or one its leaf did not take, as `attach` would decide.
    /// The leaf's verdict is settled first ([`settle_verdict`](Self::settle_verdict)); a leaf that
    /// took the child kills it with the leaf. `Err` is the kernel's refusal of the kill, with the
    /// group's members possibly left running: `EINVAL` when it refuses the flag (expected below
    /// 6.9), in which case nothing is sent, as the group's number may name another group.
    #[cfg(target_os = "linux")]
    pub(crate) fn kill_group_before_attach(&self, child: ChildHandle<'_>) -> Result<(), nix::errno::Errno> {
        if !self.group_is_containment() {
            return Ok(());
        }
        kill_group_through_pidfd(child.pidfd, Some(child.pid))
    }

    /// Watch the elevation front `pid` this spawn forked: its cgroup leaf, if it has one, records
    /// the front's place before its removal (see `CgroupLeaf::watch_front`).
    pub(crate) fn watch_front(&mut self, pid: u32) {
        #[cfg(target_os = "linux")]
        if let Some(leaf) = self.cgroup_leaf.as_mut() {
            leaf.watch_front(pid);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = pid;
    }
}

/// What a spawn achieved, beyond the child handle itself: the tree it owns and the
/// cooperative-signal mechanism, which are independent axes (see [`crate::graceful`]).
///
/// Bundled rather than threaded as separate positional arguments so the spawn constructors do
/// not grow an argument per spawn fact, and so a new fact is a compile error at every
/// construction site rather than a silently diverging path.
pub(crate) struct Attachment {
    pub tree: Tree,
    pub graceful: crate::graceful::GracefulMechanism,
}

#[cfg(windows)]
impl Attachment {
    /// The attachment for a UAC-elevated spawn, which `ShellExecuteEx("runas")` creates through
    /// a system service with creation flags this process never sees and never chose.
    ///
    /// The mechanism is `Unknown`, so [`crate::graceful::signal`] refuses this child rather than
    /// addressing a console control event to its pid. `OtherConsoleGroup` would claim a route to
    /// a group known to exist, and `None` that no cooperative signal exists from any process
    /// ever; cosca can make neither claim about a child it did not create.
    pub(crate) fn uac_elevated() -> Attachment {
        Attachment {
            tree: Tree::none(),
            graceful: crate::graceful::GracefulMechanism::Unknown,
        }
    }
}

/// Who tears a child down. The caller prefixes the teardown's log lines and names its own event in
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TeardownCaller {
    /// A `Child`'s own drop.
    Drop,
    /// A helper that owns the child and failed after its spawn (`Command::status`, `output`, `read`,
    /// `SuspendedChild::resume`).
    FailedRun,
    /// A spawn's teardown of the child it holds, when its identity read or its attach fails, and the
    /// cleanup of a child the handshake abandons.
    #[cfg_attr(
        not(any(target_os = "linux", windows)),
        allow(dead_code, reason = "only the Linux and Windows spawns tear a child down")
    )]
    FailedSpawn,
    /// The cleanup of an elevated spawn that cannot finish.
    #[cfg(unix)]
    FinishElevated,
}

impl TeardownCaller {
    /// The prefix of the caller's log lines.
    pub(crate) fn label(self) -> &'static str {
        match self {
            TeardownCaller::Drop => "Child::drop",
            TeardownCaller::FailedRun => "teardown after a failed run",
            TeardownCaller::FailedSpawn => "teardown after a failed spawn",
            #[cfg(unix)]
            TeardownCaller::FinishElevated => "finish_elevated",
        }
    }

    /// How a log line of the caller refers to its own event: a drop is "this drop", any other
    /// teardown is "this teardown".
    #[cfg(unix)]
    pub(crate) fn this_event(self) -> &'static str {
        match self {
            TeardownCaller::Drop => "this drop",
            TeardownCaller::FailedSpawn | TeardownCaller::FailedRun | TeardownCaller::FinishElevated => "this teardown",
        }
    }
}

/// What a `Child`'s drop knows about its root, for its report and for what it does to the root: the
/// one look at it. The mechanism's kill decides on [`look`](Self::look), the same look the report
/// is worded from.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct DropView {
    /// The caller's name, prefixing its log lines.
    pub(crate) caller: TeardownCaller,
    pub(crate) root_pid: u32,
    /// The root's state as the look found it: the handle's own answer
    /// ([`RootState`](crate::signal::RootState)), or `Reaped` when the root's number shows the reap
    /// the handle could not.
    pub(crate) root: RootState,
    /// This handle already killed the tree completely.
    pub(crate) tree_killed: bool,
}

#[cfg(unix)]
impl DropView {
    /// Read the state a drop or a failed-spawn cleanup decides on: the root's number first, then
    /// the handle's own answer ([`RootState`](crate::signal::RootState)). The handle is exact
    /// where the number is not: a foreign reap followed by a same-tick reuse still reads as this
    /// root by its start token. A root with no identity (`id` is `None`) has nothing the number can
    /// be compared with, so only a number that names no process shows it reaped, and the handle
    /// decides alone otherwise.
    ///
    /// Reading emits no `warn`: the caller reports once, with a
    /// [`DropReport`](crate::child::drop_report::DropReport). `caller` names itself in log lines.
    pub(crate) fn read(
        caller: TeardownCaller,
        root_pid: u32,
        id: Option<crate::identity::ProcessId>,
        root: impl FnOnce() -> RootState,
        tree: &Tree,
    ) -> DropView {
        let label = caller.label();
        let now = crate::child::root_identity_now(root_pid);
        let state = root();
        let handle_reaped = matches!(state, RootState::Reaped { .. });
        let root = if crate::child::root_reaped(handle_reaped, id, now) {
            // The number shows the reap where the handle could not say; say so in the log.
            match &state {
                RootState::Unknown(e) => log::debug!(
                    "{label}: the root's own handle could not say whether it was reaped ({report}), but its number shows it reaped",
                    report = crate::error::Report(e)
                ),
                RootState::Unpinned => log::debug!(
                    "{label}: the root is not pinned by this process, but its number shows it reaped"
                ),
                RootState::Unreaped | RootState::Reaped { .. } => {}
            }
            match state {
                reaped @ RootState::Reaped { .. } => reaped,
                // Only the number shows the reap, so no reap of this handle's own.
                RootState::Unreaped | RootState::Unknown(_) | RootState::Unpinned => RootState::Reaped { own: false },
            }
        } else {
            state
        };
        let view = DropView {
            caller,
            root_pid,
            root,
            tree_killed: tree.is_killed(),
        };
        if now.is_unknown() && !handle_reaped {
            if view.unsettled() {
                log::debug!(
                    "{label}: the root's number ({root_pid}) could not be read either; kills by that number are skipped"
                );
            } else {
                log::debug!(
                    "{label}: the root's number ({root_pid}) could not be read; treating the root as not reaped"
                );
            }
        }
        view
    }

    /// The handle could not settle whether the root is still ours to act on, and nothing else did:
    /// `Unknown`, or `Unpinned`.
    pub(crate) fn unsettled(&self) -> bool {
        matches!(self.root, RootState::Unknown(_) | RootState::Unpinned)
    }

    /// This process does not pin the root (macOS: launchd holds it), and nothing else shows it
    /// reaped: its pid is not ours to signal or wait on.
    pub(crate) fn unpinned_root(&self) -> bool {
        matches!(self.root, RootState::Unpinned)
    }

    /// Whether the root itself is neither signalled nor waited on: it is reaped, or this process
    /// does not pin it (so its pid is not ours).
    pub(crate) fn leaves_root_alone(&self) -> bool {
        matches!(self.root, RootState::Reaped { .. } | RootState::Unpinned)
    }

    /// The look the mechanism's kill decides on: the one this view is worded from.
    pub(crate) fn look(&self) -> RootState {
        self.root.duplicate()
    }

    /// Why the root's number may not be trusted, for a log line or a note.
    pub(crate) fn why_number_untrusted(&self) -> String {
        match &self.root {
            RootState::Reaped { .. } => "the root is already reaped".to_owned(),
            untrusted => crate::signal::why_untrusted(untrusted),
        }
    }
}

/// Where a `Child` handle's tree stands after the kills and drops that settled it
/// ([`TreeKilled::settle`] alone writes it): one state under one lock, so a reader sees what the last
/// settlement left. `settle` holds the lock across its kills by identity, which take a `Kernel` and
/// a `ProcessId` and never reach a `TreeKilled`, so the lock is not re-entered.
///
/// A drop that skips a number-named kill reads it to see whether it has anything to warn about
/// ([`DropView`]); a caller that has just run a kill reads the kill's own [`SettleOutcome`].
#[derive(Debug, Default)]
pub(crate) struct TreeKilled {
    state: std::sync::Mutex<TreeState>,
}

/// The settlement of a tree ([`TreeKilled`]): each state is a fact the handle knows, and [`next`]
/// moves them by one rule. Only a walk that leaves nothing vouches for the tree; only a member seen
/// running un-vouches it. A settlement, from any state:
///
/// - leaves members with identities (held ones still left, or new ones): `Left`;
/// - is a walk (`Ran`) that leaves nothing, held members included: `Killed`;
/// - leaves something running that holds no identity (a member of a handle that is not a `TreeWalk`,
///   or a walk that left the root, whatever then ended it): `Unvouched`, from any state;
/// - otherwise (a gone root, a walk not made, or a skipped kill whose sweep left nothing: none saw a
///   member running) keeps the state, except that `Left` whose held members all dropped out is
///   `Unvouched`. A held member is held because its kill was refused: it ran on and may have forked,
///   and killing it again by identity does not reach its children.
///
/// The kind of an `Unvouched` state is the latest fact:
///
/// - a walk that saw the root running names [`RootSeenRunning`](UnvouchedKind::RootSeenRunning),
///   whether or not the root had ended;
/// - held members that all dropped out name [`HeldMembersGone`](UnvouchedKind::HeldMembersGone);
/// - something else left running with no identity names [`Earlier`](UnvouchedKind::Earlier), from
///   any previous state.
///
/// A settlement with no new fact keeps the stored kind.
#[derive(Debug, Default)]
enum TreeState {
    /// Nothing has settled the tree: no kill left anything running, and no walk left nothing.
    #[default]
    Never,
    /// A walk left nothing: vouched for.
    Killed,
    /// A walk left these members, never none, so every later kill and drop answers them first: the
    /// root's death reparents them out of a later walk, so the handle kills the ones whose identity
    /// was read again and reports the others again.
    Left(Vec<crate::containment::treewalk::Left>),
    /// A kill ran, and no member it left is held now (each is gone, or the handle never held an
    /// identity for it), but no walk since has vouched for the tree: a member seen running may have
    /// forked, and its children were never looked for. The kind says what was found where the tree
    /// became unvouched: every text over this state is chosen by it.
    Unvouched(UnvouchedKind),
}

/// The state after a settlement, by the rule on [`TreeState`]. The facts: `walked`, the outcome was a
/// walk that ran; `left_now`, the members it left with identities; `running`, the outcome left
/// something running (the root included, whatever then ended it), not merely an error for a walk it
/// did not make (a gone root's or an unmade walk's error is not a member seen running);
/// `root_seen_running`, the walk left the root (whatever then ended it), which is `running`.
fn next(
    prev: &TreeState,
    walked: bool,
    left_now: Vec<crate::containment::treewalk::Left>,
    running: bool,
    root_seen_running: bool,
) -> TreeState {
    debug_assert!(
        !root_seen_running || running,
        "a root seen running is something left running"
    );
    if !left_now.is_empty() {
        return TreeState::Left(left_now);
    }
    // The kind the facts name, for a state they leave unvouched. Something running with no identity
    // and no root seen is `Earlier` from any state; with nothing running, the only way to be
    // unvouched is `Left` whose held members all dropped out.
    let named = if root_seen_running {
        UnvouchedKind::RootSeenRunning
    } else if running {
        UnvouchedKind::Earlier
    } else {
        UnvouchedKind::HeldMembersGone
    };
    match prev {
        _ if walked && !running => TreeState::Killed,
        TreeState::Never if !running => TreeState::Never,
        TreeState::Killed if !running => TreeState::Killed,
        TreeState::Unvouched(kept) if !running => TreeState::Unvouched(*kept),
        TreeState::Never | TreeState::Killed | TreeState::Left(_) | TreeState::Unvouched(_) => {
            TreeState::Unvouched(named)
        }
    }
}

impl TreeKilled {
    fn lock(&self) -> std::sync::MutexGuard<'_, TreeState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the tree is killed. Only a Unix drop reads it (`DropView`), and the tests.
    #[cfg(any(unix, test))]
    pub(crate) fn is_set(&self) -> bool {
        matches!(*self.lock(), TreeState::Killed)
    }
}

/// Which signal a tree path sends.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum TreeSignal {
    Kill,
    Term,
}

/// A tree kill that did not complete, and every member it left running. It reports none of them:
/// [`Tree::settle`] decides what the root's own death leaves, and the caller reports that, once.
#[derive(Debug)]
pub(crate) struct Unkilled {
    /// Every member left but the root. For a walk, in the order it found them; for a mechanism that
    /// is not a walk, its one error.
    pub(crate) members: Vec<Error>,
    /// The root, when a walk left it. Only a `TreeWalk` walk can: the root's own death then settles it.
    pub(crate) root: Option<Error>,
    /// The members of `members` whose identity a `TreeWalk` walk read, and whose kill was refused: a
    /// later kill can kill them again by it. The others were never read.
    pub(crate) resolved: Vec<crate::identity::ProcessId>,
}

impl Unkilled {
    /// The first member left: a member before the root. A kill that completed is not an `Unkilled`,
    /// so there is one.
    #[cfg(unix)]
    pub(crate) fn first(&self) -> &Error {
        self.members
            .first()
            .or(self.root.as_ref())
            .expect("an incomplete kill left a member")
    }

    /// [`first`](Self::first), owned, for the tests that read what a walk returned.
    #[cfg(test)]
    pub(crate) fn into_error(self) -> Error {
        self.members
            .into_iter()
            .next()
            .or(self.root)
            .expect("an incomplete kill left a member")
    }

    /// What is still left once the root's own handle has had its say: `Ok` when nothing is, else the
    /// first member and the others as data. `root_ended`: the root is not running, so a root the walk
    /// left is not left.
    pub(crate) fn unsettled(self, root_ended: bool) -> Result<(), Unsettled> {
        let mut left = self.members.into_iter().chain(self.root.filter(|_| !root_ended));
        match left.next() {
            None => Ok(()),
            Some(first) => Err(Unsettled {
                first,
                others: left.collect(),
            }),
        }
    }
}

impl From<Error> for Unkilled {
    fn from(error: Error) -> Unkilled {
        Unkilled {
            members: vec![error],
            root: None,
            resolved: Vec::new(),
        }
    }
}

/// What a tree kill left once the root's own death had its say ([`Tree::settle`]): the first
/// member left, which the caller returns, and the others, as data for the caller's one report.
#[derive(Debug)]
pub(crate) struct Unsettled {
    pub(crate) first: Error,
    pub(crate) others: Vec<Error>,
}

impl Unsettled {
    /// The error a caller returns: the first member left. The caller's one report is that error, and a
    /// `warn`, led by `caller`, for each of the others.
    pub(crate) fn report(self, caller: &str) -> Error {
        for other in &self.others {
            log::warn!("{caller}: {report}", report = crate::error::Report(other));
        }
        self.first
    }

    /// The text of a log line: every member, the first and then the others after `; `, each with its
    /// whole chain. A returned text uses [`Display`](std::fmt::Display), which has no chains.
    pub(crate) fn log_text(&self) -> String {
        std::iter::once(&self.first)
            .chain(&self.others)
            .map(|member| crate::error::Report(member).to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl std::fmt::Display for Unsettled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.first)?;
        self.others.iter().try_for_each(|other| write!(f, "; {other}"))
    }
}

/// How a [`Tree::settle`] that found nothing left came out, by the state it left ([`TreeKilled`]):
/// the answer `Ok` does not say the tree is vouched for, this does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettleOutcome {
    /// The kill ran, or found the killed tree already gone, and the state left is killed: nothing is
    /// left for the caller to report, and the tree is vouched for.
    Killed,
    /// The kill was skipped (and the sweep by identity of a macOS fd marker left nothing): it killed
    /// nothing, and the state left is not unvouched.
    Skipped,
    /// The state left is [`Unvouched`](TreeState::Unvouched), whatever the call did: a skipped kill
    /// over a tree a skip moved there from [`Left`](TreeState::Left), or a walk that left only the
    /// root, whose own end then made the answer `Ok`. `kind` says what was found.
    Unvouched { kind: UnvouchedKind },
}

/// What a settlement found of a tree it cannot vouch for ([`SettleOutcome::Unvouched`]), as far as
/// the settlement knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnvouchedKind {
    /// The tree held members an earlier kill left, which are gone now.
    HeldMembersGone,
    /// A walk saw the root running and left it. If the root's own kill then ended it, the call was
    /// `Ok`. What the root forked meanwhile was never looked for.
    RootSeenRunning,
    /// A kill, this settlement's own or an earlier one, left something running that it could not name
    /// (members the handle holds no identity for, or members since gone), and the settlement
    /// no longer knows which.
    Earlier,
}

impl UnvouchedKind {
    /// What the settlement found, as the clause of a text about a tree it cannot vouch for.
    fn found(self) -> &'static str {
        match self {
            UnvouchedKind::HeldMembersGone => {
                "the members an earlier kill left are gone now, but no later walk has checked what they forked"
            }
            UnvouchedKind::RootSeenRunning => {
                "the walk found the root running, and what the root forked meanwhile was never looked for"
            }
            UnvouchedKind::Earlier => {
                "a kill left something running that it could not name, and no later walk has checked what it forked"
            }
        }
    }

    /// The text of a cleanup's or a drop's report over a tree it cannot vouch for.
    pub(crate) fn unvouched_text(self) -> String {
        format!("{}, so the tree could not be vouched for", self.found())
    }

    /// The drop's warn for a settlement over a tree it cannot vouch for: a kind that came of a skipped
    /// kill says so.
    fn drop_text(self) -> String {
        match self {
            UnvouchedKind::HeldMembersGone | UnvouchedKind::Earlier => {
                format!("the drop skipped the kill, and {}", self.unvouched_text())
            }
            UnvouchedKind::RootSeenRunning => self.unvouched_text(),
        }
    }

    /// What a gone root answers over a tree of this kind: the tree could not be walked, but not
    /// nothing was killed.
    fn gone_root_text(self) -> &'static str {
        match self {
            UnvouchedKind::HeldMembersGone => {
                "the members an earlier kill left are gone; the tree could not be walked from its gone root, so \
                 what they forked is unknown"
            }
            UnvouchedKind::RootSeenRunning => {
                "the root an earlier walk found running is gone; the tree could not be walked from it, so what it \
                 forked is unknown"
            }
            UnvouchedKind::Earlier => {
                "a kill left something running that it could not name, and no walk since has checked what it \
                 forked; the tree could not be walked from its gone root"
            }
        }
    }
}

/// What a tree kill did ([`Contains::send_kill`](crate::containment::Contains::send_kill)): the one value [`Tree::settle`] turns into what
/// is left and into the handle's state ([`TreeKilled`]).
#[derive(Debug)]
pub(crate) enum TreeKillOutcome {
    /// The kill ran; `Err` is what it left.
    Ran(Result<(), Unkilled>),
    /// The mechanism answered without a kill that goes on to the root's backstop: its tree is empty
    /// (a Linux process group with no member left, or one this handle's own reap left empty), so
    /// there is nothing to kill, or only the marker holders a macOS fd marker names by identity were.
    /// The call that sent it ends with this answer; a drop goes on to the root. `Err` is what it left.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix mechanism answers by the root's number")
    )]
    Answered(Result<(), Unkilled>),
    /// A `TreeWalk` walk could not be made (the snapshot could not be taken, or the root exists but
    /// could not be queried), so NOTHING was killed, the root included: killing the root anyway would
    /// reparent its descendants out of the ppid walk, so a retry could no longer find them. The
    /// error says why. Every other failure is a kill that was attempted, a `TreeWalk`'s
    /// [`Error::MemberNotKilled`] included.
    Unwalked(Error),
    /// A `TreeWalk` walk found its root gone, or holding its pid no longer: there is no tree to walk
    /// from, so this kill killed nothing. It is [`Error::Unassessable`]: [`no_root_error`](Self::no_root_error)
    /// over a tree never settled, [`no_root_after_kills_error`](Self::no_root_after_kills_error) over
    /// an unvouched one, worded by what the settlement knows of it ([`UnvouchedKind`]).
    NoRoot,
    /// The root's number is untrusted, so the kill skipped what names the tree by it. The tree is
    /// not killed. The caller that has the root's handle acts on [`Skip::root_alone`].
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix mechanism skips by the root's number")
    )]
    Skipped(Skip),
}

/// A kill that ran: what [`Tree::kill`] and the paths that send by hand return.
impl From<Result<(), Unkilled>> for TreeKillOutcome {
    fn from(result: Result<(), Unkilled>) -> TreeKillOutcome {
        TreeKillOutcome::Ran(result)
    }
}

impl TreeKillOutcome {
    /// What [`NoRoot`](Self::NoRoot) is as an error: nothing was killed, because no walk ran.
    pub(crate) fn no_root_error() -> Error {
        Error::Unassessable {
            detail: "the root is gone or no longer holds its pid, so no walk ran and nothing was killed".to_owned(),
            source: None,
        }
    }

    /// What a [`NoRoot`](Self::NoRoot) is as an error over a tree an earlier kill left unvouched
    /// (`kind` says what it found): the tree could not be walked, but not nothing was killed.
    pub(crate) fn no_root_after_kills_error(kind: UnvouchedKind) -> Error {
        Error::Unassessable {
            detail: kind.gone_root_text().to_owned(),
            source: None,
        }
    }

    /// What the kill left: `Ok` for one that ran and left nothing, or a skip whose sweep left
    /// nothing. A walk that was not made or found no root left its error, as the only member.
    pub(crate) fn into_result(self) -> Result<(), Unkilled> {
        match self {
            TreeKillOutcome::Ran(result) | TreeKillOutcome::Answered(result) => result,
            TreeKillOutcome::Skipped(skip) => skip.holders.unwrap_or(Ok(())).map_err(Unkilled::from),
            TreeKillOutcome::Unwalked(error) => Err(Unkilled::from(error)),
            TreeKillOutcome::NoRoot => Err(Unkilled::from(Self::no_root_error())),
        }
    }

    /// Whether the kill reached the front it was made for: it ran and left nothing, the root
    /// included. The one predicate of every gate that asks, with a cgroup
    /// front, whether the cgroup kill ended it.
    #[cfg(unix)]
    pub(crate) fn completed(&self) -> bool {
        matches!(self, TreeKillOutcome::Ran(Ok(())) | TreeKillOutcome::Answered(Ok(())))
    }

    /// Why the kill did not leave the tree killed, or `None` when it [`completed`](Self::completed):
    /// the first member a kill left, or what a skip left undone. For the text of a gate that reads it.
    /// Its error is worded by its Display.
    #[cfg(unix)]
    pub(crate) fn incomplete(&self) -> Option<String> {
        self.incomplete_by(|error| error.to_string())
    }

    /// [`incomplete`](Self::incomplete) for a text that only reaches a log line: its error is worded
    /// as the whole chain, through [`Report`](crate::error::Report).
    #[cfg(unix)]
    pub(crate) fn incomplete_for_log(&self) -> Option<String> {
        self.incomplete_by(|error| crate::error::Report(error).to_string())
    }

    #[cfg(unix)]
    fn incomplete_by(&self, word: impl Fn(&Error) -> String) -> Option<String> {
        if self.completed() {
            return None;
        }
        Some(match self {
            TreeKillOutcome::Ran(Err(left)) | TreeKillOutcome::Answered(Err(left)) => word(left.first()),
            TreeKillOutcome::Skipped(Skip {
                holders: Some(Err(error)),
                ..
            }) => word(error),
            TreeKillOutcome::Skipped(Skip { action, .. }) => {
                format!("the kill was skipped, and would {action}")
            }
            TreeKillOutcome::Unwalked(error) => word(error),
            TreeKillOutcome::NoRoot => word(&Self::no_root_error()),
            TreeKillOutcome::Ran(Ok(())) | TreeKillOutcome::Answered(Ok(())) => {
                unreachable!("a completed kill has nothing left")
            }
        })
    }

    /// What the kill skipped, as an action, when it was skipped.
    #[cfg(unix)]
    pub(crate) fn skipped(&self) -> Option<&str> {
        match self {
            TreeKillOutcome::Skipped(skip) => Some(&skip.action),
            TreeKillOutcome::Ran(_)
            | TreeKillOutcome::Answered(_)
            | TreeKillOutcome::Unwalked(_)
            | TreeKillOutcome::NoRoot => None,
        }
    }

    /// What a drop did not do, because the root's number is untrusted and this handle had not already
    /// killed the tree: the tree it names may outlive the drop.
    #[cfg(unix)]
    pub(crate) fn left_undone(&self, view: &DropView) -> Option<String> {
        self.skipped().filter(|_| !view.tree_killed).map(str::to_owned)
    }

    /// Why and what a skipped kill left undone, for a cleanup's note.
    #[cfg(unix)]
    pub(crate) fn skip_note(&self, view: &DropView) -> Option<String> {
        self.skipped().map(|action| {
            format!(
                "{}, so its number may name another process, and the kill would {action}",
                view.why_number_untrusted()
            )
        })
    }

    /// A drop's or a cleanup's `debug` record of a kill the mechanism skipped, which logs nothing
    /// above that: the caller's one report says what the skip left undone. A reaped root's skip is
    /// the drop's warn, and an unsettled root's is part of its state's.
    #[cfg(unix)]
    pub(crate) fn log_skip(&self, view: &DropView) {
        let TreeKillOutcome::Skipped(skip) = self else {
            return;
        };
        // The drop's own look at the root words it, as its warn does.
        let why = view.why_number_untrusted();
        let (label, this, action) = (view.caller.label(), view.caller.this_event(), &skip.action);
        if view.tree_killed {
            log::debug!("{label}: {why} and this handle already killed the tree, so {this} does not {action}");
        } else if !matches!(view.root, RootState::Reaped { .. }) {
            log::debug!("{label}: {why}, so {this} does not {action}");
        }
    }
}

/// A `kill_tree` sweep that failed, and whether the root is dead all the same: its handle backstop
/// ended it. A caller that waits for the root before it returns the error reads that.
pub(crate) struct SweepFailure {
    pub(crate) error: Error,
    pub(crate) root_ended: bool,
}

/// A failure before the backstop ran, or that sent it nowhere: the root is not known dead.
impl From<Error> for SweepFailure {
    fn from(error: Error) -> SweepFailure {
        SweepFailure {
            error,
            root_ended: false,
        }
    }
}

impl SweepFailure {
    /// Whether the root is not running after a kill of it through its handle: it was killed, or was
    /// already dead ([`ChildFate::not_running`](crate::error::ChildFate::not_running)'s meaning). A
    /// kill that could not be verified (`Sent::Unverified`) may have left the root running.
    pub(crate) fn killed_root(sent: &Result<crate::signal::Sent, Error>) -> bool {
        use crate::signal::Sent;
        matches!(sent, Ok(Sent::Delivered | Sent::Gone))
    }

    /// The handle backstop's answer from its root kill's `sent`, and whether it ended the root.
    pub(crate) fn backstop_of(sent: Result<crate::signal::Sent, Error>) -> (Result<(), Error>, bool) {
        let ended = Self::killed_root(&sent);
        (sent.map(drop), ended)
    }

    /// The answer of a `kill_tree` sweep: the walk's error, settled by the root's death
    /// ([`Tree::settle`]), else the backstop's. `root_ended`: the backstop ended the root. This is
    /// the call's one report of the members the walk left: the error names the first, and each other
    /// is warned of here. `op` names the call.
    pub(crate) fn of(
        op: &str,
        tree: &Tree,
        walk: TreeKillOutcome,
        backstop: Result<(), Error>,
        root_ended: bool,
    ) -> Result<(), SweepFailure> {
        let walk = tree.settle_for_kill_tree(op, walk, root_ended);
        if let (Err(walk), Err(backstop)) = (&walk, &backstop) {
            // The backstop's error is dropped: the walk's names the member left.
            log::debug!(
                "{op} handle backstop also failed ({backstop_report}); surfacing the walk's error: {walk_report}",
                backstop_report = crate::error::Report(backstop),
                walk_report = crate::error::Report(walk)
            );
        }
        walk.and(backstop).map_err(|error| SweepFailure { error, root_ended })
    }
}

impl TreeKilled {
    /// What a tree kill's `outcome` comes to once the root's own handle has had its say: the one place
    /// that decides what a walk left behind, and the only one that writes the state. `walk`: the tree
    /// is a tree walk's. `root_ended`: the
    /// root is not running (killed, or already dead), so a root the walk left is not left. The answer
    /// is `Ok` when nothing is left. Otherwise it is the first member left, and the others as data: it
    /// reports none of them.
    ///
    /// It decides under the one lock of the state, by it and the outcome, and leaves the state
    /// by the rule on [`TreeState`]. The members a `TreeWalk` state holds are answered first, whatever
    /// the outcome. A gone root over a killed tree is `Ok`, and over held members still left it adds no
    /// error of its own; over a tree never settled it is [`TreeKillOutcome::no_root_error`], and over
    /// an unvouched one (held members that are all gone, or left so earlier) it is
    /// [`TreeKillOutcome::no_root_after_kills_error`].
    ///
    /// `kill_tree` reads `root_ended` from its backstop, which it runs for any walk; a drop or a
    /// failed spawn's cleanup reads it from the fate of the root kill it made after the walk.
    pub(crate) fn settle(
        &self,
        walk: bool,
        outcome: impl Into<TreeKillOutcome>,
        root_ended: bool,
    ) -> Result<SettleOutcome, Unsettled> {
        let outcome = outcome.into();
        let mut state = self.lock();
        let was_killed = matches!(*state, TreeState::Killed);
        // The state is read here and written once, at the end, so an unwind leaves it as it was.
        let held = match &*state {
            TreeState::Left(held) => held.clone(),
            TreeState::Never | TreeState::Killed | TreeState::Unvouched(_) => Vec::new(),
        };
        let gone_root = matches!(outcome, TreeKillOutcome::NoRoot);
        let ran = matches!(outcome, TreeKillOutcome::Ran(_) | TreeKillOutcome::Answered(_));
        // What a walk not made or a gone root leaves is its error, not a member seen running.
        let looked_for_no_member = matches!(outcome, TreeKillOutcome::NoRoot | TreeKillOutcome::Unwalked(_));
        // A walk already covered the tree unless it was never settled: a gone root adds no error of its own.
        let covered = gone_root && !matches!(*state, TreeState::Never);
        let mut result = if covered { Ok(()) } else { outcome.into_result() };
        let mut left_now = Vec::new();
        if walk {
            result = crate::containment::treewalk::with_earlier(&crate::identity::HostKernel, held, result);
            if let Err(left) = &result {
                left_now = crate::containment::treewalk::Left::of(left);
            }
        }
        // A member the walk saw running un-vouches the tree, whatever ended it afterwards: it may have
        // forked first. Only the answer follows the root's end.
        let running = result.is_err() && !looked_for_no_member;
        let root_seen_running = matches!(&result, Err(left) if left.root.is_some());
        let after = next(&state, ran, left_now, running, root_seen_running);
        if gone_root && result.is_ok() && !was_killed {
            // What an earlier walk left is gone or unknown, but nothing walked the tree for what it forked.
            let error = match after {
                TreeState::Unvouched(kind) => TreeKillOutcome::no_root_after_kills_error(kind),
                TreeState::Never | TreeState::Killed | TreeState::Left(_) => {
                    debug_assert!(
                        false,
                        "a gone root over held or unvouched members leaves the tree unvouched"
                    );
                    // Release: the gone-root answer of a tree no kill left unvouched.
                    TreeKillOutcome::no_root_error()
                }
            };
            result = Err(Unkilled::from(error));
        }
        let unsettled = match result {
            Ok(()) => Ok(()),
            Err(left) => {
                debug_assert!(left.root.is_none() || walk, "only a tree walk leaves the root alone");
                left.unsettled(root_ended)
            }
        };
        // The answer follows the state left: `Killed` only over a vouched tree. A gone root answers
        // `Ok` only over a killed tree.
        let answer = unsettled.map(|()| match &after {
            TreeState::Unvouched(kind) => SettleOutcome::Unvouched { kind: *kind },
            _ if ran || gone_root => {
                debug_assert!(matches!(after, TreeState::Killed), "`Killed` answers a killed tree");
                SettleOutcome::Killed
            }
            _ => SettleOutcome::Skipped,
        });
        *state = after;
        answer
    }

    /// [`settle`](Self::settle) for a `kill_tree` call, which reports: the error names the first member
    /// left, and each other is warned of here, once. `caller` names the call in those warns.
    pub(crate) fn settle_for_kill_tree(
        &self,
        caller: &str,
        walk: bool,
        outcome: impl Into<TreeKillOutcome>,
        root_ended: bool,
    ) -> Result<(), Error> {
        self.settle(walk, outcome, root_ended)
            .map(drop)
            .map_err(|left| left.report(caller))
    }

    /// `outcome` for a `kill_tree` that goes on to the root's backstop: a `TreeWalk` that could not
    /// walk killed nothing, and the root's death would strand the descendants beyond a retry, so it is
    /// settled here and returned as the error with the tree intact. Any other `outcome` is handed back.
    pub(crate) fn unless_unwalked(
        &self,
        caller: &str,
        walk: bool,
        outcome: TreeKillOutcome,
    ) -> Result<TreeKillOutcome, SweepFailure> {
        if !matches!(outcome, TreeKillOutcome::Unwalked(_)) {
            return Ok(outcome);
        }
        match self.settle_for_kill_tree(caller, walk, outcome, false) {
            Err(error) => Err(SweepFailure::from(error)),
            // The walk's error is a member left, and the root is not ended.
            Ok(()) => unreachable!("a walk not made leaves its error"),
        }
    }

    /// [`settle`](Self::settle) for a drop: the text of its warn when the tree is not settled, worded
    /// here and only when it will be logged.
    pub(crate) fn settle_for_drop(
        &self,
        walk: bool,
        outcome: impl Into<TreeKillOutcome>,
        root_ended: bool,
    ) -> Option<String> {
        let outcome = outcome.into();
        let after = match &outcome {
            // A drop cannot retry a walk that was not made.
            TreeKillOutcome::Unwalked(_) => "; the root is killed regardless, so its descendants may be orphaned",
            TreeKillOutcome::Ran(_)
            | TreeKillOutcome::Answered(_)
            | TreeKillOutcome::NoRoot
            | TreeKillOutcome::Skipped(_) => "",
        };
        let left = match self.settle(walk, outcome, root_ended) {
            Err(left) => left.log_text(),
            Ok(SettleOutcome::Unvouched { kind }) => kind.drop_text(),
            Ok(SettleOutcome::Killed | SettleOutcome::Skipped) => return None,
        };
        Some(format!("contained-tree teardown did not fully succeed: {left}{after}"))
    }
}

/// Returns `true` when the current process is the outermost contained root
/// (i.e. the env marker is absent). Pure function: takes the marker-presence
/// flag so it can be unit-tested without touching the process environment.
pub(crate) fn is_nested(marker_present: bool) -> bool {
    marker_present
}

/// What the spawn's identity read said of a child it cannot verify (macOS leaves such a child alone).
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "only macOS leaves a child unverified")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootIdentity {
    /// The root was already reaped (someone else reaped it, and its pid may be reused).
    Gone,
    /// The read was refused or could not be trusted.
    Unknown,
}

/// Which Unix setup action to apply to a root `Command` for a given mode.
/// Pure function: used by `prepare` and unit-tested separately to verify
/// mutual exclusivity: Session → setsid only; Strongest/default → pgroup
/// only; TreeWalk → neither (it must catch process-group escapees).
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UnixSetup {
    /// Add the `setsid` step to the spawn's in-child hook (ContainMode::Session). Must NOT be
    /// combined with ProcessGroup on the same Command (EPERM on a session leader).
    Session,
    /// Apply `process_group(0)` (ContainMode::Strongest or default).
    ProcessGroup,
    /// Apply NO pre-spawn grouping (ContainMode::TreeWalk). TreeWalk's whole
    /// point is to catch children that `setsid`/`setpgid` out of a process group,
    /// so it must not put the root in a group itself; teardown is by identity.
    None,
}

/// Decide which Unix mechanism to apply for `mode` (root spawns only).
/// Keeping this as a pure function makes the mutual-exclusivity invariant
/// directly unit-testable without inspecting `std::process::Command` internals.
#[cfg(unix)]
pub(crate) fn unix_setup_for(mode: Option<ContainMode>) -> UnixSetup {
    match mode {
        Some(ContainMode::Session) => UnixSetup::Session,
        Some(ContainMode::TreeWalk) => UnixSetup::None,
        _ => UnixSetup::ProcessGroup,
    }
}

/// The Windows pre-spawn containment decision, shared by the std `prepare` path and the raw
/// `CreateProcessW` backend. Encodes ONLY the decision; the caller applies it (`creation_flags`
/// onto the command, the root env marker, `clear_std_handle_inheritance`).
#[cfg(windows)]
pub(crate) struct WindowsContain {
    /// Creation flags to OR into the spawn: `root_flags` (suspend + new group) for a Strongest
    /// root, `group_flags` (new group only) otherwise; `0` when uncontained (`mode` is `None`).
    pub creation_flags: u32,
    /// Whether this spawn must set the inherited root marker so descendants join THIS group.
    pub marker_env: bool,
}

/// Decide the Windows pre-spawn containment flags + marker for `req`/`is_root`. Pure — directly
/// unit-testable. Returns `{ creation_flags: 0, marker_env: false }` when `req.mode` is `None`.
#[cfg(windows)]
pub(crate) fn windows_contain_setup(req: &ContainRequest, is_root: bool) -> WindowsContain {
    let Some(mode) = req.mode else {
        return WindowsContain {
            creation_flags: 0,
            marker_env: false,
        };
    };
    let creation_flags = if is_root && !matches!(mode, ContainMode::TreeWalk) {
        // Strongest root: suspend + new process group (job assigned in attach).
        crate::containment::windows::root_flags()
    } else {
        // TreeWalk root (no suspend, no job — identity teardown) and all nested spawns:
        // CREATE_NEW_PROCESS_GROUP only, so `terminate` can CTRL_BREAK the root's group.
        crate::containment::windows::group_flags()
    };
    WindowsContain {
        creation_flags,
        marker_env: is_root && req.nesting == Nesting::Mark,
    }
}

/// Phase 1 (before spawn): env-marker root detection + pre-spawn OS setup. On Unix, what the child
/// does for itself between `fork` and `exec` goes into `steps`, which the caller registers.
///
/// `teardown_warn_after` is the spawn policy's: the cgroup leaf made here warns once this long into
/// each of its waits for its drain, whoever drops or abandons it (principle 2).
///
/// `reserved_fds` and `marker_suppressed` drive the macOS fd-marker install only; every
/// other platform ignores them. `flags` is the caller's creation-flag request, which only
/// Windows can honour.
///
/// Fallible only on Windows, where the composed creation-flag word may name a reserved bit. The
/// composition runs at the very top — before anything is mutated, so a refusal leaves nothing to
/// unwind, and above the uncontained early return, so an uncontained spawn carries the caller's
/// flags too.
#[allow(
    clippy::too_many_arguments,
    reason = "each Unix platform reads its own subset of the arguments"
)]
pub(crate) fn prepare(
    std_cmd: &mut std::process::Command,
    #[cfg(unix)] steps: &mut crate::child::spawn::in_child::InChild,
    req: &ContainRequest,
    #[cfg_attr(
        not(windows),
        allow(
            unused_variables,
            reason = "only Windows can honour the caller's creation-flag request"
        )
    )]
    flags: &crate::command::flags::FlagsRequest,
    #[cfg_attr(
        not(target_os = "macos"),
        allow(unused_variables, reason = "drives the macOS fd-marker install only")
    )]
    reserved_fds: &[i32],
    #[cfg_attr(
        not(target_os = "macos"),
        allow(unused_variables, reason = "drives the macOS fd-marker install only")
    )]
    marker_suppressed: bool,
    #[cfg_attr(
        not(windows),
        allow(unused_variables, reason = "only the Windows path composes env ops into the request")
    )]
    env_ops: &[crate::command::EnvOp],
    #[cfg_attr(
        not(target_os = "linux"),
        allow(unused_variables, reason = "only a Linux cgroup leaf waits for its drain")
    )]
    teardown_warn_after: Option<std::time::Duration>,
) -> Result<Prepared, Error> {
    let mode = req.mode;
    // Read once, above every branch, so the word is composed exactly once per spawn and no two
    // compositions can disagree. Reading it for an uncontained spawn too is unobservable.
    //
    // On Unix cosca never sets this variable in its own process, so it can only change here if the
    // user `set_var`s it concurrently, which is the user's data race. On Windows `set_var` is sound
    // from any thread, so the marker comes from one snapshot, and a contained child's whole
    // environment is built from that same snapshot below: the decision and the child agree.
    #[cfg(windows)]
    let snapshot = crate::child::spawn::windows_raw::env_snapshot::EnvSnapshot::read()?;
    #[cfg(windows)]
    let marker_present = snapshot
        .var(std::ffi::OsStr::new(crate::containment::NESTED_ENV))
        .is_some();
    #[cfg(not(windows))]
    let marker_present = std::env::var_os(crate::containment::NESTED_ENV).is_some();
    let is_root = !is_nested(marker_present);

    #[cfg(windows)]
    let graceful = {
        use std::os::windows::process::CommandExt;
        let spawn =
            crate::command::flags::windows_spawn(req, *flags, is_root, crate::command::flags::SpawnBackend::Std)?;
        std_cmd.creation_flags(spawn.creation_flags);
        // Sound for THIS derivation and no other: `mechanism_from_flags` reads only
        // CREATE_NEW_PROCESS_GROUP / DETACHED_PROCESS / CREATE_NEW_CONSOLE / CREATE_NO_WINDOW,
        // and std adds and removes none of them. The word is what cosca supplies, never what
        // `CreateProcessW` receives — see `crate::command::flags`.
        crate::containment::windows::mechanism_from_flags(spawn.creation_flags)
    };

    if mode.is_none() {
        return Ok(Prepared {
            mode: None,
            is_root: false,
            #[cfg(target_os = "linux")]
            cgroup_leaf: None,
            #[cfg(target_os = "macos")]
            marker: None,
            #[cfg(windows)]
            graceful,
            #[cfg(windows)]
            frozen: flags.suspended,
        });
    }
    let marker_env = is_root && req.nesting == Nesting::Mark;
    // Windows: hand std the whole environment, rebuilt from the snapshot the marker was read from,
    // so std does not read this process's environment again at `CreateProcessW`. The marker is an
    // op after the user's, named as std names it; it survives a user `env_clear`.
    #[cfg(windows)]
    {
        use crate::child::spawn::windows_raw::{child_ops, resolve::ChildEnv};
        let env = ChildEnv::capture(&snapshot, &child_ops(env_ops, marker_env));
        std_cmd.env_clear();
        std_cmd.envs(env.captured_vars().expect("a capture is never inherited"));
    }
    // Elsewhere: set AFTER any user env ops (env_clear) have been applied to std_cmd by the spawn
    // engine, so the marker survives env_clear. `env` appends.
    #[cfg(not(windows))]
    if marker_env {
        std_cmd.env(crate::containment::NESTED_ENV, "1");
    }

    // Linux: session mode or (cgroup v2 + process group).
    // Mechanism selection via `unix_setup_for` (setsid/pgroup mutual exclusivity):
    // Session → setsid only; Strongest/TreeWalk → process_group(0) + try cgroup.
    #[cfg(target_os = "linux")]
    {
        if is_root && mode.is_some() {
            match unix_setup_for(mode) {
                UnixSetup::Session => {
                    // Session: setsid only — no process_group(0) (would EPERM).
                    crate::containment::unix::set_session(steps);
                    return Ok(Prepared {
                        mode,
                        is_root,
                        cgroup_leaf: None, // cgroup not used for Session
                    });
                }
                UnixSetup::None => {
                    // TreeWalk: NO process group / setsid / cgroup — teardown is
                    // by identity so we can catch process-group escapees.
                    return Ok(Prepared {
                        mode,
                        is_root,
                        cgroup_leaf: None,
                    });
                }
                UnixSetup::ProcessGroup => {
                    // Strongest: set a new process group + try cgroup.
                    crate::containment::unix::set_process_group(std_cmd);
                }
            }

            // A failed leaf creation degrades this spawn to the process group set above. The
            // decision is unchanged; only the silence is — `log_degrade` names the step that
            // failed and the kernel's reason for it.
            let leaf = match crate::containment::cgroup::try_create_leaf(teardown_warn_after) {
                Ok(leaf) => Some(leaf),
                Err(e) => {
                    crate::containment::cgroup::log_degrade(&e);
                    None
                }
            };
            if let Some(ref l) = leaf {
                // The child's self-placement step. A failed placement (e.g. EBUSY — "no internal
                // processes" rule) returns Ok, so the spawn proceeds and `attach` falls back to the
                // already-configured process group. Only a report the child cannot send fails the
                // spawn. Both the sync and the tokio spawn add this one step through `prepare`.
                // SAFETY: the leaf, which owns both the fd and the report channel, stays in
                // `Prepared` until after the spawn.
                unsafe { steps.place(l.procs_fd(), l.placement_slot()) };
            }
            return Ok(Prepared {
                mode,
                is_root,
                cgroup_leaf: leaf,
            });
        }
        return Ok(Prepared {
            mode,
            is_root,
            cgroup_leaf: None,
        });
    }

    // Non-Linux Unix: process group or session (mutually exclusive).
    // Mechanism selection via `unix_setup_for`: Session → setsid only;
    // Strongest (= ProcessGroup on macOS) → process_group(0).
    #[cfg(all(unix, not(target_os = "linux")))]
    if is_root && mode.is_some() {
        match unix_setup_for(mode) {
            UnixSetup::Session => crate::containment::unix::set_session(steps),
            UnixSetup::ProcessGroup => crate::containment::unix::set_process_group(std_cmd),
            UnixSetup::None => {} // TreeWalk: no pre-spawn grouping (identity teardown)
        }
    }

    // macOS: install the inherited-fd marker for every contained root, regardless of the
    // requested mode (decision: the marker survives what the mode-specific mechanism above
    // does not). `marker_wanted` gates on root/mode/suppression; `install` degrades to `None`
    // on any failure rather than failing the spawn.
    #[cfg(target_os = "macos")]
    let marker = if crate::containment::fdmarker::marker_wanted(mode, is_root, marker_suppressed) {
        crate::containment::fdmarker::install(steps, reserved_fds)
    } else {
        None
    };

    // Windows: stop the child inheriting this process's std handles. Contained spawns only, and
    // below the composition above so a refused spawn has mutated nothing. The creation-flag word
    // itself is applied at the top, since an uncontained spawn never reaches this point.
    #[cfg(windows)]
    crate::containment::windows::clear_std_handle_inheritance();

    // On `target_os = "linux"` only, every path through the `#[cfg(target_os = "linux")]` block
    // above returns, so this expression is unreachable there — but it is the live tail expression
    // on every other target.
    #[cfg_attr(
        target_os = "linux",
        expect(unreachable_code, reason = "the linux block above returns on every path")
    )]
    Ok(Prepared {
        mode,
        is_root,
        #[cfg(target_os = "linux")]
        cgroup_leaf: None,
        #[cfg(target_os = "macos")]
        marker,
        #[cfg(windows)]
        graceful,
        #[cfg(windows)]
        frozen: flags.suspended,
    })
}

/// Phase 2 (after spawn, before the `OwnedChild` adopts): attach the mechanism and bundle it with the
/// spawn's other achieved facts. Consumes `prepared` so Linux cgroup leaf ownership transfers
/// cleanly to the cgroup mechanism without requiring interior mutability — hence the
/// cooperative-signal mechanism is read off it first.
///
/// `id` is the identity the spawn read of the root, or the error of the read that failed. A
/// mechanism that names the tree by the root's identity (a tree walk, the macOS fd marker) fails the
/// attach with that error; one that attaches by pid or handle (a cgroup, a process group, a Job
/// Object) does not need it.
pub(crate) fn attach(
    #[cfg(unix)] pid: u32,
    id: Result<crate::identity::ProcessId, Error>,
    #[cfg(target_os = "linux")] child: ChildHandle<'_>,
    #[cfg(windows)] proc_handle: std::os::windows::io::RawHandle,
    prepared: Prepared,
) -> Result<Attachment, Error> {
    let graceful = prepared.graceful_mechanism();
    let tree = attach_tree(
        #[cfg(unix)]
        pid,
        id,
        #[cfg(target_os = "linux")]
        child,
        #[cfg(windows)]
        proc_handle,
        prepared,
    )?;
    Ok(Attachment { tree, graceful })
}

/// The tree-teardown half of [`attach`]: which mechanism owns this child's tree.
fn attach_tree(
    #[cfg(unix)] pid: u32,
    id: Result<crate::identity::ProcessId, Error>,
    #[cfg(target_os = "linux")] child: ChildHandle<'_>,
    #[cfg(windows)] proc_handle: std::os::windows::io::RawHandle,
    prepared: Prepared,
) -> Result<Tree, Error> {
    use crate::containment::treewalk::Walker;
    #[cfg(unix)]
    use crate::containment::unix::Group;
    // Linux: session, or cgroup v2 / process group.
    #[cfg(target_os = "linux")]
    {
        let mut prepared = prepared;
        if prepared.mode.is_some() {
            if prepared.is_root {
                // TreeWalk root: no kernel container / process group; teardown is
                // by identity: the one the spawn verified against the child's handle.
                if matches!(prepared.mode, Some(ContainMode::TreeWalk)) {
                    return Ok(Tree::contained(Mechanism::Walk(Walker::new(id?))));
                }

                let raw_pid = pid;
                debug_assert!(
                    raw_pid <= i32::MAX as u32,
                    "pid {raw_pid} exceeds i32::MAX; pgid cast would truncate"
                );
                let pgid = raw_pid as i32;

                // Session mode: setsid was applied pre-spawn; no cgroup.
                // pgid == sid == pid for the session leader; killpg works.
                if matches!(prepared.mode, Some(ContainMode::Session)) {
                    return Ok(Tree::contained(Mechanism::Group(Group::session(pgid))));
                }

                // Strongest: cgroup v2 if available, else process group.
                if let Some(mut leaf) = prepared.cgroup_leaf.take() {
                    // The pre_exec write can fail (EBUSY — the "no internal processes" rule
                    // when the supervisor is itself an undelegated leaf). The child's own
                    // report of that write decides membership; re-reading cgroup.procs cannot,
                    // because it lists only live tasks and a placed child may already have
                    // exited. Taking the verdict waits for that report — `spawn` returning does
                    // not mean the child has made it — then releases the leaf's fd and pipe.
                    match leaf.take_placement(child) {
                        Ok(()) => {
                            return Ok(Tree::contained(Mechanism::Cgroup(leaf)));
                        }
                        // Nothing of the child's is in the leaf: its final report is not Placed. The
                        // process group set pre-spawn is the real container; the leaf is
                        // removed without writing cgroup.kill.
                        Err(reason) => {
                            crate::containment::cgroup::log_degrade(&reason);
                            leaf.remove_unentered();
                            return Ok(Tree::contained(Mechanism::Group(Group::process_group(pgid))));
                        }
                    }
                }
                // No cgroup leaf: fall back to process group (set pre-spawn).
                return Ok(Tree::contained(Mechanism::Group(Group::process_group(pgid))));
            } else {
                // Nested member: it joined the ancestor's cgroup/process group (or the
                // root's tree-walk) rather than creating its own, so it owns no teardown —
                // the outermost root tears the whole tree down.
                return Ok(Tree::delegated());
            }
        }
    }

    // Non-Linux Unix: process group or session.
    // For Session: setsid was called pre-spawn (not process_group(0)); the child
    // is a session leader with pgid == pid. Teardown via killpg is identical —
    // the group mechanism is reused since the pgroup == session leader's pid.
    // For Strongest (= ProcessGroup on macOS): process_group(0) was called pre-spawn.
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        if prepared.mode.is_some() {
            if prepared.is_root {
                // macOS fd marker: installed for every contained root regardless of mode, so
                // it takes priority over the mode-specific mechanism below — it is what
                // survives setsid/reparenting/exec that the mode-specific mechanism does not.
                #[cfg(target_os = "macos")]
                if let Some(marker) = prepared.marker {
                    let pgid = match prepared.mode {
                        Some(ContainMode::TreeWalk) => None,
                        _ => {
                            debug_assert!(
                                pid <= i32::MAX as u32,
                                "pid {pid} exceeds i32::MAX; pgid cast would truncate"
                            );
                            Some(pid as i32)
                        }
                    };
                    return Ok(Tree::contained(Mechanism::Marker(
                        crate::containment::fdmarker::Marker::new(marker, id?, pgid),
                    )));
                }
                // TreeWalk root: no process group; identity teardown.
                if matches!(prepared.mode, Some(ContainMode::TreeWalk)) {
                    return Ok(Tree::contained(Mechanism::Walk(Walker::new(id?))));
                }
                let raw_pid = pid;
                debug_assert!(
                    raw_pid <= i32::MAX as u32,
                    "pid {raw_pid} exceeds i32::MAX; pgid cast would truncate"
                );
                let pgid = raw_pid as i32;
                let group = match prepared.mode {
                    Some(ContainMode::Session) => Group::session(pgid),
                    _ => Group::process_group(pgid),
                };
                return Ok(Tree::contained(Mechanism::Group(group)));
            } else {
                // Nested member: it joined the ancestor's process group (or the root's
                // tree-walk) rather than creating its own, so it owns no teardown — the
                // outermost root tears the whole tree down.
                #[cfg(target_os = "macos")]
                if prepared.marker.is_some() {
                    log::warn!(
                        "fd marker: a nested spawn's prepare() unexpectedly produced a marker; \
                         a nested member must inherit the root's marker, never create its own \
                         — discarding it"
                    );
                    debug_assert!(
                        false,
                        "a nested member inherits the root's marker and must never create one"
                    );
                }
                return Ok(Tree::delegated());
            }
        }
    }

    // Windows: Job Object (strongest available on this OS), or TreeWalk.
    #[cfg(windows)]
    {
        if prepared.mode.is_some() && prepared.is_root {
            // TreeWalk root: no job (spawned with CREATE_NEW_PROCESS_GROUP only);
            // identity teardown, with CTRL_BREAK to the group as cooperative term.
            if matches!(prepared.mode, Some(ContainMode::TreeWalk)) {
                return Ok(Tree::contained(Mechanism::Walk(Walker::new(id?))));
            }
            // A frozen root is assigned its job and left suspended. It gets no `TreeWalk` fallback:
            // a frozen root without a job would have nothing to kill it if its owner died.
            if prepared.frozen {
                return match crate::containment::windows::assign_held(proc_handle) {
                    Ok(job) => Ok(Tree::contained(Mechanism::Job(job))),
                    Err(e) => Err(Error::Containment {
                        detail: e.to_string(),
                        source: None,
                    }),
                };
            }
            match crate::containment::windows::attach_job(proc_handle) {
                Ok(Some(job)) => return Ok(Tree::contained(Mechanism::Job(job))),
                Ok(None) => {
                    // Job assignment failed: fall back to the universal TreeWalk
                    // mechanism rather than silently yielding no containment. The
                    // root was spawned with CREATE_NEW_PROCESS_GROUP (root_flags),
                    // so `terminate`'s CTRL_BREAK still reaches the group.
                    return Ok(Tree::contained(Mechanism::Walk(Walker::new(id?))));
                }
                Err(e) => {
                    return Err(Error::Containment {
                        detail: e.to_string(),
                        source: None,
                    })
                }
            }
        } else if prepared.mode.is_some() {
            // Nested member: it inherits the ancestor's job (or the root's tree-walk; no
            // new job is created), so it owns no teardown — the outermost root's job tears
            // the whole tree down.
            return Ok(Tree::delegated());
        }
    }

    // Uncontained (or unsupported platform).
    let _ = prepared;
    Ok(Tree::none())
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod dispatch_tests;
