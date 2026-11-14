//! Per-OS containment dispatch (two-phase: prepare before spawn, attach after).

use crate::containment::mechanism::{Contains, Mechanism};
use crate::containment::{ContainMode, ContainRequest, Nesting, Skip, Tree};
use crate::error::{Error, Failures};
#[cfg(unix)]
use crate::signal::RootState;
use std::sync::Arc;

/// The pre-spawn containment decision produced by `prepare` (env-marker root
/// detection plus per-OS pre-spawn setup).
pub(crate) struct Prepared {
    pub mode: Option<ContainMode>,
    pub is_root: bool,
    /// Pre-created cgroup leaf (Linux only). `Some` means the child must be
    /// placed in the cgroup by the in-child placement step; `None` means the process-group
    /// mechanism: the host offers no cgroup, or a `BestEffort` spawn could not make a leaf.
    #[cfg(target_os = "linux")]
    pub cgroup_leaf: Option<crate::containment::cgroup::CgroupLeaf>,
    /// The marker pipe for a contained macOS root. `None` for a nested member, an
    /// uncontained or elevation-derived spawn, or a failed install of any mode but `Strongest`
    /// (which degrades to the process group, or the tree walk for `TreeWalk`).
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
    ///
    /// The verdict that says the program never ran comes back as the attach's own not-started
    /// failure ([`not_started_failure`]), so a failed spawn that finds the child's identity gone
    /// answers as the attach would have.
    pub(crate) fn settle_verdict(
        &mut self,
        #[cfg(target_os = "linux")] child: ChildHandle<'_>,
    ) -> Option<AttachFailure> {
        #[cfg(target_os = "linux")]
        if let Some(leaf) = self.cgroup_leaf.as_mut().filter(|leaf| leaf.holds_verdict_to_take()) {
            if let Err(reason) = leaf.take_placement(child) {
                let path = leaf.path().display().to_string();
                let strict = self.mode.is_some_and(ContainMode::is_strict);
                return match not_started_failure(reason, &path, strict) {
                    Ok(failure) => Some(failure),
                    Err(reason) => {
                        log::debug!(
                            "cgroup v2: a failed spawn's child is not placed in its leaf: {report}",
                            report = crate::error::Report(&reason)
                        );
                        None
                    }
                };
            }
        }
        None
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
        let (now, unread) = crate::child::root_identity_now(root_pid);
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
            let why = unread
                .into_error(&format!("pid {root_pid}"))
                .map_or_else(String::new, |e| format!(": {}", crate::error::Report(&e)));
            if view.unsettled() {
                log::debug!(
                    "{label}: the root's number ({root_pid}) could not be read either; kills by that number are skipped{why}"
                );
            } else {
                log::debug!(
                    "{label}: the root's number ({root_pid}) could not be read; treating the root as not reaped{why}"
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
        self.root.clone()
    }

    /// Why the root's number may not be trusted, for a log line or a note, with the error of a handle
    /// that could not say after it.
    pub(crate) fn why_number_untrusted(&self) -> String {
        match &self.root {
            RootState::Reaped { .. } => "the root is already reaped".to_owned(),
            untrusted => crate::signal::why_untrusted_with_cause(untrusted),
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

/// The settlement of a tree ([`TreeKilled`]): two facts the handle knows, the [`Vouching`] and the
/// members it holds, and [`next`] moves them by one rule. Only a walk that leaves nothing vouches for
/// the tree; only a member seen running un-vouches it. A settlement, from any state:
///
/// - leaves members with identities (held ones still left, or new ones): holds them, and keeps an
///   `Unvouched` tree's kind, unless this settlement saw the root running (the latest fact below); a
///   `Killed` tree is `Never`, since it was seen running on;
/// - is a walk (`Ran`) that leaves nothing, held members included: `Killed`;
/// - is a walk that killed all it found but could not read the root's exit flag
///   ([`ExitUnread`](TreeKillOutcome::ExitUnread)) and leaves no member: `Unvouched`, from any state;
/// - leaves something running that holds no identity (a member of a handle that is not a `TreeWalk`,
///   or a walk that left the root, whatever then ended it): `Unvouched`, from any state;
/// - otherwise (a gone root, a walk not made, or a skipped kill whose sweep left nothing: none saw a
///   member running) keeps the vouching, except that held members that all dropped out leave a `Never`
///   tree `Unvouched`. A held member ran on after it was found, from a kill that was refused or a
///   `SIGTERM` walk that reached it, and may have forked: killing it again by identity does not
///   reach its children.
///
/// The kind of an `Unvouched` state is the latest fact:
///
/// - a walk that saw the root running names [`RootSeenRunning`](UnvouchedKind::RootSeenRunning),
///   whether or not the root had ended, and whether or not it left members to hold;
/// - held members that all dropped out of a `Never` tree name
///   [`HeldMembersGone`](UnvouchedKind::HeldMembersGone);
/// - something else left running with no identity names [`Earlier`](UnvouchedKind::Earlier), from
///   any previous state;
/// - an unread exit flag names [`ExitUnread`](UnvouchedKind::ExitUnread).
///
/// A settlement with no new fact keeps the stored kind, held members included.
///
/// A `Killed` tree holds no members: a `SIGTERM` walk that finds live ones on it has seen it run on,
/// and only the call's own complete walk can vouch for it again.
#[derive(Debug, Default)]
struct TreeState {
    vouching: Vouching,
    /// What a kill left, or a `SIGTERM` walk reached: empty when nothing is held, in every state. Every
    /// later kill and drop answers them first: the root's death reparents them out of a later walk, so
    /// the handle kills the ones whose identity was read again and reports the others again. The two
    /// kinds are told apart by the entry ([`Left`](crate::containment::treewalk::Left)): `Resolved` and
    /// `Unread` are leftovers of a kill that did not kill them, `Termed` members of a `SIGTERM` walk,
    /// which nothing has refused.
    held: Vec<crate::containment::treewalk::Left>,
}

/// Whether a walk has vouched for a tree.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Vouching {
    /// Nothing has settled the tree: no kill left anything running, and no walk left nothing.
    #[default]
    Never,
    /// A walk left nothing: vouched for.
    Killed,
    /// A kill ran, and no walk since has vouched for the tree: a member seen running may have forked,
    /// and its children were never looked for. The kind says what was found where the tree became
    /// unvouched: every text over this state is chosen by it.
    Unvouched(UnvouchedKind),
}

impl Vouching {
    /// The vouching of a tree that holds members: a killed tree was seen to run on, so it is `Never`;
    /// `Never` stays; an unvouched tree keeps its kind, unless the settlement saw the root running,
    /// which is the latest fact.
    fn under_held(self, root_seen_running: bool) -> Vouching {
        match self {
            Vouching::Killed => Vouching::Never,
            Vouching::Unvouched(_) if root_seen_running => Vouching::Unvouched(UnvouchedKind::RootSeenRunning),
            kept @ (Vouching::Never | Vouching::Unvouched(_)) => kept,
        }
    }
}

impl TreeState {
    fn new(vouching: Vouching, held: Vec<crate::containment::treewalk::Left>) -> TreeState {
        debug_assert!(
            vouching != Vouching::Killed || held.is_empty(),
            "a killed tree holds no member"
        );
        TreeState { vouching, held }
    }
}

/// The state after a settlement, by the rule on [`TreeState`]. The facts: `walked`, the outcome was a
/// walk that ran; `left_now`, the members it left with identities; `running`, the outcome left
/// something running (the root included, whatever then ended it), not merely an error for a walk it
/// did not make (a gone root's or an unmade walk's error is not a member seen running);
/// `root_seen_running`, the walk left the root (whatever then ended it), which is `running`;
/// `exit_unread`, the walk killed all it found but could not read whether the root's exit had begun,
/// which leaves nothing running and the tree unvouched.
fn next(
    prev: &TreeState,
    walked: bool,
    left_now: Vec<crate::containment::treewalk::Left>,
    running: bool,
    root_seen_running: bool,
    exit_unread: bool,
) -> TreeState {
    debug_assert!(
        !root_seen_running || running,
        "a root seen running is something left running"
    );
    debug_assert!(
        !exit_unread || (walked && !running),
        "an unread exit flag is a walk that left nothing running"
    );
    if !left_now.is_empty() {
        return TreeState::new(prev.vouching.under_held(root_seen_running), left_now);
    }
    // The kind the facts name, for a state they leave unvouched.
    let named = if root_seen_running {
        UnvouchedKind::RootSeenRunning
    } else if running {
        UnvouchedKind::Earlier
    } else {
        UnvouchedKind::HeldMembersGone
    };
    let vouching = match prev.vouching {
        _ if exit_unread => Vouching::Unvouched(UnvouchedKind::ExitUnread),
        _ if walked && !running => Vouching::Killed,
        Vouching::Never if !running && prev.held.is_empty() => Vouching::Never,
        Vouching::Killed if !running => Vouching::Killed,
        Vouching::Unvouched(kept) if !running => Vouching::Unvouched(kept),
        Vouching::Never | Vouching::Killed | Vouching::Unvouched(_) => Vouching::Unvouched(named),
    };
    TreeState::new(vouching, Vec::new())
}

impl TreeKilled {
    fn lock(&self) -> std::sync::MutexGuard<'_, TreeState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the tree is killed. Only a Unix drop reads it (`DropView`), and the tests.
    #[cfg(any(unix, test))]
    pub(crate) fn is_set(&self) -> bool {
        self.lock().vouching == Vouching::Killed
    }

    /// Whether the tree holds members: what a refused kill left, or a `SIGTERM` walk reached.
    pub(crate) fn holds_members(&self) -> bool {
        !self.lock().held.is_empty()
    }

    /// Holds `members`, which a `SIGTERM` walk found and reached, as members a later kill answers first
    /// ([`held`](TreeState::held), as `Termed` entries, not as leftovers of a refused kill): the root's
    /// exit reparents them out of every later walk, so only their identities reach them. `complete`:
    /// the walk read every candidate, so `members` list the tree whole as it saw it. `call` is the call
    /// that walked, if it will sweep: the returned token is the one its sweep may vouch with, `Some`
    /// only for a complete walk, and tags the members it reached. A member held already (the same
    /// process, by pid and start identity, in either kind) is held once, and is tagged by the call
    /// that reached it now. The vouching follows [`Vouching::under_held`].
    pub(crate) fn hold(
        &self,
        members: Vec<crate::identity::ProcessId>,
        complete: bool,
        call: Option<&crate::containment::treewalk::WalkToken>,
    ) -> Option<crate::containment::treewalk::WalkToken> {
        use crate::containment::treewalk::Left;

        let walk = call.filter(|_| complete).cloned();
        let mut state = self.lock();
        let mut held = state.held.clone();
        for id in members {
            match held.iter_mut().find(|member| match member {
                Left::Resolved(held_id) | Left::Termed { id: held_id, .. } => *held_id == id,
                Left::Unread { .. } => false,
            }) {
                Some(Left::Termed { walk: tagged, .. }) => {
                    if walk.is_some() {
                        tagged.clone_from(&walk);
                    }
                }
                Some(_) => {}
                None => held.push(Left::Termed { id, walk: walk.clone() }),
            }
        }
        if !held.is_empty() {
            // A `SIGTERM` walk is no kill's settlement: it names no root seen running.
            *state = TreeState::new(state.vouching.under_held(false), held);
        }
        walk
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
    /// Boxed so that a `Result` of an `Unkilled` stays small.
    pub(crate) root: Option<Box<Error>>,
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
            .or(self.root.as_deref())
            .expect("an incomplete kill left a member")
    }

    /// [`first`](Self::first), owned, for the tests that read what a walk returned.
    #[cfg(test)]
    pub(crate) fn into_error(self) -> Error {
        self.members
            .into_iter()
            .next()
            .or(self.root.map(|root| *root))
            .expect("an incomplete kill left a member")
    }

    /// What is still left once the root's own handle has had its say: `Ok` when nothing is, else the
    /// error that holds every member left, in order ([`Error::MembersLeft`]), with the errors that
    /// name no member as its `others` (a [`Error::Several`] when there are two or more). With no
    /// member, the first error that names none is the answer, in its own variant, with the others as
    /// its peers ([`Error::with_peers`]) (see
    /// [`Child::kill_tree`](crate::Child::kill_tree) for the contract).
    /// `root_ended`: the root is not running, so a root the walk left is not left.
    pub(crate) fn unsettled(self, root_ended: bool) -> Result<(), Error> {
        let root = self.root.filter(|_| !root_ended).map(|root| *root);
        let left = self.members.into_iter().chain(root);
        let (mut members, mut unnamed) = (Vec::new(), Vec::new());
        for error in left {
            if matches!(error, Error::MemberNotKilled { .. }) {
                members.push(Arc::new(error));
            } else {
                unnamed.push(error);
            }
        }
        match Failures::collect(members) {
            Some(members) => {
                let unnamed = Failures::collect(unnamed.into_iter().map(Arc::new));
                Err(Error::members_left(members, unnamed.map(Failures::into_cause)))
            }
            // No member: the first error is the answer, in its own variant, and the others its peers.
            None => {
                let mut unnamed = unnamed.into_iter();
                match unnamed.next() {
                    None => Ok(()),
                    Some(first) => Err(first.with_peers(unnamed.map(Arc::new))),
                }
            }
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

/// How a [`Tree::settle`] that found nothing left came out, by the state it left ([`TreeKilled`]):
/// the answer `Ok` does not say the tree is vouched for, this does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettleOutcome {
    /// The kill ran, or found the killed tree already gone, and the state left is killed: nothing is
    /// left for the caller to report, and the tree is vouched for.
    Killed,
    /// The kill was skipped (and the sweep by identity of a macOS fd marker left nothing): it killed
    /// nothing, and the state left is not unvouched. `over_killed`: the tree was already killed when
    /// the settlement found it, read under the one lock that settled it.
    Skipped { over_killed: bool },
    /// The state left is [`Unvouched`](Vouching::Unvouched), whatever the call did: a skipped kill
    /// over a tree a skip moved there from held members (refused ones, or ones a `SIGTERM` walk
    /// reached) that are gone, or a walk that left only the root, whose own end then made the answer
    /// `Ok`. `kind` says what was found.
    Unvouched { kind: UnvouchedKind },
}

/// What a settlement found of a tree it cannot vouch for ([`SettleOutcome::Unvouched`]), as far as
/// the settlement knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnvouchedKind {
    /// The tree held members, which are gone now: ones an earlier kill left (refused), or ones a
    /// `SIGTERM` walk reached that no sweep of the call that walked has vouched for. What they forked
    /// was never looked for.
    HeldMembersGone,
    /// A walk saw the root running and left it. If the root's own kill then ended it, the call was
    /// `Ok`. What the root forked meanwhile was never looked for.
    RootSeenRunning,
    /// A kill, this settlement's own or an earlier one, left something running that it could not name
    /// (members the handle holds no identity for, or members since gone), and the settlement
    /// no longer knows which.
    Earlier,
    /// A walk killed everything it found, but could not read whether the root's exit had begun
    /// ([`TreeKillOutcome::ExitUnread`]): nothing was seen running, and the children the exit may have
    /// reparented out of the walk were never looked for.
    ExitUnread,
}

impl UnvouchedKind {
    /// What the settlement found, as the clause of a text about a tree it cannot vouch for.
    fn found(self) -> &'static str {
        match self {
            UnvouchedKind::HeldMembersGone => {
                "the members an earlier kill left, or a SIGTERM walk reached, are gone now, but no later walk has \
                 checked what they forked"
            }
            UnvouchedKind::RootSeenRunning => {
                "the walk found the root running, and what the root forked meanwhile was never looked for"
            }
            UnvouchedKind::Earlier => {
                "a kill left something running that it could not name, and no later walk has checked what it forked"
            }
            UnvouchedKind::ExitUnread => {
                "the walk could not tell whether the root's exit had begun, so children it may have reparented out \
                 of the walk were never looked for"
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
            UnvouchedKind::RootSeenRunning | UnvouchedKind::ExitUnread => self.unvouched_text(),
        }
    }

    /// What a gone root answers over a tree of this kind: the tree could not be walked, but not
    /// nothing was killed.
    fn gone_root_text(self) -> &'static str {
        match self {
            UnvouchedKind::HeldMembersGone => {
                "the members an earlier kill left, or a SIGTERM walk reached, are gone; the tree could not be walked \
                 from its exited root, so what they forked is unknown"
            }
            UnvouchedKind::RootSeenRunning => {
                "the root an earlier walk found running is gone; the tree could not be walked from it, so what it \
                 forked is unknown"
            }
            UnvouchedKind::Earlier => {
                "a kill left something running that it could not name, and no walk since has checked what it \
                 forked; the tree could not be walked from its gone root"
            }
            UnvouchedKind::ExitUnread => {
                "an earlier walk could not tell whether the root's exit had begun, and the root is gone now; the tree \
                 could not be walked from it, so children its exit may have reparented are unknown"
            }
        }
    }
}

/// What a tree kill did ([`Contains::kill`](crate::containment::Contains::kill)): the one value [`Tree::settle`] turns into what
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
    /// could not be queried), so the walk killed NOTHING, the root included: killing the root anyway
    /// would reparent its descendants out of the ppid walk, so a retry could no longer find them. The
    /// error says why. The settlement kills the members the tree holds by identity, unless a `Child`
    /// keeps them for a walk from its running root ([`Keeping`]). Every other failure is a kill that was attempted, a `TreeWalk`'s
    /// [`Error::MemberNotKilled`] included.
    Unwalked(Error),
    /// A `TreeWalk` walk found its root gone, or holding its pid no longer, or (Unix) exited and not
    /// yet reaped: its children were reparented at its exit, so there is no tree to
    /// walk from, and this kill killed nothing. It is [`Error::Unassessable`]:
    /// [`no_root_error`](Self::no_root_error) over a tree never settled,
    /// [`no_root_after_kills_error`](Self::no_root_after_kills_error) over an unvouched one, worded by
    /// what the settlement knows of it ([`UnvouchedKind`]). The token, if there is one, is the call
    /// whose own complete `SIGTERM` walk listed the tree ([`in_call`](Self::in_call)): its sweep may
    /// stand on that listing.
    NoRoot(u32, Option<crate::containment::treewalk::WalkToken>),
    /// A `TreeWalk` walk found the root's exit begun, as the kernel's exit flag shows, and killed every
    /// member it found: the exit may have moved other children out of its reach, so the walk is no proof
    /// of the tree. It settles as [`NoRoot`](Self::NoRoot) does, token included
    /// ([`in_call`](Self::in_call)). A walk that left a member is [`Ran`](Self::Ran), not this.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix kernel reparents a root's children at its exit")
    )]
    RootExiting(u32, Option<crate::containment::treewalk::WalkToken>),
    /// A `TreeWalk` walk found members and killed every one it found, the root included, but could not
    /// read whether the root's exit had begun: the error says why the tree cannot be vouched for. It ran,
    /// and left nothing running that it knows of, so it is not a member seen running
    /// ([`Ran`](Self::Ran) with this error would be); it leaves the tree
    /// [`Unvouched`](UnvouchedKind::ExitUnread). A walk that left a member is `Ran`, not this.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix kernel reparents a root's children at its exit")
    )]
    ExitUnread(Error),
    /// The root's number is untrusted, so the kill skipped what names the tree by it. The tree is
    /// not killed. The caller that has the root's handle acts on [`Skip::root_alone`].
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix mechanism skips by the root's number")
    )]
    Skipped(Skip),
    /// A skipped kill as a tree call settles it ([`SkipCall`](crate::containment::SkipCall)): the call
    /// keeps the [`Skip`] to word it, and the settlement takes only the sweep by identity of a macOS fd
    /// marker's holders (`None`: the mechanism has none). It settles as [`Skipped`](Self::Skipped) does.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix mechanism skips by the root's number")
    )]
    SkippedHolders(Option<Result<(), Error>>),
}

/// What a `kill_tree` call's settlement keeps for the walk that may follow it
/// ([`TreeKilled::settle_for_kill_tree`]): a fact of the caller, read from the root's own handle. It
/// decides only a walk that was not made ([`TreeKillOutcome::Unwalked`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keeping {
    /// The handle sees the root running (or cannot say it has exited), so a later `kill_tree` walks from
    /// it and reaches the held members, and what they forked since, below it: the walk not made kills
    /// nothing, the held members included, and answers its own error.
    ForWalkFromRunningRoot,
    /// Nothing is kept for such a walk: the handle sees the root exited (no walk reaches anything), the
    /// caller is a foreign `Process`, or the call is a drop. The held members are killed by identity.
    Nothing,
}

/// A kill that ran: what [`Tree::kill`] and the paths that send by hand return.
impl From<Result<(), Unkilled>> for TreeKillOutcome {
    fn from(result: Result<(), Unkilled>) -> TreeKillOutcome {
        TreeKillOutcome::Ran(result)
    }
}

impl TreeKillOutcome {
    /// This outcome for the sweep of the call `call`, whose own complete `SIGTERM` walk listed the tree
    /// ([`NoRoot`](Self::NoRoot) and [`RootExiting`](Self::RootExiting) are the only outcomes that stand
    /// on it).
    pub(crate) fn in_call(self, call: Option<&crate::containment::treewalk::WalkToken>) -> TreeKillOutcome {
        match self {
            TreeKillOutcome::NoRoot(pid, _) => TreeKillOutcome::NoRoot(pid, call.cloned()),
            TreeKillOutcome::RootExiting(pid, _) => TreeKillOutcome::RootExiting(pid, call.cloned()),
            other => other,
        }
    }

    /// What [`RootExiting`](Self::RootExiting) of the root `pid` is as an error, and the entry of a walk
    /// that left anything of a tree whose root's exit had begun: no member is named.
    #[cfg(unix)]
    pub(crate) fn exiting_root_error(pid: u32) -> Error {
        Error::Unassessable {
            detail: format!(
                "the root (pid {pid}) had begun to exit when the walk ended, so its children may have been \
                 reparented out of the walk and the tree cannot be vouched for"
            ),
            source: None,
        }
    }

    /// What [`NoRoot`](Self::NoRoot) of the root `pid` is as an error: nothing was killed, because no
    /// walk ran.
    pub(crate) fn no_root_error(pid: u32) -> Error {
        #[cfg(unix)]
        let detail = format!(
            "the root (pid {pid}) has exited, so its descendants were reparented and a walk from its pid finds \
             none: no walk ran and nothing was killed"
        );
        // Windows never reparents: the pid names no process of this tree any more.
        #[cfg(not(unix))]
        let detail =
            format!("the root's pid ({pid}) names no process of this tree: no walk ran and nothing was killed");
        Error::Unassessable { detail, source: None }
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
            TreeKillOutcome::Skipped(Skip { holders, .. }) | TreeKillOutcome::SkippedHolders(holders) => {
                holders.unwrap_or(Ok(())).map_err(Unkilled::from)
            }
            TreeKillOutcome::Unwalked(error) => Err(Unkilled::from(error)),
            TreeKillOutcome::NoRoot(pid, _) => Err(Unkilled::from(Self::no_root_error(pid))),
            #[cfg(unix)]
            TreeKillOutcome::RootExiting(pid, _) => Err(Unkilled::from(Self::exiting_root_error(pid))),
            #[cfg(not(unix))]
            TreeKillOutcome::RootExiting(..) => unreachable!("only a Unix walk finds a root exiting"),
            TreeKillOutcome::ExitUnread(error) => Err(Unkilled::from(error)),
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
    /// the first member a kill left, or what a skip left undone. For the text of a gate or a log line
    /// that reads it: its error is worded as the whole chain, through [`Report`](crate::error::Report).
    #[cfg(unix)]
    pub(crate) fn incomplete(&self) -> Option<String> {
        if self.completed() {
            return None;
        }
        let word = |error: &Error| crate::error::Report(error).to_string();
        Some(match self {
            TreeKillOutcome::Ran(Err(left)) | TreeKillOutcome::Answered(Err(left)) => word(left.first()),
            TreeKillOutcome::Skipped(Skip {
                holders: Some(Err(error)),
                ..
            })
            | TreeKillOutcome::SkippedHolders(Some(Err(error))) => word(error),
            TreeKillOutcome::Skipped(Skip { action, .. }) => {
                format!("the kill was skipped, and would {action}")
            }
            TreeKillOutcome::SkippedHolders(_) => "the kill was skipped".to_owned(),
            TreeKillOutcome::Unwalked(error) | TreeKillOutcome::ExitUnread(error) => word(error),
            TreeKillOutcome::NoRoot(pid, _) => word(&Self::no_root_error(*pid)),
            TreeKillOutcome::RootExiting(pid, _) => word(&Self::exiting_root_error(*pid)),
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
            | TreeKillOutcome::SkippedHolders(_)
            | TreeKillOutcome::Answered(_)
            | TreeKillOutcome::Unwalked(_)
            | TreeKillOutcome::ExitUnread(_)
            | TreeKillOutcome::NoRoot(..)
            | TreeKillOutcome::RootExiting(..) => None,
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

/// A settlement's answer and the members it killed again, which the kill's wait adds to its wait
/// ([`KillWait::reaching`](crate::containment::KillWait::reaching)).
pub(crate) struct Settled<A = Result<SettleOutcome, Error>> {
    pub(crate) answer: A,
    pub(crate) killed_again: Vec<crate::identity::ProcessId>,
}

impl<A> Settled<A> {
    /// An answer that killed nothing again.
    pub(crate) fn of(answer: A) -> Settled<A> {
        Settled {
            answer,
            killed_again: Vec::new(),
        }
    }

    /// The same members, with the answer `f` makes of this one.
    pub(crate) fn map<B>(self, f: impl FnOnce(A) -> B) -> Settled<B> {
        Settled {
            answer: f(self.answer),
            killed_again: self.killed_again,
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

/// A `kill_tree` sweep's answer, with the wait for what it killed: a caller that returns once the
/// members have exited [`wait`](Self::wait)s, and one that sends alone takes the [`answer`](Self::answer).
pub(crate) struct Swept<'a> {
    /// The call the sweep is a step of, which a warn about its wait names.
    op: &'static str,
    answer: Result<(), SweepFailure>,
    wait: crate::containment::KillWait<'a>,
}

impl<'a> Swept<'a> {
    pub(crate) fn new(
        op: &'static str,
        answer: Result<(), SweepFailure>,
        wait: crate::containment::KillWait<'a>,
    ) -> Swept<'a> {
        Swept { op, answer, wait }
    }

    /// The answer of a call that killed nothing, so it waits for nothing.
    pub(crate) fn unwaited(op: &'static str, answer: Result<(), SweepFailure>) -> Swept<'a> {
        Swept::new(op, answer, crate::containment::KillWait::none())
    }

    /// The sweep's answer, for a caller that sends and does not wait.
    pub(crate) fn answer(self) -> Result<(), SweepFailure> {
        self.answer
    }

    /// The sweep's answer once every member it killed has exited. A kill that failed is the answer
    /// over a wait that failed: the wait's error is logged. A wait that failed is a failure that
    /// keeps the record of the root's kill, as a kill that failed does.
    pub(crate) fn wait(self) -> Result<(), SweepFailure> {
        let root_ended = self.wait.waits_for_root();
        let waited = self.wait.wait();
        Self::after_wait(self.op, self.answer, waited, root_ended)
    }

    /// [`wait`](Self::wait), awaited, with no runtime thread blocked.
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_async(self) -> Result<(), SweepFailure> {
        let root_ended = self.wait.waits_for_root();
        let waited = self.wait.wait_async().await;
        Self::after_wait(self.op, self.answer, waited, root_ended)
    }

    fn after_wait(
        op: &str,
        answer: Result<(), SweepFailure>,
        waited: Result<(), Error>,
        root_ended: bool,
    ) -> Result<(), SweepFailure> {
        crate::containment::tree_kill::answer_after_wait(op, answer, waited, |error| SweepFailure { error, root_ended })
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

    /// The answer of a `kill_tree` sweep: the mechanism's error, settled by the root's death
    /// ([`Tree::settle`]), with the failure of the backstop, the handle's own kill of `root`. The
    /// backstop is part of the kill, so its failure is a member left like the walk's; the contract is
    /// [`Child::kill_tree`](crate::Child::kill_tree)'s. `root_ended`: the backstop ended the root.
    pub(crate) fn of(
        tree: &Tree,
        walk: TreeKillOutcome,
        backstop: Result<(), Error>,
        root: u32,
        root_ended: bool,
    ) -> Settled<Result<(), SweepFailure>> {
        // The walk was made (an unwalked one never reaches the backstop): nothing is kept for a retry.
        tree.settle_for_kill_tree(walk, root_ended, Keeping::Nothing)
            .map(|walk| {
                let error = match (walk, backstop) {
                    (Ok(()), Ok(())) => return Ok(()),
                    (Err(walk), Ok(())) => walk,
                    (walk, Err(backstop)) => Self::with_backstop(tree, walk.err(), backstop, root),
                };
                Err(SweepFailure { error, root_ended })
            })
    }

    /// What the mechanism left, `walk`, with the failed `backstop` of `root` (see [`of`](Self::of)).
    fn with_backstop(tree: &Tree, walk: Option<Error>, backstop: Error, root: u32) -> Error {
        let backstop = Arc::new(backstop);
        let root_member = |source| Error::MemberNotKilled { pid: root, source };
        match walk {
            Some(Error::MembersLeft { members, others }) => {
                let mut root_seen = false;
                let mut members: Vec<Arc<Error>> = members
                    .iter()
                    .map(|member| match &**member {
                        Error::MemberNotKilled { pid, source } if *pid == root => {
                            root_seen = true;
                            Arc::new(root_member(
                                Failures::new(Arc::clone(&backstop), [Arc::clone(source)]).into_cause(),
                            ))
                        }
                        _ => Arc::clone(member),
                    })
                    .collect();
                if !root_seen {
                    members.push(Arc::new(root_member(backstop)));
                }
                Error::members_left(Failures::collect(members).expect("a member was left"), others)
            }
            Some(other) => other.with_peers([Arc::new(root_member(backstop))]),
            None => tree.root_left(root_member(backstop)),
        }
    }
}

impl TreeKilled {
    /// What a tree kill's `outcome` comes to once the root's own handle has had its say: the only place
    /// that writes the state. The mechanism decides what a kill left held
    /// ([`Contains::kill_left`](crate::containment::Contains::kill_left)); the settlement records it.
    /// `mechanism`: what names the tree, `None` for a tree that is none or delegated, which holds
    /// nothing. `root_ended`: the root is not running (killed, or already dead), so a root the walk
    /// left is not left. `Ok` when nothing is left, else the error that holds every member left
    /// ([`Unkilled::unsettled`]).
    ///
    /// It decides under the one lock of the state, by it and the outcome, and leaves the state
    /// by the rule on [`TreeState`]. The members a `TreeWalk` state holds are answered first, whatever
    /// the outcome. A gone root over a killed tree is `Ok`, and over held members still left it adds no
    /// error of its own; over a tree never settled it is [`TreeKillOutcome::no_root_error`], and over
    /// an unvouched one (held members that are all gone, or left so earlier) it is
    /// [`TreeKillOutcome::no_root_after_kills_error`].
    ///
    /// A `Child`'s `kill_tree` reads `root_ended` from its backstop. The backstop does not run for
    /// an [`Answered`](TreeKillOutcome::Answered) or [`Skipped`](TreeKillOutcome::Skipped) outcome
    /// (the sweep's own sends decide the root), for a tree held by a cgroup front, for a macOS root
    /// launchd holds, or for a walk not made ([`Unwalked`](TreeKillOutcome::Unwalked)): ending the
    /// root would reparent its descendants out of a retry's walk, so the root stays. A foreign
    /// `Process`'s sweep has no backstop, and a drop or a failed spawn's cleanup reads `root_ended`
    /// from the fate of the root kill it made after the walk. The held members are killed by
    /// identity, whichever the caller and whether the walk was made: a walk reaches only what is
    /// still under the root, and a member the handle holds may not be (a kill's refusal left it, or
    /// its parent or the root exited). The one exception is made before `settle`, by
    /// [`settle_for_kill_tree`](Self::settle_for_kill_tree): a `Child` that sees its root running
    /// keeps them over a walk not made, for the retry's walk from that root.
    ///
    /// A gone root whose outcome names a call ([`TreeKillOutcome::in_call`]) is that call's sweep, and
    /// it may stand on the call's own `SIGTERM` walk, which was a kill's walk before the root exited:
    /// when every held member is one that walk reached ([`Left::Termed`](crate::containment::treewalk::Left)
    /// tagged with that call), and each is gone or killed by identity and waited for, the tree is
    /// vouched for, `Killed`, and the answer `Ok`; a walk that found nothing is an empty listing. The
    /// limit is `kill_tree`'s: a process forked after the listing is not seen. A tree that holds
    /// anything else (a refused kill's leftovers, members of a separate `terminate_tree` or of an
    /// incomplete walk, an unvouched state) is not vouched: the answer is the held members' own.
    pub(crate) fn settle(
        &self,
        mechanism: Option<&Mechanism>,
        outcome: impl Into<TreeKillOutcome>,
        root_ended: bool,
    ) -> Settled {
        let outcome = outcome.into();
        let mut state = self.lock();
        let was_killed = state.vouching == Vouching::Killed;
        // Copied, not taken: the state is written once, at the end, so an unwind between leaves it as it was.
        let held = state.held.clone();
        let (gone_root_pid, call) = match &outcome {
            TreeKillOutcome::NoRoot(pid, call) | TreeKillOutcome::RootExiting(pid, call) => (Some(*pid), call.as_ref()),
            _ => (None, None),
        };
        let gone_root = gone_root_pid.is_some();
        let listing_stands = call.is_some_and(|call| {
            !matches!(state.vouching, Vouching::Unvouched(_))
                && state.held.iter().all(|member| {
                    matches!(member, crate::containment::treewalk::Left::Termed { walk: Some(walk), .. } if walk == call)
                })
        });
        let ran = matches!(
            outcome,
            TreeKillOutcome::Ran(_) | TreeKillOutcome::Answered(_) | TreeKillOutcome::ExitUnread(_)
        );
        let exit_unread = matches!(outcome, TreeKillOutcome::ExitUnread(_));
        // What a walk not made, a gone root or an unread exit flag leaves is its error, not a member seen
        // running.
        let looked_for_no_member = matches!(
            outcome,
            TreeKillOutcome::NoRoot(..)
                | TreeKillOutcome::RootExiting(..)
                | TreeKillOutcome::Unwalked(_)
                | TreeKillOutcome::ExitUnread(_)
        );
        // A walk already covered the tree unless it was never settled: a gone root adds no error of its own.
        let covered = gone_root && (listing_stands || state.vouching != Vouching::Never || !state.held.is_empty());
        let result = if covered { Ok(()) } else { outcome.into_result() };
        let crate::containment::mechanism::KillLeftOutcome {
            mut result,
            left: left_now,
            killed: killed_again,
        } = match mechanism {
            Some(mechanism) => mechanism.kill_left(result, held),
            None => crate::containment::mechanism::nothing_held(result),
        };
        // A member the walk saw running un-vouches the tree, whatever ended it afterwards: it may have
        // forked first. Only the answer follows the root's end.
        let running = result.is_err() && !looked_for_no_member;
        let root_seen_running = matches!(&result, Err(left) if left.root.is_some());
        let after = next(&state, ran, left_now, running, root_seen_running, exit_unread);
        let listing_clear = listing_stands && result.is_ok();
        let after = if listing_clear {
            TreeState::new(Vouching::Killed, Vec::new())
        } else {
            after
        };
        if gone_root && result.is_ok() && !was_killed && !listing_clear {
            // What an earlier walk left is gone or unknown, but nothing walked the tree for what it forked.
            let error = match after.vouching {
                Vouching::Unvouched(kind) => TreeKillOutcome::no_root_after_kills_error(kind),
                Vouching::Never | Vouching::Killed => {
                    debug_assert!(
                        false,
                        "a gone root over held or unvouched members leaves the tree unvouched"
                    );
                    // Release: the gone-root answer of a tree no kill left unvouched.
                    TreeKillOutcome::no_root_error(gone_root_pid.expect("a gone root has its pid"))
                }
            };
            result = Err(Unkilled::from(error));
        }
        let unsettled = match result {
            Ok(()) => Ok(()),
            Err(left) => left.unsettled(root_ended),
        };
        // The answer follows the state left: `Killed` only over a vouched tree. A gone root answers
        // `Ok` only over a killed tree.
        let answer = unsettled.map(|()| match after.vouching {
            Vouching::Unvouched(kind) => SettleOutcome::Unvouched { kind },
            _ if ran || gone_root => {
                debug_assert!(after.vouching == Vouching::Killed, "`Killed` answers a killed tree");
                SettleOutcome::Killed
            }
            _ => SettleOutcome::Skipped {
                over_killed: was_killed,
            },
        });
        *state = after;
        Settled { answer, killed_again }
    }

    /// [`settle`](Self::settle) for a `kill_tree` call: the error holds every member left, so the call
    /// reports each of them once, in it.
    ///
    /// `keeping`: with [`Keeping::ForWalkFromRunningRoot`] a walk not made
    /// ([`Unwalked`](TreeKillOutcome::Unwalked)) settles nothing: the state and the members it holds
    /// stay for the retry, which walks from the running root. The answer is its own error beside every
    /// held member an earlier kill refused and that may still run
    /// ([`refused_still`](crate::containment::treewalk::refused_still)), as a settlement would report
    /// it. Every other outcome is settled whatever `keeping` says.
    pub(crate) fn settle_for_kill_tree(
        &self,
        mechanism: Option<&Mechanism>,
        outcome: impl Into<TreeKillOutcome>,
        root_ended: bool,
        keeping: Keeping,
    ) -> Settled<Result<(), Error>> {
        match (outcome.into(), keeping) {
            (TreeKillOutcome::Unwalked(error), Keeping::ForWalkFromRunningRoot) => {
                let mut members =
                    crate::containment::treewalk::refused_still(&crate::identity::HostKernel, &self.lock().held);
                members.push(error);
                Settled::of(
                    Unkilled {
                        members,
                        root: None,
                        resolved: Vec::new(),
                    }
                    .unsettled(false),
                )
            }
            (outcome, _) => self
                .settle(mechanism, outcome, root_ended)
                .map(|answer| answer.map(drop)),
        }
    }

    /// [`settle`](Self::settle) for a drop: what is left when the tree is not settled, the text of the
    /// drop's warn (worded here and only when it will be logged) and the error, if the settlement's
    /// was one.
    pub(crate) fn settle_for_drop(
        &self,
        mechanism: Option<&Mechanism>,
        outcome: impl Into<TreeKillOutcome>,
        root_ended: bool,
    ) -> Option<TreeLeft> {
        let outcome = outcome.into();
        // A drop cannot retry a walk that was not made.
        let unwalked = matches!(outcome, TreeKillOutcome::Unwalked(_));
        let settled = self.settle(mechanism, outcome, root_ended);
        let (left, failure) = match settled.answer {
            Err(left) => (crate::error::Report(&left).to_string(), Some(left)),
            Ok(SettleOutcome::Unvouched { kind }) => (kind.drop_text(), None),
            Ok(SettleOutcome::Killed | SettleOutcome::Skipped { .. }) => return None,
        };
        let after = match (unwalked, &settled.killed_again[..]) {
            (false, _) => String::new(),
            (true, []) => "; the root is killed regardless, so its other descendants may be orphaned".to_owned(),
            (true, killed) => {
                let pids: Vec<String> = killed.iter().map(|id| id.pid().to_string()).collect();
                format!(
                    "; the members this handle held were killed by identity (pid {}), and the root is killed \
                     regardless, so its other descendants may be orphaned",
                    pids.join(", ")
                )
            }
        };
        Some(TreeLeft {
            text: format!("contained-tree teardown did not fully succeed: {left}{after}"),
            failure,
        })
    }
}

/// What a drop or a failed run's teardown found left of its contained tree
/// ([`TreeKilled::settle_for_drop`]).
pub(crate) struct TreeLeft {
    /// The text of the teardown's warn.
    pub(crate) text: String,
    /// The tree kill's failure, as an error: absent when the tree is only not vouched for, which is a
    /// state, not a failure.
    pub(crate) failure: Option<Error>,
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
/// Fallible on Windows (a reserved creation-flag bit; composed first, so nothing is left to
/// unwind, and above the uncontained early return, so an uncontained spawn carries the caller's
/// flags too) and for a `Strongest` spawn on Linux and macOS ([`Error::Containment`], nothing
/// forked).
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

            let strict = mode.is_some_and(ContainMode::is_strict);
            let leaf = if strict {
                // `Strongest` decides by the setup calls (see `leaf_if_offered`). A host that
                // offers no cgroup is the process group set above.
                crate::containment::cgroup::leaf_if_offered(
                    crate::containment::cgroup::offered_cgroup(),
                    teardown_warn_after,
                )?
            } else {
                // A failed leaf creation degrades this spawn to the process group set above, and
                // `log_degrade` names the step that failed and the kernel's reason for it.
                match crate::containment::cgroup::try_create_leaf(teardown_warn_after) {
                    Ok(leaf) => Some(leaf),
                    Err(e) => {
                        crate::containment::cgroup::log_degrade(&e);
                        None
                    }
                }
            };
            if let Some(ref l) = leaf {
                // The child's self-placement step. Under `Strongest` a failed placement stops the
                // child before `exec` (see `ReportSlot::refusing`). Otherwise it returns Ok (e.g.
                // EBUSY — "no internal processes" rule), so the spawn proceeds and `attach` falls
                // back to the already-configured process group. Both the sync and the tokio spawn
                // add this one step through `prepare`.
                let slot = l.placement_slot();
                // SAFETY: the leaf, which owns both the fd and the report channel, stays in
                // `Prepared` until after the spawn.
                unsafe { steps.place(l.procs_fd(), if strict { slot.refusing() } else { slot }) };
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
    // does not). `marker_wanted` gates on root/mode/suppression. A failed install fails a
    // `Strongest` spawn; every other mode degrades to the mechanism the marker outranks.
    #[cfg(target_os = "macos")]
    let marker = if crate::containment::fdmarker::marker_wanted(mode, is_root, marker_suppressed) {
        match crate::containment::fdmarker::install(steps, reserved_fds) {
            Ok(marker) => Some(marker),
            Err(e) if mode.is_some_and(ContainMode::is_strict) => return Err(e),
            Err(e) => {
                log::warn!(
                    "{report}; falling back to the pre-existing containment channel for this mode",
                    report = crate::error::Report(&e)
                );
                None
            }
        }
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

/// Why a child could not be contained, and what failed in the cleanup the attach made of it (on
/// Windows, the kill of the job after a failed resume): the failed spawn returns the cause, with the
/// cleanup beside it (`cleanup` of [`Error::MayHaveStarted`]).
#[derive(Debug)]
pub(crate) struct AttachFailure {
    pub(crate) cause: Error,
    pub(crate) cleanup: Option<Failures>,
    /// The program never ran, and the attach proves it: on Linux the child's own report (a
    /// `Strongest` child stopped before `exec` because its placement in its leaf was refused, or a
    /// child in any mode sent no report, which its hook only leaves unsent by ending the child
    /// before `exec`); on Windows a strict root that could not be put in its Job Object and is proved not
    /// to have run (`prove_not_started`). Every other failure may have started the program.
    #[cfg_attr(
        not(any(target_os = "linux", windows)),
        allow(dead_code, reason = "read only by the Linux and Windows arms of the spawn")
    )]
    pub(crate) not_started: bool,
    /// Windows: the root's initial thread, held suspended by the proof that the program never ran,
    /// until the caller has ended the process (see [`ProvenRoot`](crate::containment::windows::ProvenRoot)).
    /// Boxed so that a `Result` of an `AttachFailure` stays small (`clippy::result_large_err`).
    #[cfg(windows)]
    pub(crate) proven: Option<Box<crate::containment::windows::ProvenRoot>>,
}

/// The not-started failure of a child that is not in its leaf (`reason`, in the leaf at `path`), or
/// `reason` back when the child may have run its program.
///
/// The program never ran when the child sent no report (its hook ends it before `exec` after every
/// report it can send), or, under `strict`, its placement write failed (it stops before `exec`). A
/// failed write otherwise is a child that went on in the process group. The error names the leaf;
/// the write's errno is its source, and a failed read of `cgroup.procs` for the diagnosis a second
/// cause beside it. The diagnosis itself is said at `debug`.
#[cfg(target_os = "linux")]
pub(crate) fn not_started_failure(
    reason: crate::containment::cgroup::NotPlaced,
    path: &str,
    strict: bool,
) -> Result<AttachFailure, crate::containment::cgroup::NotPlaced> {
    use crate::containment::cgroup::NotEntered;
    let (detail, source) = match reason.report() {
        NotEntered::NotReported => (
            format!(
                "cgroup v2: the child did not report its placement in leaf cgroup {path}, so the program did not run"
            ),
            None,
        ),
        NotEntered::WriteFailed(errno) if strict => (
            format!("cgroup v2: the child could not be placed in its leaf cgroup {path}, so the program did not run"),
            Some(Error::io_cause(std::io::Error::from_raw_os_error(errno))),
        ),
        NotEntered::WriteFailed(_) => return Err(reason),
    };
    log::debug!(
        "cgroup v2: the program did not run: {report}",
        report = crate::error::Report(&reason)
    );
    let cause = Error::Containment { detail, source }.with_peers(reason.into_read_failure().map(Error::io_cause));
    Ok(AttachFailure {
        cause,
        cleanup: None,
        not_started: true,
        #[cfg(windows)]
        proven: None,
    })
}

impl From<Error> for AttachFailure {
    fn from(cause: Error) -> AttachFailure {
        AttachFailure {
            cause,
            cleanup: None,
            not_started: false,
            #[cfg(windows)]
            proven: None,
        }
    }
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
) -> Result<Attachment, AttachFailure> {
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
) -> Result<Tree, AttachFailure> {
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

                // Strongest and BestEffort: the cgroup leaf if `prepare` made one, else the
                // process group.
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
                            let path = leaf.path().display().to_string();
                            leaf.remove_unentered();
                            let strict = prepared.mode.is_some_and(ContainMode::is_strict);
                            return match not_started_failure(reason, &path, strict) {
                                Ok(failure) => Err(failure),
                                // A failed write under `BestEffort` is a child that went on to run
                                // in the process group set before the spawn: a degrade.
                                Err(reason) => {
                                    crate::containment::cgroup::log_degrade(&reason);
                                    Ok(Tree::contained(Mechanism::Group(Group::process_group(pgid))))
                                }
                            };
                        }
                    }
                }
                // No cgroup leaf (none offered, or a `BestEffort` spawn made none): the process
                // group set pre-spawn.
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

    // Windows: a Job Object, or for a request that accepts less, TreeWalk.
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
                        detail: "the frozen child could not be put in its Job Object".to_owned(),
                        source: Some(Error::io_cause(e)),
                    }
                    .into()),
                };
            }
            let strict = prepared.mode.is_some_and(ContainMode::is_strict);
            match crate::containment::windows::attach_job(proc_handle, strict) {
                Ok(Some(job)) => return Ok(Tree::contained(Mechanism::Job(job))),
                Ok(None) => {
                    // Fall back to the universal TreeWalk mechanism rather than silently yielding no
                    // containment.
                    // The root was spawned with CREATE_NEW_PROCESS_GROUP (root_flags), so
                    // `terminate`'s CTRL_BREAK still reaches the group.
                    return Ok(Tree::contained(Mechanism::Walk(Walker::new(id?))));
                }
                Err(failure) => return Err(failure),
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
