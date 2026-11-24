//! What a tree kill reached, and the wait for those members to exit ([`TreeKill`], [`KillWait`]).
//!
//! A kill names its members, and nothing is held for them past the send: [`KillWait`] holds their
//! identities, and re-opens each one by identity, one at a time, when it waits. A member whose open
//! finds nothing has exited.
//!
//! The Linux `Ticks` limit of the by-identity open applies (see [`Child::kill_tree`](crate::Child::kill_tree)).

use std::collections::HashSet;
use std::time::Instant;

use crate::containment::dispatch::TreeKillOutcome;
use crate::containment::drain_edge::DrainEdge;
use crate::containment::TreeDrain;
use crate::error::Error;
use crate::identity::{Kernel, ProcessId};
use crate::os_process::OsProcess;
use crate::stop::{ClockKind, Deadline};

/// What a tree kill did ([`Contains::kill`](crate::containment::Contains::kill)) and what
/// it left to wait on. Its [`outcome`](Self::outcome) is what the kill left running; a caller that
/// returns once the members have exited [`split`](Self::split)s off the wait as well.
#[must_use = "a kill is complete only once its wait settles"]
pub(crate) struct TreeKill<'a> {
    outcome: TreeKillOutcome,
    wait: KillWait<'a>,
}

/// The members a kill reached, and what else to wait on, as a value: the part of a [`TreeKill`] that a
/// caller settles the kill's outcome without. Every identity is a member the kill reached (the root
/// is not one: its owner waits for it, [`with_root`](Self::with_root)), so it exits whether or not
/// the call answered `Ok`.
pub(crate) struct KillWait<'a> {
    /// Every member a send or a re-kill reached, in the order they were reached. One reached twice
    /// is waited for once.
    members: Vec<ProcessId>,
    /// Members a send reached but could not name by identity, so their exit cannot be observed.
    unobserved: Vec<Unnamed>,
    /// The tree's own edge for "no member runs", chosen by the mechanism: only a kernel tree whose
    /// kill landed has one.
    edge: Option<DrainEdge<'a>>,
    root: RootEnd<'a>,
    kernel: &'a dyn Kernel,
}

/// A member a kill's send reached but whose identity could not be had (or a listing that failed
/// whole), so its exit cannot be observed. `why` says so; `pid` names the member where the listing
/// had one, so a later wait that meets the same member does not report it again ([`Settled`]).
#[derive(Debug)]
pub(crate) struct Unnamed {
    pub(crate) pid: Option<u32>,
    why: Error,
}

impl Unnamed {
    /// The member `pid`, whose identity could not be had for `cause`.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn member(pid: u32, cause: Error) -> Unnamed {
        Unnamed {
            pid: Some(pid),
            why: exit_unobserved(pid, cause),
        }
    }

    /// A member, or a listing, with no pid to name: `why` is the whole error.
    #[cfg(any(target_os = "linux", windows, test))]
    pub(crate) fn nameless(why: Error) -> Unnamed {
        Unnamed { pid: None, why }
    }

    /// The error saying the member's exit cannot be observed, for a row that states its words.
    #[cfg(all(test, any(target_os = "linux", windows)))]
    pub(crate) fn why(&self) -> &Error {
        &self.why
    }
}

/// What a kill's wait has settled when it waits on the tree's edge, which neither waits for nor reports
/// it again. Only a Job's edge reads it.
///
/// A snapshot entry with a readable identity is settled iff that identity is one of the `members`,
/// each of which the wait saw exit or reported (the root too, when its handle reads an identity). An
/// entry whose identity cannot be read is settled iff its pid is one of the `reported`: the pid of a
/// member or the root whose wait failed, or of one the listing could not name. The pid of a member whose
/// exit was seen is never matched: it names another process now.
#[derive(Default)]
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only a Job's edge reads what a wait settled")
)]
pub(crate) struct Settled {
    members: Vec<ProcessId>,
    reported: Vec<u32>,
}

#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only a Job's edge reads what a wait settled")
)]
impl Settled {
    pub(crate) fn new(members: Vec<ProcessId>, reported: Vec<u32>) -> Settled {
        Settled { members, reported }
    }

    /// Whether the member `id`, whose identity a snapshot read, is settled.
    pub(crate) fn covers_identity(&self, id: ProcessId) -> bool {
        self.members.contains(&id)
    }

    /// Whether the entry `pid`, whose identity a snapshot could not read, is settled.
    pub(crate) fn covers_unreadable(&self, pid: u32) -> bool {
        self.reported.contains(&pid)
    }
}

/// What a [`KillWait`] does about the root, which its owner holds.
enum RootEnd<'a> {
    /// Its kill did not land, or nothing says it did: it is not waited for, so a refused kill returns
    /// the refusal instead of hanging.
    NotKilled,
    /// The mechanism's own kill ended it (a tree walk), for a caller that holds the root's handle but no
    /// backstop ([`Process::kill_tree`](crate::Process::kill_tree)).
    Killed,
    /// Its kill landed, and it is waited for through its owner's handle. `pid` is the root's, as its
    /// owner knows it, and `id` its identity, if its owner has one: a wait that ran out names it.
    Waited {
        os: &'a dyn OsProcess,
        pid: u32,
        id: Option<ProcessId>,
    },
}

impl<'a> TreeKill<'a> {
    /// A kill that did `outcome`, which reached no member yet. Its wait re-opens the members through
    /// `kernel`, the kernel of whatever made the kill.
    pub(crate) fn of(outcome: impl Into<TreeKillOutcome>, kernel: &'a dyn Kernel) -> TreeKill<'a> {
        TreeKill {
            outcome: outcome.into(),
            wait: KillWait::none(kernel),
        }
    }

    /// The kill reached `members`.
    pub(crate) fn reaching(mut self, members: impl IntoIterator<Item = ProcessId>) -> TreeKill<'a> {
        self.wait.members.extend(members);
        self
    }

    /// The kill reached a member whose identity could not be had: `why` names it, and its exit cannot
    /// be observed.
    #[cfg(test)]
    pub(crate) fn unobserved(mut self, why: Error) -> TreeKill<'a> {
        self.wait.unobserved.push(Unnamed::nameless(why));
        self
    }

    /// The kill of a tree the kernel names (a cgroup leaf, a Job Object), whose `members` were listed
    /// before it, as `sent` says it went. One that landed reached them and the tree's own `edge`, which
    /// sees a member forked after the listing. One that failed reached none of them: nothing is waited
    /// for, and the listing's `unobserved` failures are logged, not reported.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn listed(
        sent: TreeKillOutcome,
        members: Vec<ProcessId>,
        unobserved: Vec<Unnamed>,
        edge: DrainEdge<'a>,
        kernel: &'a dyn Kernel,
    ) -> TreeKill<'a> {
        if !matches!(sent, TreeKillOutcome::Ran(Ok(()))) {
            for unnamed in &unobserved {
                log::debug!(
                    "the kill failed, so a member the listing could not name is not waited for: {report}",
                    report = crate::error::Report(&unnamed.why)
                );
            }
            return TreeKill::of(sent, kernel);
        }
        let mut kill = TreeKill::of(sent, kernel).reaching(members);
        kill.wait.unobserved = unobserved;
        kill.wait.edge = Some(edge);
        kill
    }

    /// Whether the root's kill landed in the mechanism's own kill: the state is `landed`, either way.
    pub(crate) fn root_killed(mut self, landed: bool) -> TreeKill<'a> {
        self.wait.root = if landed { RootEnd::Killed } else { RootEnd::NotKilled };
        self
    }

    /// What the kill did, for a caller that sends and does not wait.
    pub(crate) fn outcome(self) -> TreeKillOutcome {
        self.outcome
    }

    /// What the kill did, and the wait for what it reached.
    pub(crate) fn split(self) -> (TreeKillOutcome, KillWait<'a>) {
        (self.outcome, self.wait)
    }
}

impl<'a> KillWait<'a> {
    /// A wait that names nothing yet; what it is given to wait for is re-opened through `kernel`.
    pub(crate) fn none(kernel: &'a dyn Kernel) -> KillWait<'a> {
        KillWait {
            members: Vec::new(),
            unobserved: Vec::new(),
            edge: None,
            root: RootEnd::NotKilled,
            kernel,
        }
    }

    /// Members a later kill of the tree reached (a walk's held members, killed again by the
    /// settlement).
    pub(crate) fn reaching(&mut self, members: impl IntoIterator<Item = ProcessId>) {
        self.members.extend(members);
    }

    /// The members the kill reached, for a row that states what a mechanism named.
    #[cfg(test)]
    pub(crate) fn members_for_test(&self) -> &[ProcessId] {
        &self.members
    }

    /// Whether the mechanism's kill ended the root ([`TreeKill::root_killed`]).
    pub(crate) fn root_killed(&self) -> bool {
        matches!(self.root, RootEnd::Killed)
    }

    /// Whether the wait is for the root too: its kill landed, so it is dead whatever the wait finds.
    pub(crate) fn waits_for_root(&self) -> bool {
        matches!(self.root, RootEnd::Waited { .. })
    }

    /// Wait for the root, whose pid its owner knows as `pid` and whose identity is `id`, through its owner's
    /// handle if `landed`, whether its kill landed. A kill that did not land leaves what the mechanism recorded
    /// ([`TreeKill::root_killed`]) as it is.
    pub(crate) fn with_root(
        mut self,
        root: &'a dyn OsProcess,
        pid: u32,
        id: Option<ProcessId>,
        landed: bool,
    ) -> KillWait<'a> {
        if landed {
            self.root = RootEnd::Waited { os: root, pid, id };
        }
        self
    }

    /// Wait until every member reached has exited, then the root, then the tree's own edge. There is no deadline
    /// unless the call was given a timeout: `deadline` is that timeout's instant, `None` for ever.
    ///
    /// # Errors
    ///
    /// The first member whose exit could not be observed (a failed open or look is not an exit), as
    /// [`Error::Unassessable`] naming it, with the others whole below it ([`Error::with_peers`]), once
    /// every other member has been waited for.
    ///
    /// [`Error::TimedOut`] when the deadline ran out with a member, the root or the tree's drain not seen
    /// to exit: `members` are the members and the root that were running at their final look, none for a
    /// drain edge, which names none, and the errors above are below it.
    pub(crate) fn wait(self, deadline: Option<Deadline>) -> Result<(), Error> {
        let KillWait {
            members,
            unobserved: unnamed,
            edge,
            root,
            kernel,
        } = self;
        let by = deadline.and_then(|deadline| deadline.at_on(ClockKind::Real));
        let mut members: Vec<ProcessId> = once_each(members).collect();
        let mut reported = reported_pids(&unnamed);
        let mut unseen = Unseen::new(unnamed, deadline.is_some());
        for &id in &members {
            if unseen.after_member(id, wait_for_member(kernel, id, by)) {
                reported.push(id.pid());
            }
        }
        if let RootEnd::Waited { os: root, pid, id } = root {
            let unsettled = unseen.after_root(id, crate::os_process::drive::exited_until(root, by));
            settle_root(kernel, root, pid, unsettled, &mut members, &mut reported);
        }
        if let Some(edge) = edge {
            // Every member reached is settled: it exited or was reported above, once.
            let settled = Settled::new(members, reported);
            unseen.after_edge(edge.wait_past(by, &settled));
        }
        unseen.answer()
    }

    /// [`wait`](Self::wait), awaited: the same members in the same order, with no runtime thread
    /// blocked, and the same answer. Dropping the future stops the wait only; the kill was sent
    /// before it.
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_async(self, deadline: Option<Deadline>) -> Result<(), Error> {
        let KillWait {
            members,
            unobserved: unnamed,
            edge,
            root,
            kernel,
        } = self;
        // A process is waited for on the clock its wait runs on, the tree's edge on tokio's.
        let by = deadline.and_then(|deadline| deadline.at_on(ClockKind::ASYNC_PROCESS_WAIT));
        let edge_by = deadline.and_then(|deadline| deadline.at_on(ClockKind::Tokio));
        let mut members: Vec<ProcessId> = once_each(members).collect();
        let mut reported = reported_pids(&unnamed);
        let mut unseen = Unseen::new(unnamed, deadline.is_some());
        for &id in &members {
            if unseen.after_member(id, wait_for_member_async(kernel, id, by).await) {
                reported.push(id.pid());
            }
        }
        if let RootEnd::Waited { os: root, pid, id } = root {
            let unsettled = unseen.after_root(id, crate::tokio::drive::exited_until(root, by).await);
            settle_root(kernel, root, pid, unsettled, &mut members, &mut reported);
        }
        if let Some(edge) = edge {
            let settled = Settled::new(members, reported);
            unseen.after_edge(edge.wait_async_past(edge_by, &settled).await);
        }
        unseen.answer()
    }
}

/// What a [`KillWait`] did not see happen: the failures of the exits it could not observe and, for a wait
/// that ran into its deadline, what was still running at the final look.
struct Unseen {
    /// The failures, in the order they were met.
    unobserved: Vec<Error>,
    /// Whether the wait had a deadline to run into: one with none ends only on what it waits for.
    bounded: bool,
    /// The members and the root that were running when the deadline ran out, in the order waited for.
    running: Vec<ProcessId>,
    /// The root was running when the deadline ran out, and its owner knows no identity for it.
    root_unnamed: bool,
    /// The tree's drain edge had not fired when the deadline ran out.
    drain_unseen: bool,
}

impl Unseen {
    fn new(unnamed: Vec<Unnamed>, bounded: bool) -> Unseen {
        Unseen {
            unobserved: unnamed.into_iter().map(|unnamed| unnamed.why).collect(),
            bounded,
            running: Vec::new(),
            root_unnamed: false,
            drain_unseen: false,
        }
    }

    /// The wait for the member `id` ended as `waited`. Whether the member is `reported`, which the tree's edge
    /// then neither waits for nor names again ([`Settled`]): its exit was not seen, or not observed.
    fn after_member(&mut self, id: ProcessId, waited: Result<bool, Error>) -> bool {
        match waited {
            Ok(exited) => {
                self.exited_or_running(exited);
                if !exited {
                    self.running.push(id);
                }
                !exited
            }
            Err(why) => {
                self.unobserved.push(exit_unobserved(id.pid(), why));
                true
            }
        }
    }

    /// The wait for the root, whose identity its owner knows as `id`, ended as `waited`. Whether the root is
    /// unsettled: its exit was not seen, or not observed.
    fn after_root(&mut self, id: Option<ProcessId>, waited: Result<bool, Error>) -> bool {
        match waited {
            Ok(exited) => {
                self.exited_or_running(exited);
                if !exited {
                    match id {
                        Some(id) => self.running.push(id),
                        None => self.root_unnamed = true,
                    }
                }
                !exited
            }
            Err(why) => {
                self.unobserved.push(root_unobserved(why));
                true
            }
        }
    }

    /// The tree's edge answered `waited`: `MembersRemain` is a drain not seen when the wait had a deadline,
    /// and no verdict when it had none ([`drained`]).
    fn after_edge(&mut self, waited: Result<TreeDrain, Error>) {
        match waited {
            Ok(TreeDrain::MembersRemain) if self.bounded => self.drain_unseen = true,
            waited => {
                if let Err(why) = waited.and_then(drained) {
                    self.unobserved.push(why);
                }
            }
        }
    }

    /// A wait that answered `exited`: one that did not exit is an answer only a wait with a deadline gives.
    fn exited_or_running(&self, exited: bool) {
        debug_assert!(exited || self.bounded, "a wait with no deadline ends only on an exit");
    }

    /// The answer: `Ok` when every exit was seen, [`Error::TimedOut`] when one was not, else the failures of
    /// the exits that could not be observed.
    fn answer(self) -> Result<(), Error> {
        let named = !self.running.is_empty() || self.root_unnamed;
        if !named && !self.drain_unseen {
            return answer_of(self.unobserved);
        }
        let detail = match (named, self.drain_unseen) {
            (true, true) => {
                "the call was waiting for the processes its kill reached to exit and for the tree to \
                             drain: it did not see the exit of the ones named, nor the tree's drain"
            }
            (true, false) => "the call was waiting for the processes its kill reached to exit",
            (false, _) => "the call was waiting for the killed tree to drain: the tree's drain was not seen",
        };
        Err(Error::TimedOut {
            detail: detail.to_owned(),
            members: self.running,
            source: None,
        }
        .with_peers(self.unobserved.into_iter().map(std::sync::Arc::new)))
    }
}

/// The pids of the members a listing could not name: the first of a wait's `reported` ([`Settled`]).
fn reported_pids(unnamed: &[Unnamed]) -> Vec<u32> {
    unnamed.iter().filter_map(|unnamed| unnamed.pid).collect()
}

/// Settle the root, whose pid its owner gave as `pid`, once its wait ended: its identity, if its handle
/// can read one, is a settled member (it is matched by identity alone, never by its pid), and `pid` is
/// `reported` when the wait `failed` or ran out, so a snapshot entry for the root whose identity cannot be read is
/// not named again. A root whose identity cannot be read is logged at `warn`: what it would have
/// settled is lost, so a snapshot entry for it that reads an identity can be named a second time. Only a
/// Job's edge reads the settlement.
#[cfg(windows)]
fn settle_root(
    kernel: &dyn Kernel,
    root: &dyn OsProcess,
    pid: u32,
    failed: bool,
    members: &mut Vec<ProcessId>,
    reported: &mut Vec<u32>,
) {
    use std::os::windows::io::AsRawHandle as _;

    let raw = windows::Win32::Foundation::HANDLE(root.os_handle().as_raw_handle());
    if failed {
        reported.push(pid);
    }
    match crate::identity::windows_identity_from_handle_result(kernel, raw, pid) {
        Ok(id) => members.push(id),
        Err(e) => log::warn!(
            "the identity of the root, pid {pid}, cannot be read, so the drain's snapshot may name it again: \
             {report}",
            report = crate::error::Report(&e)
        ),
    }
}

/// Only a Job's edge reads the root's settlement ([`Settled`]).
#[cfg(not(windows))]
fn settle_root(
    _kernel: &dyn Kernel,
    _root: &dyn OsProcess,
    _pid: u32,
    _failed: bool,
    _members: &mut Vec<ProcessId>,
    _reported: &mut Vec<u32>,
) {
}

/// `members`, each one once, in the order they were reached.
fn once_each(members: Vec<ProcessId>) -> impl Iterator<Item = ProcessId> {
    let mut seen = HashSet::new();
    members.into_iter().filter(move |id| seen.insert(*id))
}

/// The error of a wait that could not observe every exit: the first, with each other's whole error
/// below its variant ([`Error::with_peers`]). A first that is an [`Error::Io`] has no slot for them, so
/// it goes below an `Unassessable` with the others.
fn answer_of(unobserved: Vec<Error>) -> Result<(), Error> {
    let mut unobserved = unobserved.into_iter();
    let Some(first) = unobserved.next() else {
        return Ok(());
    };
    Err(first.with_peers_or_unassessable(
        || "the exit of the members a kill reached could not be observed".to_owned(),
        None,
        unobserved.map(std::sync::Arc::new),
    ))
}

fn root_unobserved(cause: Error) -> Error {
    Error::Unassessable {
        detail: "the root was killed, but its exit cannot be observed".to_owned(),
        source: Some(std::sync::Arc::new(cause)),
    }
}

/// What a wait for a tree's edge with no deadline comes to: `MembersRemain` is a verdict only of a
/// deadline's expiry, so one here says the edge did not hold, and the tree is not drained.
fn drained(verdict: TreeDrain) -> Result<(), Error> {
    match verdict {
        TreeDrain::AllMembersExited | TreeDrain::AllMarkersClosed => Ok(()),
        TreeDrain::MembersRemain => Err(Error::Unassessable {
            detail: "the tree's drain edge reported members remaining from a wait with no deadline".to_owned(),
            source: None,
        }),
    }
}

/// Wait for the member `id` to exit until `deadline` (`None`: for ever): re-open it by its identity,
/// wait on it, close it. `Ok(true)` is an exit, and so is a member that cannot be opened because it is
/// gone; `Ok(false)` is a member still running at the deadline's final look. One that cannot be opened
/// for another reason has not exited as far as anyone can tell: the error is that cause.
pub(crate) fn wait_for_member(kernel: &dyn Kernel, id: ProcessId, deadline: Option<Instant>) -> Result<bool, Error> {
    match crate::os_process::open_with(kernel, id).map_err(|failure| failure.into_open_error())? {
        Some(os) => crate::os_process::drive::exited_until(&*os, deadline),
        None => Ok(true),
    }
}

/// [`wait_for_member`], awaited. A Windows `deadline` is on the real clock.
#[cfg(feature = "tokio")]
pub(crate) async fn wait_for_member_async(
    kernel: &dyn Kernel,
    id: ProcessId,
    deadline: Option<Instant>,
) -> Result<bool, Error> {
    match crate::os_process::open_with(kernel, id).map_err(|failure| failure.into_open_error())? {
        Some(os) => crate::tokio::drive::exited_until(&*os, deadline).await,
        None => Ok(true),
    }
}

pub(crate) fn exit_unobserved(pid: u32, cause: Error) -> Error {
    Error::Unassessable {
        detail: format!("pid {pid} was killed, but its exit cannot be observed"),
        source: Some(std::sync::Arc::new(cause)),
    }
}

/// [`exit_unobserved`] for a member whose open was refused, the cause the tests state.
#[cfg(test)]
pub(crate) fn refused_unobserved(pid: u32) -> Error {
    exit_unobserved(
        pid,
        Error::Unassessable {
            detail: "refused".to_owned(),
            source: None,
        },
    )
}

/// The call's answer once its wait has run: a call that failed answers as [`failure_after_wait`] says;
/// otherwise the wait's failure, if any, is the answer.
pub(crate) fn answer_after_wait(op: &str, answer: Result<(), Error>, waited: Result<(), Error>) -> Result<(), Error> {
    match answer {
        Ok(()) => waited,
        Err(failure) => Err(failure_after_wait(op, failure, waited)),
    }
}

/// A failed call's answer once its wait has run: a wait that ran out ([`Error::TimedOut`]) is the answer,
/// with `failure` below it; otherwise `failure` is the answer, over a wait that failed, whose error is
/// logged once, naming the call `op`.
pub(crate) fn failure_after_wait(op: &str, failure: Error, waited: Result<(), Error>) -> Error {
    match waited {
        Ok(()) => failure,
        Err(timed_out @ Error::TimedOut { .. }) => timed_out.with_peers([std::sync::Arc::new(failure)]),
        Err(waited) => {
            log_failed_wait(&format!("a failed {op}"), &waited);
            failure
        }
    }
}

/// Log the failed wait behind a failed answer, which stays the answer: the one place that policy's
/// log is written. `after` names the call that failed first. A wait that failed means a member's exit
/// was not seen, which the answer does not say, so it is a `warn`.
fn log_failed_wait(after: &str, waited: &Error) {
    log::warn!(
        "the wait after {after} also failed: {report}",
        report = crate::error::Report(waited)
    );
}

#[cfg(test)]
#[path = "tree_kill_tests.rs"]
mod tree_kill_tests;
