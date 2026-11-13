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
use crate::identity::{HostKernel, Kernel, ProcessId};
use crate::os_process::OsProcess;

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
    /// kill landed has one. It is waited for with no deadline.
    edge: Option<DrainEdge<'a>>,
    root: RootEnd<'a>,
    kernel: &'a dyn Kernel,
}

/// A member a kill's send reached but whose identity could not be had (or a listing that failed
/// whole), so its exit cannot be observed. `why` says so; `pid` names the member where the listing
/// had one, so a later wait that meets the same member does not report it again ([`Settled`]). Only
/// a Job's edge reads the pid, so it is kept on Windows, and on Linux in tests.
#[derive(Debug)]
pub(crate) struct Unnamed {
    #[cfg(any(windows, all(test, target_os = "linux")))]
    pid: Option<u32>,
    why: Error,
}

impl Unnamed {
    /// The member `pid`, whose identity could not be had for `cause`.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn member(pid: u32, cause: Error) -> Unnamed {
        Unnamed {
            #[cfg(any(windows, all(test, target_os = "linux")))]
            pid: Some(pid),
            why: exit_unobserved(pid, cause),
        }
    }

    /// A member, or a listing, with no pid to name: `why` is the whole error.
    #[cfg(any(target_os = "linux", windows, test))]
    pub(crate) fn nameless(why: Error) -> Unnamed {
        Unnamed {
            #[cfg(any(windows, all(test, target_os = "linux")))]
            pid: None,
            why,
        }
    }

    /// The pid of the member, for a row that states which one the listing named.
    #[cfg(all(test, any(windows, target_os = "linux")))]
    pub(crate) fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// The error saying the member's exit cannot be observed, for a row that states its words.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn why(&self) -> &Error {
        &self.why
    }
}

/// What a kill's wait has settled when it waits on the tree's edge, which neither waits for nor reports
/// it again. Only a Job's edge reads it, so it is kept on Windows alone.
///
/// A snapshot entry with a readable identity is settled iff that identity is one of the `members`,
/// each of which the wait saw exit or reported (the root too, when its handle reads an identity). An
/// entry whose identity cannot be read is settled iff its pid is one of the `reported`: the pid of a
/// member or the root whose wait failed, or of one the listing could not name. The pid of a member whose exit was seen is never matched: an exited process is not
/// in a snapshot, so that pid names another process.
#[derive(Default)]
pub(crate) struct Settled {
    #[cfg(windows)]
    members: Vec<ProcessId>,
    #[cfg(windows)]
    reported: Vec<u32>,
}

#[cfg(windows)]
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
    /// Its kill landed, and it is waited for through its owner's handle.
    Waited(&'a dyn OsProcess),
}

impl<'a> TreeKill<'a> {
    /// A kill that did `outcome`, which reached no member yet. Members are re-opened through the
    /// host's kernel unless [`through`](Self::through) says otherwise.
    pub(crate) fn of(outcome: impl Into<TreeKillOutcome>) -> TreeKill<'a> {
        TreeKill {
            outcome: outcome.into(),
            wait: KillWait::none(),
        }
    }

    /// Re-open the members through `kernel`.
    pub(crate) fn through(mut self, kernel: &'a dyn Kernel) -> TreeKill<'a> {
        self.wait.kernel = kernel;
        self
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
    ) -> TreeKill<'a> {
        if !matches!(sent, TreeKillOutcome::Ran(Ok(()))) {
            for unnamed in &unobserved {
                log::debug!(
                    "the kill failed, so a member the listing could not name is not waited for: {report}",
                    report = crate::error::Report(&unnamed.why)
                );
            }
            return TreeKill::of(sent);
        }
        let mut kill = TreeKill::of(sent).reaching(members);
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
    pub(crate) fn none() -> KillWait<'a> {
        KillWait {
            members: Vec::new(),
            unobserved: Vec::new(),
            edge: None,
            root: RootEnd::NotKilled,
            kernel: &HostKernel,
        }
    }

    /// Members a later kill of the tree reached (a walk's held members, killed again by the
    /// settlement).
    pub(crate) fn reaching(&mut self, members: impl IntoIterator<Item = ProcessId>) {
        self.members.extend(members);
    }

    /// The members the kill reached, for a row that states what a mechanism named.
    #[cfg(all(test, any(windows, target_os = "linux")))]
    pub(crate) fn members_for_test(&self) -> &[ProcessId] {
        &self.members
    }

    /// Whether the mechanism's kill ended the root ([`TreeKill::root_killed`]).
    pub(crate) fn root_killed(&self) -> bool {
        matches!(self.root, RootEnd::Killed)
    }

    /// Whether the wait is for the root too: its kill landed, so it is dead whatever the wait finds.
    pub(crate) fn waits_for_root(&self) -> bool {
        matches!(self.root, RootEnd::Waited(_))
    }

    /// Wait for the root through its owner's handle if `landed`, whether its kill landed. A kill that
    /// did not land leaves what the mechanism recorded ([`TreeKill::root_killed`]) as it is.
    pub(crate) fn with_root(mut self, root: &'a dyn OsProcess, landed: bool) -> KillWait<'a> {
        if landed {
            self.root = RootEnd::Waited(root);
        }
        self
    }

    /// Wait until every member reached has exited, then the root, then the tree's own edge. There is
    /// no deadline.
    ///
    /// # Errors
    ///
    /// The first member whose exit could not be observed (a failed open or look is not an exit), as
    /// [`Error::Unassessable`] naming it, with the others whole below it ([`Error::with_peers`]), once
    /// every other member has been waited for.
    pub(crate) fn wait(self) -> Result<(), Error> {
        let KillWait {
            members,
            unobserved: unnamed,
            edge,
            root,
            kernel,
        } = self;
        #[cfg_attr(
            not(windows),
            allow(unused_mut, reason = "only a Job's edge reads the root's settlement")
        )]
        let mut members: Vec<ProcessId> = once_each(members).collect();
        #[cfg(windows)]
        let mut reported = reported_pids(&unnamed);
        let mut unobserved: Vec<Error> = unnamed.into_iter().map(|unnamed| unnamed.why).collect();
        for &id in &members {
            if let Err(why) = wait_for_member(kernel, id, None).and_then(exit_seen) {
                #[cfg(windows)]
                reported.push(id.pid());
                unobserved.push(exit_unobserved(id.pid(), why));
            }
        }
        if let RootEnd::Waited(root) = root {
            let waited = wait_for_exit(root);
            #[cfg(windows)]
            settle_root(root, waited.is_err(), &mut members, &mut reported);
            if let Err(why) = waited {
                unobserved.push(root_unobserved(why));
            }
        }
        if let Some(edge) = edge {
            // Every member reached is settled: it exited or was reported above, once.
            #[cfg(windows)]
            let settled = Settled::new(members, reported);
            #[cfg(not(windows))]
            let settled = Settled::default();
            if let Err(why) = edge.wait_past(None, &settled).and_then(drained) {
                unobserved.push(why);
            }
        }
        answer_of(unobserved)
    }

    /// [`wait`](Self::wait), awaited: the same members in the same order, with no runtime thread
    /// blocked, and the same answer. Dropping the future stops the wait only; the kill was sent
    /// before it.
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_async(self) -> Result<(), Error> {
        let KillWait {
            members,
            unobserved: unnamed,
            edge,
            root,
            kernel,
        } = self;
        #[cfg_attr(
            not(windows),
            allow(unused_mut, reason = "only a Job's edge reads the root's settlement")
        )]
        let mut members: Vec<ProcessId> = once_each(members).collect();
        #[cfg(windows)]
        let mut reported = reported_pids(&unnamed);
        let mut unobserved: Vec<Error> = unnamed.into_iter().map(|unnamed| unnamed.why).collect();
        for &id in &members {
            if let Err(why) = wait_for_member_async(kernel, id, None).await.and_then(exit_seen) {
                #[cfg(windows)]
                reported.push(id.pid());
                unobserved.push(exit_unobserved(id.pid(), why));
            }
        }
        if let RootEnd::Waited(root) = root {
            let waited = wait_for_exit_async(root).await;
            #[cfg(windows)]
            settle_root(root, waited.is_err(), &mut members, &mut reported);
            if let Err(why) = waited {
                unobserved.push(root_unobserved(why));
            }
        }
        if let Some(edge) = edge {
            #[cfg(windows)]
            let settled = Settled::new(members, reported);
            #[cfg(not(windows))]
            let settled = Settled::default();
            if let Err(why) = edge.wait_async_past(None, &settled).await.and_then(drained) {
                unobserved.push(why);
            }
        }
        answer_of(unobserved)
    }
}

/// The pids of the members a listing could not name: the first of a wait's `reported`
/// ([`Settled`]), on Windows alone, where an edge reads them.
#[cfg(windows)]
fn reported_pids(unnamed: &[Unnamed]) -> Vec<u32> {
    unnamed.iter().filter_map(|unnamed| unnamed.pid).collect()
}

/// Settle the root, once its wait ended: its identity, if its handle can read one, is a settled member
/// (it is matched by identity alone, never by its pid), and its pid is `reported` when the wait `failed`,
/// so a snapshot entry for the root whose identity cannot be read is not named again. A handle that
/// names no process (a fake's) settles nothing.
#[cfg(windows)]
fn settle_root(root: &dyn OsProcess, failed: bool, members: &mut Vec<ProcessId>, reported: &mut Vec<u32>) {
    use std::os::windows::io::AsRawHandle as _;

    let raw = windows::Win32::Foundation::HANDLE(root.os_handle().as_raw_handle());
    let Ok(pid) = crate::containment::windows::process_pid_of(raw) else {
        return;
    };
    if failed {
        reported.push(pid);
    }
    if let Ok(id) = crate::identity::windows_identity_from_handle_result(raw, pid) {
        members.push(id);
    }
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

/// What a wait with no deadline comes to: it ends only on an exit, so `exited` is `true`.
fn exit_seen(exited: bool) -> Result<(), Error> {
    debug_assert!(exited, "a wait with no deadline ends only on an exit");
    Ok(())
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

fn wait_for_exit(os: &dyn OsProcess) -> Result<(), Error> {
    crate::os_process::drive::exited_until(os, None).and_then(exit_seen)
}

#[cfg(feature = "tokio")]
async fn wait_for_exit_async(os: &dyn OsProcess) -> Result<(), Error> {
    crate::tokio::drive::exited_held(os, None).await.and_then(exit_seen)
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

/// The call's answer once its wait has run: a kill that failed is the answer, over a wait that failed
/// too (the wait's error is logged, once, naming the call `op`); otherwise a wait that failed is the
/// failure, as `as_failure` makes it.
pub(crate) fn answer_after_wait<F>(
    op: &str,
    answer: Result<(), F>,
    waited: Result<(), Error>,
    as_failure: impl FnOnce(Error) -> F,
) -> Result<(), F> {
    match (answer, waited) {
        (Ok(()), waited) => waited.map_err(as_failure),
        (Err(failure), Ok(())) => Err(failure),
        (Err(failure), Err(waited)) => {
            log_failed_wait(&format!("a failed {op}"), &waited);
            Err(failure)
        }
    }
}

/// Log the failed wait behind a failed answer, which stays the answer: the one place that policy's
/// log is written. `after` names the call that failed first. A wait that failed means a member's exit
/// was not seen, which the answer does not say, so it is a `warn`.
pub(crate) fn log_failed_wait(after: &str, waited: &Error) {
    log::warn!(
        "the wait after {after} also failed: {report}",
        report = crate::error::Report(waited)
    );
}

#[cfg(test)]
#[path = "tree_kill_tests.rs"]
mod tree_kill_tests;
