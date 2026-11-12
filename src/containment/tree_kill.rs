//! What a tree kill reached, and the wait for those members to exit ([`TreeKill`], [`KillWait`]).
//!
//! A kill names its members, and nothing is held for them past the send: [`KillWait`] holds their
//! identities, and re-opens each one by identity, one at a time, when it waits. A member whose open
//! finds nothing has exited. One that cannot be opened or looked at has not: its exit cannot be
//! observed, and the wait says so after it has waited for the rest.
//!
//! The Linux `Ticks` limit of the by-identity open applies (see [`Child::kill_tree`](crate::Child::kill_tree)).

use std::collections::HashSet;

use crate::containment::dispatch::TreeKillOutcome;
#[cfg(any(target_os = "linux", windows))]
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
    unobserved: Vec<Error>,
    /// The tree's own edge for "no member runs", chosen by the mechanism: only a kernel tree whose
    /// kill landed has one. It is the edge's wait with no deadline.
    edge: Option<EdgeWait<'a>>,
    /// What the wait does about the root.
    root: RootEnd<'a>,
    /// What the members are re-opened through.
    kernel: &'a dyn Kernel,
}

/// A tree's edge waited for with no deadline, and the verdict it comes to.
type EdgeWait<'a> = Box<dyn FnOnce() -> Result<TreeDrain, Error> + 'a>;

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
        self.wait.unobserved.push(why);
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
        unobserved: Vec<Error>,
        edge: DrainEdge<'a>,
    ) -> TreeKill<'a> {
        if !matches!(sent, TreeKillOutcome::Ran(Ok(()))) {
            for why in &unobserved {
                log::debug!(
                    "the kill failed, so a member the listing could not name is not waited for: {report}",
                    report = crate::error::Report(why)
                );
            }
            return TreeKill::of(sent);
        }
        let mut kill = TreeKill::of(sent).reaching(members);
        kill.wait.unobserved = unobserved;
        kill.wait.edge = Some(Box::new(move || edge.wait(None)));
        kill
    }

    /// The kill's wait ends on `edge`, a stated answer.
    #[cfg(test)]
    pub(crate) fn until(mut self, edge: impl FnOnce() -> Result<TreeDrain, Error> + 'a) -> TreeKill<'a> {
        self.wait.edge = Some(Box::new(edge));
        self
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
    /// Nothing to wait for.
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
    /// [`Error::Unassessable`] naming it, with the others in its note, once every other member has been
    /// waited for.
    pub(crate) fn wait(self) -> Result<(), Error> {
        let KillWait {
            members,
            mut unobserved,
            edge,
            root,
            kernel,
        } = self;
        let mut seen = HashSet::new();
        for id in members.into_iter().filter(|id| seen.insert(*id)) {
            if let Err(why) = wait_for_member(kernel, id) {
                unobserved.push(why);
            }
        }
        if let RootEnd::Waited(root) = root {
            if let Err(why) = wait_for_exit(root) {
                unobserved.push(Error::Unassessable {
                    detail: "the root was killed, but its exit cannot be observed".to_owned(),
                    source: Some(Box::new(why)),
                });
            }
        }
        if let Some(edge) = edge {
            if let Err(why) = edge().and_then(drained) {
                unobserved.push(why);
            }
        }
        let mut unobserved = unobserved.into_iter();
        let Some(first) = unobserved.next() else {
            return Ok(());
        };
        let others: Vec<String> = unobserved.map(|why| crate::error::Report(&why).to_string()).collect();
        Err(if others.is_empty() {
            first
        } else {
            first.with_note(&format!(
                "the exit of {} more could not be observed either: {}",
                others.len(),
                others.join("; ")
            ))
        })
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

/// Wait for the member `id` to exit: re-open it by its identity, wait on it, close it. One that cannot
/// be opened because it is gone has exited.
fn wait_for_member(kernel: &dyn Kernel, id: ProcessId) -> Result<(), Error> {
    let os = match crate::os_process::open_with(kernel, id) {
        Ok(Some(os)) => os,
        Ok(None) => return Ok(()),
        Err(failure) => return Err(exit_unobserved(id.pid(), failure.into_open_error())),
    };
    wait_for_exit(&*os).map_err(|why| exit_unobserved(id.pid(), why))
}

fn wait_for_exit(os: &dyn OsProcess) -> Result<(), Error> {
    let exited = crate::os_process::drive::exited_until(os, None)?;
    debug_assert!(exited, "a wait with no deadline ends only on an exit");
    Ok(())
}

pub(crate) fn exit_unobserved(pid: u32, cause: Error) -> Error {
    Error::Unassessable {
        detail: format!("pid {pid} was killed, but its exit cannot be observed"),
        source: Some(Box::new(cause)),
    }
}

/// The call's answer once its wait has run: a kill that failed is the answer, over a wait that failed
/// too (the wait's error is logged); otherwise a wait that failed is the failure, as `as_failure`
/// makes it.
pub(crate) fn answer_after_wait<F>(
    answer: Result<(), F>,
    waited: Result<(), Error>,
    as_failure: impl FnOnce(Error) -> F,
) -> Result<(), F> {
    match (answer, waited) {
        (Ok(()), waited) => waited.map_err(as_failure),
        (Err(failure), Ok(())) => Err(failure),
        (Err(failure), Err(waited)) => {
            log::debug!(
                "the wait after a failed kill_tree also failed: {report}",
                report = crate::error::Report(&waited)
            );
            Err(failure)
        }
    }
}

#[cfg(test)]
#[path = "tree_kill_tests.rs"]
mod tree_kill_tests;
