//! A mechanism of stated answers, for the tests of what consumes a [`Tree`](crate::containment::Tree):
//! it names no process, and answers from what the test stated. It records only which sends it was
//! asked for, which is what a consumer's row reads.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::containment::drain_edge::DrainEdge;
#[cfg(windows)]
use crate::containment::mechanism::Members;
#[cfg(unix)]
use crate::containment::mechanism::Release;
use crate::containment::mechanism::{nothing_held, Contains, KillLeftOutcome};
#[cfg(unix)]
use crate::containment::tree_kill::refused_unobserved;
use crate::containment::treewalk::{Left, Listing};
use crate::containment::{Containment, Root, TerminateOutcome, TreeKill, TreeStop};
use crate::identity::ProcessId;

/// The sends a [`FakeContains`] was asked for, in order: `"kill"`, `"terminate"`, `"disarm"` and
/// `"release"`.
pub(crate) type Sends = Arc<Mutex<Vec<&'static str>>>;

/// The answers of a mechanism that names a tree no process is in.
#[derive(Debug)]
pub(crate) struct FakeContains {
    kind: Containment,
    /// Whether a kill through it reaches the child asked about ([`Contains::would_reach`]).
    #[cfg_attr(windows, allow(dead_code, reason = "only Unix asks whether a kill reaches"))]
    reaches: bool,
    /// The members its kill states it reached, for the wait over them.
    killed: Vec<ProcessId>,
    /// The members its settlement states it killed again, for the wait over them.
    killed_again: Vec<ProcessId>,
    /// The pids its kill states it reached but whose exit cannot be observed, which fail the wait.
    #[cfg(unix)]
    unobserved: Vec<u32>,
    /// Whether its kill states that its walk was not made.
    unwalked: bool,
    /// Windows: the members it states it names, and what it states it could not name or list
    /// ([`Contains::member_ids`]).
    #[cfg(windows)]
    members: StatedMembers,
    /// What each [`send_kill`](Contains::send_kill) answers, in order, once; a send past them is the
    /// kill that leaves nothing running.
    kill_answers: Mutex<VecDeque<TreeKillOutcome>>,
    /// What each [`send_terminate`](Contains::send_terminate) answers, in order, once; a send past them
    /// is, on Windows, the answer of the stop it is given, as a job states it, and on Unix the signal that
    /// went out and found nothing wrong.
    terminate_answers: Mutex<VecDeque<TerminateOutcome>>,
    sends: Sends,
}

/// The members a [`FakeContains`] states it names, the ones it states it cannot name, and a listing it
/// states it cannot make.
#[cfg(windows)]
#[derive(Debug, Default)]
struct StatedMembers {
    named: Vec<ProcessId>,
    /// The detail of each member it could not name.
    unnamed: Vec<String>,
    /// The detail of a listing it cannot make.
    unlistable: Option<String>,
}

impl FakeContains {
    /// A mechanism that reports `kind`, and whose kill reaches the child asked about if `reaches`,
    /// with the sends it was asked for.
    pub(crate) fn new(kind: Containment, reaches: bool) -> (FakeContains, Sends) {
        let sends = Sends::default();
        let fake = FakeContains {
            kind,
            reaches,
            killed: Vec::new(),
            killed_again: Vec::new(),
            #[cfg(unix)]
            unobserved: Vec::new(),
            unwalked: false,
            #[cfg(windows)]
            members: StatedMembers::default(),
            kill_answers: Mutex::default(),
            terminate_answers: Mutex::default(),
            sends: sends.clone(),
        };
        (fake, sends)
    }

    /// A mechanism whose successive [`send_kill`](Contains::send_kill)s answer `outcomes`, as a tree
    /// whose sweeps went one way or another.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only a macOS row states what each sweep of a tree answered")
    )]
    pub(crate) fn answering_kills(self, outcomes: impl IntoIterator<Item = TreeKillOutcome>) -> FakeContains {
        *self
            .kill_answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = outcomes.into_iter().collect();
        self
    }

    /// A mechanism whose successive [`send_terminate`](Contains::send_terminate)s answer `outcomes`, as
    /// a tree whose cooperative route went one way or another (a skipped root, say).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only a Linux row states what the cooperative route answered")
    )]
    pub(crate) fn answering_terminates(self, outcomes: impl IntoIterator<Item = TerminateOutcome>) -> FakeContains {
        *self
            .terminate_answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = outcomes.into_iter().collect();
        self
    }

    /// A mechanism whose settlement states that it killed `members` again, as a tree walk does for
    /// the members an earlier kill left.
    pub(crate) fn killing_again(mut self, members: impl IntoIterator<Item = ProcessId>) -> FakeContains {
        self.killed_again = members.into_iter().collect();
        self
    }

    /// A mechanism whose kill states that it reached `members`: it kills none of them, so a wait over
    /// them ends when the test ends them.
    pub(crate) fn reaching(mut self, members: impl IntoIterator<Item = ProcessId>) -> FakeContains {
        self.killed = members.into_iter().collect();
        self
    }

    /// A mechanism whose kill states that it reached `pid`, whose exit cannot be observed: the wait
    /// over that kill fails.
    #[cfg(unix)]
    pub(crate) fn reaching_unobserved(mut self, pid: u32) -> FakeContains {
        self.unobserved.push(pid);
        self
    }

    /// A mechanism whose kill states that its walk was not made ([`TreeKillOutcome::Unwalked`]).
    #[cfg_attr(windows, allow(dead_code, reason = "only a Unix row states an unwalked walk"))]
    pub(crate) fn unwalked(mut self) -> FakeContains {
        self.unwalked = true;
        self
    }

    /// Windows: a mechanism that states it names `members`.
    #[cfg(windows)]
    pub(crate) fn naming(mut self, members: impl IntoIterator<Item = ProcessId>) -> FakeContains {
        self.members.named = members.into_iter().collect();
        self
    }

    /// Windows: a mechanism that states it could not name a member, for `detail`: one more of the members
    /// it lists.
    #[cfg(windows)]
    pub(crate) fn unable_to_name(mut self, detail: &str) -> FakeContains {
        self.members.unnamed.push(detail.to_owned());
        self
    }

    /// Windows: a mechanism that states its listing cannot be made, for `detail`.
    #[cfg(windows)]
    pub(crate) fn unable_to_list(mut self, detail: &str) -> FakeContains {
        self.members.unlistable = Some(detail.to_owned());
        self
    }

    fn record(&self, send: &'static str) {
        self.sends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(send);
    }
}

impl Contains for FakeContains {
    /// The next answer [`answering_kills`](FakeContains::answering_kills) stated, else the kill that
    /// [`kill`](Self::kill) is.
    fn send_kill(&self, root: Option<&dyn Root>) -> TreeKillOutcome {
        let stated = self
            .kill_answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front();
        match stated {
            Some(answer) => {
                self.record("kill");
                answer
            }
            None => self.kill(root).outcome(),
        }
    }

    /// A kill that leaves nothing running, and states the members it reached.
    fn kill(&self, _root: Option<&dyn Root>) -> TreeKill<'_> {
        self.record("kill");
        if self.unwalked {
            let error = crate::error::Error::Unassessable {
                detail: "the process table could not be read".into(),
                source: None,
            };
            return TreeKill::of(TreeKillOutcome::Unwalked(error));
        }
        let kill = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching(self.killed.iter().copied());
        #[cfg(unix)]
        let kill = self
            .unobserved
            .iter()
            .fold(kill, |kill, &pid| kill.unobserved(refused_unobserved(pid)));
        kill
    }

    fn kill_left(&self, result: Result<(), Unkilled>, _left: Vec<Left>) -> KillLeftOutcome {
        KillLeftOutcome {
            killed: self.killed_again.clone(),
            ..nothing_held(result)
        }
    }

    fn send_terminate(
        &self,
        _pid: u32,
        _root: Option<&dyn Root>,
        how: TreeStop,
    ) -> (TerminateOutcome, Option<Listing>) {
        self.record("terminate");
        let stated = self
            .terminate_answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front();
        let sent = stated.unwrap_or_else(|| {
            let earlier = Some(how.earlier());
            #[cfg(windows)]
            return TerminateOutcome::of(how.into_sent(), earlier);
            // Unix: a `TreeStop` carries no answer of its own, so the signal went out.
            #[cfg(unix)]
            TerminateOutcome::Sent {
                result: Ok(()),
                earlier,
            }
        });
        (sent, None)
    }

    /// What it states it names ([`naming`](FakeContains::naming), [`unable_to_name`](FakeContains::unable_to_name),
    /// [`unable_to_list`](FakeContains::unable_to_list)).
    #[cfg(windows)]
    fn member_ids(&self) -> Result<Members, crate::error::Error> {
        let unassessable = |detail: &String| crate::error::Error::Unassessable {
            detail: detail.clone(),
            source: None,
        };
        match &self.members.unlistable {
            Some(detail) => Err(unassessable(detail)),
            None => Ok(Members {
                named: self.members.named.clone(),
                unnamed: self.members.unnamed.iter().map(unassessable).collect(),
            }),
        }
    }

    /// It has no drain edge.
    fn drain_edge(&self) -> Option<DrainEdge<'_>> {
        None
    }

    fn kind(&self) -> Containment {
        self.kind
    }

    fn disarm(&self) -> std::io::Result<()> {
        self.record("disarm");
        Ok(())
    }

    #[cfg(unix)]
    fn subject(&self) -> String {
        format!("{:?}", self.kind)
    }

    #[cfg(unix)]
    fn would_reach(&self, _pid: u32, _pidfd: Option<std::os::fd::BorrowedFd<'_>>) -> Result<bool, crate::error::Error> {
        Ok(self.reaches)
    }

    #[cfg(unix)]
    fn reached(&self, _child: &crate::child::owned::OwnedChild) -> Result<bool, crate::error::Error> {
        Ok(self.reaches)
    }

    #[cfg(unix)]
    fn release(self) -> (Release, Option<FakeContains>) {
        self.record("release");
        (Release::nothing(), Some(self))
    }

    #[cfg(all(feature = "tokio", target_os = "linux"))]
    fn awaitable_release(&self) -> Option<crate::containment::mechanism::AwaitableRelease<'_>> {
        None
    }
}
