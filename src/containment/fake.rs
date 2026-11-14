//! A mechanism of stated answers, for the tests of what consumes a [`Tree`](crate::containment::Tree):
//! it names no process, and answers from what the test stated. It records only which sends it was
//! asked for, which is what a consumer's row reads.

use std::sync::{Arc, Mutex};

use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::containment::drain_edge::DrainEdge;
#[cfg(unix)]
use crate::containment::mechanism::Release;
use crate::containment::mechanism::{nothing_held, Contains, KillLeftOutcome};
#[cfg(unix)]
use crate::containment::tree_kill::refused_unobserved;
use crate::containment::treewalk::{Left, Listing};
use crate::containment::{Containment, Root, TerminateOutcome, TreeKill};
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
    sends: Sends,
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
            sends: sends.clone(),
        };
        (fake, sends)
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

    fn record(&self, send: &'static str) {
        self.sends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(send);
    }
}

impl Contains for FakeContains {
    /// A kill that leaves nothing running, and states the members it reached.
    fn kill(&self, _root: Option<&dyn Root>) -> TreeKill<'_> {
        self.record("kill");
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

    fn send_terminate(&self, _pid: u32, _root: Option<&dyn Root>) -> (TerminateOutcome, Option<Listing>) {
        self.record("terminate");
        let sent = TerminateOutcome::Sent {
            result: Ok(()),
            earlier: Some("the SIGTERM"),
        };
        (sent, None)
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
    fn would_reach(&self, _pid: u32, _pidfd: Option<std::os::fd::BorrowedFd<'_>>) -> std::io::Result<bool> {
        Ok(self.reaches)
    }

    #[cfg(unix)]
    fn reached(&self, _child: &crate::child::owned::OwnedChild) -> std::io::Result<bool> {
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
