//! A mechanism of stated answers, for the tests of what consumes a [`Tree`](crate::containment::Tree):
//! it names no process, and answers from what the test stated. It records only which signals it was
//! asked to send, which is what a consumer's row reads.

use std::sync::{Arc, Mutex};

use crate::containment::dispatch::TreeKillOutcome;
use crate::containment::drain_edge::DrainEdge;
use crate::containment::mechanism::Contains;
#[cfg(unix)]
use crate::containment::mechanism::Release;
use crate::containment::{Containment, Root, TerminateOutcome};

/// The sends a [`FakeContains`] was asked for, in order: `"kill"` and `"terminate"`.
pub(crate) type Sends = Arc<Mutex<Vec<&'static str>>>;

/// The answers of a mechanism that names a tree no process is in.
#[derive(Debug)]
pub(crate) struct FakeContains {
    kind: Containment,
    /// Whether a kill through it reaches the child asked about ([`Contains::would_reach`]).
    #[cfg_attr(windows, allow(dead_code, reason = "only Unix asks whether a kill reaches"))]
    reaches: bool,
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
            sends: sends.clone(),
        };
        (fake, sends)
    }

    fn record(&self, send: &'static str) {
        self.sends
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(send);
    }
}

impl Contains for FakeContains {
    /// A kill that leaves nothing running.
    fn send_kill(&self, _root: Option<&dyn Root>) -> TreeKillOutcome {
        self.record("kill");
        TreeKillOutcome::Ran(Ok(()))
    }

    fn send_terminate(&self, _pid: u32, _root: Option<&dyn Root>) -> TerminateOutcome {
        self.record("terminate");
        TerminateOutcome::Sent {
            result: Ok(()),
            earlier: Some("the SIGTERM"),
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
        Ok(())
    }

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
    fn release(self) -> Release {
        Release::nothing()
    }
}
