//! The platform-neutral parts of the death-watched accepts, shared by `tests/common` and the lib's
//! `test_child` through `#[path]`: the ack, which event wins, and how a tree's drain wait ended.
#![allow(dead_code, reason = "each consumer uses only the parts its platform needs")]

use std::fmt::{Debug, Display};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

use super::ack;

/// Writes the ack to `stream`, which the caller has accepted and left in blocking mode.
pub fn ack_now(mut stream: TcpStream) -> TcpStream {
    ack::send_ack(&mut stream)
        .unwrap_or_else(|e| panic!("writing the accept acknowledgement to the control connection failed: {e}"));
    stream
}

/// Accepts the connection a wait reported ready and acks it.
pub fn accept_and_ack(listener: &TcpListener) -> TcpStream {
    let (stream, _) = listener.accept().expect("accept a control connection");
    ack_now(stream)
}

/// What a wait that saw both kinds of event reports.
#[derive(Debug, PartialEq, Eq)]
pub enum Ready {
    /// A watched process exited, or the tree drained.
    Exit,
    /// The source (a listener or a stream) is ready.
    Source,
}

/// An exit wins over a ready source, on every platform: both being ready means the target broke
/// the ack handshake, and either verdict then reports that misuse.
pub fn first_ready(exit: bool, source: bool) -> Option<Ready> {
    if exit {
        Some(Ready::Exit)
    } else if source {
        Some(Ready::Source)
    } else {
        None
    }
}

/// How a tree's drain wait ended, handed from the watcher thread to the acceptor: a wait that
/// FAILED must not be reported as the tree having drained.
#[derive(Default)]
pub struct DrainOutcome(Mutex<Option<Result<String, String>>>);

impl DrainOutcome {
    pub fn store<T: Debug, E: Display>(&self, result: Result<T, E>) {
        let outcome = result.map(|drain| format!("{drain:?}")).map_err(|e| e.to_string());
        *self.0.lock().expect("the drain outcome lock") = Some(outcome);
    }

    /// Panics with the stored outcome; `what` names the drained thing ("leaf", "tree").
    pub fn fail(&self, what: &str) -> ! {
        match self.0.lock().expect("the drain outcome lock").take() {
            Some(Ok(drain)) => panic!("the {what} drained ({drain}) before anything connected"),
            Some(Err(e)) => panic!("wait_tree failed while waiting for a connection: {e}"),
            None => unreachable!("the drain is signalled only after the outcome is stored"),
        }
    }
}

/// Runs `wait` (a `wait_tree`) on a watcher thread: stores its result, then calls `wake`. The
/// outcome is stored before `wake`, so an acceptor woken by it always finds one. A `wait` that
/// panics stores an `Err` and wakes too, so the acceptor fails instead of waiting forever.
pub fn run_watcher<T: Debug, E: Display>(
    outcome: &DrainOutcome,
    wake: impl FnOnce(),
    wait: impl FnOnce() -> Result<T, E>,
) {
    struct OnUnwind<'a, W: FnOnce()> {
        outcome: &'a DrainOutcome,
        wake: Option<W>,
    }
    impl<W: FnOnce()> Drop for OnUnwind<'_, W> {
        fn drop(&mut self) {
            if let Some(wake) = self.wake.take() {
                self.outcome
                    .store(Err::<(), _>("the watcher panicked before wait_tree returned"));
            }
        }
    }
    let mut guard = OnUnwind {
        outcome,
        wake: Some(wake),
    };
    let result = wait();
    outcome.store(result);
    (guard.wake.take().expect("the wake is called once"))();
}
