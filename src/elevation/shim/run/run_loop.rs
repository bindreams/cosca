//! The shim's loop: it polls, gathers what is ready into [`Events`], calls [`decide`] and performs
//! the returned [`Actions`].
//!
//! The loop's blocking calls are these, each commented where it is made:
//! - the single `poll` of each round;
//! - the reap after the shim's own SIGKILL ([`reap`] with `ready = false`);
//! - the wait for a host thread's reap, when a test hook installed one;
//! - the traced-zombie wait inside [`reap`].

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::io::Errno;
use rustix::net::{recv, RecvFlags};

use super::child::{died_before_exec, not_executed, signal};
use super::fds::wait_readable;
use super::log::Log;
use super::reap::{kill, reap};
use crate::child::spawn::fork_exec::{Failure, Progress, Status};
use crate::elevation::shim::protocol::NotExecuted;
use crate::elevation::shim::step::{decide, Actions, Control, Events, ExecEvent, LoopState};
use crate::os_process::linux::fork::NewChild;
use crate::resolve::Candidate;

/// What the loop ended with: the inputs of [`conclude`](crate::elevation::shim::step::conclude).
pub(super) struct Finished {
    pub(super) report: Option<NotExecuted>,
    pub(super) reaped: Option<i32>,
    pub(super) lost: bool,
    /// cosca's connection is still open, so the frame can be sent.
    pub(super) conn_open: bool,
}

pub(super) struct Loop<'a> {
    pub(super) log: &'a Log,
    pub(super) conn: BorrowedFd<'a>,
    pub(super) owner: BorrowedFd<'a>,
    pub(super) child: &'a NewChild,
    /// The candidates the child was to run: a stop in its walk of the later ones is worded from them.
    pub(super) candidates: &'a [Candidate],
    /// The read end of the pipe the signal handlers write to.
    pub(super) wake: BorrowedFd<'a>,
    /// The spawn core's status channel.
    pub(super) status: &'a mut Status,
    /// Test hook: becomes readable to fail supervision.
    pub(super) failure: Option<OwnedFd>,
    /// Test hook: a host thread's reap is complete once this is readable.
    pub(super) host_reap_done: Option<BorrowedFd<'a>>,
    pub(super) state: LoopState,
}

/// What reading the status channel gave.
enum Drained {
    Report(NotExecuted),
    /// The channel ended after the ready record: the `exec` closed it.
    Eof,
    /// The channel ended with no ready record: the child died inside its steps, and no `execve` ran.
    Died,
    Nothing,
}

/// Reads the status channel without blocking. A read that fails is logged, and the loop goes on: the
/// child's exit ends the wait for a report. A ready record is nothing yet: the report is a failure,
/// and the end is the `exec`, or the child's death before it.
fn drain_status(status: &mut Status, candidates: &[Candidate], log: &Log) -> Drained {
    drained(status.progress(), candidates, log)
}

/// What the loop makes of what the status channel said. The wire to cosca says a number for a stop in
/// the child's walk of the later candidates, as for an `exec` failure; the log line keeps the text the
/// spawn's error has for it (`candidates` hold the candidate and its `PATH` element).
fn drained(progress: std::io::Result<Progress>, candidates: &[Candidate], log: &Log) -> Drained {
    match progress {
        Ok(Progress::Failed(failure)) => match not_executed(failure) {
            Ok(report) => {
                if let Failure::Unexamined { errno, candidate } = failure {
                    let stop = crate::resolve::posix::walk_stop(candidates, candidate, errno);
                    log.line(format_args!("status pipe: {}", crate::error::Report(&stop)));
                }
                Drained::Report(report)
            }
            Err(e) => unreadable(&e, log),
        },
        Ok(Progress::Ended { ready: true }) => Drained::Eof,
        Ok(Progress::Ended { ready: false }) => Drained::Died,
        Ok(Progress::Pending | Progress::Ready) => Drained::Nothing,
        Err(e) => unreadable(&e, log),
    }
}

/// A status channel that said what it cannot say: logged, and nothing to act on.
fn unreadable(e: &std::io::Error, log: &Log) -> Drained {
    log.warn(format_args!("reading the status pipe: {}", crate::error::Report(e)));
    Drained::Nothing
}

/// Reads without blocking what cosca has sent, in order: the bytes, then `Eof` if the connection ended.
fn drain_control(conn: BorrowedFd<'_>, log: &Log) -> Vec<Control> {
    let mut controls = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match recv(conn, &mut byte[..], RecvFlags::DONTWAIT) {
            Ok((1, _)) => controls.push(Control::Byte(byte[0])),
            Ok((0, _)) => {
                controls.push(Control::Eof);
                return controls;
            }
            Ok((n, _)) => unreachable!("a one-byte recv returned {n}"),
            Err(Errno::INTR) => {}
            // Nothing more yet.
            Err(Errno::AGAIN) => return controls,
            // A reset is the connection ending.
            Err(Errno::CONNRESET) => {
                controls.push(Control::Eof);
                return controls;
            }
            // The connection is unusable, which ends it as well, but not silently.
            Err(e) => {
                log.warn(format_args!(
                    "recv from cosca: errno {} ({})",
                    e.raw_os_error(),
                    crate::error::Report(&e)
                ));
                debug_assert!(
                    !matches!(e, Errno::BADF | Errno::INVAL),
                    "recv on the shim's own connection: {}",
                    crate::error::Report(&e)
                );
                controls.push(Control::Eof);
                return controls;
            }
        }
    }
}

impl Loop<'_> {
    pub(super) fn run(mut self) -> Finished {
        let mut report = None;
        let (reaped, lost) = loop {
            let mut events = Events::NONE;
            let st = self.state;
            // The loop's single blocking call.
            let polled = wait_readable([
                Some(self.wake),
                Some(self.child.pidfd.as_fd()),
                st.conn_open.then_some(self.conn),
                st.owner_watched.then_some(self.owner),
                self.failure.as_ref().map(|f| f.as_fd()),
                st.exec_pending.then(|| self.status.as_fd()),
            ]);
            let [_, child_ready, _, owner_ready, failure_ready, status_ready] = match polled {
                Ok(ready) => ready,
                Err(e) => {
                    self.log.warn(format_args!("poll failed: {}", crate::error::Report(&e)));
                    break self.kill_and_reap();
                }
            };
            events.signaled = self.drain_wake();
            events.child_exited = child_ready;
            events.owner_exited = owner_ready;
            events.forced_failure = failure_ready;
            if status_ready || (events.child_exited && st.exec_pending) {
                match drain_status(self.status, self.candidates, self.log) {
                    Drained::Report(r) => {
                        events.exec = ExecEvent::Report;
                        self.log.line(format_args!("status pipe: report {r:?}"));
                        report = Some(r);
                    }
                    Drained::Eof => {
                        events.exec = ExecEvent::Eof;
                        self.log.line(format_args!("status pipe: EOF"));
                    }
                    Drained::Died => {
                        // The report is made after the reap, which names how the child died.
                        events.exec = ExecEvent::Eof;
                        self.log
                            .line(format_args!("status pipe: ended before the ready record"));
                    }
                    Drained::Nothing => {}
                }
            }
            // Every byte cosca has sent, in order, before the owner's exit or the connection's end: the
            // poll's snapshot can have the owner's exit without the bytes that preceded it.
            let mut controls = if st.conn_open {
                drain_control(self.conn, self.log)
            } else {
                Vec::new()
            };
            let last = controls.pop().unwrap_or(Control::Nothing);
            for control in controls {
                let earlier = Events {
                    control,
                    ..Events::NONE
                };
                let actions = decide(&mut self.state, &earlier);
                self.perform(&earlier, &actions);
            }
            events.control = last;
            let actions = decide(&mut self.state, &events);
            if actions.lost {
                self.log.line(format_args!("seam: supervision forced to fail"));
                break self.kill_and_reap();
            }
            self.perform(&events, &actions);
            if actions.reap {
                if let Some(done) = self.host_reap_done {
                    // Blocks until the host thread's reap is done: the child is exiting, so it ends.
                    if let Err(e) = wait_readable([Some(done)]) {
                        self.log.warn(format_args!(
                            "waiting for the host thread's reap: {}",
                            crate::error::Report(&e)
                        ));
                    }
                }
                let status = reap(self.child, true, self.log);
                self.log.line(format_args!("reaped status {status:?}"));
                break (status, false);
            }
        };
        if report.is_none() {
            // A report already written is positive evidence, whatever the reap gave. So is a channel
            // that ended with no ready record: no `execve` ran, and the reap says how the child died.
            match drain_status(self.status, self.candidates, self.log) {
                Drained::Report(r) => report = Some(r),
                Drained::Died => report = Some(died_before_exec(reaped)),
                Drained::Eof | Drained::Nothing => {}
            }
        }
        Finished {
            report,
            reaped,
            lost,
            conn_open: self.state.conn_open,
        }
    }

    /// Logs a step's events and sends its signal.
    fn perform(&self, events: &Events, actions: &Actions) {
        self.log_events(events, actions);
        if let Some(to) = actions.signal {
            let sent = signal(self.child, to);
            self.log.line(format_args!("control: signal {to:?} rc={sent:?}"));
        }
    }

    /// Supervision failed: kill the child through its handle, reap it, and say so.
    fn kill_and_reap(&self) -> (Option<i32>, bool) {
        kill(self.child, self.log);
        // The child dies of the SIGKILL just sent; this blocks until it has.
        (reap(self.child, false, self.log), true)
    }

    /// Reads the signal numbers the handlers wrote; whether there were any.
    fn drain_wake(&self) -> bool {
        let mut any = false;
        let mut buf = [0u8; 32];
        loop {
            match rustix::io::read(self.wake, &mut buf) {
                Ok(0) | Err(Errno::AGAIN) => return any,
                Ok(n) => {
                    any = true;
                    for signal in &buf[..n] {
                        self.log.line(format_args!("shim received signal {signal}"));
                    }
                }
                Err(Errno::INTR) => {}
                Err(e) => {
                    self.log.warn(format_args!(
                        "reading the signal pipe: errno {} ({})",
                        e.raw_os_error(),
                        crate::error::Report(&e)
                    ));
                    return any;
                }
            }
        }
    }

    fn log_events(&self, events: &Events, actions: &Actions) {
        if actions.violation {
            let Control::Byte(b) = events.control else {
                unreachable!("a violation is a byte")
            };
            self.log.line(format_args!(
                "protocol violation: byte {b:#04x} from cosca; the program is killed"
            ));
        }
        if actions.pong {
            self.log.line(format_args!("pong"));
        }
        match events.control {
            Control::Byte(b'D') => self.log.line(format_args!("disarmed")),
            Control::Eof => self.log.line(format_args!("EOF (armed={})", self.state.armed)),
            _ => {}
        }
        if events.owner_exited {
            self.log.line(format_args!("owner exited (armed={})", self.state.armed));
        }
    }
}

#[cfg(test)]
#[path = "run_loop_tests.rs"]
mod run_loop_tests;
