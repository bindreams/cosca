//! The shim's loop (plan F, D3): it polls, gathers what is ready into [`Events`], calls
//! [`decide`] and performs the returned [`Actions`]. It reviews by inspection.
//!
//! The loop's blocking calls are these, each commented where it is made:
//! - the single `poll` of each round;
//! - the reap after the shim's own SIGKILL ([`Spawned::reap`] with `ready = false`);
//! - the wait for a host thread's reap, when a test hook installed one;
//! - the traced-zombie wait inside [`Spawned::reap`].

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use super::child::{decode_report, Spawned};
use super::log::Log;
use crate::elevation::shim::protocol::NotExecuted;
use crate::elevation::shim::step::{decide, Actions, Control, Events, ExecEvent, LoopState, ToChild};

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
    pub(super) child: &'a Spawned,
    /// The read end of the pipe the signal handlers write to.
    pub(super) wake: BorrowedFd<'a>,
    /// The read end of the status pipe.
    pub(super) status: BorrowedFd<'a>,
    /// Test hook: becomes readable to fail supervision.
    pub(super) failure: Option<OwnedFd>,
    /// Test hook: a host thread's reap is complete once this is readable.
    pub(super) host_reap_done: Option<BorrowedFd<'a>>,
    pub(super) state: LoopState,
}

/// What reading the status pipe gave.
enum Status {
    Report(NotExecuted),
    Eof,
    Nothing,
}

fn drain_status(fd: RawFd) -> Status {
    let mut value = [0u8; 4];
    loop {
        // SAFETY: `value` is valid for 4 bytes.
        let n = unsafe { libc::read(fd, value.as_mut_ptr().cast(), value.len()) };
        return match n {
            4 => Status::Report(decode_report(i32::from_le_bytes(value))),
            0 => Status::Eof,
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => continue,
            // `EAGAIN`: the child has not exec'd yet.
            _ => Status::Nothing,
        };
    }
}

fn ready(p: &libc::pollfd) -> bool {
    p.revents != 0
}

impl Loop<'_> {
    pub(super) fn run(mut self) -> Finished {
        let mut report = None;
        let (reaped, lost) = loop {
            let mut events = Events::NONE;
            let failure_fd = self.failure.as_ref().map_or(-1, |f| f.as_raw_fd());
            let st = self.state;
            let mut polled = [
                pollfd(self.wake.as_raw_fd()),
                pollfd(self.child.pidfd.as_raw_fd()),
                pollfd(if st.conn_open { self.conn.as_raw_fd() } else { -1 }),
                pollfd(if st.owner_watched { self.owner.as_raw_fd() } else { -1 }),
                pollfd(failure_fd),
                pollfd(if st.exec_pending { self.status.as_raw_fd() } else { -1 }),
            ];
            // The loop's single blocking call.
            // SAFETY: `polled` is valid for its length.
            if unsafe { libc::poll(polled.as_mut_ptr(), polled.len() as _, -1) } < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                self.log
                    .line(format_args!("poll failed: {}", std::io::Error::last_os_error()));
                break self.kill_and_reap();
            }
            events.signaled = self.drain_wake();
            events.child_exited = ready(&polled[1]);
            events.owner_exited = st.owner_watched && ready(&polled[3]);
            events.forced_failure = failure_fd >= 0 && ready(&polled[4]);
            let status_ready = st.exec_pending && ready(&polled[5]);
            if status_ready || (events.child_exited && st.exec_pending) {
                match drain_status(self.status.as_raw_fd()) {
                    Status::Report(r) => {
                        events.exec = ExecEvent::Report;
                        self.log.line(format_args!("status pipe: report {r:?}"));
                        report = Some(r);
                    }
                    Status::Eof => {
                        events.exec = ExecEvent::Eof;
                        self.log.line(format_args!("status pipe: EOF"));
                    }
                    Status::Nothing => {}
                }
            }
            // Every byte cosca has sent, in order, before the owner's exit or the connection's end: the
            // poll's snapshot can have the owner's exit without the bytes that preceded it.
            let mut controls = if st.conn_open { self.drain_control() } else { Vec::new() };
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
                    wait_readable(done.as_raw_fd());
                }
                let status = self.child.reap(true, self.log);
                self.log.line(format_args!("reaped status {status:?}"));
                break (status, false);
            }
        };
        if report.is_none() {
            // A report already written is positive evidence, whatever the reap gave.
            if let Status::Report(r) = drain_status(self.status.as_raw_fd()) {
                report = Some(r);
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
            let sent = self.child.signal(to);
            self.log.line(format_args!("control: signal {to:?} rc={sent:?}"));
        }
    }

    /// Supervision failed: kill the child through its handle, reap it, and say so.
    fn kill_and_reap(&self) -> (Option<i32>, bool) {
        _ = self.child.signal(ToChild::Kill);
        // The child dies of the SIGKILL just sent; this blocks until it has.
        (self.child.reap(false, self.log), true)
    }

    /// Reads the signal numbers the handlers wrote; whether there were any.
    fn drain_wake(&self) -> bool {
        let mut any = false;
        let mut buf = [0u8; 32];
        loop {
            // SAFETY: `buf` is valid for its length.
            let n = unsafe { libc::read(self.wake.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return any;
            }
            any = true;
            for signal in &buf[..n as usize] {
                self.log.line(format_args!("shim received signal {signal}"));
            }
        }
    }

    /// Reads without blocking what cosca has sent, in order: the bytes, then `Eof` if the connection ended.
    fn drain_control(&self) -> Vec<Control> {
        let mut controls = Vec::new();
        loop {
            let mut byte = 0u8;
            // SAFETY: `byte` is valid for 1 byte.
            let n = unsafe {
                libc::recv(
                    self.conn.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_DONTWAIT,
                )
            };
            match n {
                1 => controls.push(Control::Byte(byte)),
                0 => {
                    controls.push(Control::Eof);
                    return controls;
                }
                _ => match std::io::Error::last_os_error().kind() {
                    std::io::ErrorKind::Interrupted => {}
                    // Nothing more yet.
                    std::io::ErrorKind::WouldBlock => return controls,
                    // A reset is the connection ending.
                    _ => {
                        controls.push(Control::Eof);
                        return controls;
                    }
                },
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

fn pollfd(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Blocks until `fd` is readable. A deliberate blocking call, see the module doc.
fn wait_readable(fd: RawFd) {
    let mut p = [pollfd(fd)];
    loop {
        // SAFETY: `p` is valid for its length.
        let r = unsafe { libc::poll(p.as_mut_ptr(), 1, -1) };
        if r >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return;
        }
    }
}
