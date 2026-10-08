//! The shim process (plan F): it connects to cosca's socket, proves that the listener and the
//! writer of the answer are cosca, starts the program, and supervises it until the program is gone.
//!
//! [`handshake`] is everything up to the answer, [`child`] makes the program's process,
//! [`run_loop`] supervises it, and the pure [`step`](super::step) decides what each wake means.

use std::fmt::Arguments;
use std::os::fd::{AsFd, OwnedFd};

use super::codes;
use super::hooks::{Gate, Inject, ShimTestHooks};
use super::protocol::{Frame, Refusal, ShimArgs};

mod child;
mod handshake;
mod log;
mod reap;
mod run_loop;
mod signals;
mod start;

use log::Log;

/// An exit code the shim has already reported.
struct Exit(i32);

struct Shim {
    hooks: Option<&'static dyn ShimTestHooks>,
    log: Log,
    conn: Option<OwnedFd>,
    hello_sent: bool,
}

/// Runs the shim for `args` and returns its exit code.
pub(crate) fn run(args: &ShimArgs, hooks: Option<&'static dyn ShimTestHooks>) -> i32 {
    let mut shim = Shim {
        hooks,
        log: Log::new(hooks.and_then(|h| h.log_fd())),
        conn: None,
        hello_sent: false,
    };
    match shim.go(args) {
        Ok(code) | Err(Exit(code)) => code,
    }
}

impl Shim {
    fn go(&mut self, args: &ShimArgs) -> Result<i32, Exit> {
        if is_set_id() {
            return Err(self.refuse(codes::SET_ID, "refusing a set-id context"));
        }
        // SAFETY: `getpid` and `getppid` have no preconditions.
        let (pid, ppid) = unsafe { (libc::getpid(), libc::getppid()) };
        self.log.line(format_args!("shim pid={pid} ppid={ppid}"));
        self.log
            .line(format_args!("sigpipe at entry: {}", signals::sigpipe_state()));
        self.gate(Gate::BeforeConnect);
        self.connect(args)?;
        self.gate(Gate::BeforeIdentity);
        self.verify_listener(args)?;
        let owner = self.watch_owner(args)?;
        self.say_hello()?;
        self.await_answer(args, &owner)?;
        self.gate(Gate::AfterAnswer);
        self.recheck_owner(&owner)?;
        start::start_and_supervise(self, args, &owner)
    }

    fn gate(&self, gate: Gate) {
        if let Some(hooks) = self.hooks {
            self.log.line(format_args!("gate: waiting at {}", gate.name()));
            hooks.gate(gate);
        }
    }

    fn injected(&self, what: Inject) -> bool {
        let on = self.hooks.is_some_and(|h| h.inject(what));
        if on {
            self.log.line(format_args!("seam: {}", what.name()));
        }
        on
    }

    fn conn(&self) -> &OwnedFd {
        self.conn.as_ref().expect("connected before it is used")
    }

    /// Writes one frame to cosca. A failure is ignored: cosca may be gone, and every exit path sends
    /// exactly one frame.
    fn send(&self, frame: Frame) {
        if let Some(conn) = &self.conn {
            _ = handshake::send_all(conn.as_fd(), &frame.encode());
        }
    }

    /// Reports a refusal: one stderr line naming the code, the seam log, and `R` once hello is out.
    fn refuse(&self, code: i32, why: &str) -> Exit {
        use std::io::Write;
        // Whether the front's stderr still exists is not the shim's to decide.
        _ = writeln!(
            std::io::stderr(),
            "cosca-elevation-shim: {why}; the program was not started (exit {code})"
        );
        self.log.line(format_args!("refused {code}: {why}"));
        if self.hello_sent {
            if let Some(refusal) = Refusal::from_code(code) {
                self.send(Frame::Refused(refusal));
            }
        }
        Exit(code)
    }

    /// A stderr line only: the program never ran, and the status pipe's report is the frame.
    fn stderr_line(&self, args: Arguments<'_>) {
        use std::io::Write;
        _ = writeln!(std::io::stderr(), "cosca-elevation-shim: {args}");
    }
}

/// D1a: set-id contexts are refused.
fn is_set_id() -> bool {
    // SAFETY: these calls have no preconditions and cannot fail.
    unsafe { libc::getuid() != libc::geteuid() || libc::getgid() != libc::getegid() }
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod run_tests;
