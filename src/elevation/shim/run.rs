//! The shim process: it connects to cosca's socket, proves that the listener and the writer of the
//! answer are cosca, starts the program, and supervises it until the program is gone.
//!
//! [`handshake`] is everything up to the answer, [`child`] makes the program's process,
//! [`run_loop`] supervises it, and the pure [`step`](super::step) decides what each wake means.

use std::os::fd::{AsFd, OwnedFd};

use super::codes;
use super::hooks::{Gate, Inject, ShimTestHooks};
use super::protocol::{Errno, Frame, NotExecuted, Refusal, ShimArgs};

mod child;
mod fds;
mod handshake;
mod log;
mod reap;
mod run_loop;
mod signals;
mod start;

use log::Log;
use signals::{Inherited, Wake};

/// An exit code the shim has already reported.
struct Exit(i32);

struct Shim {
    hooks: Option<&'static dyn ShimTestHooks>,
    log: Log,
    conn: Option<OwnedFd>,
    hello_sent: bool,
    /// The dispositions the shim started with, until the program's process takes them.
    inherited: Option<Inherited>,
    /// The pipe the shim's signal handlers write to, from before hello on.
    wake: Option<Wake>,
}

/// Runs the shim for `args` and returns its exit code.
pub(crate) fn run(args: &ShimArgs, hooks: Option<&'static dyn ShimTestHooks>) -> i32 {
    let log = Log::new(hooks.and_then(|h| h.log_fd()));
    log.say_panics();
    let mut shim = Shim {
        hooks,
        log,
        conn: None,
        hello_sent: false,
        inherited: None,
        wake: None,
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
        let (pid, ppid) = (rustix::process::getpid(), rustix::process::getppid());
        self.log.line(format_args!(
            "shim pid={} ppid={}",
            pid.as_raw_nonzero(),
            ppid.map_or(0, |p| p.as_raw_nonzero().get())
        ));
        self.gate(Gate::BeforeConnect);
        self.connect(args)?;
        self.gate(Gate::BeforeIdentity);
        self.verify_listener(args)?;
        let owner = self.watch_owner(args)?;
        self.catch_signals()?;
        self.say_hello()?;
        self.await_answer(args, &owner)?;
        self.gate(Gate::AfterAnswer);
        self.recheck_owner(&owner)?;
        start::start_and_supervise(self, args, &owner)
    }

    /// Catches the signals that would end the shim, so that none can kill it once cosca has been
    /// told it is there: a signal then stops the program instead.
    fn catch_signals(&mut self) -> Result<(), Exit> {
        let inherited = Inherited::read();
        let wake = Wake::new().map_err(|e| self.refuse(codes::NO_ANSWER, &format!("cannot create a pipe: {e}")))?;
        signals::install(&inherited, std::os::fd::AsRawFd::as_raw_fd(&wake.tx));
        self.inherited = Some(inherited);
        self.wake = Some(wake);
        Ok(())
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

    fn wake(&self) -> &Wake {
        self.wake.as_ref().expect("the signals are caught before hello")
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

    /// Reports a refusal before hello: one stderr line naming the code and the seam log. Nothing is
    /// written to cosca, which answers a connection only after hello, so it sees a shim that never
    /// connected.
    fn refuse(&self, code: i32, why: &str) -> Exit {
        debug_assert!(
            !self.hello_sent,
            "after hello a refusal is a `Refusal` and goes to cosca: use `refuse_with`"
        );
        self.say_refused(code, why);
        Exit(code)
    }

    /// Reports a refusal after hello: the stderr line, the seam log, and `R` to cosca.
    fn refuse_with(&self, refusal: Refusal, why: &str) -> Exit {
        debug_assert!(self.hello_sent, "before hello nothing goes to cosca: use `refuse`");
        self.say_refused(refusal as i32, why);
        self.send(Frame::Refused(refusal));
        Exit(refusal as i32)
    }

    fn say_refused(&self, code: i32, why: &str) {
        super::stderr::line(format_args!("{why}; the program was not started (exit {code})"));
        self.log.line(format_args!("refused {code}: {why}"));
    }

    /// Reports a failure before the program could run: `F` to cosca, the stderr line and the seam log.
    fn not_executed(&self, report: NotExecuted, what: &str, e: &std::io::Error) -> Exit {
        self.log
            .line(format_args!("refused {}: {what}: {e}", codes::NOT_EXECUTED));
        super::stderr::line(format_args!(
            "{what}: {e}; the program was not started (exit {})",
            codes::NOT_EXECUTED
        ));
        self.send(Frame::NotExecuted(report));
        Exit(codes::NOT_EXECUTED)
    }

    /// [`not_executed`](Self::not_executed) for a failed system call.
    fn setup_failed(&self, what: &str, errno: rustix::io::Errno) -> Exit {
        self.not_executed(
            NotExecuted::SetupFailed(Errno(errno.raw_os_error())),
            what,
            &std::io::Error::from_raw_os_error(errno.raw_os_error()),
        )
    }
}

/// Set-id contexts are refused.
fn is_set_id() -> bool {
    use rustix::process::{getegid, geteuid, getgid, getuid};
    getuid() != geteuid() || getgid() != getegid()
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod run_tests;
