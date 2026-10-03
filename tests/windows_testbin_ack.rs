//! Windows: the testbin modes that spawn a child of their own and accept its connection
//! (`report-nested-terminate`, `report-console-terminate`, `report-console-lone`,
//! `report-breakaway`) watch that child's death, and opt it in to the accept handshake themselves.
//!
//! Both properties are invisible from the outside when everything goes right, so each mode runs
//! under a testbin seam (`testbin/ack.rs`, `SEAM_ENV`):
//! - `strict`: the mode drops the opt-in from its own environment after connecting, and a child
//!   that was not opted in explicitly panics before connecting. Without the mode's own
//!   `.env(ACK_ENV, ..)` the child dies and the mode cannot report.
//! - `die`: the mode's child exits before connecting. The mode must fail naming the death instead
//!   of blocking in a plain `accept()`.

#[cfg(windows)]
use std::io::Read;
#[cfg(windows)]
use std::net::TcpListener;

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;

#[cfg(windows)]
use common::Target;

#[cfg(windows)]
const SEAM_ENV: &str = "COSCA_TEST_ACK_SEAM";

#[cfg(windows)]
/// How a mode is launched and read.
struct Case {
    /// The mode's argv after the executable, given the report address.
    args: fn(&str) -> Vec<String>,
    /// Spawned through `cosca::Command::contain`, as `report-nested-terminate` requires.
    contained: bool,
    /// The mode reports one line and then waits for the socket to close, instead of closing.
    one_line: bool,
}

#[cfg(windows)]
struct Run {
    report: String,
    success: bool,
    stderr: String,
}

#[cfg(windows)]
enum Helper {
    Std(std::process::Child),
    Cosca(cosca::Child),
}

#[cfg(windows)]
impl Target for Helper {
    fn pid(&self) -> u32 {
        match self {
            Helper::Std(c) => c.id(),
            Helper::Cosca(c) => c.id().pid(),
        }
    }

    fn has_exited(&mut self) -> bool {
        match self {
            Helper::Std(c) => c.has_exited(),
            Helper::Cosca(c) => c.has_exited(),
        }
    }
}

#[cfg(windows)]
fn run(case: &Case, seam: &str) -> Run {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let args = (case.args)(&addr);
    let mut helper = if case.contained {
        let mut cmd = cosca::Command::new();
        cmd.executable(common::testbin())
            .args(&args)
            .env(common::ACK_ENV, "1")
            .env(SEAM_ENV, seam)
            .stderr(cosca::Stdio::pipe())
            .expect("pipe stderr")
            .contain();
        Helper::Cosca(cmd.spawn().expect("spawn the mode"))
    } else {
        let mut cmd = std::process::Command::new(common::testbin());
        cmd.args(&args)
            .env(common::ACK_ENV, "1")
            .env(SEAM_ENV, seam)
            .stderr(std::process::Stdio::piped());
        Helper::Std(common::spawn_locked(&mut cmd).expect("spawn the mode"))
    };
    let mut sock = common::accept_or_die(&listener, &mut helper);
    let mut report = String::new();
    if case.one_line {
        report = common::read_report_line(&sock);
        drop(sock);
    } else {
        sock.read_to_string(&mut report).expect("read the report");
    }
    let (success, mut stderr) = (
        match &mut helper {
            Helper::Std(c) => c.wait().expect("reap the mode").success(),
            Helper::Cosca(c) => c.wait().expect("reap the mode").success(),
        },
        String::new(),
    );
    match &mut helper {
        Helper::Std(c) => c.stderr.take().expect("piped").read_to_string(&mut stderr),
        Helper::Cosca(c) => c.stderr().expect("piped").read_to_string(&mut stderr),
    }
    .expect("read the mode's stderr");
    Run {
        report,
        success,
        stderr,
    }
}

#[cfg(windows)]
macro_rules! mode_tests {
    ($($module:ident: $case:expr;)*) => {$(
        mod $module {
            use super::*;

            /// The mode's child exits before connecting: the mode fails naming the death.
            #[skuld::test]
            fn death_watch_accept_or_die_fails_when_the_modes_child_dies_before_connecting() {
                let r = run(&$case, "die");
                assert!(!r.success, "the mode must fail, stderr: {}", r.stderr);
                assert!(r.report.is_empty(), "nothing can have been reported: {:?}", r.report);
                assert!(
                    r.stderr.contains("died before it connected"),
                    "expected the death-watched accept's panic, got: {}",
                    r.stderr
                );
            }

            /// The mode does not inherit the opt-in, so its own explicit one is what reaches the child.
            #[skuld::test]
            fn death_watch_accept_or_die_child_is_opted_in_by_the_mode_not_inherited() {
                let r = run(&$case, "strict");
                assert!(r.success, "the mode failed, stderr: {}", r.stderr);
                assert!(!r.report.is_empty(), "the mode reported nothing, stderr: {}", r.stderr);
            }
        }
    )*};
}

#[cfg(windows)]
fn nested_terminate_args(addr: &str) -> Vec<String> {
    ["cosca_testbin", "report-nested-terminate", addr]
        .map(String::from)
        .to_vec()
}
#[cfg(windows)]
fn console_terminate_args(addr: &str) -> Vec<String> {
    ["report-console-terminate", addr].map(String::from).to_vec()
}
#[cfg(windows)]
fn console_lone_args(addr: &str) -> Vec<String> {
    ["report-console-lone", addr].map(String::from).to_vec()
}
#[cfg(windows)]
fn breakaway_raw_args(addr: &str) -> Vec<String> {
    ["report-breakaway", addr, "permit", "raw"].map(String::from).to_vec()
}
#[cfg(windows)]
fn breakaway_argv_args(addr: &str) -> Vec<String> {
    ["report-breakaway", addr, "permit", "argv"].map(String::from).to_vec()
}
#[cfg(windows)]
fn breakaway_exec_args(addr: &str) -> Vec<String> {
    ["report-breakaway", addr, "permit", "exec"].map(String::from).to_vec()
}

#[cfg(windows)]
mode_tests! {
    report_nested_terminate: Case { args: nested_terminate_args, contained: true, one_line: false };
    report_console_terminate: Case { args: console_terminate_args, contained: false, one_line: false };
    report_console_lone: Case { args: console_lone_args, contained: false, one_line: false };
    report_breakaway_raw: Case { args: breakaway_raw_args, contained: false, one_line: true };
    report_breakaway_argv: Case { args: breakaway_argv_args, contained: false, one_line: true };
    report_breakaway_exec: Case { args: breakaway_exec_args, contained: false, one_line: true };
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
