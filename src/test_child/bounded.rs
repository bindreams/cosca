//! Re-exec fixtures that block on something outside the library (a traced child, a kernel wait)
//! get failure bounds: the driver's wait for the fixture, and the fixture's own watchdog. Both are
//! bounds on an external event, never a synchronisation: a passing fixture exits long before.

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Output};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

use crate::child::shared::SharedChild;
use crate::identity::ProcessId;

/// [`run_fixture_output`](super::run_fixture_output) from `program` (a modified copy of this
/// binary, say), under a failure `bound`: `Ok` with the fixture's output once it exits, `Err`
/// with it after the fixture was killed for still running at `bound`.
pub(crate) fn run_fixture_output_within(
    fixture: &str,
    marker_env: &str,
    program: &Path,
    bound: Duration,
) -> Result<Output, Output> {
    let mut cmd = crate::test_reexec::command(program);
    super::configure_fixture_command(&mut cmd, fixture);
    cmd.env(marker_env, std::process::id().to_string());
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn fixture child");
    output_within(child, bound)
}

/// `child`'s output once it exits (`Ok`), or, if it is still running after `bound`, its output
/// after it is killed and reaped (`Err`). Needs piped stdout and stderr.
fn output_within(mut child: Child, bound: Duration) -> Result<Output, Output> {
    fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            // A failed read ends the capture; say so in the capture, so a truncated one reads as
            // truncated in the diagnostics that print it.
            if let Err(e) = pipe.read_to_end(&mut bytes) {
                bytes.extend(format!("\n[the capture ended early: {e}]\n").bytes());
            }
            bytes
        })
    }
    let stdout = drain(child.stdout.take().expect("piped stdout"));
    let stderr = drain(child.stderr.take().expect("piped stderr"));
    // Adopted so that the kill below is identity-checked: the waiting thread may reap at any
    // moment, and a bare pid could then name another process.
    let id = ProcessId::of(child.id())
        .found()
        .expect("the live child has an identity");
    let shared = Arc::new(SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}")));
    let (tx, rx) = channel();
    let waiter = {
        let shared = Arc::clone(&shared);
        // The receiver outlives the waiter: a failed send needs no handling.
        std::thread::spawn(move || _ = tx.send(shared.wait()))
    };
    let (status, in_time) = match rx.recv_timeout(bound) {
        Ok(status) => (status, true),
        Err(RecvTimeoutError::Timeout) => {
            shared.kill().expect("kill the hung fixture");
            (rx.recv().expect("the waiter ended without a result"), false)
        }
        Err(RecvTimeoutError::Disconnected) => panic!("the waiter ended without a result"),
    };
    waiter.join().expect("the waiter");
    let output = Output {
        status: status.expect("wait for the fixture"),
        stdout: stdout.join().expect("stdout reader"),
        stderr: stderr.join().expect("stderr reader"),
    };
    if in_time {
        Ok(output)
    } else {
        Err(output)
    }
}

/// Ends the watchdog when dropped.
pub(crate) struct Watchdog(#[allow(dead_code, reason = "dropping the sender ends the watchdog")] Sender<()>);

/// In a fixture: if it is still running after `bound`, name the step it is in ([`step`]) on the
/// stderr and abort, so the driver's assertion shows where it hung.
pub(crate) fn watchdog(name: &'static str, bound: Duration) -> Watchdog {
    let (tx, rx) = channel::<()>();
    std::thread::spawn(move || {
        if rx.recv_timeout(bound) == Err(RecvTimeoutError::Timeout) {
            // Stderr is unbuffered, so the line is out before the abort.
            _ = writeln!(
                std::io::stderr(),
                "WATCHDOG: {name} still running after {bound:?}; last step: {}",
                step_name()
            );
            std::process::abort();
        }
    });
    Watchdog(tx)
}

static STEP: std::sync::Mutex<&'static str> = std::sync::Mutex::new("start");

/// Record the step a fixture has reached, for the [`watchdog`].
pub(crate) fn step(name: &'static str) {
    _ = writeln!(std::io::stderr(), "step: {name}");
    *STEP.lock().unwrap_or_else(|e| e.into_inner()) = name;
}

fn step_name() -> &'static str {
    *STEP.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
#[path = "bounded_tests.rs"]
mod bounded_tests;
