//! `output_within`: the driver's failure bound.

use std::os::unix::process::ExitStatusExt as _;
use std::process::Stdio;
use std::time::Duration;

use super::output_within;

fn sh(script: &str) -> std::process::Child {
    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    crate::test_spawn::spawn(&mut cmd).expect("spawn sh")
}

/// A child that exits is `Ok`, with both streams whole.
///
/// Mutant: either stream dropped, or the exit taken for the bound.
#[test]
fn a_child_that_exits_is_ok_with_its_output() {
    let output = output_within(sh("echo out; echo err >&2"), Duration::from_secs(3600)).expect("it exits");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
}

/// A child still running at the bound is killed and reaped, and is `Err`. The bound is the
/// subject here, so it is short.
///
/// Mutant: no kill, or the bound ignored (the test then waits on the child).
#[test]
fn a_child_still_running_at_the_bound_is_killed_and_is_err() {
    let mut child = sh("exec cat");
    let _stdin = child.stdin.take().expect("piped stdin");
    let output = output_within(child, Duration::from_millis(50)).expect_err("it never exits by itself");
    assert_eq!(output.status.signal(), Some(libc::SIGKILL), "{:?}", output.status);
}
