//! `output_within`: the driver's failure bound.

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
#[skuld::test]
fn a_child_that_exits_is_ok_with_its_output() {
    let output = output_within(sh("echo out; echo err >&2"), Duration::from_secs(3600)).expect("it exits");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
}
