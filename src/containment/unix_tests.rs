// Unit tests for the Unix process-group signal wrappers.
// Substantive end-to-end coverage is in the integration test
// (`unix_kill_tree_reaps_the_grandchild` in `tests/spawn_io.rs`).

use super::{kill_group, term_group};

// Spawn a short-lived child, retrieve its pid, wait for it to exit, then
// return the pid of the (now-dead, reaped) process so callers can target a
// genuinely ESRCH-inducing pgid.
fn dead_pid() -> i32 {
    let mut child = std::process::Command::new("true").spawn().expect("spawn true");
    let pid = child.id() as i32;
    child.wait().expect("wait true");
    pid
}

/// kill_group with an ESRCH pgid (process already gone) must return Ok — the
/// goal is "gone" and it already is.
#[test]
fn kill_group_esrch_is_ok() {
    // Use a real reaped PID rather than an arbitrary magic number, so the kernel
    // genuinely returns ESRCH (no process in that group, not EPERM).
    assert!(kill_group(dead_pid()).is_ok());
}

/// term_group with an ESRCH pgid must return Ok.
#[test]
fn term_group_esrch_is_ok() {
    assert!(term_group(dead_pid()).is_ok());
}

/// kill_group on a real owned process group succeeds; the dead-group ESRCH arm
/// is also exercised after the child is reaped.
#[test]
fn kill_group_on_owned_group_succeeds() {
    use std::os::unix::process::CommandExt;
    // Spawn a child in its own private group (pgid == child pid) so we can
    // SIGKILL it without disturbing the test runner's own group.
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .expect("spawn sleep");
    let pgid = child.id() as i32;
    assert!(kill_group(pgid).is_ok(), "kill_group on owned group must succeed");
    let _ = child.wait();
    // After reaping, the same pgid is gone — ESRCH arm must also return Ok.
    assert!(
        kill_group(pgid).is_ok(),
        "kill_group on dead group must still be Ok (ESRCH)"
    );
}
