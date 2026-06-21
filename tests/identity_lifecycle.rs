//! End-to-end identity lifecycle, portable across all supported OSes. Uses a
//! re-exec trick for a fully controllable child with no external binary and no
//! timing: a hidden in-binary "test" blocks on stdin only when an env var is
//! set, so the parent ends it deterministically by closing the pipe.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use subprocess::identity::ProcessId;

const BLOCK_VAR: &str = "SUBPROCESS_IDENTITY_TEST_BLOCK";

/// When this integration-test binary is re-spawned with `BLOCK_VAR` set, this
/// "test" blocks reading stdin until the parent closes the pipe. In a normal
/// run the var is unset and it returns immediately.
#[test]
fn helper_block_on_stdin() {
    if std::env::var_os(BLOCK_VAR).is_none() {
        return;
    }
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
}

fn spawn_blocking_child() -> Child {
    let exe = std::env::current_exe().expect("current_exe");
    Command::new(exe)
        .args(["--exact", "helper_block_on_stdin"])
        .env(BLOCK_VAR, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn blocking child")
}

#[test]
fn child_is_alive_while_running_then_not_after_exit() {
    let mut child = spawn_blocking_child();
    let pid = child.id();

    let id = ProcessId::of(pid).expect("a running child has an identity");
    assert!(id.is_alive(), "child must be alive (running) right after spawn");
    assert!(id.exists(), "child must be resolvable right after spawn");
    assert_ne!(id, ProcessId::current(), "child identity differs from ours");

    // End the child deterministically: close its stdin (EOF) and reap it.
    drop(child.stdin.take());
    let _ = child.wait().expect("reap child");
    // Do NOT drop `child` yet: keeping its handle open prevents PID reuse, so
    // is_alive checks exactly our (now-exited) process. is_alive reads the
    // signaled state on Windows / `/proc` absence on Unix, so it is false
    // synchronously — no teardown-window wait. (exists() may still be true here
    // on Windows during teardown; that is exists()'s documented behavior, so we
    // do not assert on it.)
    assert!(!id.is_alive(), "child must read not-running immediately after it exits");

    drop(child);
}

#[test]
fn created_at_is_present_and_not_in_the_future() {
    let me = ProcessId::current();
    let created = me.created_at().expect("current process has a creation time");
    // Sanity bound (not a synchronization wait): our start time is in the past.
    // A few seconds of slack absorbs clock-source granularity differences.
    assert!(created <= SystemTime::now() + Duration::from_secs(5));
}
