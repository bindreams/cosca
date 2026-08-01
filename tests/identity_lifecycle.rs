//! End-to-end identity lifecycle, portable across all supported OSes. Uses a
//! re-exec trick for a fully controllable child with no external binary and no
//! timing: a hidden in-binary "test" blocks on stdin only when an env var is
//! set, so the parent ends it deterministically by closing the pipe.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use cosca::identity::ProcessId;

#[path = "common/mod.rs"]
mod common;

const BLOCK_VAR: &str = "COSCA_IDENTITY_TEST_BLOCK";

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

    let id = ProcessId::of(pid).found().expect("a running child has an identity");
    assert_eq!(id.is_alive(), cosca::identity::Liveness::Alive, "child must be alive (running) right after spawn");
    assert_eq!(id.exists(), cosca::identity::Existence::Present, "child must be resolvable right after spawn");
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
    assert_eq!(id.is_alive(), cosca::identity::Liveness::Dead, "child must read not-running immediately after it exits");

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

/// An exited-but-unreaped (zombie) child must still resolve by identity on EVERY platform.
/// Exit is proven by stdout EOF — the child's write end closes at process exit.
#[test]
fn identity_resolves_an_exited_unreaped_child() {
    // RAW std::process::Command: argv[0] is the exe path, so the testbin mode is args[1].
    let mut child = Command::new(common::testbin())
        .args(["exit", "0"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut buf = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut buf)
        .expect("EOF");
    let id = ProcessId::of(child.id()).found().expect("an unreaped exit must resolve by pid");
    assert_eq!(id.exists(), cosca::identity::Existence::Present, "an unreaped exit must remain visible to exists()");
    child.wait().expect("reap");
}

/// The start token must be STABLE across the alive -> zombie transition — the property
/// `is_running`'s reused-PID guard depends on. `waitid(WEXITED | WNOWAIT)` pins the
/// zombie: it returns only once the child IS a zombie and leaves it unreaped.
#[cfg(unix)]
#[test]
fn identity_survives_the_alive_to_zombie_transition() {
    // _sock must stay alive: dropping our socket end would unblock the child early.
    let (child, _sock) = common::spawn_blocker();
    let id = ProcessId::of(child.id().pid()).found().expect("live child resolves");
    assert_eq!(id.exists(), cosca::identity::Existence::Present, "live child exists");
    assert_eq!(id.is_alive(), cosca::identity::Liveness::Alive, "live child is alive");
    child.kill().expect("kill");
    // WNOWAIT: leaves the zombie unreaped.
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `si` is a valid out-param; the child is ours and unreaped.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id().pid() as libc::id_t,
            &mut si,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    assert_eq!(rc, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());
    assert_eq!(id.exists(), cosca::identity::Existence::Present, "the pre-exit token must still match the unreaped zombie");
    assert_eq!(id.is_alive(), cosca::identity::Liveness::Dead, "a zombie is not alive");
    child.wait().expect("reap");
    assert_eq!(id.exists(), cosca::identity::Existence::Gone, "a reaped process is gone");
}
