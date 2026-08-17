//! End-to-end identity lifecycle, portable across all supported OSes. Uses a
//! re-exec trick for a fully controllable child with no external binary and no
//! timing: a hidden in-binary "test" blocks on stdin only when an env var is
//! set, so the parent ends it deterministically by closing the pipe.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use cosca::identity::ProcessId;

// All four are used only by the serde-gated tests at the end of this file; ungated they
// would be unused imports with the feature off. The body above reaches `Liveness` through
// fully-qualified paths, which does not count as a use of an import.
#[cfg(feature = "serde")]
use cosca::identity::{Existence, Liveness, ProcessIdRecord};
#[cfg(feature = "serde")]
use std::io::BufRead;

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
    assert_eq!(
        id.is_alive(),
        cosca::identity::Liveness::Alive,
        "child must be alive (running) right after spawn"
    );
    assert_eq!(
        id.exists(),
        cosca::identity::Existence::Present,
        "child must be resolvable right after spawn"
    );
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
    assert_eq!(
        id.is_alive(),
        cosca::identity::Liveness::Dead,
        "child must read not-running immediately after it exits"
    );

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
    let id = ProcessId::of(child.id())
        .found()
        .expect("an unreaped exit must resolve by pid");
    assert_eq!(
        id.exists(),
        cosca::identity::Existence::Present,
        "an unreaped exit must remain visible to exists()"
    );
    child.wait().expect("reap");
}

/// The start token must be STABLE across the alive -> zombie transition — the property
/// `is_running`'s reused-PID guard depends on. `common::block_until_zombie` pins the zombie:
/// it returns only once the child IS a zombie and leaves it unreaped.
#[cfg(unix)]
#[test]
fn identity_survives_the_alive_to_zombie_transition() {
    // _sock must stay alive: dropping our socket end would unblock the child early.
    let (child, _sock) = common::spawn_blocker();
    let id = ProcessId::of(child.id().pid()).found().expect("live child resolves");
    assert_eq!(id.exists(), cosca::identity::Existence::Present, "live child exists");
    assert_eq!(id.is_alive(), cosca::identity::Liveness::Alive, "live child is alive");
    child.kill().expect("kill");
    common::block_until_zombie(child.id().pid());
    assert_eq!(
        id.exists(),
        cosca::identity::Existence::Present,
        "the pre-exit token must still match the unreaped zombie"
    );
    assert_eq!(id.is_alive(), cosca::identity::Liveness::Dead, "a zombie is not alive");
    child.wait().expect("reap");
    assert_eq!(
        id.exists(),
        cosca::identity::Existence::Gone,
        "a reaped process is gone"
    );
}

// Persist / restore ====================================================================

// Both consts are used only by the two serde-gated tests below; ungated they would be
// dead with the feature off.
#[cfg(feature = "serde")]
const RECORD_VAR: &str = "COSCA_IDENTITY_TEST_RECORD_PATH";
/// Printed by the helper on stdout once its record file is complete.
#[cfg(feature = "serde")]
const RECORD_READY: &str = "COSCA_RECORD_WRITTEN";

/// Re-exec helper: when `RECORD_VAR` names a path, write this process's own identity
/// record there, announce it on stdout, then block on stdin so the parent controls the
/// exit. The record is produced by a genuinely different process — a real cross-process
/// restart, not a round trip inside one test. Inert in a normal run, like
/// `helper_block_on_stdin` above.
#[test]
#[cfg(feature = "serde")]
fn helper_write_own_record() {
    let Some(path) = std::env::var_os(RECORD_VAR) else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let record = ProcessId::current().to_record().expect("to_record");
    let json = serde_json::to_string(&record).expect("serialize");
    // Write-then-rename: the parent must never observe a half-written file. Rename over an
    // existing name is atomic on all three platforms.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json).expect("write record");
    std::fs::rename(&tmp, &path).expect("rename record into place");
    // The handshake proper: a byte on the pipe, not an elapsed interval.
    println!("{RECORD_READY}");
    use std::io::Write;
    std::io::stdout().flush().expect("flush");
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
}

#[test]
#[cfg(feature = "serde")]
fn an_identity_written_by_another_process_restores_and_names_that_process() {
    use cosca::Process;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("id.json");
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        // The filter is mandatory: an unfiltered re-exec runs the whole suite recursively.
        // `--nocapture` is what lets the helper's marker reach our pipe at all.
        .args(["helper_write_own_record", "--exact", "--nocapture"])
        .env(RECORD_VAR, &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn helper");

    // Synchronise on the pipe: read lines until the marker. libtest prints its own banner
    // first, so scan rather than reading a single line. EOF without the marker means the
    // helper died before writing — a real failure, reported as one.
    let stdout = child.stdout.take().expect("piped stdout");
    let ready = std::io::BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .any(|l| l.trim() == RECORD_READY);
    assert!(ready, "the helper exited without writing its record");

    let json = std::fs::read_to_string(&path).expect("the record file is complete by now");
    let record: ProcessIdRecord = serde_json::from_str(&json).expect("deserialize");
    let restored = ProcessId::try_from(&record).expect("a record from this boot must restore");

    // Derived independently of the record: the parent's own view of the child's identity.
    let live = ProcessId::of(child.id()).found().expect("the live child resolves");
    assert_eq!(restored, live, "the restored identity must be the child's identity");
    assert_eq!(restored.pid(), child.id());
    // The restored identity is usable as a handle, and querying through that handle finds
    // the live child — the whole point of persisting it.
    let restored_handle = Process::from_id(restored);
    assert_eq!(restored_handle.exists(), Existence::Present);
    assert_eq!(restored_handle.is_alive(), Liveness::Alive);

    // End it, and the same restored identity now reports the process is not running.
    // `is_alive`, not `exists`: `child` still holds the handle, which on Windows keeps the
    // process object resolvable after exit.
    drop(child.stdin.take());
    child.wait().expect("wait");
    assert_eq!(restored.is_alive(), Liveness::Dead);
}
