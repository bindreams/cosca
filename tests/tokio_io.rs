//! Async (tokio) I/O integration tests.
#![cfg(feature = "tokio")]

#[path = "common/mod.rs"]
mod common;

#[tokio::test]
async fn async_spawn_status_reports_exit_code() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "exit", "7"]);
    assert_eq!(cmd.status().await.expect("status").code(), Some(7));
}

#[tokio::test]
async fn async_id_is_a_real_stable_identity() {
    // id() returns the stored ProcessId — a real, resolvable identity that survives wait (tokio's
    // own Child::id() would be None after reap).
    use std::io::Write as _;
    let (mut child, mut sock) = common::spawn_blocker_async();
    let id = child.id();
    assert_eq!(
        subprocess::Process::from_id(id).map(|p| p.id()),
        Some(id),
        "id() is a resolvable identity"
    );
    sock.write_all(b"x").expect("release");
    child.wait().await.expect("wait");
    assert_eq!(child.id(), id, "id() stays the stable ProcessId after wait");
}

#[tokio::test]
async fn async_try_wait_is_none_before_exit_then_some_after() {
    // A blocker child is structurally wedged on its never-written socket → still running.
    let (mut child, mut sock) = common::spawn_blocker_async();
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "wedged child must be running"
    );
    use std::io::Write as _;
    sock.write_all(b"x").expect("release the child");
    child.wait().await.expect("wait"); // sync point: the exit, not a timer
    assert!(
        child.try_wait().expect("try_wait").is_some(),
        "reaped child reports Some"
    );
}

#[tokio::test]
async fn async_env_reaches_child() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "env", "SP_PLAN8"])
        .env("SP_PLAN8", "async");
    let out = cmd.output().await.expect("output");
    assert_eq!(out.stdout, b"SP_PLAN8=async\n");
}

#[tokio::test]
async fn async_output_captures_streams() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "5", "3"]);
    let out = cmd.output().await.expect("output");
    assert_eq!(out.stdout, vec![b'o'; 5]);
    assert_eq!(out.stderr, vec![b'e'; 3]);
    assert!(out.status.success());
}

#[tokio::test]
async fn async_communicate_is_deadlock_free() {
    // tee-both copies stdin to BOTH stdout and stderr; a non-concurrent reader would deadlock
    // once a pipe buffer fills. Concurrent try_join! must complete with all bytes on both.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "tee-both"]);
    cmd.stdin(subprocess::Stdio::pipe()).unwrap();
    cmd.stdout(subprocess::Stdio::pipe()).unwrap();
    cmd.stderr(subprocess::Stdio::pipe()).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    let payload = vec![b'z'; 4 * 1024 * 1024];
    let out = child.communicate(Some(payload.clone())).await.expect("communicate");
    assert_eq!(out.stdout, payload);
    assert_eq!(out.stderr, payload);
}

#[tokio::test]
async fn async_communicate_tolerates_early_stdin_close() {
    // A child that exits without reading all of stdin closes the pipe early; write_all then
    // yields BrokenPipe. communicate must treat that as EOF and still return captured output.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "2", "0"]); // never reads stdin
    cmd.stdin(subprocess::Stdio::pipe()).unwrap();
    cmd.stdout(subprocess::Stdio::pipe()).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    // 4 MiB > any pipe buffer, so write_all is still in flight when `emit` exits and closes its
    // stdin read end — deterministically forcing the BrokenPipe the tolerance branch handles.
    let out = child
        .communicate(Some(vec![b'x'; 4 * 1024 * 1024]))
        .await
        .expect("communicate tolerates BrokenPipe");
    assert_eq!(out.stdout, vec![b'o'; 2]);
    assert!(out.status.success());
}

#[tokio::test]
async fn async_communicate_none_with_piped_stdin_signals_eof() {
    // Piped stdin + no input: the write future takes `Some(writer)`, skips the write, and drops the
    // writer to signal EOF. `tee-both` reads stdin to EOF, so with no input it must complete rather
    // than hang waiting on a stdin that never closes.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "tee-both"]);
    cmd.stdin(subprocess::Stdio::pipe()).unwrap();
    cmd.stdout(subprocess::Stdio::pipe()).unwrap();
    cmd.stderr(subprocess::Stdio::pipe()).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    let out = child
        .communicate(None)
        .await
        .expect("communicate completes once EOF is signaled");
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "no input → tee-both emits nothing"
    );
    assert!(out.status.success());
}

#[tokio::test]
async fn async_read_errors_on_invalid_utf8() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit-raw", "61", "ff", "62"]);
    let err = cmd.read().await.expect_err("invalid utf-8 must error");
    assert!(matches!(err, subprocess::error::Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData));
}

#[test] // NOT #[tokio::test] — verifies the no-runtime guard returns Err (not panic / deferred failure)
fn async_spawn_outside_runtime_errors() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "exit", "0"]);
    let err = cmd.spawn().expect_err("spawn outside a tokio runtime must Err");
    assert!(matches!(err, subprocess::error::Error::Io(_)), "got {err:?}");
}

// An IO-disabled runtime is tokio's business and platform-specific (we cannot preflight it, so we
// pin the actual behavior — see `Command::spawn`'s Runtime docs).
#[cfg(unix)]
#[test]
fn async_spawn_on_io_disabled_runtime_panics_on_unix() {
    // Build the runtime OUTSIDE the observed region, so only `cmd.spawn()`'s panic — not the
    // runtime `.build().expect()` — can satisfy this test.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build an IO-disabled current-thread runtime");
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let mut cmd = subprocess::tokio::Command::new();
            cmd.executable(common::testbin())
                .args(["subprocess_testbin", "exit", "0"]);
            let _ = cmd.spawn();
        })
    }))
    .expect_err("spawning on an IO-disabled runtime must panic on Unix (child reaping needs the IO driver)");
    // Pin tokio's specific driver-absent panic (IO driver on Linux, signal driver on macOS), not
    // merely "something, somewhere, panicked".
    let msg = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        msg.contains("IO is disabled") || msg.contains("signal driver"),
        "expected tokio's driver-absent panic, got: {msg:?}"
    );
}

#[cfg(windows)]
#[test]
fn async_spawn_on_io_disabled_runtime_succeeds_on_windows() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build an IO-disabled current-thread runtime");
    let spawned = rt.block_on(async {
        let mut cmd = subprocess::tokio::Command::new();
        cmd.executable(common::testbin())
            .args(["subprocess_testbin", "exit", "0"]);
        cmd.spawn().is_ok()
    });
    assert!(
        spawned,
        "on Windows, spawn does not require the IO driver at spawn time"
    );
}

#[tokio::test]
async fn async_merge_into_pipe_is_unsupported() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "exit", "0"]);
    cmd.stdout(subprocess::Stdio::pipe()).unwrap();
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT)).unwrap();
    let err = cmd.spawn().expect_err("merge into a piped target is unsupported");
    assert!(
        matches!(err, subprocess::error::Error::Unsupported { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn async_fd3_is_unsupported() {
    // The async strict-subset rejection of arbitrary fd >= 3 (a non-pipe slot, so `fd()` itself
    // accepts it; the rejection is at spawn).
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "exit", "0"]);
    cmd.fd(subprocess::Fd::from(3), subprocess::Stdio::null()).unwrap();
    let err = cmd.spawn().expect_err("fd >= 3 is unsupported on the async API");
    assert!(
        matches!(err, subprocess::error::Error::Unsupported { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn async_chained_merge_is_unsupported() {
    // A merge whose target is itself a merge → Unsupported (mirrors the sync chained-merge test):
    // stderr -> stdout, and stdout -> stdin, so stdout's resolved kind is Merge.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "exit", "0"]);
    cmd.stdout(subprocess::Stdio::merge(subprocess::Fd::STDIN)).unwrap();
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT)).unwrap();
    let err = cmd.spawn().expect_err("chained merges are unsupported");
    assert!(
        matches!(err, subprocess::error::Error::Unsupported { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn async_run_builds_command_from_args() {
    // `run([...])` derives the program from the first arg (mirrors the sync run free fn).
    let s = subprocess::tokio::run([common::testbin(), "echo-argv", "world"])
        .read()
        .await
        .expect("read");
    assert_eq!(s, "world\n");
}

#[tokio::test]
async fn async_run_line_round_trips() {
    // `run_line(line)` routes through `.commandline()`: POSIX splits via shlex, Windows passes the
    // line through and derives the program from the first token (mirrors the sync round-trip test).
    let line = format!(r#""{}" echo-argv hello"#, common::testbin());
    let s = subprocess::tokio::run_line(line).read().await.expect("read");
    assert_eq!(s, "hello\n");
}

#[tokio::test]
async fn async_drop_tears_down_a_contained_tree() {
    use std::io::Read as _;
    let (child, mut root, mut grand) = common::spawn_grandchild_async(true);
    // The containment assert guards the EOFs below from passing for unrelated reasons.
    assert_ne!(
        child.containment(),
        subprocess::Containment::None,
        "contained spawn must engage a mechanism"
    );
    let root_id = child.id();
    drop(child);
    // The root is deterministically dead — reap_now blocked until its exit before Drop returned.
    assert!(!root_id.is_alive(), "the contained root must be torn down by Drop");
    // The grandchild's death is proven by its control-socket EOF: a survivor blocks the read (a CI failure).
    for (who, s) in [("root", &mut root), ("grandchild", &mut grand)] {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("{who} not torn down on drop: {other:?}"),
        }
    }
}

#[tokio::test]
async fn async_drop_after_wait_still_tears_down_the_tree() {
    // After awaiting the root's exit it is already reaped (reap_now is then a no-op), so the tree
    // teardown must come from attached.hard_kill() on Drop — proven by the grandchild's EOF.
    use std::io::{Read as _, Write as _};
    let (mut child, mut root, mut grand) = common::spawn_grandchild_async(true);
    let root_id = child.id();
    root.write_all(b"x").expect("release the root so it exits");
    child.wait().await.expect("wait reaps the root");
    assert!(!root_id.is_alive(), "root exited");
    drop(child); // root already reaped → reap_now no-op; attached.hard_kill must still kill the grandchild
    let mut buf = [0u8; 1];
    match grand.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("grandchild not torn down by hard_kill after the root was waited: {other:?}"),
    }
}

#[tokio::test]
async fn async_detach_leaves_the_tree_running() {
    use std::io::{Read as _, Write as _};
    let (mut child, mut root, _grand) = common::spawn_grandchild_async(true);
    let root_id = child.id();
    child.detach();
    drop(child); // detached → Drop must NOT kill
                 // Positive liveness (no race — we never signaled it): a buggy detach that let Drop kill the
                 // root would make this false.
    assert!(
        root_id.is_alive(),
        "detach must leave the root running after the handle drops"
    );
    // Release it and observe a CLEAN voluntary exit (Ok(0) EOF), distinct from a kill's reset.
    root.write_all(b"x").expect("release the live root");
    let mut buf = [0u8; 1];
    assert!(
        matches!(root.read(&mut buf), Ok(0)),
        "released root exits cleanly (EOF)"
    );
    // _grand drops here → its socket closes → the reparented grandchild exits.
}

#[tokio::test]
async fn async_kill_on_drop_false_leaves_the_root_running() {
    // `kill_on_drop(false)` hits the async Drop early-return with `attached` STILL ARMED (unlike
    // detach(), which also disarms). Drop must NOT run the teardown (hard_kill + reap_now), so the
    // root stays alive. Proven by positive liveness on the never-signaled root (race-free, mirroring
    // async_detach_leaves_the_tree_running). UNCONTAINED on purpose: a Windows JobObject's
    // KILL_ON_JOB_CLOSE fires when the job handle field drops (only `disarm()` clears it, and
    // kill_on_drop(false) does not disarm), so a *contained* tree would die on Windows regardless of
    // the flag — `Attached::None` isolates the kill_on_drop(false) early-return on every platform.
    use std::io::{Read as _, Write as _};
    let (child, mut root, _grand) = common::spawn_grandchild_async_with(false, false);
    let root_id = child.id();
    drop(child); // kill_on_drop(false) → Drop early-returns; teardown must NOT run
    assert!(
        root_id.is_alive(),
        "kill_on_drop(false) must leave the root running after the handle drops"
    );
    // Release it and observe a CLEAN voluntary exit (Ok(0) EOF), best-effort tearing the tree down.
    // `_grand` drops here too → its socket closes → the reparented grandchild exits.
    root.write_all(b"x").expect("release the live root");
    let mut buf = [0u8; 1];
    assert!(
        matches!(root.read(&mut buf), Ok(0)),
        "released root exits cleanly (EOF)"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn async_drop_leaves_no_zombie() {
    // The guaranteed-reap contract: after Drop the child is FULLY reaped (reap_now waited for exit,
    // then tokio's field-drop collected the zombie). Reuse-immune proof: the child's original
    // identity (pid + start token) is gone. A zombie would still resolve to `Some(id)` (Linux /proc
    // persists); a reaped pid resolves to `None` or, if recycled, a different identity — so a
    // recycled pid never false-fails (no pid-reuse race, which a bare-pid `waitpid` would risk).
    let (child, _sock) = common::spawn_blocker_async();
    let id = child.id();
    drop(child);
    assert_ne!(
        subprocess::identity::ProcessId::of(id.pid()),
        Some(id),
        "Drop must fully reap the child (no lingering process/zombie at its identity)"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn async_windows_contained_spawn_runs_then_job_tears_down() {
    // Verifies the CREATE_SUSPENDED + job-assign + out-of-band resume dance works under tokio.
    use std::io::Read as _;
    let (child, mut root, mut grand) = common::spawn_grandchild_async(true);
    assert_eq!(
        child.containment(),
        subprocess::Containment::JobObject,
        "Windows Strongest => JobObject"
    );
    let root_id = child.id();
    drop(child);
    assert!(!root_id.is_alive(), "the contained root must be torn down by Drop");
    for (who, s) in [("root", &mut root), ("grandchild", &mut grand)] {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("{who} not torn down: {other:?}"),
        }
    }
}
