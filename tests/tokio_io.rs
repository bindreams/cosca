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

// Arbitrary fd (n>=3) — Unix only, wired via command-fds (async mirror of spawn_io.rs) =====

/// Async twin of sync `unix_fd3_pipe_round_trips`: the testbin's `fd3-echo` mode reads fd 3
/// and copies it to stdout. Write a known payload into the parent write end, close it (EOF),
/// read stdout to EOF — no timers, fully deterministic.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd3_pipe_round_trips() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-echo"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::pipe_in()).expect("fd 3 pipe_in");
    let mut child = cmd.spawn().expect("spawn with fd 3");
    let mut stdout = child.stdout().expect("stdout reader");
    let mut fd3_writer = child.fd_write_end(subprocess::Fd::from(3)).expect("fd 3 writer");

    fd3_writer.write_all(b"hello fd3").await.expect("write to fd 3");
    drop(fd3_writer); // EOF on the child's fd 3 read end

    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).await.expect("read stdout");
    drop(stdout);
    let _ = child.wait().await;

    assert_eq!(buf, b"hello fd3");
}

/// Async twin of sync `unix_fd3_null_is_accepted`: fd 3 as `Stdio::null()` spawns, the child
/// reads immediate EOF from /dev/null and produces no output, exiting cleanly.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd3_null_is_accepted() {
    use tokio::io::AsyncReadExt;
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-echo"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::null()).expect("fd 3 null");
    let mut child = cmd.spawn().expect("spawn with null fd 3");
    let mut stdout = child.stdout().expect("stdout reader");
    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).await.expect("read stdout");
    let status = child.wait().await.expect("reap");
    assert!(buf.is_empty(), "null fd 3 is immediate EOF — no echo, got {buf:?}");
    assert_eq!(status.code(), Some(0));
}

/// Async twin of sync `arbitrary_fd_is_unsupported_on_windows`: config attaches fine, spawn
/// rejects with the sync path's typed error.
#[cfg(windows)]
#[tokio::test]
async fn async_fd3_is_unsupported_on_windows() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "exit", "0"]);
    cmd.fd(3, subprocess::Stdio::pipe_out()).unwrap(); // attaches fine
    let err = cmd.spawn().unwrap_err(); // but spawn rejects it on Windows
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }));
}

/// fd 3 as pipe_out: the testbin's `fd3-write` mode writes a token to fd 3; the parent
/// reads it back via the reactor-registered `fd_read_end`.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd3_pipe_out_delivers_child_bytes() {
    use tokio::io::AsyncReadExt;
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-write", "fd3-token"]);
    cmd.fd(3, subprocess::Stdio::pipe_out()).expect("fd 3 pipe_out");
    let mut child = cmd.spawn().expect("spawn with fd 3 out");
    let mut fd3_reader = child.fd_read_end(subprocess::Fd::from(3)).expect("fd 3 reader");
    let mut buf = Vec::new();
    fd3_reader.read_to_end(&mut buf).await.expect("read fd 3");
    let _ = child.wait().await;
    assert_eq!(buf, b"fd3-token");
}

/// A wrong-direction accessor must NOT consume the stashed end (the put-back arm): after
/// the mismatched take returns `None`, the correctly-directioned accessor still yields a
/// WORKING end — proven by a full round-trip, both directions.
#[cfg(unix)]
#[tokio::test]
async fn async_fd3_wrong_direction_take_puts_the_end_back() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // pipe_in: the read-accessor first (wrong) must not lose the write end.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-echo"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::pipe_in()).expect("fd 3 pipe_in");
    let mut child = cmd.spawn().expect("spawn");
    assert!(
        child.fd_read_end(subprocess::Fd::from(3)).is_none(),
        "wrong direction is None"
    );
    let mut w = child
        .fd_write_end(subprocess::Fd::from(3))
        .expect("the write end survives the wrong-direction take");
    w.write_all(b"put-back").await.expect("write");
    drop(w);
    let mut buf = Vec::new();
    child
        .stdout()
        .expect("stdout")
        .read_to_end(&mut buf)
        .await
        .expect("read");
    let _ = child.wait().await;
    assert_eq!(buf, b"put-back");

    // pipe_out: the write-accessor first (wrong) must not lose the read end.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-write", "still-here"]);
    cmd.fd(3, subprocess::Stdio::pipe_out()).expect("fd 3 pipe_out");
    let mut child = cmd.spawn().expect("spawn");
    assert!(
        child.fd_write_end(subprocess::Fd::from(3)).is_none(),
        "wrong direction is None"
    );
    let mut r = child
        .fd_read_end(subprocess::Fd::from(3))
        .expect("the read end survives the wrong-direction take");
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).await.expect("read fd 3");
    let _ = child.wait().await;
    assert_eq!(buf, b"still-here");
}

// Merge into a piped target (all platforms; our-owned pipes) =====

#[tokio::test]
async fn async_merge_stderr_onto_stdout_combines_output() {
    use tokio::io::AsyncReadExt;
    let mut cmd = subprocess::tokio::Command::new();
    // Same scenario as sync merge_stderr_onto_stdout_combines_output (tests/spawn_io.rs):
    // emit 3 bytes to stdout, 2 to stderr; merged, all 5 arrive on the one stdout pipe.
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "2"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT))
        .expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn merged");
    let mut reader = child.stdout().expect("merged stdout reader");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.expect("read merged");
    drop(reader);
    let _ = child.wait().await;
    // All 5 bytes arrive; order between stdout/stderr is unspecified, but the COUNTS are
    // exact — a regression that drops stderr and doubles stdout cannot pass.
    assert_eq!(
        buf.len(),
        5,
        "expected 5 bytes (3 stdout + 2 stderr merged), got {buf:?}"
    );
    assert_eq!(
        buf.iter().filter(|&&b| b == b'o').count(),
        3,
        "3 stdout bytes, got {buf:?}"
    );
    assert_eq!(
        buf.iter().filter(|&&b| b == b'e').count(),
        2,
        "2 stderr bytes, got {buf:?}"
    );
}

#[tokio::test]
async fn async_merge_into_unpiped_targets_still_works() {
    // Regression: merge into null stays on the existing (non-owned) path.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "2"]);
    cmd.stdout(subprocess::Stdio::null()).expect("stdout null");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT))
        .expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn");
    let status = child.wait().await.expect("reap");
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn async_communicate_reads_a_merged_stream() {
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "2"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT))
        .expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn");
    let out = child.communicate(None).await.expect("communicate");
    assert_eq!(
        out.stdout.len(),
        5,
        "merged bytes arrive on stdout, got {:?}",
        out.stdout
    );
    assert!(out.stderr.is_empty(), "stderr was merged away");
}

#[tokio::test]
async fn async_merged_stream_accessor_has_take_semantics() {
    // stdout() as a piped merge target: first take yields the reader, second is None
    // (take semantics, matching the tokio-owned branch).
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "2"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDOUT))
        .expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn");
    let first = child.stdout();
    assert!(first.is_some(), "first stdout() take yields the merged reader");
    assert!(
        child.stdout().is_none(),
        "second stdout() take must be None (take semantics)"
    );
    // The MERGING slot (stderr) has no stream of its own: tokio's stderr was never piped.
    assert!(child.stderr().is_none(), "a merged-away slot yields no stream");
    drop(first); // close the parent end so the child's writes cannot block forever
    let _ = child.wait().await;
}

#[tokio::test]
async fn async_non_merged_stream_accessor_has_take_semantics() {
    // Regression: the pre-pass skips slots it does not assign, so stdin/stdout/stderr keep
    // plain take-semantics in a non-merge config.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "5", "0"]);
    cmd.stdin(subprocess::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::null()).expect("stderr null");
    let mut child = cmd.spawn().expect("spawn");

    assert!(child.stdin().is_some(), "first stdin() take");
    assert!(child.stdin().is_none(), "second stdin() take is None");
    assert!(child.stdout().is_some(), "first stdout() take");
    assert!(child.stdout().is_none(), "second stdout() take is None");
    assert!(child.stderr().is_none(), "stderr is null, so takes are always None");

    let _ = child.wait().await;
}

#[tokio::test]
async fn async_plain_piped_stream_accessor_has_take_semantics() {
    // The tokio-owned (non-merge) branch's take-semantics: stdout piped (no merge), so
    // tokio owns the internal pipe. Verifies parity with the merge-owned case above.
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "emit", "3", "0"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let first = child.stdout();
    assert!(first.is_some(), "first take yields the tokio-owned reader");
    assert!(child.stdout().is_none(), "second take must be None (take semantics)");
    drop(first);
    let _ = child.wait().await;
}

/// In-direction merge target on ALL platforms: stdin is piped and stderr merges into it,
/// so the pre-pass owns stdin's pipe (tokio cannot share its internal one). The child's
/// `stdin-split-echo` mode reads EXACTLY 3 bytes from fd 0, then fd 2 to EOF: dup'd
/// descriptors share ONE pipe, so `abc|def` proves the merging slot's handle is a LIVE dup
/// of that pipe — a silently skipped dup could not produce the tail. Parent writes via the
/// OWNED stdin path (Windows `WinOwnedWrite`; Unix `pipe::Sender`), EOF by drop.
#[tokio::test]
async fn async_merge_into_piped_stdin_feeds_the_merged_child() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "stdin-split-echo", "3"]);
    cmd.stdin(subprocess::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(subprocess::Stdio::merge(subprocess::Fd::STDIN))
        .expect("stderr merges into stdin");
    let mut child = cmd.spawn().expect("spawn merged-stdin child");
    let mut stdin = child.stdin().expect("owned stdin writer");
    stdin.write_all(b"abcdef").await.expect("write");
    drop(stdin); // buffered data is delivered first, then EOF (verified teardown order)
    let mut buf = Vec::new();
    child
        .stdout()
        .expect("stdout reader")
        .read_to_end(&mut buf)
        .await
        .expect("read echo");
    let _ = child.wait().await;
    assert_eq!(buf, b"abc|def");
}

/// fd >= 3 as a merge SOURCE into a piped Out target: the pre-pass routes the dup'd write
/// end through command-fds (never silently dropped). testbin's `fd3-write` emits its token
/// on fd 3 — a dup of stdout's owned pipe — so the token arrives on the stdout reader.
#[cfg(unix)]
#[tokio::test]
async fn async_fd3_source_merges_into_piped_stdout() {
    use tokio::io::AsyncReadExt;
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-write", "fd3-merged"]);
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::merge(subprocess::Fd::STDOUT))
        .expect("fd 3 merges into stdout");
    let mut child = cmd.spawn().expect("spawn");
    let mut buf = Vec::new();
    child
        .stdout()
        .expect("stdout reader")
        .read_to_end(&mut buf)
        .await
        .expect("read");
    let _ = child.wait().await;
    assert_eq!(buf, b"fd3-merged");
}

/// fd >= 3 as a merge SOURCE into a piped In target (one parent writer, several child read
/// fds — the user-decided shape): fd 3 is a dup of the owned stdin read end; testbin's
/// `fd3-echo` copies fd 3 to stdout, so the parent's stdin writes round-trip through the DUP.
#[cfg(unix)]
#[tokio::test]
async fn async_fd3_source_merges_into_piped_stdin() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cmd = subprocess::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "fd3-echo"]);
    cmd.stdin(subprocess::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(subprocess::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, subprocess::Stdio::merge(subprocess::Fd::STDIN))
        .expect("fd 3 merges into stdin");
    let mut child = cmd.spawn().expect("spawn");
    let mut stdin = child.stdin().expect("stdin writer");
    stdin.write_all(b"via-the-dup").await.expect("write");
    drop(stdin); // the parent writer is the ONLY write end — drop is EOF for the child
    let mut buf = Vec::new();
    child
        .stdout()
        .expect("stdout reader")
        .read_to_end(&mut buf)
        .await
        .expect("read");
    let _ = child.wait().await;
    assert_eq!(buf, b"via-the-dup");
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
