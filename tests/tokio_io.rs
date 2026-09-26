//! Async (tokio) I/O integration tests.
#![cfg(feature = "tokio")]

#[path = "common/mod.rs"]
mod common;

#[tokio::test]
async fn async_spawn_status_reports_exit_code() {
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "exit", "7"]);
    assert_eq!(cmd.status().await.expect("status").code(), Some(7));
}

#[tokio::test]
async fn async_id_is_a_real_stable_identity() {
    // id() returns the stored ProcessId — a real, resolvable identity that survives wait (tokio's
    // own Child::id() would be None after reap).
    use std::io::Write as _;
    let (mut child, mut sock) = common::spawn_blocker_async();
    let id = child.id();
    let p = cosca::Process::from_id(id);
    assert_eq!(p.id(), id);
    assert_eq!(
        p.exists(),
        cosca::identity::Existence::Present,
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "env", "SP_PLAN8"])
        .env("SP_PLAN8", "async");
    let out = cmd.output().await.expect("output");
    assert_eq!(out.stdout, b"SP_PLAN8=async\n");
}

#[tokio::test]
async fn async_output_captures_streams() {
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit", "5", "3"]);
    let out = cmd.output().await.expect("output");
    assert_eq!(out.stdout, vec![b'o'; 5]);
    assert_eq!(out.stderr, vec![b'e'; 3]);
    assert!(out.status.success());
}

#[tokio::test]
async fn async_communicate_is_deadlock_free() {
    // tee-both copies stdin to BOTH stdout and stderr; a non-concurrent reader would deadlock
    // once a pipe buffer fills. Concurrent try_join! must complete with all bytes on both.
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "tee-both"]);
    cmd.stdin(cosca::Stdio::pipe()).unwrap();
    cmd.stdout(cosca::Stdio::pipe()).unwrap();
    cmd.stderr(cosca::Stdio::pipe()).unwrap();
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit", "2", "0"]); // never reads stdin
    cmd.stdin(cosca::Stdio::pipe()).unwrap();
    cmd.stdout(cosca::Stdio::pipe()).unwrap();
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "tee-both"]);
    cmd.stdin(cosca::Stdio::pipe()).unwrap();
    cmd.stdout(cosca::Stdio::pipe()).unwrap();
    cmd.stderr(cosca::Stdio::pipe()).unwrap();
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit-raw", "61", "ff", "62"]);
    let err = cmd.read().await.expect_err("invalid utf-8 must error");
    assert!(matches!(err, cosca::error::Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData));
}

#[test] // NOT #[tokio::test] — verifies the no-runtime guard returns Err (not panic / deferred failure)
fn async_spawn_outside_runtime_errors() {
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "exit", "0"]);
    let err = cmd.spawn().expect_err("spawn outside a tokio runtime must Err");
    assert!(matches!(err, cosca::error::Error::Io(_)), "got {err:?}");
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
            let mut cmd = cosca::tokio::Command::new();
            cmd.executable(common::testbin()).args(["cosca_testbin", "exit", "0"]);
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
        let mut cmd = cosca::tokio::Command::new();
        cmd.executable(common::testbin()).args(["cosca_testbin", "exit", "0"]);
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "exit", "0"]);
    cmd.stdout(cosca::Stdio::merge(cosca::Fd::STDIN)).unwrap();
    cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT)).unwrap();
    let err = cmd.spawn().expect_err("chained merges are unsupported");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
}

#[tokio::test]
async fn async_run_builds_command_from_args() {
    // `run([...])` derives the program from the first arg (mirrors the sync run free fn).
    let s = cosca::tokio::run([common::testbin(), "echo-argv", "world"])
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
    let s = cosca::tokio::run_line(line).read().await.expect("read");
    assert_eq!(s, "hello\n");
}

/// The cgroup leaf a contained tree was placed in, if it got one. Read while the root is alive.
#[cfg(target_os = "linux")]
fn cgroup_leaf_of(child: &cosca::tokio::Child) -> Option<std::path::PathBuf> {
    (child.containment() == cosca::Containment::CgroupV2).then(|| common::cgroup::cgroup_of(child.id().pid()))
}

#[cfg(not(target_os = "linux"))]
fn cgroup_leaf_of(_: &cosca::tokio::Child) -> Option<std::path::PathBuf> {
    None
}

/// Remove the leaf a test's tree left behind, once the tree drains. Call it only after every
/// member has been released or killed.
fn remove_leftover_leaf(leaf: Option<std::path::PathBuf>) {
    #[cfg(target_os = "linux")]
    if let Some(leaf) = leaf {
        common::cgroup::drain_and_remove_leaf(&leaf);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = leaf;
}

#[tokio::test]
async fn async_drop_tears_down_a_contained_tree() {
    use std::io::Read as _;
    let (child, mut root, mut grand) = common::spawn_grandchild_async(true);
    let leaf = cgroup_leaf_of(&child);
    // The containment assert guards the EOFs below from passing for unrelated reasons.
    assert_ne!(
        child.containment(),
        cosca::Containment::None,
        "contained spawn must engage a mechanism"
    );
    drop(child);
    // No post-drop liveness assertion: `Drop` signals and does not wait, and `start_kill` is
    // asynchronous. Each process's death is proven by its own control-socket EOF: a survivor
    // blocks the read (a CI failure).
    for (who, s) in [("root", &mut root), ("grandchild", &mut grand)] {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("{who} not torn down on drop: {other:?}"),
        }
    }
    // The reaper thread drops the leaf after the reap, possibly before the killed grandchild
    // has left it.
    remove_leftover_leaf(leaf);
}

#[tokio::test]
async fn async_drop_after_wait_still_tears_down_the_tree() {
    // After awaiting the root's exit it is already reaped, so `Drop` submits no job at all and the
    // tree teardown must come from attached.hard_kill() — proven by the grandchild's EOF.
    use std::io::{Read as _, Write as _};
    let (mut child, mut root, mut grand) = common::spawn_grandchild_async(true);
    let leaf = cgroup_leaf_of(&child);
    let root_id = child.id();
    root.write_all(b"x").expect("release the root so it exits");
    child.wait().await.expect("wait reaps the root");
    assert_eq!(root_id.is_alive(), cosca::identity::Liveness::Dead, "root exited");
    drop(child); // root already reaped → nothing submitted; attached.hard_kill must still kill the grandchild
    let mut buf = [0u8; 1];
    match grand.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("grandchild not torn down by hard_kill after the root was waited: {other:?}"),
    }
    // This `Drop` ran on this thread, and waits for the leaf to drain before removing it.
    if let Some(leaf) = leaf {
        assert!(
            !leaf.exists(),
            "Drop must remove the leaf once it drains: {}",
            leaf.display()
        );
    }
}

#[tokio::test]
async fn async_detach_leaves_the_tree_running() {
    use std::io::{Read as _, Write as _};
    let (mut child, mut root, grand) = common::spawn_grandchild_async(true);
    let leaf = cgroup_leaf_of(&child);
    let root_id = child.id();
    child.detach();
    drop(child); // detached → Drop must NOT kill
                 // Positive liveness (no race — we never signaled it): a buggy detach that let Drop kill the
                 // root would make this false.
    assert_eq!(
        root_id.is_alive(),
        cosca::identity::Liveness::Alive,
        "detach must leave the root running after the handle drops"
    );
    // Release it and observe a CLEAN voluntary exit (Ok(0) EOF), distinct from a kill's reset.
    root.write_all(b"x").expect("release the live root");
    let mut buf = [0u8; 1];
    assert!(
        matches!(root.read(&mut buf), Ok(0)),
        "released root exits cleanly (EOF)"
    );
    drop(grand); // its socket closes → the reparented grandchild exits
    remove_leftover_leaf(leaf);
}

#[tokio::test]
async fn async_kill_on_drop_false_leaves_the_root_running() {
    // `kill_on_drop(false)` hits the async Drop early-return, so the teardown (hard_kill + the
    // root's kill) must not run and the root stays alive. Proven by positive liveness on the
    // never-signaled root (race-free, mirroring async_detach_leaves_the_tree_running).
    // UNCONTAINED on purpose: `Attached::None` isolates the early-return itself from the
    // containment resource's own drop, which
    // `async_kill_on_drop_false_leaves_a_contained_tree_running` covers separately.
    use std::io::{Read as _, Write as _};
    let (child, mut root, _grand) = common::spawn_grandchild_async_with(false, false);
    let root_id = child.id();
    drop(child); // kill_on_drop(false) → Drop early-returns; teardown must NOT run
    assert_eq!(
        root_id.is_alive(),
        cosca::identity::Liveness::Alive,
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

#[tokio::test]
async fn async_kill_on_drop_false_leaves_a_contained_tree_running() {
    // The spawn disarms the resource (see `Attached::honor_kill_on_drop`). On Linux outside the
    // cgroup lane this is a process group, whose disarm is a no-op;
    // `linux_cgroup_v2_async_kill_on_drop_false_leaves_the_tree_running` pins the leaf's.
    use std::io::{Read as _, Write as _};
    let (child, mut root, grand) = common::spawn_grandchild_async_with(true, false);
    assert_ne!(
        child.containment(),
        cosca::Containment::None,
        "contained spawn must engage a mechanism"
    );
    let leaf = cgroup_leaf_of(&child);
    let root_id = child.id();
    drop(child); // contained + kill_on_drop(false) → nothing may kill the tree
    assert_eq!(
        root_id.is_alive(),
        cosca::identity::Liveness::Alive,
        "kill_on_drop(false) must leave a CONTAINED tree running after the handle drops"
    );
    root.write_all(b"x").expect("release the live root");
    let mut buf = [0u8; 1];
    assert!(
        matches!(root.read(&mut buf), Ok(0)),
        "released root exits cleanly (EOF)"
    );
    drop(grand); // its socket closes → the reparented grandchild exits
    remove_leftover_leaf(leaf);
}

/// `detach()` must leave a cgroup-contained tree running: `CgroupLeaf::drop` kills an occupied
/// leaf unless the detach disarmed it. Proven by a byte round trip through both members.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn linux_cgroup_v2_async_detach_leaves_the_tree_running() {
    common::cgroup::require_lane();
    assert_async_opted_out_tree_survives(true, |mut child| child.detach());
}

/// `kill_on_drop(false)` must leave a cgroup-contained tree running, as `detach()` does (see
/// `Attached::honor_kill_on_drop`).
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn linux_cgroup_v2_async_kill_on_drop_false_leaves_the_tree_running() {
    common::cgroup::require_lane();
    assert_async_opted_out_tree_survives(false, drop);
}

/// Async twin of `linux_cgroup_v2_kill_on_drop_false_kill_tree_still_waits_for_the_leaf_to_drain`
/// in `spawn_io.rs`: `kill_on_drop(false)` hits `Child::drop`'s early return (see its doc), so
/// tokio's own teardown never runs — but `os.attached` (the `CgroupLeaf`) still drops as an
/// ordinary struct field the moment `Child::drop` returns, on this thread, and its own `Drop`
/// must wait for an already-fired `kill_tree()`'s drain before its `rmdir`, exactly as the sync
/// `Child` does.
///
/// No `wait_tree()` before the drop: that would force the drain itself and mask the race.
///
/// This is a real-kernel regression check, not the deterministic proof of the fix: the leaf being
/// gone when `drop` returns is also what the pre-fix single, unwaited `rmdir` would produce if the
/// drain happens to finish first — which `let _ = child.wait().await` reaping the root just above
/// makes likely, since the kernel has to reap every member before that call returns. The unit test
/// `a_disarmed_leaf_whose_tree_was_killed_removes_itself_only_after_it_drains` (`leaf_tests.rs`)
/// is what deterministically forces the race and proves `Drop` itself waits — no sleeps, no
/// polling from the test.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn linux_cgroup_v2_async_kill_on_drop_false_kill_tree_still_waits_for_the_leaf_to_drain() {
    common::cgroup::require_lane();
    common::install_log_capture();
    let common::AsyncEchoTree {
        mut child,
        root,
        grand,
        grand_pid,
    } = common::spawn_echo_tree_async(false);
    assert_eq!(child.containment(), cosca::Containment::CgroupV2);
    let leaf = common::cgroup::cgroup_of(grand_pid);

    let mark = common::log_mark();
    child.kill_tree().expect("kill_tree");
    let _ = child.wait().await; // reap the root
    drop(child); // no wait_tree(): Drop alone must wait for the drain before its rmdir

    assert!(
        !leaf.exists(),
        "an explicit kill_tree(), even through a handle that opted out of kill_on_drop, must \
         wait for the leaf to drain before Drop's rmdir: {}",
        leaf.display()
    );
    assert!(
        !common::contains_since(mark, &format!("{} was not removed", leaf.display())),
        "Drop must not report this leaf left behind once it waited for the drain"
    );
    drop((root, grand));
}

/// Shared body of the two async cgroup opt-out tests: assert the tree got `CgroupV2`, release
/// the handle through `opt_out`, prove both members alive, then remove the leaf the tree keeps.
#[cfg(target_os = "linux")]
fn assert_async_opted_out_tree_survives(kill_on_drop: bool, opt_out: impl FnOnce(cosca::tokio::Child)) {
    let common::AsyncEchoTree {
        child,
        mut root,
        mut grand,
        grand_pid,
    } = common::spawn_echo_tree_async(kill_on_drop);
    assert_eq!(
        child.containment(),
        cosca::Containment::CgroupV2,
        "a process group's disarm is a no-op, so only CgroupV2 tests the leaf's"
    );
    let leaf = common::cgroup::cgroup_of(grand_pid);
    assert!(
        leaf.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("cosca-")),
        "the tree must be in a cosca leaf, got {}",
        leaf.display()
    );

    opt_out(child);

    common::assert_echoes(&mut root, "the opted-out root");
    common::assert_echoes(&mut grand, "the opted-out grandchild");

    // Release both: each read returns Ok(0) and the member exits on its own.
    drop(root);
    drop(grand);
    common::cgroup::drain_and_remove_leaf(&leaf);
}

// `async_drop_leaves_no_zombie` moved to `drop_reaps_on_a_worker_thread` in
// `src/tokio/child/reaper_tests.rs`: once `Drop` returns before the reap, only the
// `#[cfg(test)]` probe offers an edge to sequence the no-zombie check after.

// Arbitrary fd (n>=3) — Unix only, wired via command-fds (async mirror of spawn_io.rs) =====

/// Async twin of sync `unix_fd3_pipe_round_trips`: the testbin's `fd3-echo` mode reads fd 3
/// and copies it to stdout. Write a known payload into the parent write end, close it (EOF),
/// read stdout to EOF — no timers, fully deterministic.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd3_pipe_round_trips() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "fd3-echo"]);
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, cosca::Stdio::pipe_in()).expect("fd 3 pipe_in");
    let mut child = cmd.spawn().expect("spawn with fd 3");
    let mut stdout = child.stdout().expect("stdout reader");
    let mut fd3_writer = child.fd_write_end(cosca::Fd::from(3)).expect("fd 3 writer");

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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "fd3-echo"]);
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, cosca::Stdio::null()).expect("fd 3 null");
    let mut child = cmd.spawn().expect("spawn with null fd 3");
    let mut stdout = child.stdout().expect("stdout reader");
    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).await.expect("read stdout");
    let status = child.wait().await.expect("reap");
    assert!(buf.is_empty(), "null fd 3 is immediate EOF — no echo, got {buf:?}");
    assert_eq!(status.code(), Some(0));
}

// Windows fd >= 3 routes through the async raw `CreateProcessW` backend (Plan 12 Task 8): the
// MSVCRT fd-table wires the descriptor and the parent end is the overlapped-named-pipe async end.
// Its round-trips (both directions) + contained twin live in `tests/raw_windows_async.rs`,
// alongside the rest of the raw-backend proofs.

/// fd 3 as pipe_out: the testbin's `fd3-write` mode writes a token to fd 3; the parent
/// reads it back via the reactor-registered `fd_read_end`.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd3_pipe_out_delivers_child_bytes() {
    use tokio::io::AsyncReadExt;
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "fd3-write", "fd3-token"]);
    cmd.fd(3, cosca::Stdio::pipe_out()).expect("fd 3 pipe_out");
    let mut child = cmd.spawn().expect("spawn with fd 3 out");
    let mut fd3_reader = child.fd_read_end(cosca::Fd::from(3)).expect("fd 3 reader");
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "fd3-echo"]);
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, cosca::Stdio::pipe_in()).expect("fd 3 pipe_in");
    let mut child = cmd.spawn().expect("spawn");
    assert!(
        child.fd_read_end(cosca::Fd::from(3)).is_none(),
        "wrong direction is None"
    );
    let mut w = child
        .fd_write_end(cosca::Fd::from(3))
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "fd3-write", "still-here"]);
    cmd.fd(3, cosca::Stdio::pipe_out()).expect("fd 3 pipe_out");
    let mut child = cmd.spawn().expect("spawn");
    assert!(
        child.fd_write_end(cosca::Fd::from(3)).is_none(),
        "wrong direction is None"
    );
    let mut r = child
        .fd_read_end(cosca::Fd::from(3))
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
    let mut cmd = cosca::tokio::Command::new();
    // Same scenario as sync merge_stderr_onto_stdout_combines_output (tests/spawn_io.rs):
    // emit 3 bytes to stdout, 2 to stderr; merged, all 5 arrive on the one stdout pipe.
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit", "3", "2"]);
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT))
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit", "3", "2"]);
    cmd.stdout(cosca::Stdio::null()).expect("stdout null");
    cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT))
        .expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn");
    let status = child.wait().await.expect("reap");
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn async_communicate_reads_a_merged_stream() {
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit", "3", "2"]);
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT))
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit", "3", "2"]);
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT))
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit", "5", "0"]);
    cmd.stdin(cosca::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(cosca::Stdio::null()).expect("stderr null");
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "emit", "3", "0"]);
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "stdin-split-echo", "3"]);
    cmd.stdin(cosca::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDIN))
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "fd3-write", "fd3-merged"]);
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, cosca::Stdio::merge(cosca::Fd::STDOUT))
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
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin()).args(["cosca_testbin", "fd3-echo"]);
    cmd.stdin(cosca::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(cosca::Stdio::pipe()).expect("stdout pipe");
    cmd.fd(3, cosca::Stdio::merge(cosca::Fd::STDIN))
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
        cosca::Containment::JobObject,
        "Windows Strongest => JobObject"
    );
    drop(child);
    // As in `async_drop_tears_down_a_contained_tree`: `Drop` does not wait, so the control-socket
    // EOFs are the real edges.
    for (who, s) in [("root", &mut root), ("grandchild", &mut grand)] {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("{who} not torn down: {other:?}"),
        }
    }
}
