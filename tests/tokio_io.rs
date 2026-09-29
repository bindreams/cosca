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
    let (mut child, mut sock) = common::spawn_blocker_async().await;
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
    let (mut child, mut sock) = common::spawn_blocker_async().await;
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
    let (child, mut root, mut grand) = common::spawn_grandchild_async(true).await;
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
    // `Drop` releases the leaf right after the kill without waiting for the drain, so the killed
    // members may not have left it yet.
    remove_leftover_leaf(leaf);
}

/// Either the leaf `Drop` was given is gone and no warning names it, or it is still there and a
/// warning at `warn` does. `Drop` writes `cgroup.kill` and reads the drain once: whether the kernel
/// has finished the kill by then is not this test's to decide, and `Drop` waits for neither.
#[cfg(target_os = "linux")]
fn assert_leaf_gone_or_warned_about(leaf: &std::path::Path, mark: usize) {
    let levels = common::levels_since(mark, &leaf.display().to_string());
    if leaf.exists() {
        assert!(
            levels.contains(&log::Level::Warn),
            "a leaf left behind must be warned about, got {levels:?}: {}",
            leaf.display()
        );
    } else {
        assert!(
            !levels.contains(&log::Level::Warn),
            "a leaf that was removed must not be warned about, got {levels:?}: {}",
            leaf.display()
        );
    }
}

#[tokio::test]
async fn async_drop_after_wait_still_tears_down_the_tree() {
    // After awaiting the root's exit it is already reaped, so the drop has no root to signal and
    // the tree teardown must come from attached.hard_kill() — proven by the grandchild's EOF.
    // The drop stays the killer: `wait_tree` never kills, so waiting on it first would hang.
    use std::io::{Read as _, Write as _};
    common::install_log_capture();
    let (mut child, mut root, mut grand) = common::spawn_grandchild_async(true).await;
    let leaf = cgroup_leaf_of(&child);
    let root_id = child.id();
    root.write_all(b"x").expect("release the root so it exits");
    child.wait().await.expect("wait reaps the root");
    assert_eq!(root_id.is_alive(), cosca::identity::Liveness::Dead, "root exited");
    let mark = common::log_mark();
    drop(child); // root already reaped → nothing to signal; attached.hard_kill must still kill the grandchild
    let mut buf = [0u8; 1];
    match grand.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("grandchild not torn down by hard_kill after the root was waited: {other:?}"),
    }
    // `Drop` releases the leaf without waiting for the drain: the leaf is removed if the kill had
    // finished by then, and left with a warning if not.
    #[cfg(target_os = "linux")]
    if let Some(leaf) = &leaf {
        assert_leaf_gone_or_warned_about(leaf, mark);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = mark;
    remove_leftover_leaf(leaf);
}

#[tokio::test]
async fn async_detach_leaves_the_tree_running() {
    use std::io::{Read as _, Write as _};
    let (mut child, mut root, grand) = common::spawn_grandchild_async(true).await;
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
    let (child, mut root, _grand) = common::spawn_grandchild_async_with(false, false).await;
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
    let (child, mut root, grand) = common::spawn_grandchild_async_with(true, false).await;
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
async fn linux_cgroup_v2_async_detach_leaves_the_tree_running() {
    if !common::require_group("CGROUP") {
        return;
    }
    assert_async_opted_out_tree_survives(true, |mut child| child.detach()).await;
}

/// `kill_on_drop(false)` must leave a cgroup-contained tree running, as `detach()` does (see
/// `Attached::honor_kill_on_drop`).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_cgroup_v2_async_kill_on_drop_false_leaves_the_tree_running() {
    if !common::require_group("CGROUP") {
        return;
    }
    assert_async_opted_out_tree_survives(false, drop).await;
}

/// Async twin of `linux_cgroup_v2_kill_on_drop_false_kill_tree_still_waits_for_the_leaf_to_drain`
/// in `spawn_io.rs`, with the wait made explicit: the async `Drop` never waits for a drain, so an
/// opted-out handle that killed its tree removes the leaf only if the caller awaited the drain
/// first.
///
/// `kill_tree()`, `wait()` for the root, and `wait_tree().await` for the drain. After it the leaf
/// reads `populated 0`, so the drop's one `rmdir` removes it, and nothing is warned.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_cgroup_v2_async_kill_tree_then_wait_tree_then_drop_leaves_no_leaf() {
    if !common::require_group("CGROUP") {
        return;
    }
    common::install_log_capture();
    let common::AsyncEchoTree {
        mut child,
        root,
        grand,
        grand_pid,
    } = common::spawn_echo_tree_async(false).await;
    assert_eq!(child.containment(), cosca::Containment::CgroupV2);
    let leaf = common::cgroup::cgroup_of(grand_pid);

    let mark = common::log_mark();
    child.kill_tree().expect("kill_tree");
    child.wait().await.expect("reap the root");
    child.wait_tree().await.expect("wait_tree");
    drop(child);

    assert!(
        !leaf.exists(),
        "a drop after wait_tree must find the leaf drained and remove it: {}",
        leaf.display()
    );
    assert_eq!(
        common::levels_since(mark, &leaf.display().to_string()),
        Vec::<log::Level>::new(),
        "a leaf that was removed must not be warned about"
    );
    drop((root, grand));
}

/// `kill_tree()` is not called: the drop alone is the killer. A member the test itself spawned and
/// placed in the leaf dies of `SIGKILL`, which the test reads by reaping it (a grandchild of the
/// root cannot be reaped here, because tokio owns the root's children's parent).
///
/// Whether the drain has finished by the drop's single read is a race this test does not depend
/// on: either the leaf is gone and nothing warned, or it is left and a warning names it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_cgroup_v2_async_drop_alone_kills_the_members_and_logs_the_leftover() {
    use std::io::Read as _;
    use std::os::unix::process::ExitStatusExt as _;

    if !common::require_group("CGROUP") {
        return;
    }
    common::install_log_capture();
    let common::AsyncEchoTree {
        child,
        mut root,
        mut grand,
        grand_pid,
    } = common::spawn_echo_tree_async(true).await;
    assert_eq!(child.containment(), cosca::Containment::CgroupV2);
    let leaf = common::cgroup::cgroup_of(grand_pid);

    // A member of the test's own, blocked on its stdin and placed in the leaf.
    let mut member = {
        let _spawn = cosca::test_spawn_lock();
        std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn a member")
    };
    let member_stdin = member.stdin.take().expect("the member's piped stdin");
    std::fs::OpenOptions::new()
        .write(true)
        .open(leaf.join("cgroup.procs"))
        .and_then(|mut procs| std::io::Write::write_all(&mut procs, member.id().to_string().as_bytes()))
        .expect("place the member in the leaf");
    assert_eq!(
        common::cgroup::cgroup_of(member.id()),
        leaf,
        "the member must be in the tree's leaf"
    );

    let mark = common::log_mark();
    drop(child);

    // `cgroup.kill` signalled the member before its stdin closes, so it dies of SIGKILL rather
    // than of the end of its input.
    drop(member_stdin);
    let status = member.wait().expect("reap the member");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the drop must kill the leaf's members"
    );
    for (who, s) in [("root", &mut root), ("grandchild", &mut grand)] {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("{who} not torn down on drop: {other:?}"),
        }
    }
    assert_leaf_gone_or_warned_about(&leaf, mark);
    common::cgroup::drain_and_remove_leaf(&leaf);
}

/// Shared body of the two async cgroup opt-out tests: assert the tree got `CgroupV2`, release
/// the handle through `opt_out`, prove both members alive, then remove the leaf the tree keeps.
#[cfg(target_os = "linux")]
async fn assert_async_opted_out_tree_survives(kill_on_drop: bool, opt_out: impl FnOnce(cosca::tokio::Child)) {
    let common::AsyncEchoTree {
        child,
        mut root,
        mut grand,
        grand_pid,
    } = common::spawn_echo_tree_async(kill_on_drop).await;
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

// There is no zombie check for a dropped root: tokio's orphan queue reaps it, best-effort, once a
// runtime next sees `SIGCHLD`, and cosca offers no edge to sequence one after
// (`docs/principles.md`, principle 3).

// Arbitrary fd (n>=3) — Unix only, wired via fd_map (async mirror of spawn_io.rs) =====

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

/// Async twin of sync `unix_fd_out_of_range_fails_spawn_cleanly_not_abort`: an out-of-range but
/// syscall-representable child fd (far beyond any real process' open-file limit) must fail the
/// SPAWN with an ordinary `Err` — never `Ok` followed by the child dying of SIGABRT.
///
/// Deliberately NOT `i32::MAX` (that's `async_unix_fd_i32_max_fails_spawn_cleanly_not_abort`,
/// the pathological edge that used to overflow `command-fds`' own arithmetic): this test's own
/// `child_fd`, 100_000, only fails because `RestoreRlimitNofile` deterministically lowers this
/// process' `RLIMIT_NOFILE` first — see the sync twin's doc for why a fixed large value alone is
/// runner-dependent on Linux.
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd_out_of_range_fails_spawn_cleanly_not_abort() {
    let _rlimit_guard = common::RestoreRlimitNofile::lower_to(256);

    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "exit", "0"])
        .fd(100_000, cosca::Stdio::null())
        .expect("fd() itself accepts an out-of-range but representable number");
    let err = cmd
        .spawn()
        .expect_err("dup2 onto an unachievable fd number must fail the spawn with Err, not abort");
    let cosca::error::Error::Io(io_err) = err else {
        panic!("expected a plain Io error (propagated via the child's error pipe), got {err:?}");
    };
    assert_eq!(
        io_err.raw_os_error(),
        Some(libc::EBADF),
        "dup2 onto an out-of-range target must fail with EBADF specifically, got {io_err:?}"
    );
}

/// Async twin of sync `unix_fd_i32_max_fails_spawn_cleanly_not_abort`: `fd(i32::MAX, ...)` must
/// fail — never abort the child — with an ordinary `Err` from `spawn()`. `Command::fd()` itself
/// accepts `i32::MAX`; the failure happens post-fork, at `dup2`, exactly like any other
/// out-of-range child fd (`EBADF`).
#[cfg(unix)]
#[tokio::test]
async fn async_unix_fd_i32_max_fails_spawn_cleanly_not_abort() {
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "exit", "0"])
        .fd(i32::MAX, cosca::Stdio::null())
        .expect("fd() itself accepts i32::MAX — install() does too");
    let err = cmd
        .spawn()
        .expect_err("dup2 onto i32::MAX must fail the spawn with Err, not abort");
    let cosca::error::Error::Io(io_err) = err else {
        panic!("expected a plain Io error (propagated via the child's error pipe), got {err:?}");
    };
    assert_eq!(
        io_err.raw_os_error(),
        Some(libc::EBADF),
        "dup2 onto i32::MAX must fail with EBADF specifically, got {io_err:?}"
    );
}

/// Async twin of sync `a_mapped_fd_does_not_leak_into_a_stderr_pipe_when_fd2_is_closed`: with
/// this process' own fd 2 closed and freed, a plain `fd(3, null)` mapping must not end up
/// readable as the child's stderr just because `install()`'s own bookkeeping happens to source
/// or park something at that exact number. `sh -c 'echo LEAK >&3'` writes to the child's fd 3;
/// the parent's stderr pipe must receive nothing.
#[cfg(unix)]
#[tokio::test]
async fn async_a_mapped_fd_does_not_leak_into_a_stderr_pipe_when_fd2_is_closed() {
    use tokio::io::AsyncReadExt;

    let _restore = common::RestoreStdio::close(&[2]);

    let mut cmd = cosca::tokio::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "echo LEAK >&3"]);
    cmd.stderr(cosca::Stdio::pipe()).expect("stderr pipe");
    cmd.fd(3, cosca::Stdio::null()).expect("fd 3 null");
    let mut child = cmd.spawn().expect("spawn");
    let mut stderr = child.stderr().expect("stderr reader");
    let mut buf = Vec::new();
    stderr.read_to_end(&mut buf).await.expect("read stderr");
    let _ = child.wait().await;

    assert!(
        buf.is_empty(),
        "the stderr pipe must not receive fd 3's bytes ('LEAK'), got {buf:?}"
    );
}

/// Async twin of sync `relocating_a_low_parent_fd_keeps_spawn_errors_reported`: with this
/// process' own fd 1 and fd 2 closed, `.stdout(Stdio::from_file(...))` and
/// `.stderr(Stdio::from_file(...))`'s `try_clone`s land their dup'd targets at 3 or above (the
/// from_file source files are already open at some higher number before `spawn()` even starts
/// resolving anything). What lands at fd 1 and fd 2 instead are the `fd(5, null)` and `fd(6,
/// null)` mappings' own null sources — the lowest numbers free at the point each is opened —
/// followed by an always-invalid `fd(i32::MAX, null)` mapping (`i32::MAX` exceeds Linux's
/// `nr_open` ceiling, so it fails `dup2` regardless of the runner's own `ulimit -n`; the exact
/// numeric value isn't otherwise significant here — only that it reliably fails). Relocating a
/// low mapping source out of `install()` must not free that exact number back to the OS before
/// `std_cmd.spawn()`'s own internal fd allocation (its child-to-parent error-reporting pipe) is
/// done with it — see `fd_map::install`'s module docs. The spawn must fail cleanly (`Err`), and
/// the stderr file must receive nothing (no leaked exec-error-pipe bytes).
#[cfg(unix)]
#[tokio::test]
async fn async_relocating_a_low_parent_fd_keeps_spawn_errors_reported() {
    use std::io::{Read, Seek, SeekFrom};

    let out_f = tempfile::tempfile().expect("tempfile for stdout target");
    let mut err_f = tempfile::tempfile().expect("tempfile for stderr target");

    let _restore = common::RestoreStdio::close(&[1, 2]);

    let mut cmd = cosca::tokio::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "true"]);
    cmd.stdout(cosca::Stdio::from_file(out_f.try_clone().expect("clone stdout target")))
        .expect("stdout from_file");
    cmd.stderr(cosca::Stdio::from_file(err_f.try_clone().expect("clone stderr target")))
        .expect("stderr from_file");
    cmd.fd(5, cosca::Stdio::null()).expect("fd 5 null");
    cmd.fd(6, cosca::Stdio::null()).expect("fd 6 null");
    cmd.fd(i32::MAX, cosca::Stdio::null()).expect("fd i32::MAX null");

    let err = cmd
        .spawn()
        .expect_err("a relocated low parent fd must fail the spawn cleanly, not corrupt it into Ok");

    let mut buf = Vec::new();
    err_f.seek(SeekFrom::Start(0)).expect("seek stderr target");
    err_f.read_to_end(&mut buf).expect("read stderr target");

    assert!(
        matches!(err, cosca::error::Error::Io(_)),
        "expected a plain Io error, got {err:?}"
    );
    assert!(
        buf.is_empty(),
        "the stderr target file must receive nothing — no leaked exec-error-pipe bytes, got {buf:?}"
    );
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
/// end through fd_map (never silently dropped). testbin's `fd3-write` emits its token
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
    let (child, mut root, mut grand) = common::spawn_grandchild_async(true).await;
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

// Death-watched accept =====

/// Awaits `fut` on this test's own thread and returns the message it panicked with. The runtime is
/// `current_thread`, so a spawned task runs on this thread and the thread-local
/// `common::last_reported_grandchild` is visible to the test.
async fn panic_message_of<T: Send + 'static>(fut: impl std::future::Future<Output = T> + Send + 'static) -> String {
    let join_err = match ::tokio::spawn(fut).await {
        Ok(_) => panic!("the future returned instead of panicking"),
        Err(e) => e,
    };
    assert!(join_err.is_panic(), "expected the task to panic, got: {join_err:?}");
    common::panic_message(join_err.into_panic())
}

fn assert_died_before_connecting(message: &str, pid: u32) {
    assert!(
        message.contains(&format!("the control target (pid {pid}) died before it connected")),
        "expected pid {pid} to be reported as died before it connected, got: {message:?}"
    );
}

/// Async sibling of the sync `spawn_control_panics_if_its_death_watch_is_ever_reverted_to_a_plain_accept`
/// regression in `tests/process.rs` — same mutant coverage, for `spawn_control_async`.
#[tokio::test(flavor = "current_thread")]
async fn spawn_control_async_panics_if_its_death_watch_is_ever_reverted_to_a_plain_accept() {
    let message = panic_message_of(common::spawn_control_async("--not-a-real-mode", &[], false)).await;
    assert!(message.contains("died before it connected"), "got: {message:?}");
}

/// Async sibling of `spawn_tree_panics_if_its_death_watch_is_ever_reverted_to_a_plain_accept`.
#[tokio::test(flavor = "current_thread")]
async fn spawn_tree_async_panics_if_its_death_watch_is_ever_reverted_to_a_plain_accept() {
    let message = panic_message_of(common::spawn_tree_async("--not-a-real-mode", |_| {})).await;
    assert!(message.contains("died before it connected"), "got: {message:?}");
}

fn bind_and_spawn(args: &[&str], ack: bool) -> (::tokio::net::TcpListener, cosca::tokio::Child) {
    let (listener, addr) = common::bind_async_listener();
    let mut cmd = cosca::tokio::Command::new();
    let mut argv = vec![common::testbin().to_string()];
    argv.extend(args.iter().map(|a| a.replace("{addr}", &addr)));
    cmd.args(argv);
    if ack {
        cmd.env(common::ACK_ENV, "1");
    }
    (listener, cmd.spawn().expect("spawn"))
}

/// A target that dies before connecting makes `accept_or_die_async` panic naming it, not hang.
#[tokio::test(flavor = "current_thread")]
async fn accept_or_die_async_panics_loudly_when_the_target_dies_first() {
    let (listener, mut child) = bind_and_spawn(&["--not-a-real-mode"], false);
    let pid = child.id().pid();
    let message = panic_message_of(async move { common::accept_or_die_async(&listener, &mut child).await }).await;
    assert_died_before_connecting(&message, pid);
}

/// A target that connects and exits without waiting for the ack is dead whether or not its
/// connection reached the accept queue. The child is awaited to completion first.
#[tokio::test(flavor = "current_thread")]
async fn accept_or_die_async_reports_a_target_that_connected_and_exited_without_the_ack_as_dead() {
    let (listener, mut child) = bind_and_spawn(&["control-once", "{addr}", "R"], false);
    let pid = child.id().pid();
    let status = child.wait().await.expect("wait for the target to exit");
    assert!(status.success(), "control-once should exit 0, got {status}");
    let message = panic_message_of(async move { common::accept_or_die_async(&listener, &mut child).await }).await;
    assert_died_before_connecting(&message, pid);
}

/// An opted-in target sends its tag only after `accept_or_die_async` wrote the ack.
#[tokio::test(flavor = "current_thread")]
async fn accept_or_die_async_acks_the_connection_it_accepts() {
    use std::io::{Read as _, Write as _};
    let (listener, mut child) = bind_and_spawn(&["control-block", "{addr}", "R"], true);
    let mut sock = common::accept_or_die_async(&listener, &mut child).await;
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("the acked target sends its tag");
    assert_eq!(&tag, b"R");
    sock.write_all(b"x").expect("release");
    child.wait().await.expect("reap");
}

/// Async twin of `accept_or_die_also_reports_a_gone_descendant_as_dead`.
#[tokio::test(flavor = "current_thread")]
async fn accept_or_die_async_also_reports_a_gone_descendant_as_dead() {
    use std::process::Stdio;
    let (listener, mut target) = bind_and_spawn(&["sleep-marker"], false);
    let mut gone = std::process::Command::new(common::testbin())
        .arg("hold-until-stdin-eof")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn the descendant");
    let gone_id = cosca::identity::ProcessId::of(gone.id())
        .found()
        .expect("the live descendant resolves");
    drop(gone.stdin.take());
    gone.wait().expect("reap the descendant: its identity is now Gone");
    drop(gone); // Windows: closing the handle is what makes `OpenProcess` fail for the pid

    let message =
        panic_message_of(async move { common::accept_or_die_async_also(&listener, &mut target, Some(gone_id)).await })
            .await;
    assert_died_before_connecting(&message, gone_id.pid());
}

/// Only the GRANDCHILD dies (root alive, connected): the panic names the grandchild the root
/// reported.
#[tokio::test(flavor = "current_thread")]
async fn spawn_tree_async_panics_when_the_grandchild_dies_before_connecting_while_the_root_lives() {
    let message = panic_message_of(common::spawn_tree_async("spawn-grandchild-dies", |_| {})).await;
    let grandchild = common::last_reported_grandchild().expect("the root reported its grandchild");
    assert_died_before_connecting(&message, grandchild);
}

/// [`spawn_echo_tree_async`]'s twin of the test above.
#[tokio::test(flavor = "current_thread")]
async fn spawn_echo_tree_async_panics_when_the_grandchild_dies_before_connecting_while_the_root_lives() {
    let message = panic_message_of(common::spawn_echo_tree_async_mode("spawn-grandchild-echo-dies", true)).await;
    let grandchild = common::last_reported_grandchild().expect("the root reported its grandchild");
    assert_died_before_connecting(&message, grandchild);
}

/// The root reports a live grandchild, then exits without connecting: the main loop fails on the
/// root.
#[tokio::test(flavor = "current_thread")]
async fn spawn_tree_async_panics_when_the_root_dies_after_reporting_before_connecting() {
    let message = panic_message_of(common::spawn_tree_async("spawn-grandchild-report-then-exit", |_| {})).await;
    let grandchild = common::last_reported_grandchild().expect("the root reported before it exited");
    assert!(message.contains("died before it connected"), "got: {message:?}");
    assert!(
        !message.contains(&format!("(pid {grandchild})")),
        "the live grandchild must not be the one blamed: {message:?}"
    );
}

/// The root connects to the report address and exits without reporting.
#[tokio::test(flavor = "current_thread")]
async fn spawn_tree_async_panics_when_the_root_dies_before_reporting_the_grandchild_pid() {
    let message = panic_message_of(common::spawn_tree_async("spawn-grandchild-report-eof", |_| {})).await;
    assert!(
        message.contains("died before it reported the grandchild pid"),
        "got: {message:?}"
    );
}
