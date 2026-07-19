//! Async (tokio) raw-`CreateProcessW` backend tests (Plan 12 Tasks 7-8). Windows + tokio only: the
//! raw backend is a Windows concern, and its async mirror needs the tokio runtime.
#![cfg(all(windows, feature = "tokio"))]

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "common/mod.rs"]
mod common;

/// Async twin of sync `executable_independent_of_argv0_on_windows`: the raw backend loads
/// `executable()` while argv[0] is the command line's first token. `argv0-report` echoes both,
/// proving the loaded image (`testbin`) differs from the reported argv[0] (`pretend-name`). The
/// stdout pipe is served by the tokio overlapped-named-pipe machinery.
#[tokio::test]
async fn async_executable_independent_of_argv0() {
    let exe = common::testbin();
    let mut c = subprocess::tokio::Command::new();
    c.executable(exe)
        .commandline("pretend-name argv0-report")
        .stdout(subprocess::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut s = String::new();
    child.stdout().unwrap().read_to_string(&mut s).await.unwrap();
    child.wait().await.unwrap();
    assert!(
        s.contains("argv0=pretend-name") && s.to_lowercase().contains("testbin"),
        "{s}"
    );
}

// Async raw fd >= 3 via the MSVCRT lpReserved2 table (Plan 12 Task 8) =====

/// Async twin of sync `fd3_pipe_out_delivers_child_bytes`: a child-writes pipe on fd 3 delivers the
/// child's bytes to the parent's async read end (`AsyncReadExt`). The fd-table wired fd 3 into the
/// child's CRT; EOF (child closing fd 3 on exit) bounds the read — no timer.
#[tokio::test]
async fn async_fd3_pipe_out_delivers_child_bytes() {
    let mut c = subprocess::tokio::Command::new();
    c.executable(common::testbin())
        .args(["subprocess_testbin", "write-fd", "3", "hi-fd3"])
        .fd(3, subprocess::Stdio::pipe_out())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut r = child.fd_read_end(subprocess::Fd::from(3)).expect("fd 3 reader");
    let mut s = String::new();
    r.read_to_string(&mut s).await.unwrap();
    child.wait().await.unwrap();
    assert_eq!(s, "hi-fd3");
}

/// Async twin of sync `fd3_pipe_in_feeds_child`: a parent-writes pipe on fd 3 feeds the child
/// (`AsyncWriteExt`). The child copies fd 3 to stdout, so dropping the parent's write end (EOF)
/// makes it echo exactly what was written. EOF bounds both reads — no timer.
#[tokio::test]
async fn async_fd3_pipe_in_feeds_child() {
    let mut c = subprocess::tokio::Command::new();
    c.executable(common::testbin())
        .args(["subprocess_testbin", "read-fd", "3"])
        .fd(3, subprocess::Stdio::pipe_in())
        .unwrap()
        .stdout(subprocess::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut w = child.fd_write_end(subprocess::Fd::from(3)).expect("fd 3 writer");
    w.write_all(b"ping3").await.unwrap();
    drop(w); // child reads to EOF, copies, exits
    let mut s = String::new();
    child.stdout().unwrap().read_to_string(&mut s).await.unwrap();
    child.wait().await.unwrap();
    assert_eq!(s, "ping3");
}

// Async containment over the raw backend (Plan 12 Task 8) =====

/// Async twin of sync `contained_raw_child_is_in_our_job_and_kill_tree_reaps`: a CONTAINED child
/// loaded via `executable()` (with fd >= 3) routes through the async raw backend AND lands in OUR
/// Job Object — `test_job_handle_contains_self()` confirms membership (immutable once assigned).
/// fd 3 delivers the child's bytes over the async read end, and `kill_tree()` tears the tree down.
/// EOF (child closing fd 3 on exit) bounds the read — no timer.
#[tokio::test]
async fn async_contained_raw_child_is_in_our_job() {
    let mut c = subprocess::tokio::Command::new();
    c.executable(common::testbin())
        .args(["subprocess_testbin", "write-fd", "3", "x"])
        .fd(3, subprocess::Stdio::pipe_out())
        .unwrap()
        .contain();
    let mut child = c.spawn().expect("contained raw spawn");
    // Fixed at spawn (run-state-independent): the achieved mechanism is the Job Object.
    assert_eq!(child.containment(), subprocess::Containment::JobObject);
    assert!(child.test_job_handle_contains_self(), "child must be inside OUR job");
    let mut r = child.fd_read_end(subprocess::Fd::from(3)).expect("fd 3 reader");
    let mut s = String::new();
    r.read_to_string(&mut s).await.unwrap();
    assert_eq!(s, "x");
    child.kill_tree().expect("kill_tree");
}
