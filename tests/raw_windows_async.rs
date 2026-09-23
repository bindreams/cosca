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
    let mut c = cosca::tokio::Command::new();
    c.executable(exe)
        .commandline("pretend-name argv0-report")
        .stdout(cosca::Stdio::pipe())
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
    let mut c = cosca::tokio::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "write-fd", "3", "hi-fd3"])
        .fd(3, cosca::Stdio::pipe_out())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut r = child.fd_read_end(cosca::Fd::from(3)).expect("fd 3 reader");
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
    let mut c = cosca::tokio::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "read-fd", "3"])
        .fd(3, cosca::Stdio::pipe_in())
        .unwrap()
        .stdout(cosca::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut w = child.fd_write_end(cosca::Fd::from(3)).expect("fd 3 writer");
    w.write_all(b"ping3").await.unwrap();
    drop(w); // child reads to EOF, copies, exits
    let mut s = String::new();
    child.stdout().unwrap().read_to_string(&mut s).await.unwrap();
    child.wait().await.unwrap();
    assert_eq!(s, "ping3");
}

/// Async twin of the sync `argv_only_fd3_routes_through_the_raw_backend_and_works`: an argv-only
/// tokio `Command` (no `.executable()`) that maps fd >= 3 still routes through the ASYNC raw
/// backend. std has no way to hand a child fd >= 3 on Windows at all: `spawn_unelevated`'s fd >= 3
/// collection loop is `#[cfg(unix)]`-gated (`src/child/spawn.rs`), so fd 3 actually delivering the
/// marker bytes below is itself proof this went through the raw backend.
#[tokio::test]
async fn async_argv_only_fd3_routes_through_the_raw_backend_and_works() {
    let mut c = cosca::tokio::Command::new();
    c.args([common::testbin(), "write-fd", "3", "argv-only-fd3"])
        .fd(3, cosca::Stdio::pipe_out())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn via the argv-only + fd>=3 route");
    let mut r = child.fd_read_end(cosca::Fd::from(3)).expect("fd 3 reader");
    let mut s = String::new();
    r.read_to_string(&mut s).await.unwrap();
    assert!(child.wait().await.unwrap().success());
    assert_eq!(s, "argv-only-fd3");
}

/// Async twin of the sync `commandline_only_fd3_routes_through_the_raw_backend_and_works`: a tokio
/// `Command` built with `.commandline(...)` instead of `.args(...)`, no `.executable()`, that maps
/// fd >= 3 — exercising `program_token`'s `CommandLine` arm (`first_token_wide`) through the ASYNC
/// raw backend, a different code path from the argv-only test above. Same proof shape: std has no
/// way to hand a child fd >= 3 on Windows at all (`spawn_unelevated`'s fd >= 3 collection loop is
/// `#[cfg(unix)]`-gated, `src/child/spawn.rs`), so fd 3 delivering the marker bytes below is itself
/// proof this went through the raw backend via the `CommandLine` token.
#[tokio::test]
async fn async_commandline_only_fd3_routes_through_the_raw_backend_and_works() {
    let wide_args: Vec<Vec<u16>> = [common::testbin(), "write-fd", "3", "commandline-only-fd3"]
        .iter()
        .map(|a| a.encode_utf16().collect())
        .collect();
    let refs: Vec<&[u16]> = wide_args.iter().map(Vec::as_slice).collect();
    let line = String::from_utf16(&cosca::quote::windows::join_wide(&refs)).unwrap();

    let mut c = cosca::tokio::Command::new();
    c.commandline(line).fd(3, cosca::Stdio::pipe_out()).unwrap();
    let mut child = c.spawn().expect("raw spawn via the commandline + fd>=3 route");
    let mut r = child.fd_read_end(cosca::Fd::from(3)).expect("fd 3 reader");
    let mut s = String::new();
    r.read_to_string(&mut s).await.unwrap();
    assert!(child.wait().await.unwrap().success());
    assert_eq!(s, "commandline-only-fd3");
}

// Async containment over the raw backend (Plan 12 Task 8) =====

/// Async twin of sync `contained_raw_child_is_in_our_job_and_kill_tree_reaps`: a CONTAINED child
/// loaded via `executable()` (with fd >= 3) routes through the async raw backend AND lands in OUR
/// Job Object — `test_job_handle_contains_self()` confirms membership (immutable once assigned).
/// fd 3 delivers the child's bytes over the async read end, and `kill_tree()` tears the tree down.
/// EOF (child closing fd 3 on exit) bounds the read — no timer.
#[tokio::test]
async fn async_contained_raw_child_is_in_our_job() {
    let mut c = cosca::tokio::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "write-fd", "3", "x"])
        .fd(3, cosca::Stdio::pipe_out())
        .unwrap()
        .contain();
    let mut child = c.spawn().expect("contained raw spawn");
    // Fixed at spawn (run-state-independent): the achieved mechanism is the Job Object.
    assert_eq!(child.containment(), cosca::Containment::JobObject);
    assert!(child.test_job_handle_contains_self(), "child must be inside OUR job");
    let mut r = child.fd_read_end(cosca::Fd::from(3)).expect("fd 3 reader");
    let mut s = String::new();
    r.read_to_string(&mut s).await.unwrap();
    assert_eq!(s, "x");
    child.kill_tree().expect("kill_tree");
}

/// Async twin of sync `fd3_only_routing_does_not_load_a_binary_planted_in_the_process_cwd`: a
/// `Command` with no `.executable()` still routes to the async raw backend purely via fd >= 3, so
/// `image` used to be `None` and `lpApplicationName` NULL. `CreateProcessW`'s own search for a
/// NULL `lpApplicationName` visits, at step 2 of its documented order, the CALLING process's
/// current directory — never the child's `lpCurrentDirectory`/`Command::cwd()`.
///
/// That calling process cannot be THIS test process: mutating this process's own cwd under
/// `cosca::test_spawn_lock()` while also calling `cosca::tokio::Command::spawn()` would
/// self-deadlock, because that spawn takes the exact same non-reentrant mutex internally (see
/// `tests/common/mod.rs`'s `output_locked`/`status_locked` docs and `src/test_child.rs`). Instead,
/// this test plants the decoy in a tempdir and spawns the `cosca_testbin` helper's
/// `report-bare-argv0-cwd-spawn-async` mode via one ordinary, single-level
/// `cosca::tokio::Command::spawn()` call, passing the decoy directory as an argument. That helper
/// — a fresh, isolated process with its own cwd — does the chdir and the vulnerable/fixed ASYNC
/// spawn itself (exercising the async raw backend specifically), and reports the outcome on
/// stdout.
///
/// With the bug, the helper's inner spawn would find and load the planted decoy from its own
/// current directory (CWE-426/427) and report "loaded". Fixed, the bare argv[0] resolves through
/// the crate's own resolver — the system directories (app dir, `System32`, the Windows directory)
/// and then `PATH`, never any cwd for a bare name — so the planted copy is never loaded and the
/// helper reports "notfound".
///
/// The decoy is planted under a FABRICATED name, never the literal "cosca_testbin" — see the sync
/// twin's doc for why: that literal name can legitimately resolve via the runner's ACTUAL `PATH`
/// (measured on CI, where it made an earlier, undiscriminating version of this test report
/// "loaded" for a reason unrelated to the bug). A name that exists nowhere but the planted decoy
/// means any successful resolution of it can only have come from the vulnerable cwd search — and,
/// since the decoy lives ONLY in this tempdir cwd, never the app dir, `System32`, or the Windows
/// directory either, the resolver's system-directory search step cannot accidentally find it and
/// mask a cwd-search regression this test would otherwise catch.
#[tokio::test]
async fn async_fd3_only_routing_does_not_load_a_binary_planted_in_the_process_cwd() {
    let dir = tempfile::tempdir().unwrap();
    let decoy_program = "cosca_testbin_b2_cwd_decoy";
    std::fs::copy(common::testbin(), dir.path().join(format!("{decoy_program}.exe"))).unwrap();

    let mut c = cosca::tokio::Command::new();
    c.executable(common::testbin())
        .args([
            "cosca_testbin",
            "report-bare-argv0-cwd-spawn-async",
            dir.path().to_str().expect("tempdir path is valid UTF-8"),
            decoy_program,
        ])
        .stdout(cosca::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("spawn the probe helper");
    let mut s = String::new();
    child.stdout().unwrap().read_to_string(&mut s).await.unwrap();
    child.wait().await.unwrap();
    assert_eq!(s.trim(), "notfound", "helper report: {s}");
}
