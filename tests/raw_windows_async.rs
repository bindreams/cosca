//! Async (tokio) raw-`CreateProcessW` backend tests (Plan 12 Tasks 7-8). Windows + tokio only: the
//! raw backend is a Windows concern, and its async mirror needs the tokio runtime.

#[cfg(all(windows, feature = "tokio"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(all(windows, feature = "tokio"))]
#[path = "common/mod.rs"]
mod common;

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `executable_independent_of_argv0_on_windows`: the raw backend loads
/// `executable()` while argv[0] is the command line's first token. `argv0-report` echoes both,
/// proving the loaded image (`testbin`) differs from the reported argv[0] (`pretend-name`). The
/// stdout pipe is served by the tokio overlapped-named-pipe machinery.
#[skuld::test]
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

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `fd3_pipe_out_delivers_child_bytes`: a child-writes pipe on fd 3 delivers the
/// child's bytes to the parent's async read end (`AsyncReadExt`). The fd-table wired fd 3 into the
/// child's CRT; EOF (child closing fd 3 on exit) bounds the read — no timer.
#[skuld::test]
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

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `fd3_pipe_in_feeds_child`: a parent-writes pipe on fd 3 feeds the child
/// (`AsyncWriteExt`). The child copies fd 3 to stdout, so dropping the parent's write end (EOF)
/// makes it echo exactly what was written. EOF bounds both reads — no timer.
#[skuld::test]
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

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of the sync `argv_only_fd3_routes_through_the_raw_backend_and_works`: an argv-only
/// tokio `Command` (no `.executable()`) that maps fd >= 3 still routes through the ASYNC raw
/// backend. Same proof shape as the sync `argv_only_fd3_routes_through_the_raw_backend_and_works`
/// (see its doc for why fd 3 delivery proves raw-backend routing).
#[skuld::test]
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

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of the sync `commandline_only_fd3_routes_through_the_raw_backend_and_works`: a tokio
/// `Command` built with `.commandline(...)` instead of `.args(...)`, no `.executable()`, that maps
/// fd >= 3 — exercising `program_token`'s `CommandLine` arm (`first_token_wide`) through the ASYNC
/// raw backend, a different code path from the argv-only test above. Same proof shape as
/// `argv_only_fd3_routes_through_the_raw_backend_and_works` (see its doc for why fd 3 delivery
/// proves raw-backend routing).
#[skuld::test]
async fn async_commandline_only_fd3_routes_through_the_raw_backend_and_works() {
    let line = common::commandline_from(&[common::testbin(), "write-fd", "3", "commandline-only-fd3"]);

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

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `contained_raw_child_is_in_our_job`: a CONTAINED child
/// loaded via `executable()` (with fd >= 3) routes through the async raw backend AND lands in OUR
/// Job Object — `test_job_handle_contains_self()` confirms membership (immutable once assigned).
/// fd 3 delivers the child's bytes over the async read end; EOF bounds the read — no timer.
#[skuld::test]
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
    child.wait().await.expect("reap the child that exited by itself");
}

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `contained_raw_child_is_killed_by_kill_tree`.
///
/// Mutant: `kill_tree` is a no-op.
#[skuld::test]
async fn async_contained_raw_child_is_killed_by_kill_tree() {
    let mut c = cosca::tokio::Command::new();
    c.executable(common::stdin_blocker_program())
        .args(["more"])
        .stdin(cosca::Stdio::pipe())
        .unwrap()
        .stdout(cosca::Stdio::null())
        .unwrap()
        .contain();
    let mut child = c.spawn().expect("contained raw spawn");
    assert_eq!(child.containment(), cosca::Containment::JobObject);
    assert!(child.test_job_handle_contains_self(), "child must be inside OUR job");
    let stdin = child.stdin().expect("piped stdin");

    child.kill_tree().expect("kill_tree");
    drop(stdin);

    assert_eq!(
        child.wait().await.expect("reap").code(),
        Some(1),
        "kill_tree must kill the raw-backend child (exit code 1), not leave it to exit on EOF"
    );
}

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `fd3_only_routing_does_not_load_a_binary_planted_in_the_process_cwd`: a
/// `Command` with no `.executable()` still routes to the async raw backend purely via fd >= 3, so
/// `image` used to be `None` and `lpApplicationName` NULL. `CreateProcessW`'s own search for a
/// NULL `lpApplicationName` visits, at step 2 of its documented order, the CALLING process's
/// current directory — never the child's `lpCurrentDirectory`/`Command::cwd()`.
///
/// That calling process cannot be THIS test process: mutating this process's own cwd under
/// `cosca::test_spawn_lock()` while also calling `cosca::tokio::Command::spawn()` would
/// self-deadlock, because that spawn takes the exact same non-reentrant mutex internally (see
/// `tests/common/locked.rs`'s docs and `src/test_child.rs`). Instead,
/// this test plants the decoy in a tempdir and spawns the `cosca_testbin` helper's
/// `report-bare-argv0-cwd-spawn-async` mode via one ordinary, single-level
/// `cosca::tokio::Command::spawn()` call, passing the decoy directory as an argument. That helper
/// — a fresh, isolated process with its own cwd — does the chdir and the vulnerable/fixed ASYNC
/// spawn itself (exercising the async raw backend specifically), and reports the outcome on
/// stdout.
///
/// With the bug, the helper's inner spawn would find and load the planted decoy from its own
/// current directory (CWE-426/427) and report "loaded". Fixed, the bare argv[0] resolves through
/// the crate's own resolver — the system directories (`System32`, the Windows directory) and then
/// `PATH`, never the app directory and never any cwd for a bare name — so the planted copy is
/// never loaded and the helper reports "notfound".
///
/// The decoy is planted under a FABRICATED name, never the literal "cosca_testbin" — see the sync
/// twin's doc for why: that literal name can legitimately resolve via the runner's ACTUAL `PATH`
/// (measured on CI, where it made an earlier, undiscriminating version of this test report
/// "loaded" for a reason unrelated to the bug). A name that exists nowhere but the planted decoy
/// means any successful resolution of it can only have come from the vulnerable cwd search — and,
/// since the decoy lives ONLY in this tempdir cwd, never `System32` or the Windows directory
/// either, the resolver's system-directory search step cannot accidentally find it and mask a
/// cwd-search regression this test would otherwise catch.
#[skuld::test]
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

#[cfg(all(windows, feature = "tokio"))]
/// Async: All three parent std handles null (a GUI or service): the child gets null handles, no
/// `STARTF_USESTDHANDLES`, and no unlisted handle; where the caller configures a child end (a pipe,
/// the null device, fd 3), the child gets it. Mutants: `GetFileType(NULL)` (fails with 6);
/// `STARTF_USESTDHANDLES` always set; `bInheritHandles` TRUE without a HANDLE_LIST; the flag set
/// only when this process holds a live std handle (`pipe_out`, `null_io`, `pipe_fd3`).
#[skuld::test]
fn async_raw_spawn_with_null_parent_std_handles_gives_the_child_null() {
    common::null_std::assert_every_route("tokio", "all");
}

#[cfg(all(windows, feature = "tokio"))]
/// Async: Only one parent std handle null: the child gets that one null and the others inherited,
/// and a live slot merged from the null one is null too. Mutants: `STARTF_USESTDHANDLES` set only
/// when some child end is non-null (`merge_live`); `GetFileType(NULL)`.
#[skuld::test]
fn async_raw_spawn_with_one_null_parent_std_handle_gives_the_child_that_one_null() {
    for nulled in ["stdin", "stdout", "stderr"] {
        common::null_std::assert_every_route("tokio", nulled);
    }
}

#[cfg(all(windows, feature = "tokio"))]
/// Async: Two parent std handles null, one live: `STARTF_USESTDHANDLES` is still set, the null slots
/// are gaps, and a live slot merged from a null one is null too, with a NUL device as the whole
/// HANDLE_LIST. Mutants: the flag set only when some child end is non-null (`merge_live` and
/// `exe_merge` with `stdin+stdout` nulled); the flag keyed on one parent slot only (each set).
#[skuld::test]
fn async_raw_spawn_with_two_null_parent_std_handles_gives_the_child_two_null() {
    for nulled in ["stdin+stdout", "stdin+stderr", "stdout+stderr"] {
        common::null_std::assert_every_route("tokio", nulled);
    }
}

#[cfg(all(windows, feature = "tokio"))]
/// Async: a parent whose std handles are `INVALID_HANDLE_VALUE` is treated as one whose are null,
/// as `std` treats it.
#[skuld::test]
fn async_raw_spawn_with_invalid_parent_std_handles_gives_the_child_null() {
    for set in ["invalid:all", "invalid:stdout"] {
        common::null_std::assert_every_route("tokio", set);
    }
}

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `an_unlisted_inheritable_handle_does_not_reach_the_child`. Mutant: no
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
#[skuld::test]
async fn async_an_unlisted_inheritable_handle_does_not_reach_the_child() {
    let (mut reader, writer) = common::inheritable_pipe();
    let value = std::os::windows::io::AsRawHandle::as_raw_handle(&writer) as usize;
    let mut c = cosca::tokio::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "write-handle", &format!("{value:x}")]);
    let mut child = c.spawn().expect("raw spawn");
    drop(writer);
    let got = tokio::task::spawn_blocking(move || {
        let mut got = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut got).expect("read the pipe");
        got
    })
    .await
    .unwrap();
    child.wait().await.unwrap();
    assert_eq!(got, b"", "the child inherited the unlisted handle {value:x}");
}

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `no_inheritable_handle_outlives_a_raw_spawn`, over the tokio backend's child
/// ends (overlapped named pipes included). Mutant: `drop(child_ends)` in the tokio `spawn_raw`
/// replaced by `std::mem::forget(child_ends)`.
#[skuld::test]
async fn async_no_inheritable_handle_outlives_a_raw_spawn() {
    for (kind, targets) in common::inheritable::child_end_kinds() {
        let before = common::inheritable::snapshot();
        let mut c = cosca::tokio::Command::new();
        c.executable(common::testbin()).args(["cosca_testbin", "exit", "0"]);
        for (slot, target) in targets {
            c.fd(slot, target).unwrap();
        }
        let mut child = c.spawn().unwrap_or_else(|e| panic!("{kind}: raw spawn: {e}"));
        let leaked: Vec<_> = common::inheritable::snapshot().difference(&before).copied().collect();
        child.wait().await.unwrap();
        assert!(leaked.is_empty(), "{kind}: inheritable handles left open: {leaked:x?}");
    }
}

#[cfg(all(windows, feature = "tokio"))]
/// Async twin of sync `no_inheritable_handle_outlives_a_failed_raw_spawn`. Mutant: `drop(child_ends)` in the
/// tokio `spawn_raw` runs only when the spawn succeeded.
#[skuld::test]
async fn async_no_inheritable_handle_outlives_a_failed_raw_spawn() {
    let missing = format!("{}.missing", common::testbin());
    for (kind, targets) in common::inheritable::child_end_kinds() {
        let before = common::inheritable::snapshot();
        let mut c = cosca::tokio::Command::new();
        c.raw_executable(&missing).args(["cosca_testbin", "exit", "0"]);
        for (slot, target) in targets {
            c.fd(slot, target).unwrap();
        }
        assert!(
            c.spawn().is_err(),
            "{kind}: spawning a nonexistent executable succeeded"
        );
        let leaked: Vec<_> = common::inheritable::snapshot().difference(&before).copied().collect();
        assert!(leaked.is_empty(), "{kind}: inheritable handles left open: {leaked:x?}");
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
