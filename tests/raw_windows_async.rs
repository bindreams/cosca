//! Async (tokio) raw-`CreateProcessW` backend tests (Plan 12 Task 7). Windows + tokio only: the
//! raw backend is a Windows concern, and its async mirror needs the tokio runtime.
#![cfg(all(windows, feature = "tokio"))]

use tokio::io::AsyncReadExt;

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

/// A CONTAINED `executable()` async spawn has no raw backend yet (Task 8 wires async containment):
/// it must be rejected LOUDLY, not fall through to the std path — which would silently drop the
/// user's argv[0] (std's arg0 preservation is Unix-only on Windows). Covers ARGV input; the
/// commandline case is separately rejected by `build_from_commandline`.
#[tokio::test]
async fn async_contained_executable_is_unsupported() {
    let mut c = subprocess::tokio::Command::new();
    c.executable(common::testbin())
        .args(["fakename", "exit", "0"]) // argv[0] "fakename" ≠ the loaded image
        .contain();
    let err = c
        .spawn()
        .expect_err("contained executable() must be rejected until Task 8");
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }), "{err:?}");
}
