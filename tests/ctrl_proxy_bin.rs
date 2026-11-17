//! The `cosca-ctrl-proxy` executable: what it answers when it is started without a proxy invocation
//! or with one that sends nothing, and (Windows, the `CTRL_PROXY` group) that it plays the proxy
//! for a child on a console of its own.
//!
//! The argv below is the protocol's wire form, spelled out: the protocol is crate-private.

#[path = "common/mod.rs"]
mod common;

#[cfg(windows)]
use common::test_groups::{ctrl_proxy, Group};

/// The exit code of a proxy that was not given a valid invocation (`ProxyAnswer::Usage`).
const USAGE: i32 = 151;
/// The exit code of a proxy whose target has no process (`ProxyAnswer::TargetGone`) on Windows, and
/// of a platform that has no proxy (`ProxyAnswer::NoProxyHere`) elsewhere.
const NO_SUCH_TARGET: i32 = if cfg!(windows) { 153 } else { 159 };
/// A pid no process has: far above any this host hands out, and a multiple of 4 (a Windows pid is).
const NO_SUCH_PID: u32 = 0x7FFF_FFF0;

fn proxy_exe() -> std::path::PathBuf {
    std::env::var_os("NEXTEST_BIN_EXE_cosca-ctrl-proxy")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cosca-ctrl-proxy").into())
        .into()
}

/// Mutant: `main` returns without saying so, or exits 0, so a caller that runs the executable by
/// hand takes it for having worked.
#[skuld::test]
fn started_without_a_proxy_invocation_it_answers_usage() {
    let mut cmd = std::process::Command::new(proxy_exe());
    let out = common::output_locked(&mut cmd).expect("run the executable");
    assert_eq!(out.status.code(), Some(USAGE), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr.lines().count(), 1, "one line says why: {stderr:?}");
    assert!(stderr.starts_with("cosca-ctrl-proxy: "), "{stderr:?}");
}

/// A target that has no process: the executable runs `cosca::init()`, which answers for it, and
/// sends nothing. Mutant: `main` does not call `init`, so the invocation is taken for a missing one.
#[skuld::test]
fn started_with_a_proxy_invocation_it_runs_the_proxy() {
    let mut cmd = std::process::Command::new(proxy_exe());
    cmd.args([
        "--cosca-ctrl-proxy=1".to_owned(),
        NO_SUCH_PID.to_string(),
        "0".to_owned(),
        "break".to_owned(),
        std::process::id().to_string(),
    ]);
    let out = common::output_locked(&mut cmd).expect("run the executable");
    assert_eq!(out.status.code(), Some(NO_SUCH_TARGET), "{out:?}");
}

/// A stop through `CtrlProxy::Executable` of this executable sends Ctrl+Break to a child with a console
/// of its own, which ends it by the default disposition. The stop's answer is asserted first (`Sent` is
/// `Ok`), so a proxy that sent nothing fails by assertion and not by waiting for the child.
#[cfg(windows)]
#[skuld::test]
fn the_cosca_ctrl_proxy_executable_plays_the_proxy(#[fixture(ctrl_proxy)] _group: &Group) {
    /// `STATUS_CONTROL_C_EXIT`: how a process with no handler ends on a delivered break.
    const STATUS_CONTROL_C_EXIT: i32 = 0xC000_013A_u32 as i32;

    // Uncontained, with a window-less console of its own: no group of ours reaches it.
    let (child, sock) = common::spawn_control_with("control-block", &["R"], false, |cmd| {
        cmd.ctrl_proxy(cosca::CtrlProxy::Executable(proxy_exe()));
    });
    cosca::stop::send_console_event_via_proxy(&cosca::StopTarget::from(&child), cosca::CtrlEvent::CtrlBreak)
        .expect("the executable plays the proxy and answers Sent");

    let status = child.wait().expect("the child's exit");
    assert_eq!(status.code(), Some(STATUS_CONTROL_C_EXIT), "{status:?}");
    drop(sock);
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
