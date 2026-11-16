//! The hook, in re-executions of the test binary (whose `main` calls it first). No console event is
//! sent in any of them: the proxy arguments here either are refused, or name a pid no process has.

use std::process::Output;

use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer, ProxyArgs};

/// A pid no process has: far above any this host hands out, and a multiple of 4 (a Windows pid is).
const NO_SUCH_PID: u32 = 0x7FFF_FFF0;

fn reexec(args: &[&str]) -> Output {
    let mut command = crate::test_reexec::command(std::env::current_exe().expect("the test binary's path"));
    command.args(args);
    crate::test_spawn::output_captured(&mut command).expect("the test binary re-executes")
}

#[cfg(unix)]
#[skuld::test]
fn init_marks_the_process_installed() {
    // The test binary's `main` calls `init`, so only a fresh process can show `installed` going from
    // false to true; it asks (`testbin/shim_hooks.rs`) and exits.
    let mut command = std::process::Command::new(std::env::current_exe().expect("the test binary's path"));
    command.env_clear().env(crate::shim_env_hooks::INIT_PROBE_ENV, "1");
    let out = crate::test_spawn::output_captured(&mut command).expect("the probe runs");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "installed before=false after=true\n",
        "`init` returns in a process that is not a shim, having marked it installed"
    );
}

/// `main` of the test binary calls the hook first, so a test of it that runs in a re-executed binary
/// sees the process installed. Mutant: `init` does not mark the process.
#[cfg(windows)]
#[skuld::test]
fn init_marks_the_process_installed_on_windows() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(init_marks_the_process_installed_on_windows),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    assert!(crate::installed(), "the binary's `main` called `init`");
}

/// Mutant: the proxy runs on the arguments of a platform that has none, or does not run on one that has.
#[skuld::test]
fn proxy_arguments_run_the_proxy_where_there_is_one() {
    let args = ProxyArgs {
        target: NO_SUCH_PID,
        target_key: 0,
        event: CtrlEvent::CtrlBreak,
        caller: std::process::id(),
    };
    let argv = args.to_argv(std::ffi::OsStr::new("test-binary"));
    let out = reexec(&argv[1..].iter().map(|a| a.to_str().expect("ascii")).collect::<Vec<_>>());
    let stderr = String::from_utf8_lossy(&out.stderr);
    if cfg!(windows) {
        assert_eq!(out.status.code(), Some(ProxyAnswer::TargetGone.code()), "{out:?}");
    } else {
        assert_eq!(out.status.code(), Some(ProxyAnswer::NoProxyHere.code()), "{out:?}");
        assert!(
            stderr.contains("this platform has no console-event proxy"),
            "the refusal says why: {stderr}"
        );
    }
    assert!(out.stdout.is_empty(), "the proxy writes nothing to stdout: {out:?}");
}

/// The hook plays one role, chosen by `argv[1]`: a shim invocation reaches only the shim (even with a
/// proxy invocation after it), and a proxy invocation only the proxy. The shim's own answer to a
/// flag it does not know is its invocation code, and the proxy's on a Unix platform is `NoProxyHere`,
/// so each role is told apart by its code and by the name its stderr line carries. Mutant: the proxy
/// role is tried before the shim, or both run.
#[cfg(unix)]
#[skuld::test]
fn a_shim_invocation_reaches_only_the_shim_and_a_proxy_invocation_only_the_proxy() {
    use crate::elevation::shim::codes::INVOCATION;
    use crate::role::{PROXY, SHIM};

    let shim_then_proxy = reexec(&[
        "--cosca-elevation-shim=9",
        "--cosca-ctrl-proxy=1",
        "1",
        "1",
        "break",
        "1",
    ]);
    let stderr = String::from_utf8_lossy(&shim_then_proxy.stderr);
    assert_eq!(shim_then_proxy.status.code(), Some(INVOCATION), "{shim_then_proxy:?}");
    assert!(stderr.starts_with(&format!("{SHIM}: ")), "{stderr}");
    assert!(!stderr.contains(PROXY), "the proxy role did not run: {stderr}");

    let proxy = reexec(&["--cosca-ctrl-proxy=1", "1", "1", "break", "1"]);
    let stderr = String::from_utf8_lossy(&proxy.stderr);
    assert_eq!(proxy.status.code(), Some(ProxyAnswer::NoProxyHere.code()), "{proxy:?}");
    assert!(stderr.starts_with(&format!("{PROXY}: ")), "{stderr}");
    assert!(!stderr.contains(SHIM), "the shim role did not run: {stderr}");
}

/// Mutant: a version the proxy does not speak runs it, or is answered as a usage error. Every platform
/// refuses the version before it knows whether it has a proxy.
#[skuld::test]
fn another_protocol_version_is_answered_before_anything_runs() {
    let out = reexec(&["--cosca-ctrl-proxy=2", "1", "1", "break", "1"]);
    assert_eq!(out.status.code(), Some(ProxyAnswer::VersionMismatch.code()), "{out:?}");
}

/// Mutant: a malformed invocation is run, or is taken for a program's own arguments and ignored.
#[skuld::test]
fn a_malformed_proxy_invocation_is_answered_usage() {
    for argv in [
        &["--cosca-ctrl-proxy=1"][..],
        &["--cosca-ctrl-proxy=1", "x", "1", "break", "1"],
        &["--cosca-ctrl-proxy=1", "1", "1", "ctrl-break", "1"],
        &["--cosca-ctrl-proxy=x", "1", "1", "break", "1"],
    ] {
        let out = reexec(argv);
        assert_eq!(out.status.code(), Some(ProxyAnswer::Usage.code()), "{argv:?}: {out:?}");
    }
}
