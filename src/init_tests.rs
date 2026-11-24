//! The hook, in re-executions of the test binary (whose `main` calls it first). The program's own
//! `main` is the test runner, which refuses an argument it does not know with exit 2 and an
//! `error: unexpected argument` line: that line says the program ran. No console event is sent in any
//! of them: the proxy arguments here either are refused, or name a pid no process has.

use std::ffi::OsStr;
use std::process::Output;

use crate::role::{CTRL_PROXY, HELPER, HELPER_ENV, PROXY, UNKNOWN_HELPER_ROLE};
use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer, ProxyArgs, VERSION};

/// A pid no process has: far above any this host hands out, and a multiple of 4 (a Windows pid is).
const NO_SUCH_PID: u32 = 0x7FFF_FFF0;

/// What the test runner (the program's own `main`) answers an argument it does not know, which is what
/// an argument that no hook took reaches.
const PROGRAM_RAN_EXIT: i32 = 2;
const PROGRAM_RAN_LINE: &str = "error: unexpected argument";

/// Runs the test binary with `helper` as the value of [`HELPER_ENV`] (unset for `None`) and `args`.
fn reexec(helper: Option<&str>, args: &[&str]) -> Output {
    let mut command = crate::test_reexec::command(std::env::current_exe().expect("the test binary's path"));
    command.env_remove(HELPER_ENV).args(args);
    if let Some(helper) = helper {
        command.env(HELPER_ENV, helper);
    }
    crate::test_spawn::output_captured(&mut command).expect("the test binary re-executes")
}

/// A refusal line begins `<name>: started with __COSCA_HELPER=<value>: <reason>`, the value escaped as
/// `str::escape_debug` does. Mutant: a refusal that leaves the variable out.
#[track_caller]
fn assert_names_the_variable(stderr: &str, name: &str, value: &str) {
    let start = format!("{name}: started with {HELPER_ENV}={}: ", value.escape_debug());
    assert!(
        stderr.starts_with(&start),
        "expected a line starting {start:?}: {stderr:?}"
    );
}

/// The proxy's valid argument tail (everything after `argv[0]`) for a target no process has.
fn valid_tail() -> Vec<String> {
    let args = ProxyArgs {
        target: NO_SUCH_PID,
        target_key: 0,
        event: CtrlEvent::CtrlBreak,
        caller: std::process::id(),
    };
    args.to_argv(OsStr::new("test-binary"))[1..]
        .iter()
        .map(|a| a.to_str().expect("ascii").to_owned())
        .collect()
}

fn as_strs(tail: &[String]) -> Vec<&str> {
    tail.iter().map(String::as_str).collect()
}

/// The helper role ran and the program did not: the test binary's own `main` printed nothing.
#[track_caller]
fn assert_program_did_not_run(out: &Output) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(PROGRAM_RAN_LINE) && out.stdout.is_empty(),
        "the program's own main ran: {out:?}"
    );
}

#[cfg(unix)]
#[skuld::test]
fn init_helpers_marks_the_helpers_initialized() {
    // The test binary's `main` calls `init_helpers`, so only a fresh process can show
    // `helpers_initialized` going from false to true; it asks (`testbin/shim_hooks.rs`) and exits.
    let mut command = std::process::Command::new(std::env::current_exe().expect("the test binary's path"));
    command.env_clear().env(crate::shim_env_hooks::INIT_PROBE_ENV, "1");
    let out = crate::test_spawn::output_captured(&mut command).expect("the probe runs");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "helpers_initialized before=false after=true\n",
        "`init_helpers` returns in a process that is not a helper, having marked the helpers initialized"
    );
}

/// `main` of the test binary calls the hook first, so a test of it that runs in a re-executed binary
/// sees the helpers initialized. Mutant: `init_helpers` does not mark the process.
#[cfg(windows)]
#[skuld::test]
fn init_helpers_marks_the_helpers_initialized_on_windows() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(init_helpers_marks_the_helpers_initialized_on_windows),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    assert!(
        crate::helpers_initialized(),
        "the binary's `main` called `init_helpers`"
    );
}

/// A program whose own first argument is `--cosca-ctrl-proxy`, started without the variable, runs as
/// itself: the arguments never decide. Mutant: detection by arguments, which
/// plays the proxy (or, where there is none, answers 159) and never reaches the program.
#[skuld::test]
fn the_old_proxy_flag_without_the_variable_is_the_programs_own_argument() {
    let tail = valid_tail();
    let with_tail: Vec<&str> = std::iter::once("--cosca-ctrl-proxy=1")
        .chain(tail[1..].iter().map(String::as_str))
        .collect();
    for args in [
        &["--cosca-ctrl-proxy=1"][..],
        &with_tail[..],
        &["--cosca-ctrl-proxy=2", "x"],
    ] {
        let out = reexec(None, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(PROGRAM_RAN_EXIT), "{args:?}: {out:?}");
        assert!(stderr.starts_with(PROGRAM_RAN_LINE), "{args:?}: {stderr}");
        assert!(
            !stderr.contains(&format!("{PROXY}: ")),
            "{args:?}: the proxy role did not run: {stderr}"
        );
    }
}

/// Mutant: the proxy runs on the arguments of a platform that has none, or does not run on one that has.
#[skuld::test]
fn the_proxy_role_runs_the_proxy_where_there_is_one() {
    let tail = valid_tail();
    let out = reexec(Some(CTRL_PROXY), &as_strs(&tail));
    let stderr = String::from_utf8_lossy(&out.stderr);
    if cfg!(windows) {
        assert_eq!(out.status.code(), Some(ProxyAnswer::TargetGone.code()), "{out:?}");
    } else {
        assert_eq!(out.status.code(), Some(ProxyAnswer::NoProxyHere.code()), "{out:?}");
        assert!(
            stderr.contains("this platform has no console-event proxy"),
            "the refusal says why: {stderr}"
        );
        assert_names_the_variable(&stderr, PROXY, CTRL_PROXY);
    }
    assert_program_did_not_run(&out);
}

/// The variable alone decides: the proxy role takes its arguments whatever the first one is, so the
/// arguments of a program (`dump-argv`, which the runner would refuse) are the proxy's data and are
/// refused as such. Mutant: the role is played only when the arguments look like a proxy invocation,
/// or the program runs after the proxy refuses.
#[skuld::test]
fn the_variable_decides_whatever_the_arguments_are() {
    let out = reexec(Some(CTRL_PROXY), &["dump-argv", "1", "1", "break", "1"]);
    assert_eq!(out.status.code(), Some(ProxyAnswer::Usage.code()), "{out:?}");
    assert_program_did_not_run(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_names_the_variable(&stderr, PROXY, CTRL_PROXY);
}

/// Mutant: a malformed invocation is run, taken for a program's own arguments and ignored, or lets the
/// program run.
#[skuld::test]
fn a_malformed_proxy_invocation_is_answered_usage_and_the_program_does_not_run() {
    let version = VERSION.to_string();
    let version = version.as_str();
    for args in [
        &[][..],
        &[version],
        &[version, "x", "1", "break", "1"],
        &[version, "1", "1", "ctrl-break", "1"],
        &["x", "1", "1", "break", "1"],
        &[version, "1", "1", "break", "1", "extra"],
    ] {
        let out = reexec(Some(CTRL_PROXY), args);
        assert_eq!(out.status.code(), Some(ProxyAnswer::Usage.code()), "{args:?}: {out:?}");
        assert_program_did_not_run(&out);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_names_the_variable(&stderr, PROXY, CTRL_PROXY);
    }
}

/// Mutant: a version the proxy does not speak runs it, or is answered as a usage error. Every platform
/// refuses the version before it knows whether it has a proxy.
#[skuld::test]
fn another_protocol_version_is_answered_before_anything_runs() {
    let other = (VERSION + 1).to_string();
    let out = reexec(Some(CTRL_PROXY), &[&other, "1", "1", "break", "1"]);
    assert_eq!(out.status.code(), Some(ProxyAnswer::VersionMismatch.code()), "{out:?}");
    assert_program_did_not_run(&out);
    assert_names_the_variable(&String::from_utf8_lossy(&out.stderr), PROXY, CTRL_PROXY);
}

/// A role this build does not have is refused with one line and a code that is no answer of either
/// role's protocol, and the program does not run, whatever the arguments are. Mutant: an unknown role
/// runs the program, or the proxy, or exits with a code the shim or the proxy reads, or (Windows) the
/// shim's name is dispatched there.
#[skuld::test]
fn an_unknown_role_is_refused_and_the_program_does_not_run() {
    // Only the proxy's collision can be derived from production: its answers are enumerable
    // (`ProxyAnswer::from_code`). The shim's codes are separate constants (`elevation::shim::codes`), not an
    // enumerable set, so no range copied from a doc comment is checked here.
    assert_eq!(
        ProxyAnswer::from_code(UNKNOWN_HELPER_ROLE),
        None,
        "the code is no answer of the proxy's protocol"
    );
    let tail = valid_tail();
    // The shim is a role of Unix builds only; elsewhere its name is as unknown as any other.
    let shim_elsewhere: &[&str] = if cfg!(unix) { &[] } else { &["elevation-shim"] };
    let near_misses = ["", "proxy", "CTRL-PROXY", "ctrl-proxy ", "x", "x\ny", "x\r\ny"];
    for &role in near_misses.iter().chain(shim_elsewhere) {
        for args in [&[][..], &as_strs(&tail)[..]] {
            let out = reexec(Some(role), args);
            assert_eq!(
                out.status.code(),
                Some(UNKNOWN_HELPER_ROLE),
                "{role:?} {args:?}: {out:?}"
            );
            assert_program_did_not_run(&out);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(stderr.lines().count(), 1, "one line says why: {stderr:?}");
            assert_names_the_variable(&stderr, HELPER, role);
            assert!(stderr.contains("no such helper role"), "{role:?}: {stderr}");
        }
    }
}

/// A program whose own first argument is `--cosca-elevation-shim=1` (or the hex form, or another
/// version), started without the variable, runs as itself: the arguments never decide. Mutant: detection
/// by the first argument's prefix, which plays the shim (or, on Windows, runs the program only by
/// luck) and never reaches the program.
#[skuld::test]
fn the_old_shim_flag_without_the_variable_is_the_programs_own_argument() {
    for args in [
        &["--cosca-elevation-shim=1"][..],
        &["--cosca-elevation-shim=1x", "x"],
        &["--cosca-elevation-shim=9", "1", "1", "break", "1"],
        &["--cosca-elevation-shim"],
    ] {
        let out = reexec(None, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(PROGRAM_RAN_EXIT), "{args:?}: {out:?}");
        assert!(stderr.starts_with(PROGRAM_RAN_LINE), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("cosca-elevation-shim: "),
            "{args:?}: the shim role did not run: {stderr}"
        );
    }
}

/// With the variable naming the shim, the process is the shim and its arguments are the shim's data:
/// valid ones start it (here, on a directory with no listener, so it answers that it could not connect,
/// as Linux's shim does; macOS has no shim and says so, in the `started with` line), and the program
/// does not run. Mutant: the role is not played, or is played as the proxy, or the program runs, or a
/// platform without a shim leaves the variable out of its line (macOS only).
#[cfg(unix)]
#[skuld::test]
fn the_shim_role_with_valid_arguments_is_the_shim() {
    use crate::elevation::shim::codes::{INVOCATION, NO_ANSWER};
    use crate::elevation::shim::fixtures::shim_args;
    use crate::role::{ELEVATION_SHIM, SHIM};

    let dir = tempfile::tempdir().expect("a directory with no listener");
    let mut args = shim_args(b"/bin/true", &[]);
    args.dir = dir.path().to_owned();
    let argv = args.to_argv(OsStr::new("test-binary"), false);
    let tail: Vec<&str> = argv[1..].iter().map(|a| a.to_str().expect("ascii")).collect();
    let out = reexec(Some(ELEVATION_SHIM), &tail);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let want = if cfg!(target_os = "linux") {
        NO_ANSWER
    } else {
        INVOCATION
    };
    assert_eq!(out.status.code(), Some(want), "{out:?}");
    assert!(stderr.starts_with(&format!("{SHIM}: ")), "{stderr}");
    if !cfg!(target_os = "linux") {
        // A platform without a shim refuses in the same shape as every other refusal of the role.
        assert_names_the_variable(&stderr, SHIM, ELEVATION_SHIM);
    }
    assert!(!stderr.contains("no such helper role"), "{stderr}");
    assert!(!stderr.contains(&format!("{PROXY}: ")), "{stderr}");
    assert_program_did_not_run(&out);
}

/// With the variable naming the shim, arguments it cannot use are refused with the `started with` line
/// and the invocation code, whatever they look like, and the program does not run. Mutant: the
/// arguments are taken for the program's own when they lack the flag, or the refusal leaves the
/// variable out.
#[cfg(unix)]
#[skuld::test]
fn the_shim_role_with_unusable_arguments_is_refused_and_the_program_does_not_run() {
    use crate::elevation::shim::codes::INVOCATION;
    use crate::role::{ELEVATION_SHIM, SHIM};

    for args in [
        &[][..],
        &["dump-argv"],
        &["--cosca-elevation-shim=9", "1", "1", "break", "1"],
        &["--cosca-elevation-shim=1"],
        &["--cosca-elevation-shim=1", "/tmp", "1", "-", "1", "-", "--"],
        &["--cosca-ctrl-proxy=1", "1", "1", "break", "1"],
    ] {
        let out = reexec(Some(ELEVATION_SHIM), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(INVOCATION), "{args:?}: {out:?}");
        assert_program_did_not_run(&out);
        assert_eq!(stderr.lines().count(), 1, "{args:?}: one line says why: {stderr:?}");
        assert_names_the_variable(&stderr, SHIM, ELEVATION_SHIM);
    }
}

/// With the variable set the hook plays the one role it names: shim arguments under the proxy's value
/// reach no shim, and the arguments are the proxy's. Each role is told apart by its code and by the
/// name its stderr line carries. Mutant: the shim's role runs for another value, or the proxy's runs
/// for the shim's.
#[cfg(unix)]
#[skuld::test]
fn the_variable_names_the_one_role_that_runs() {
    use crate::elevation::shim::codes::INVOCATION;
    use crate::role::{ELEVATION_SHIM, SHIM};

    let shim_flag = ["--cosca-elevation-shim=9", "1", "1", "break", "1"];

    let shim = reexec(Some(ELEVATION_SHIM), &shim_flag);
    let stderr = String::from_utf8_lossy(&shim.stderr);
    assert_eq!(shim.status.code(), Some(INVOCATION), "{shim:?}");
    assert!(stderr.starts_with(&format!("{SHIM}: ")), "{stderr}");
    assert!(
        !stderr.contains(&format!("{PROXY}: ")),
        "the proxy role did not run: {stderr}"
    );

    let proxy = reexec(Some(CTRL_PROXY), &shim_flag);
    let stderr = String::from_utf8_lossy(&proxy.stderr);
    assert_eq!(proxy.status.code(), Some(ProxyAnswer::Usage.code()), "{proxy:?}");
    assert!(stderr.starts_with(&format!("{PROXY}: ")), "{stderr}");
    assert!(
        !stderr.contains(&format!("{SHIM}: ")),
        "the shim role did not run: {stderr}"
    );
}
