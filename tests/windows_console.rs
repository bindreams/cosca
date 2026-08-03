//! Windows: the console-group graceful signal (`CTRL_BREAK`) is delivered only within the
//! CALLING process's console. Everything under `cargo test` has a console, so the
//! console-less caller is reached by re-launching the testbin with `DETACHED_PROCESS`.
//! Both tests drive the SAME helper mode; they must disagree.
#![cfg(windows)]

use std::io::Read;
use std::net::TcpListener;
use std::os::windows::process::CommandExt;
use std::process::Command;

/// `DETACHED_PROCESS`: the new process gets NO console and does not inherit ours — the
/// GUI-app / service / detached-spawn caller these tests run against.
const DETACHED_PROCESS: u32 = 0x0000_0008;

/// Run the `report-console-terminate` helper and return its one-line report.
///
/// The helper is launched DIRECTLY, never through a shell or launcher: a wrapper would be the
/// detached process, and would then re-spawn the testbin as an ordinary child — which, coming
/// from a console-less parent, gets a fresh private console. The console-less scenario would
/// silently stop reproducing while these tests still passed.
///
/// The helper connects before doing any work, so the read returns on socket EOF whether it
/// reported or crashed — a real event, never a timer. `wait()` then supplies the real status.
fn run_probe(detached: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cosca_testbin"));
    cmd.args(["report-console-terminate", &addr]);
    if detached {
        cmd.creation_flags(DETACHED_PROCESS);
    }
    let mut helper = cmd.spawn().expect("spawn probe helper");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut report = String::new();
    sock.read_to_string(&mut report).expect("read report");
    let status = helper.wait().expect("reap probe helper");
    assert!(
        status.success(),
        "probe helper failed: {status:?} — report so far: {report:?}"
    );
    report
}

/// Exact value of one `key=value` field. Substring matching is not safe here: `console=0` is a
/// substring of `c1_in_console=0`, so a `contains` guard could be satisfied by the wrong field
/// entirely.
fn field<'a>(report: &'a str, key: &str) -> &'a str {
    report
        .split_ascii_whitespace()
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no field {key} in report: {report}"))
}

#[test]
fn tree_graceful_ops_report_no_console_from_a_console_less_caller() {
    let r = run_probe(true);
    // A MEASURED absence — the helper reports `?` if its own probe failed — so this guard
    // cannot be satisfied by a broken probe.
    assert_eq!(
        field(&r, "console"),
        "0",
        "helper must have NO console, else vacuous: {r}"
    );
    assert_eq!(
        field(&r, "c1_in_console"),
        "0",
        "a console-less caller shares no console: {r}"
    );
    assert_eq!(
        field(&r, "containment"),
        "job",
        "the root must be contained — the bug is about a contained root: {r}"
    );
    assert_eq!(field(&r, "terminate_tree"), "NoConsole", "{r}");
    assert_eq!(
        field(&r, "alive_after_terminate"),
        "alive",
        "a fail-fast terminate must leave the tree untouched: {r}"
    );
    // The acker is hard-killed on this path, and a killed peer resets its socket rather than
    // closing it, so the read errors (`E`) about as often as it sees EOF (`0`) — both mean
    // "died without acking". `?` (an unexpected byte) and `K` (the teardown failed, so
    // delivery was never observable) stay distinct and neither may pass here.
    let seen = field(&r, "terminate_break");
    assert!(
        matches!(seen, "0" | "E"),
        "no signal can have been delivered, got {seen}: {r}"
    );
    assert_eq!(field(&r, "graceful"), "NoConsole", "{r}");
    assert_eq!(
        field(&r, "alive_after_graceful"),
        "alive",
        "graceful_shutdown_tree must fail before signalling, not after hard-killing: {r}"
    );
    assert_eq!(field(&r, "kill_tree"), "Ok", "hard teardown needs no console: {r}");
    assert_eq!(field(&r, "graceful_cleanup"), "Ok", "{r}");
}

#[test]
fn tree_graceful_ops_work_from_a_caller_that_has_a_console() {
    // Positive control. `terminate_break=1` is load-bearing: the child acknowledges the
    // CTRL_BREAK over its own socket, so this cannot pass on a return code alone —
    // `GenerateConsoleCtrlEvent` reports success even when it delivers nothing.
    let r = run_probe(false);
    assert_eq!(field(&r, "console"), "1", "{r}");
    assert_eq!(field(&r, "c1_in_console"), "1", "the root must share our console: {r}");
    assert_eq!(field(&r, "containment"), "job", "{r}");
    assert_eq!(field(&r, "terminate_tree"), "Ok", "{r}");
    assert_eq!(
        field(&r, "terminate_break"),
        "1",
        "the child must receive CTRL_BREAK: {r}"
    );
    assert_eq!(field(&r, "graceful"), "Ok", "{r}");
    assert_eq!(field(&r, "kill_tree"), "Ok", "{r}");
    assert_eq!(
        field(&r, "graceful_cleanup"),
        "Skipped",
        "a successful graceful needs no sweep: {r}"
    );
    // Independent of the function's own word for it: the tree is actually gone. The acker
    // ignores CTRL_BREAK, so only the escalation can have killed it.
    assert_eq!(
        field(&r, "alive_after_graceful"),
        "dead",
        "a successful graceful_shutdown_tree must leave nothing alive: {r}"
    );
}
