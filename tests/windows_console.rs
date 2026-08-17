//! Windows: the console-group graceful signal (`CTRL_BREAK`) is delivered only within the
//! CALLING process's console. Everything under `cargo test` has a console, so the
//! console-less caller is reached by re-launching the testbin with `DETACHED_PROCESS`.
//! Each console-less/with-console pair drives the SAME helper mode; the pair must disagree.
//!
//! The flag-matrix tests at the top measure what the creation-flag word does and does not
//! settle about console membership, and their discriminating power comes from the control legs
//! disagreeing with the exclusion legs — not from a before/after.
#![cfg(windows)]

use std::io::Read;
use std::net::TcpListener;
use std::os::windows::process::CommandExt;
use std::process::Command;

#[path = "common/mod.rs"]
mod common;

/// `DETACHED_PROCESS`: the new process gets NO console and does not inherit ours — the
/// GUI-app / service / detached-spawn caller these tests run against.
const DETACHED_PROCESS: u32 = 0x0000_0008;

/// The three creation flags that keep a child out of the spawner's console, and the group flag
/// whose presence is what makes a child individually addressable at all. Raw constants because
/// `CommandExt::creation_flags` takes a plain `u32` (winbase.h).
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Spawn `exe` with exactly `flags`, block on its 1-byte tag, and hand back the child and its
/// socket. The tag is the load-bearing part: console registration is not synchronous with
/// `CreateProcess` returning, so a membership probe taken before it reads "absent" for every
/// flag word, including one with no detaching flag at all — and a matrix asserted at that
/// instant could never fail.
fn spawn_tagged_with_flags(exe: &str, args: &[&str], flags: u32) -> (std::process::Child, std::net::TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new(exe);
    cmd.args(args).arg(&addr).creation_flags(flags);
    let child = {
        let _guard = cosca::test_spawn_lock();
        cmd.spawn().expect("spawn flag-matrix child")
    };
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// Kill and reap a flag-matrix child, dropping its socket first so a child blocked on the read
/// can also exit on EOF.
fn end(mut child: std::process::Child, sock: std::net::TcpStream) {
    drop(sock);
    let _ = child.kill();
    child.wait().expect("reap flag-matrix child");
}

/// The control: membership does NOT come from `CREATE_NEW_PROCESS_GROUP`, and it does not come
/// from passing no flags either. Both legs must read present, which is what makes the exclusion
/// tests below discriminating rather than vacuous — and what fails if the tag handshake above
/// stopped being a real happens-before edge.
#[test]
fn console_group_flag_keeps_a_child_in_our_console() {
    for flags in [CREATE_NEW_PROCESS_GROUP, 0] {
        let (child, sock) = spawn_tagged_with_flags(env!("CARGO_BIN_EXE_cosca_testbin"), &["control-block"], flags);
        let seen = common::in_our_console(child.id());
        assert_eq!(
            seen,
            Some(true),
            "a console-subsystem child spawned with flags {flags:#x} must be in our console"
        );
        end(child, sock);
    }
}

/// Each of the three detaching/suppressing flags excludes the child from our console, under the
/// same post-handshake timing the control above measures as present.
#[test]
fn console_detaching_flags_leave_a_child_outside_our_console() {
    for flag in [DETACHED_PROCESS, CREATE_NEW_CONSOLE, CREATE_NO_WINDOW] {
        let (child, sock) = spawn_tagged_with_flags(
            env!("CARGO_BIN_EXE_cosca_testbin"),
            &["control-block"],
            CREATE_NEW_PROCESS_GROUP | flag,
        );
        let seen = common::in_our_console(child.id());
        // `Some(false)`, never a bare falsy: a `None` probe result must fail this test, not
        // pass it.
        assert_eq!(
            seen,
            Some(false),
            "flag {flag:#x} must keep the child out of our console"
        );
        end(child, sock);
    }
}

/// A GUI-subsystem image is outside our console under the exact flag word that keeps a
/// console-subsystem image inside it. This is why the creation-flag word is a sound negative
/// and an unsound positive: no flag can establish membership.
#[test]
fn a_gui_subsystem_child_is_outside_our_console_whatever_its_flags() {
    let (child, sock) = spawn_tagged_with_flags(env!("CARGO_BIN_EXE_cosca_testbin_gui"), &[], CREATE_NEW_PROCESS_GROUP);
    let seen = common::in_our_console(child.id());
    assert_eq!(
        seen,
        Some(false),
        "a GUI-subsystem child never attaches to the spawner's console"
    );
    end(child, sock);
}

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

/// Sibling of [`run_probe`] driving the `report-console-lone` mode — the LONE graceful ops
/// (`terminate` / `graceful_shutdown`) against a contained root, instead of the tree ops. Same
/// direct-launch discipline and same connect-before-work EOF guarantee; see [`run_probe`].
fn run_lone_probe(detached: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cosca_testbin"));
    cmd.args(["report-console-lone", &addr]);
    if detached {
        cmd.creation_flags(DETACHED_PROCESS);
    }
    let mut helper = cmd.spawn().expect("spawn lone probe helper");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut report = String::new();
    sock.read_to_string(&mut report).expect("read report");
    let status = helper.wait().expect("reap lone probe helper");
    assert!(
        status.success(),
        "lone probe helper failed: {status:?} — report so far: {report:?}"
    );
    report
}

#[test]
fn lone_graceful_ops_report_no_console_from_a_console_less_caller() {
    let r = run_lone_probe(true);
    // A MEASURED absence — the helper reports `?` if its own probe failed — so this guard
    // cannot be satisfied by a broken probe.
    assert_eq!(
        field(&r, "console"),
        "0",
        "helper must have NO console, else vacuous: {r}"
    );
    assert_eq!(
        field(&r, "mechanism"),
        "console-group",
        "the child's own flags do not exclude delivery; it is the CALLER that cannot send: {r}"
    );
    assert_eq!(field(&r, "terminate"), "NoConsole", "{r}");
    assert_eq!(
        field(&r, "alive_after_terminate"),
        "alive",
        "a fail-fast terminate must leave the child untouched: {r}"
    );
    // Killed rather than signalled, and a killed peer resets its socket about as often as it
    // closes it. `?` and `K` stay distinct and neither may pass here.
    let seen = field(&r, "break");
    assert!(
        matches!(seen, "0" | "E"),
        "no signal can have been delivered, got {seen}: {r}"
    );
    assert_eq!(field(&r, "graceful"), "NoConsole", "{r}");
    assert_eq!(field(&r, "graceful_code"), "none", "{r}");
    assert_eq!(
        field(&r, "alive_after_graceful"),
        "alive",
        "graceful_shutdown must fail before signalling, never after hard-killing: {r}"
    );
    assert_eq!(field(&r, "cleanup"), "Ok", "hard teardown needs no console: {r}");
}

#[test]
fn lone_graceful_ops_work_from_a_caller_that_has_a_console() {
    // Positive control. `break=1` is load-bearing: the child acknowledges the CTRL_BREAK over
    // its own socket, so this cannot pass on a return code alone. `graceful_code=1` names the
    // escalation's exit code — the acker survives its break, so ZERO grace escalates — and a
    // build that escalated nothing would report a different code and `alive_after_graceful=alive`.
    let r = run_lone_probe(false);
    assert_eq!(field(&r, "console"), "1", "{r}");
    assert_eq!(field(&r, "c_in_console"), "1", "the child must share our console: {r}");
    assert_eq!(field(&r, "mechanism"), "console-group", "{r}");
    assert_eq!(field(&r, "terminate"), "Ok", "{r}");
    assert_eq!(
        field(&r, "alive_after_terminate"),
        "alive",
        "the acker handles the break and keeps running: {r}"
    );
    assert_eq!(field(&r, "break"), "1", "the child must receive CTRL_BREAK: {r}");
    assert_eq!(field(&r, "graceful"), "Ok", "{r}");
    assert_eq!(field(&r, "graceful_code"), "1", "the escalation's kill: {r}");
    assert_eq!(field(&r, "alive_after_graceful"), "dead", "{r}");
    assert_eq!(field(&r, "cleanup"), "Ok", "{r}");
}
