//! Windows: which console does a child get under each creation flag, measured BY THE CHILD.
//!
//! Console registration is not synchronous with `CreateProcess` returning, so a parent that
//! enumerates its own console list immediately after spawning reads "absent" for every flag
//! word — including one with no detaching flag at all. Every membership fact here is therefore
//! reported by the child about itself, after it has written its report line, so it is provably
//! running and registered. Do not "simplify" this into a parent-side enumeration.
//!
//! The matrix is discriminating because of its control leg: the no-flags row asserts the
//! caller's pid IS in the child's list, under the identical handshake as every absence below.
#![cfg(windows)]

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::os::windows::process::CommandExt;

#[path = "common/mod.rs"]
mod common;

/// Raw winbase.h values: `CommandExt::creation_flags` takes a plain `u32`.
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A running `report-console-identity` child plus the report line it wrote. The child blocks on
/// the same socket until [`Probe::end`] closes it, so every field describes a LIVE process.
struct Probe {
    child: std::process::Child,
    sock: TcpStream,
    report: String,
}

impl Probe {
    fn field(&self, key: &str) -> &str {
        field(&self.report, key)
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn end(mut self) {
        drop(self.sock);
        let _ = self.child.kill();
        self.child.wait().expect("reap identity probe child");
    }
}

/// Exact-key field extraction: substring matching is unsafe here because `console=0` is a
/// substring of nothing but `sees_caller=0` shares its value alphabet with every other field.
fn field<'a>(report: &'a str, key: &str) -> &'a str {
    report
        .split_ascii_whitespace()
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no field {key} in report: {report}"))
}

/// The escaping `report-console-identity` applies to `argv0`, reproduced here so a test can
/// state its expectation in plain text. Everything outside `[A-Za-z0-9._-]` becomes `%XX`,
/// because `argv[0]` is unbounded caller data in a whitespace-delimited record and a checkout
/// path containing a space would otherwise split it.
fn escape_field(value: &str) -> String {
    let mut out = String::new();
    for b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Bind a report listener, spawn `exe` in `report-console-identity` mode with exactly `flags`
/// through a RAW `std::process::Command` (cosca cannot express these flags in Task 1), and read
/// the one report line the child writes before it blocks.
fn probe_raw(exe: &str, argv_head: &[&str], flags: u32) -> Probe {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind report listener");
    let addr = listener.local_addr().unwrap().to_string();
    let me = std::process::id().to_string();
    let mut cmd = std::process::Command::new(exe);
    cmd.args(argv_head)
        .args(["report-console-identity", addr.as_str(), me.as_str()])
        .creation_flags(flags);
    let child = {
        let _guard = cosca::test_spawn_lock();
        cmd.spawn().expect("spawn identity probe child")
    };
    let (sock, _) = listener.accept().expect("accept report socket");
    let report = read_report(&sock);
    Probe { child, sock, report }
}

/// Read exactly the one report line. A child that panicked after connecting reaches us as EOF
/// (an empty line), which fails the caller's field lookup loudly instead of hanging.
fn read_report(sock: &TcpStream) -> String {
    let mut reader = BufReader::new(sock.try_clone().expect("clone report socket"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read report line");
    line
}

/// The CONTROL leg. A console-subsystem child spawned with no flags joins the caller's console,
/// and reports the caller's own pid in its list. Every `sees_caller=0` below is discriminating
/// only because this one reads `1` under identical timing — a timing artefact, a wrong argv
/// index or a broken probe fails here first.
#[test]
fn plain_child_joins_the_callers_console() {
    let p = probe_raw(env!("CARGO_BIN_EXE_cosca_testbin"), &[], 0);
    assert_eq!(
        p.field("console"),
        "1",
        "a plain console child has a console: {}",
        p.report
    );
    assert_eq!(
        p.field("sees_caller"),
        "1",
        "a plain console child shares OUR console: {}",
        p.report
    );
    p.end();
}

/// `CREATE_NO_WINDOW` gives the child its OWN (windowless) console — it does not merely hide a
/// window. That is what takes such a child out of reach of an in-process console-group signal.
#[test]
fn no_window_child_gets_its_own_console() {
    let p = probe_raw(env!("CARGO_BIN_EXE_cosca_testbin"), &[], CREATE_NO_WINDOW);
    assert_eq!(
        p.field("console"),
        "1",
        "CREATE_NO_WINDOW still gives a console: {}",
        p.report
    );
    assert_eq!(
        p.field("sees_caller"),
        "0",
        "CREATE_NO_WINDOW's console is not ours: {}",
        p.report
    );
    p.end();
}

/// `DETACHED_PROCESS`: no console at all. A MEASURED absence (`0`), not the probe-failure token
/// (`?`), so a broken probe fails this rather than satisfying it.
#[test]
fn detached_child_gets_no_console() {
    let p = probe_raw(env!("CARGO_BIN_EXE_cosca_testbin"), &[], DETACHED_PROCESS);
    assert_eq!(p.field("console"), "0", "a detached child has no console: {}", p.report);
    p.end();
}

/// Adding `CREATE_NO_WINDOW` to `DETACHED_PROCESS` changes nothing: no console either way. The
/// value differs from the `CREATE_NO_WINDOW`-only row's `1`, which is what makes this row
/// carry information rather than repeat the row above.
#[test]
fn detached_plus_no_window_behaves_as_detached() {
    let p = probe_raw(
        env!("CARGO_BIN_EXE_cosca_testbin"),
        &[],
        DETACHED_PROCESS | CREATE_NO_WINDOW,
    );
    assert_eq!(
        p.field("console"),
        "0",
        "detached wins over window suppression: {}",
        p.report
    );
    p.end();
}

/// The non-skipping guard: if a lane ever runs this suite without a console, every `sees_caller=0`
/// above would be satisfied by there being no console to be in. This says so in one line rather
/// than leaving the control leg to imply it.
#[test]
fn caller_has_a_console_to_be_measured_against() {
    assert_eq!(
        common::in_our_console(std::process::id()),
        Some(true),
        "this test process must have a console, else every membership row here is vacuous"
    );
}

/// `CREATE_NEW_CONSOLE` gives the child its own console too. It deliberately does NOT assert the
/// `hwnd`/`visible` columns: those need an interactive session, which is one of the two reasons
/// this bit stays reserved rather than getting a named intent.
#[test]
fn new_console_child_gets_its_own_console() {
    let p = probe_raw(env!("CARGO_BIN_EXE_cosca_testbin"), &[], CREATE_NEW_CONSOLE);
    assert_eq!(
        p.field("console"),
        "1",
        "a new console is still a console: {}",
        p.report
    );
    assert_eq!(p.field("sees_caller"), "0", "the new console is not ours: {}", p.report);
    p.end();
}

/// Console membership is NOT a function of the creation-flag word. A GUI-subsystem image with no
/// flags at all gets no console, where the console-subsystem control in this same file gets one
/// and joins ours. This is the loud-failure guard behind the shipped rustdoc's one-directional
/// wording: absence of a detaching flag establishes nothing.
#[test]
fn a_gui_subsystem_child_never_joins_the_callers_console() {
    let p = probe_raw(env!("CARGO_BIN_EXE_cosca_testbin_gui"), &[], 0);
    assert_eq!(
        p.field("console"),
        "0",
        "a windows-subsystem image gets no console: {}",
        p.report
    );
    assert_eq!(
        p.field("sees_caller"),
        "?",
        "with no console there is no list to be in: {}",
        p.report
    );
    p.end();
}

/// Windows reports SUCCESS for a console control event that reaches nobody, so the return value
/// is evidence in neither direction. The child's own `sees_caller=0` is the structural proof the
/// event cannot arrive on this route — no timing, and no betting on how long a non-delivery takes.
#[test]
fn ctrl_break_reports_success_for_a_child_outside_our_console() {
    use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};

    let p = probe_raw(
        env!("CARGO_BIN_EXE_cosca_testbin"),
        &[],
        CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
    );
    assert_eq!(
        p.field("sees_caller"),
        "0",
        "the child must be provably outside our console: {}",
        p.report
    );
    // SAFETY: standard Win32 call; the live `std::process::Child` pins the pid.
    let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, p.pid()) };
    assert!(
        sent.is_ok(),
        "Win32 reports success for an undeliverable CTRL_BREAK: {sent:?}"
    );
    p.end();
}

/// Only the raw `CreateProcessW` backend can give a child an `argv[0]` that differs from the
/// image it loaded, so the escaping of `argv[0]` is how later tasks prove which backend ran.
/// Pinned here, at the mode that emits it: a plain std spawn's `argv[0]` IS the image path.
#[test]
fn the_report_escapes_argv0_so_a_spaced_path_cannot_split_the_record() {
    let exe = env!("CARGO_BIN_EXE_cosca_testbin");
    let p = probe_raw(exe, &[], 0);
    assert_eq!(
        p.field("argv0"),
        escape_field(exe),
        "argv0 is the image path, escaped: {}",
        p.report
    );
    assert!(
        !p.field("argv0").contains(char::is_whitespace),
        "an escaped field is one whitespace-free token: {}",
        p.report
    );
    p.end();
}
