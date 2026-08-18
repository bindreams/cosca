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

use common::{escape_report_field as escape_field, read_report_line, report_field as field};

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
    let report = read_report_line(&sock);
    Probe { child, sock, report }
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

// ===== cosca's own spawn paths =====

/// A running cosca-spawned `report-console-identity` child plus its report line. Argv-only, so
/// it routes to the **std** backend: an `executable()` or any fd >= 3 would route to the raw
/// `CreateProcessW` one instead, and the existing testbin idiom uses `executable()` — so a test
/// written in the house style would silently leave the std path unproven.
struct CoscaProbe {
    child: cosca::Child,
    sock: TcpStream,
    report: String,
}

impl CoscaProbe {
    fn field(&self, key: &str) -> &str {
        field(&self.report, key)
    }

    fn end(self) {
        drop(self.sock);
        let _ = self.child.kill_tree();
        self.child.wait().expect("reap cosca identity probe child");
    }
}

/// Spawn the testbin through `cosca::Command` with the image path as `argv[0]`, apply
/// `configure`, and read the one report line.
fn probe_cosca(configure: impl FnOnce(&mut cosca::Command)) -> CoscaProbe {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind report listener");
    let addr = listener.local_addr().unwrap().to_string();
    let me = std::process::id().to_string();
    let mut cmd = cosca::Command::new();
    cmd.args([
        env!("CARGO_BIN_EXE_cosca_testbin"),
        "report-console-identity",
        addr.as_str(),
        me.as_str(),
    ]);
    configure(&mut cmd);
    let child = cmd.spawn().expect("spawn cosca identity probe child");
    let (sock, _) = listener.accept().expect("accept report socket");
    let report = read_report_line(&sock);
    CoscaProbe { child, sock, report }
}

/// `no_window()` reaches the child on the std backend — the path most spawns take.
#[test]
fn cosca_no_window_child_gets_its_own_console_on_the_std_path() {
    let p = probe_cosca(|c| {
        c.contain().no_window();
    });
    assert_eq!(p.field("console"), "1", "still a console, just not ours: {}", p.report);
    assert_eq!(
        p.field("sees_caller"),
        "0",
        "the suppressed child got a console of its own: {}",
        p.report
    );
    p.end();
}

/// The same on an UNCONTAINED spawn, which is the branch `prepare` returns from before it ever
/// reaches its Windows work — so a composition placed inside the containment branch drops the
/// caller's word here and nowhere else.
#[test]
fn cosca_uncontained_raw_flags_reach_the_child() {
    let p = probe_cosca(|c| {
        c.no_window();
    });
    assert_eq!(
        p.field("sees_caller"),
        "0",
        "an uncontained spawn must carry the caller's flags too: {}",
        p.report
    );
    p.end();
}

/// The control for both of the above, through the identical `cosca::Command` path with no flag
/// methods called. A red result here would mean the harness broke, not the feature.
#[test]
fn a_plain_cosca_child_still_joins_the_callers_console() {
    let p = probe_cosca(|_| {});
    assert_eq!(
        p.field("sees_caller"),
        "1",
        "a plain cosca child shares OUR console: {}",
        p.report
    );
    p.end();
}

/// `graceful_mechanism()` must be derived from the word cosca actually composed, not from the
/// containment half of it: a hidden child has no in-process route, and reporting `ConsoleGroup`
/// for it tells the caller the opposite.
///
/// The two children are what make this discriminate. A derivation reading only the containment
/// half reports `ConsoleGroup` for both, so the second assertion fails; a hardcoded
/// `OtherConsoleGroup` fails the first.
#[test]
fn a_no_window_contained_child_reports_no_in_process_route() {
    use cosca::GracefulMechanism;

    let plain = probe_cosca(|c| {
        c.contain();
    });
    assert_eq!(
        plain.child.graceful_mechanism(),
        GracefulMechanism::ConsoleGroup,
        "a contained child leads a group in OUR console"
    );
    let hidden = probe_cosca(|c| {
        c.contain().no_window();
    });
    assert_eq!(
        hidden.child.graceful_mechanism(),
        GracefulMechanism::OtherConsoleGroup,
        "a hidden child's group is in a console of its own"
    );
    plain.end();
    hidden.end();
}
