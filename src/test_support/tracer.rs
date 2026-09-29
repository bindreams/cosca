//! A debugger stand-in for tests: a helper process that attaches to one of the test's own
//! children with `ptrace`, as a debugger would, so tests can drive the "child held by a tracer"
//! paths deterministically.
//!
//! The helper is a separate process, never the tracee's parent: attaching reparents the tracee
//! to the helper, which is the shape (`ECHILD` in the parent, the zombie handed back after the
//! tracer's reap) that a real debugger creates. It is a re-exec of this test binary, filtered to
//! [`uh_helper_entry`], and takes its inputs from env vars (libtest rejects unknown options):
//!
//! - `COSCA_UH_ROLE=helper` marks the re-exec; without it the `#[test]` is a no-op;
//! - `COSCA_UH_MODE` is `auto` or `hold` ([`Mode`]);
//! - `COSCA_UH_FORCE=<tag>:<directive>[,…]` injects results and events (transition tests only);
//! - `COSCA_UH_TRACE=1` adds a `state <name>` report on entry to every state (transition tests
//!   only);
//! - `COSCA_UH_MARKER` frames the reports.
//!
//! Its stdin is the *signal pipe*: the pid as a first `pid <n>` line, then one byte per signal,
//! and EOF to end the session. Its stdout is the *report pipe*. The state machine is in
//! [`machine`], its transition table in `machine`'s docs.
//!
//! **Entitlement (measured on CI).** macOS refuses `ptrace` attach with `EPERM` to an ad-hoc
//! signed tracer unless the tracee carries `com.apple.security.get-task-allow` or the tracer
//! carries `com.apple.security.cs.debugger`. So the helper runs from a copy of this binary
//! ad-hoc signed with `cs.debugger`, made per helper in a temporary directory, which lets it
//! attach to any child of the test.

use std::io::Write as _;

mod machine;
mod sys;

const DEFAULT_MARKER: &str = "@@cosca-uh@@";

/// What the helper does once the traced tracee exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Reap it at once, handing the zombie back to the test.
    Auto,
    /// Report `exited` with the tracee a zombie on the helper's own list, and reap it only on
    /// the next signal byte or EOF.
    Hold,
}

impl Mode {
    fn as_env(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::Hold => "hold",
        }
    }
}

/// A report from the helper.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Report {
    /// The tracee is traced and running again.
    Attached,
    /// [`Mode::Hold`] only: the tracee has exited and is a zombie on the helper's list.
    Exited,
    /// The helper reaped the tracee, so XNU has handed the zombie back to the test.
    Reaped,
    /// The tracee is no longer traced and is the test's child again. Any signal but `SIGSTOP`
    /// that stopped it was delivered. Whether it runs depends on the OS (measured on CI: stopped
    /// by `SIGSTOP` on macOS 26, running on macOS 15), so the test ends it with `SIGKILL` through
    /// its handle, which ends it either way.
    Detached,
    /// The protocol failed in `state`.
    Error { cause: Cause, state: String },
    /// `COSCA_UH_TRACE=1` only: entry into the named state.
    State(String),
}

/// Why an [`Report::Error`] happened.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    /// A syscall failed with this errno.
    Errno(i32),
    /// An event arrived where the table allows none (`NOTE_EXIT`, `SIGNAL`, `EOF`).
    Event(String),
}

impl Report {
    fn parse(text: &str) -> Report {
        match text {
            "attached" => Report::Attached,
            "exited" => Report::Exited,
            "reaped" => Report::Reaped,
            "detached" => Report::Detached,
            _ => {
                if let Some(rest) = text.strip_prefix("error ") {
                    let (cause, state) = rest
                        .split_once(' ')
                        .unwrap_or_else(|| panic!("malformed tracer helper error report: {text:?}"));
                    let cause = match cause.parse() {
                        Ok(errno) => Cause::Errno(errno),
                        Err(_) => Cause::Event(cause.to_string()),
                    };
                    Report::Error {
                        cause,
                        state: state.to_string(),
                    }
                } else if let Some(name) = text.strip_prefix("state ") {
                    Report::State(name.to_string())
                } else {
                    panic!("unrecognized tracer helper report: {text:?}")
                }
            }
        }
    }
}

/// The report pipe's reader. A report is a line carrying the marker, anywhere in it; every
/// other line (the helper's libtest banner, or its panic output) is echoed to stderr.
struct Reports {
    rx: std::io::BufReader<std::process::ChildStdout>,
    marker: String,
}

impl Reports {
    /// The next report, or `None` at EOF: the helper, the pipe's only writer, has exited.
    fn next(&mut self) -> Option<Report> {
        use std::io::BufRead as _;
        loop {
            let mut line = String::new();
            if self
                .rx
                .read_line(&mut line)
                .expect("read the tracer helper's report pipe")
                == 0
            {
                return None;
            }
            let Some(idx) = line.find(self.marker.as_str()) else {
                if !line.trim().is_empty() {
                    let echo = format!("tracer helper stdout: {line}");
                    eprint!("{echo}");
                }
                continue;
            };
            let text = line[idx + self.marker.len()..].trim();
            // One formatted argument, so one `write`: the helper shares this stderr.
            let echo = format!("tracer helper report: {text}\n");
            eprint!("{echo}");
            return Some(Report::parse(text));
        }
    }
}

/// A running helper and its pipes. Its `Drop` is the only teardown: it closes the signal pipe,
/// reads the report pipe to EOF (proof the helper has exited), then reaps the helper through its
/// own handle.
///
/// EOF ends a helper that has reported `reaped`, `detached` or `error`, or has not attached yet,
/// and one in S1h, S3 or S3x. S6 ignores it, and S5 blocks in `wait4`, until the tracee exits,
/// so a test that drops a helper in those states ends its tracee first.
/// Only a test that is already panicking kills the helper, through its handle.
struct Session {
    helper: std::process::Child,
    signal_tx: Option<std::process::ChildStdin>,
    /// `None` once a test closes the report pipe (the EPIPE row's test).
    reports: Option<Reports>,
    /// Holds the signed copy the helper runs from; removed after the helper is reaped.
    _exe_dir: tempfile::TempDir,
}

impl Session {
    fn signal_tx(&mut self) -> &mut std::process::ChildStdin {
        self.signal_tx.as_mut().expect("the signal pipe is already closed")
    }

    fn next_report(&mut self) -> Option<Report> {
        self.reports.as_mut().expect("the report pipe is already closed").next()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // The test failed, and may still hold the tracee's stdin, on which a helper blocked
            // in S5's `wait4` depends: end the helper through its own handle instead. XNU then
            // kills a tracee it still traced.
            if let Err(e) = self.helper.kill() {
                eprintln!("could not kill the tracer helper after a test failure: {e}");
            }
        }
        drop(self.signal_tx.take());
        if let Some(reports) = &mut self.reports {
            while reports.next().is_some() {}
        }
        let status = self.helper.wait().expect("reap the tracer helper");
        // With its report pipe closed by the test, the helper's libtest fails to print its
        // summary, so only a helper that could report is held to a clean exit.
        if self.reports.is_some() && !std::thread::panicking() {
            assert!(
                status.success(),
                "the tracer helper failed ({status}); its output is above"
            );
        }
    }
}

/// A helper that has not been told its tracee yet (state S-1).
pub(crate) struct Pending {
    session: Session,
}

/// Launches a helper for client tests, without transition traces or injections.
#[allow(
    dead_code,
    reason = "UH's own tests use start_forced; UA's tracer tests are the first callers"
)]
pub(crate) fn start(mode: Mode) -> Pending {
    launch(mode, None)
}

/// Launches a helper with `COSCA_UH_TRACE=1` and the injections in `force`, for the transition
/// tests.
pub(crate) fn start_forced(mode: Mode, force: &str) -> Pending {
    launch(mode, Some(force))
}

fn launch(mode: Mode, force: Option<&str>) -> Pending {
    let exe_dir = tempfile::tempdir().expect("create a directory for the signed helper");
    let exe = debugger_signed_copy(exe_dir.path());
    let marker = DEFAULT_MARKER.to_string();
    let mut cmd = std::process::Command::new(exe);
    cmd.args([
        "--test-threads=1",
        "--exact",
        crate::test_child::fixture_path!(uh_helper_entry),
    ])
    .env("COSCA_UH_ROLE", "helper")
    .env("COSCA_UH_MODE", mode.as_env())
    .env("COSCA_UH_MARKER", &marker)
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    // Inherited: the probe's lines and a failing helper's messages reach this test's stderr.
    .stderr(std::process::Stdio::inherit());
    match force {
        Some(force) => cmd.env("COSCA_UH_TRACE", "1").env("COSCA_UH_FORCE", force),
        // Not inherited from the test's own environment into a client's helper.
        None => cmd.env_remove("COSCA_UH_TRACE").env_remove("COSCA_UH_FORCE"),
    };
    // Under `spawn_lock()`: macOS pipes get `FD_CLOEXEC` after `pipe()`, so a concurrent fork
    // could otherwise inherit this helper's pipe ends.
    let mut helper = {
        let _guard = crate::child::spawn::spawn_lock();
        cmd.spawn().expect("spawn the tracer helper")
    };
    let signal_tx = helper.stdin.take().expect("the helper's stdin is piped");
    let rx = std::io::BufReader::new(helper.stdout.take().expect("the helper's stdout is piped"));
    Pending {
        session: Session {
            helper,
            signal_tx: Some(signal_tx),
            reports: Some(Reports { rx, marker }),
            _exe_dir: exe_dir,
        },
    }
}

/// Copies this test binary into `dir` and ad-hoc signs the copy with
/// `com.apple.security.cs.debugger`, which macOS requires of a tracer (see the module docs).
fn debugger_signed_copy(dir: &std::path::Path) -> std::path::PathBuf {
    const ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.debugger</key><true/></dict></plist>
"#;
    let exe = dir.join("tracer-helper");
    let plist = dir.join("entitlements.plist");
    let codesign = {
        // Writes and the fork under one guard, as `test_child::cwd_and_path_tools` does: no
        // concurrent fork may hold the copy's writable descriptor.
        let _guard = crate::child::spawn::spawn_lock();
        std::fs::copy(std::env::current_exe().expect("current_exe"), &exe).expect("copy the test binary");
        std::fs::write(&plist, ENTITLEMENTS).expect("write the entitlements plist");
        std::process::Command::new("/usr/bin/codesign")
            .args(["--sign", "-", "--force", "--entitlements"])
            .arg(&plist)
            .arg(&exe)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn codesign")
    };
    let out = codesign.wait_with_output().expect("wait for codesign");
    assert!(
        out.status.success(),
        "codesign of the tracer helper failed ({}): {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    exe
}

impl Pending {
    /// Sends the tracee's pid (S-1 → S0).
    ///
    /// Takes `&'a mut`: `Child::wait`/`try_wait` take `&self`, so only an exclusive borrow stops
    /// the test from reaping the tracee, and letting its pid be reused, while the helper may
    /// still attach to it or stop it.
    pub(crate) fn attach(mut self, tracee: &mut crate::Child) -> TracerHelper<'_> {
        let pid = tracee.id().pid();
        let tx = self.session.signal_tx();
        writeln!(tx, "pid {pid}").expect("send the pid line to the tracer helper");
        tx.flush().expect("flush the pid line");
        TracerHelper {
            session: self.session,
            tracee,
        }
    }
}

/// A helper with its tracee. While it lives the test can reach the tracee only through it, and
/// nothing here exposes `wait` or `try_wait`. Dropping it tears the helper down before the
/// borrow of the tracee ends.
pub(crate) struct TracerHelper<'a> {
    session: Session,
    #[allow(
        dead_code,
        reason = "held for the exclusive borrow; UA's kill_tracee is the first reader"
    )]
    tracee: &'a mut crate::Child,
}

impl TracerHelper<'_> {
    /// Blocks for the next report. Panics at EOF: a test reads only reports the protocol
    /// promises.
    pub(crate) fn recv(&mut self) -> Report {
        self.session
            .next_report()
            .expect("the tracer helper exited before the report this test waits for")
    }

    /// Writes one signal byte.
    pub(crate) fn signal(&mut self) {
        let tx = self.session.signal_tx();
        tx.write_all(b"x").expect("write a signal byte");
        tx.flush().expect("flush the signal byte");
    }
}

/// Spawns [`uh_tracee_fixture`], uncontained, with a piped stdin: closing it ends the tracee.
pub(crate) fn spawn_tracee() -> crate::Child {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = crate::Command::new();
    cmd.executable(&exe)
        .args([
            "cosca_unit_tests",
            "--test-threads=1",
            "--exact",
            crate::test_child::fixture_path!(uh_tracee_fixture),
        ])
        .env("COSCA_UH_ROLE", "tracee");
    cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("stdout null");
    cmd.stderr(crate::Stdio::null()).expect("stderr null");
    cmd.spawn().expect("spawn the tracee fixture")
}

/// The tracee: reads stdin until EOF or one byte, then exits 0. A no-op unless
/// `COSCA_UH_ROLE=tracee`, so an ordinary suite run does not block on stdin.
#[test]
fn uh_tracee_fixture() {
    if std::env::var("COSCA_UH_ROLE").as_deref() != Ok("tracee") {
        return;
    }
    let _ = sys::read_byte(0);
}

/// The helper's entry point. A no-op unless `COSCA_UH_ROLE=helper`.
#[test]
fn uh_helper_entry() {
    if std::env::var("COSCA_UH_ROLE").as_deref() != Ok("helper") {
        return;
    }
    machine::main();
}

#[cfg(test)]
#[path = "tracer_tests.rs"]
mod tracer_tests;
