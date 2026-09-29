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
//! and EOF to end the session. Its stdout is the *report pipe*. The state machine and its
//! transition table are in [`machine`].
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

/// What ends a wait the helper reports with [`Report::Blocking`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Until {
    /// The signal pipe's EOF, among other events.
    Eof,
    /// Only the tracee's exit.
    Exit,
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
    /// The tracee is no longer traced and is the test's child again. Every signal that stopped
    /// it, but the `SIGSTOP`s the attach and the detach sent, was delivered: a stop signal is
    /// re-sent after the detach, unless a later `SIGCONT` cancelled it (see [`machine`]).
    /// Measured on CI: on macOS 15 the tracee runs, or is job-stopped by the re-sent signal; on
    /// macOS 26 it may instead stay stopped by the detach's `SIGSTOP`, against which XNU discards
    /// the re-sent one. So the test ends it with `SIGKILL` through its handle, which ends it
    /// either way.
    Detached,
    /// The protocol failed in `state`.
    Error { cause: Cause, state: String },
    /// `COSCA_UH_TRACE=1` only: entry into the named state.
    State(String),
    /// The helper is about to wait in `state` with no timeout.
    Blocking { state: String, until: Until },
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
                } else if let Some(rest) = text.strip_prefix("blocking ") {
                    let until = match rest.rsplit_once(' ') {
                        Some((state, "eof")) => (state, Until::Eof),
                        Some((state, "exit")) => (state, Until::Exit),
                        _ => panic!("malformed tracer helper blocking report: {text:?}"),
                    };
                    Report::Blocking {
                        state: until.0.to_string(),
                        until: until.1,
                    }
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
            if let Some(text) = self.echo(&line) {
                return Some(Report::parse(text.trim()));
            }
        }
    }

    /// Reads to EOF without parsing, and stops at a read error: for a test that is already
    /// failing, where a panic would abort the process.
    fn discard_rest(&mut self) {
        use std::io::BufRead as _;
        let mut line = String::new();
        while self.rx.read_line(&mut line).is_ok_and(|n| n > 0) {
            self.echo(&line);
            line.clear();
        }
    }

    /// Echoes `line` to stderr, and returns the report text if it is one.
    fn echo<'l>(&self, line: &'l str) -> Option<&'l str> {
        let Some(idx) = line.find(self.marker.as_str()) else {
            if !line.trim().is_empty() {
                // One formatted argument, so one `write`: the helper shares this stderr.
                let echo = format!("tracer helper stdout: {line}");
                eprint!("{echo}");
            }
            return None;
        };
        let text = &line[idx + self.marker.len()..];
        let echo = format!("tracer helper report: {}\n", text.trim());
        eprint!("{echo}");
        Some(text)
    }
}

/// A running helper and its pipes. [`Session::finish`], or else its `Drop`, is the only
/// teardown: it closes the signal pipe, reads the report pipe to EOF (proof the helper has
/// exited), then reaps the helper through its own handle.
///
/// EOF ends the helper except while it waits for the tracee's exit (a `blocking <state> exit`
/// report). Dropping it there would wait on a tracee the test may keep alive, so the teardown
/// kills the helper instead, as it does for a test that is already failing, and then fails the
/// test naming the state. XNU kills a tracee its killed tracer still traced.
struct Session {
    helper: std::process::Child,
    signal_tx: Option<std::process::ChildStdin>,
    /// `None` once a test closes the report pipe (the EPIPE row's test).
    reports: Option<Reports>,
    /// The state of the last report read, if it was a wait for the tracee's exit.
    awaits_exit: Option<String>,
    finished: bool,
    /// Holds the signed copy the helper runs from; removed after the helper is reaped.
    _exe_dir: tempfile::TempDir,
}

impl Session {
    fn signal_tx(&mut self) -> &mut std::process::ChildStdin {
        self.signal_tx.as_mut().expect("the signal pipe is already closed")
    }

    fn next_report(&mut self) -> Option<Report> {
        let report = self.reports.as_mut().expect("the report pipe is already closed").next();
        self.awaits_exit = match &report {
            Some(Report::Blocking {
                state,
                until: Until::Exit,
            }) => Some(state.clone()),
            _ => None,
        };
        report
    }

    /// Tears the helper down (see [`Session`]) and returns its exit status.
    fn finish(&mut self) -> std::process::ExitStatus {
        debug_assert!(!self.finished, "the tracer helper is already torn down");
        self.finished = true;
        let panicking = std::thread::panicking();
        let stuck = self.awaits_exit.take();
        if panicking || stuck.is_some() {
            if let Err(e) = self.helper.kill() {
                eprintln!("could not kill the tracer helper: {e}");
            }
        }
        drop(self.signal_tx.take());
        if let Some(reports) = &mut self.reports {
            if panicking || stuck.is_some() {
                reports.discard_rest();
            } else {
                while reports.next().is_some() {}
            }
        }
        let status = self.helper.wait().expect("reap the tracer helper");
        if let Some(state) = stuck {
            if !panicking {
                panic!(
                    "the test dropped the tracer helper while it waited in {state} for the tracee's \
                     exit, which EOF does not end; it was killed instead. Read its reports through \
                     the terminal one first"
                );
            }
        }
        status
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let status = self.finish();
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
    // Under `spawn_lock()` (via `test_spawn`): macOS pipes get `FD_CLOEXEC` after `pipe()`, so a
    // concurrent fork could otherwise inherit this helper's pipe ends.
    let mut helper = crate::test_spawn::spawn(&mut cmd).expect("spawn the tracer helper");
    let signal_tx = helper.stdin.take().expect("the helper's stdin is piped");
    let rx = std::io::BufReader::new(helper.stdout.take().expect("the helper's stdout is piped"));
    Pending {
        session: Session {
            helper,
            signal_tx: Some(signal_tx),
            reports: Some(Reports { rx, marker }),
            awaits_exit: None,
            finished: false,
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
        let mut cmd = std::process::Command::new("/usr/bin/codesign");
        cmd.args(["--sign", "-", "--force", "--entitlements"])
            .arg(&plist)
            .arg(&exe)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // `test_spawn::spawn` would re-take the non-reentrant lock; `_guard` is spawn_lock.
        #[allow(
            clippy::disallowed_methods,
            reason = "`_guard` is spawn_lock, held over the copy and the fork"
        )]
        cmd.spawn().expect("spawn codesign")
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
    /// Sends the tracee's pid (S-1 → S0). Panics unless `tracee` is still this process's
    /// unreaped child, whose pid nothing else can hold.
    ///
    /// Takes `&mut`: `Child::wait`/`try_wait` take `&self`, so only an exclusive borrow stops the
    /// test from reaping the tracee (and freeing its pid for reuse) while the helper may still
    /// act on it.
    pub(crate) fn attach(mut self, tracee: &mut crate::Child) -> TracerHelper<'_> {
        let pid = tracee.id().pid();
        if let Err(e) = sys::peek_child(pid) {
            panic!(
                "attach: the tracee {pid} is not this process's unreaped child (waitid: errno {e}), \
                 so its pid may name another process"
            );
        }
        let tx = self.session.signal_tx();
        writeln!(tx, "pid {pid}").expect("send the pid line to the tracer helper");
        tx.flush().expect("flush the pid line");
        TracerHelper {
            session: self.session,
            _tracee: std::marker::PhantomData,
        }
    }
}

/// A helper with its tracee. While it lives the test cannot reach the tracee. Dropping it tears
/// the helper down before the borrow of the tracee ends.
pub(crate) struct TracerHelper<'a> {
    session: Session,
    _tracee: std::marker::PhantomData<&'a mut crate::Child>,
}

impl TracerHelper<'_> {
    /// Blocks for the next report, skipping [`Report::Blocking`]. Panics at EOF: a test reads
    /// only reports the protocol promises.
    pub(crate) fn recv(&mut self) -> Report {
        loop {
            match self.session.next_report() {
                Some(Report::Blocking { .. }) => {}
                Some(report) => return report,
                None => panic!("the tracer helper exited before the report this test waits for"),
            }
        }
    }

    /// Writes one signal byte.
    pub(crate) fn signal(&mut self) {
        let tx = self.session.signal_tx();
        tx.write_all(b"x").expect("write a signal byte");
        tx.flush().expect("flush the signal byte");
    }
}

/// The exit status of a tracee spawned to catch `SIGTERM`, once it gets one.
pub(crate) const SIGTERM_EXIT: i32 = 15;

/// What [`uh_tracee_fixture`] writes to its stdout once its handlers and ignores are set up.
pub(crate) const TRACEE_READY: &[u8] = b"uh-tracee: ready\n";
/// What its `SIGTSTP` handler writes to stdout.
pub(crate) const TRACEE_HANDLED_SIGTSTP: &str = "uh-tracee: handled SIGTSTP\n";
/// What it writes to stdout for each byte read from its stdin. A signal the tracee was handed
/// runs its handler on the tracee's next return to user mode, so a tick read means every
/// handler pending before the byte was sent has already written its line.
pub(crate) const TRACEE_TICK: &str = "uh-tracee: tick\n";

/// Spawns [`uh_tracee_fixture`], uncontained, with a piped stdin: closing it ends the tracee.
/// With `catch_sigterm` the tracee exits with [`SIGTERM_EXIT`] on `SIGTERM`.
pub(crate) fn spawn_tracee(catch_sigterm: bool) -> crate::Child {
    spawn_tracee_with(if catch_sigterm { "SIGTERM" } else { "" }, "", false)
}

/// [`spawn_tracee`] with the signals it `catch`es and `ignore`s, each a comma-separated list of
/// `SIGTERM` or `SIGTSTP`; and, with `pipe_stdout`, its stdout piped instead of null.
pub(crate) fn spawn_tracee_with(catch: &str, ignore: &str, pipe_stdout: bool) -> crate::Child {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = crate::Command::new();
    cmd.executable(&exe)
        .args([
            "cosca_unit_tests",
            "--test-threads=1",
            "--exact",
            crate::test_child::fixture_path!(uh_tracee_fixture),
        ])
        .env("COSCA_UH_ROLE", "tracee")
        .env("COSCA_UH_CATCH", catch)
        .env("COSCA_UH_IGNORE", ignore);
    cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
    let stdout = if pipe_stdout {
        crate::Stdio::pipe()
    } else {
        crate::Stdio::null()
    };
    cmd.stdout(stdout).expect("stdout");
    cmd.stderr(crate::Stdio::null()).expect("stderr null");
    cmd.spawn().expect("spawn the tracee fixture")
}

/// The tracee: sets up the signals named by `COSCA_UH_CATCH` and `COSCA_UH_IGNORE`, writes
/// [`TRACEE_READY`] to stdout, then answers each stdin byte with [`TRACEE_TICK`] until EOF, then
/// exits 0. A no-op
/// unless `COSCA_UH_ROLE=tracee`, so an ordinary suite run does not block on stdin.
#[test]
fn uh_tracee_fixture() {
    if std::env::var("COSCA_UH_ROLE").as_deref() != Ok("tracee") {
        return;
    }
    extern "C" fn exit_on_sigterm(_: libc::c_int) {
        // SAFETY: `_exit` is async-signal-safe.
        unsafe { libc::_exit(SIGTERM_EXIT) }
    }
    extern "C" fn note_sigtstp(_: libc::c_int) {
        write_stdout(TRACEE_HANDLED_SIGTSTP.as_bytes());
    }
    let install = |name: &str, action: libc::sighandler_t| {
        let signal = match name {
            "SIGTERM" => libc::SIGTERM,
            "SIGTSTP" => libc::SIGTSTP,
            other => panic!("the tracee fixture cannot set up {other:?}"),
        };
        // SAFETY: the handlers call only async-signal-safe functions; this process runs no other
        // test.
        let previous = unsafe { libc::signal(signal, action) };
        assert_ne!(previous, libc::SIG_ERR, "set up {name}");
    };
    let names = |var: &str| std::env::var(var).unwrap_or_default();
    for name in names("COSCA_UH_CATCH").split(',').filter(|n| !n.is_empty()) {
        let handler = if name == "SIGTERM" {
            exit_on_sigterm as *const () as libc::sighandler_t
        } else {
            note_sigtstp as *const () as libc::sighandler_t
        };
        install(name, handler);
    }
    for name in names("COSCA_UH_IGNORE").split(',').filter(|n| !n.is_empty()) {
        install(name, libc::SIG_IGN);
    }
    write_stdout(TRACEE_READY);
    while sys::read_byte(0).is_some() {
        write_stdout(TRACEE_TICK.as_bytes());
    }
}

/// `write(2)` to fd 1, async-signal-safe. A failed write is ignored: the reader is gone.
fn write_stdout(bytes: &[u8]) {
    // SAFETY: `bytes` is a valid buffer.
    let _ = unsafe { libc::write(1, bytes.as_ptr().cast(), bytes.len()) };
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
