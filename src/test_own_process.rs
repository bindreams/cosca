//! Runs a test that must change process-global state in a process of its own.
//!
//! Closing fd 0/1/2 or lowering `RLIMIT_NOFILE` in a test hits every other test thread in the
//! process: `cargo test` runs them as threads of one process, so a concurrent `open` lands on the
//! closed slot, and a restore `dup2`s over whatever took it. nextest hides this by giving each
//! test its own process. A guard that restores the state cannot fix it, because the damage
//! happens inside the window.
//!
//! Also mounted by `#[path]` into `tests/common`, so it names nothing of its crate: the caller
//! passes the [`Spawn`] hook that takes `spawn_lock` around the fork.
//!
//! # The gate
//!
//! The parent re-executes the test binary as
//! `<exe> --exact <test> --test-threads=1 --nocapture` with
//! `COSCA_TEST_OWN_PROCESS=<parent pid>:<token fd>:<test>`. A process takes the child role only if
//! all of these hold at once: the value's pid is its real parent's, its test is the one being
//! gated, and its argv is exactly the shape above. An environment variable alone is forgeable
//! and inheritable (a shell export, an outer harness, a grandchild); the parent pid binds the
//! value to the process that set it, and the argv proves libtest was told to run this one test on
//! one thread, so the process is the test's own.
//!
//! # The completion token
//!
//! The parent hands the child the write end of a private pipe. The child writes a start token when
//! it accepts the role and a return token when its [`Completion`] drops without a panic; the parent
//! requires both as well as a successful exit. `process::exit(0)` inside the body leaves no return
//! token, and a filter that matches no test (libtest exits 0 for both) leaves no start token. A pipe
//! rather than a stdout line because these bodies close fd 1 and 2, and because a private fd cannot
//! be printed by anything else.
//!
//! # The witness
//!
//! [`own_process`] returns the [`Completion`] only in the child. A guard that changes
//! process-global state takes `&Completion`, so a test that forgot `own_process` does not compile.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::process::{parent_id, CommandExt as _};
use std::process::{Child, Command, ExitStatus, Stdio};

/// Forks `command` with `spawn_lock` held for the fork alone: `test_spawn::spawn` in the library's
/// tests, `common::spawn_locked` in the integration tests.
pub(crate) type Spawn = fn(&mut Command) -> std::io::Result<Child>;

/// The role marker: `<parent pid>:<token fd>:<test>`. See the module doc.
pub(crate) const ENV: &str = "COSCA_TEST_OWN_PROCESS";

/// What the child writes to the token pipe when it accepts the role.
const STARTED: &[u8] = b"started";

/// What the child writes to the token pipe once its body has returned.
const RETURNED: &[u8] = b"returned";

/// The path of the test fn `$name` (sync or `async`), for [`own_process`]. `let _ = $name;` makes a
/// stale name a compile error rather than a filter that matches nothing.
#[allow(
    unused_macros,
    reason = "unused in the integration binaries that mount this file only for `tests/common`"
)]
macro_rules! test_path {
    ($name:ident) => {{
        let _ = $name;
        concat!(module_path!(), "::", stringify!($name))
    }};
}

/// libtest's filter for a [`test_path!`]: `module_path!()` always leads with a crate segment, which
/// the filter has none of.
pub(crate) fn test_filter(path: &str) -> &str {
    path.split_once("::")
        .unwrap_or_else(|| panic!("{path:?} has no crate segment"))
        .1
}

/// What [`role`] decided this process is.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// Re-executes the test; runs no body.
    Parent,
    /// The re-executed process; completion is reported on `token_fd`.
    Child { token_fd: RawFd },
}

/// The argv (after the program name) of a re-executed test.
///
/// `--nocapture` keeps skuld's fd-level capture from swallowing the child's stdout and stderr,
/// which the parent reports.
pub(crate) fn child_args(test: &str) -> [&str; 4] {
    ["--exact", test, "--test-threads=1", super::test_reexec::NOCAPTURE]
}

/// Classifies a process from its inherited [`ENV`] value, its real parent's pid and its argv; see
/// the module doc.
pub(crate) fn role(inherited: Option<&str>, parent_pid: u32, args: &[OsString], test: &str) -> Role {
    let Some(inherited) = inherited else {
        return Role::Parent;
    };
    let mut parts = inherited.splitn(3, ':');
    let (Some(pid), Some(fd), Some(named)) = (parts.next(), parts.next(), parts.next()) else {
        return Role::Parent;
    };
    let Ok(token_fd) = fd.parse::<RawFd>() else {
        return Role::Parent;
    };
    let exact_argv = args
        .iter()
        .map(OsString::as_os_str)
        .eq(child_args(test).iter().map(std::ffi::OsStr::new));
    if pid == parent_pid.to_string() && named == test && exact_argv && token_fd > 2 {
        Role::Child { token_fd }
    } else {
        Role::Parent
    }
}

/// Whether `inherited` says this very process was re-executed for `test` by its real parent. Such a
/// process that was not accepted as the child is a bug in the gate; re-executing again would
/// recurse without end.
pub(crate) fn is_reexecution(inherited: Option<&str>, parent_pid: u32, test: &str) -> bool {
    let mut parts = inherited.unwrap_or_default().splitn(3, ':');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(pid), Some(_), Some(named)) if pid == parent_pid.to_string() && named == test
    )
}

/// Proof that this process is an `own_process` child, and the report that its body returned. A
/// guard that changes process-global state takes `&Completion`.
///
/// Dropped by a panicking body, or never dropped by one that exits the process, it reports nothing.
#[must_use = "the body's completion is reported when this drops; bind it for the whole body"]
pub(crate) struct Completion(pub(crate) File);

impl Drop for Completion {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.0
                .write_all(RETURNED)
                .expect("report that the isolated body returned");
        }
    }
}

/// Call first in a test that changes process-global state:
/// `let Some(done) = own_process(test_path!(this_fn), spawn) else { return };`.
///
/// In the parent this re-executes the test binary to run only this test, waits for it, and
/// panics with its output unless it passed; it returns `None`. In the child it returns the
/// [`Completion`] to hold for the whole body, which runs alone in its process.
#[must_use = "`let Some(done) = own_process(..) else { return };`: without the witness the test is not isolated"]
pub(crate) fn own_process(path: &str, spawn: Spawn) -> Option<Completion> {
    if let Some(done) = child_completion(path) {
        return Some(done);
    }
    if let Err(failure) = run(test_filter(path), &[], spawn) {
        panic!("{failure}");
    }
    None
}

/// The [`Completion`] if this process was re-executed for `path` by its real parent, else `None`
/// with nothing run. For a test whose parent does more than one [`run`], such as one per case.
///
/// The role is decided by [`role`], never by the presence of an environment variable, which a
/// shell export or an outer harness can set.
#[must_use = "without the witness the test is not isolated"]
pub(crate) fn child_completion(path: &str) -> Option<Completion> {
    let test = test_filter(path);
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match role(std::env::var(ENV).ok().as_deref(), parent_id(), &args, test) {
        Role::Child { token_fd } => Some(accept(token_fd)),
        Role::Parent => {
            let inherited = std::env::var(ENV).ok();
            assert!(
                !is_reexecution(inherited.as_deref(), parent_id(), test),
                "re-executed for {test} but not accepted as its own process: got {args:?} with {ENV}={inherited:?}, \
                 expected {:?}",
                child_args(test)
            );
            None
        }
    }
}

/// Takes the token pipe and reports that the role was accepted.
fn accept(token_fd: RawFd) -> Completion {
    // The body's own children must not inherit the token.
    // SAFETY: `token_fd` is open (checked below).
    let set = rustix::io::fcntl_setfd(
        unsafe { rustix::fd::BorrowedFd::borrow_raw(token_fd) },
        rustix::io::FdFlags::CLOEXEC,
    );
    if let Err(e) = set {
        panic!("the token fd {token_fd} is not open: {e}");
    }
    // SAFETY: the parent passed this pipe end down for this process alone.
    let mut token = unsafe { File::from_raw_fd(token_fd) };
    token.write_all(STARTED).expect("report that the isolated run started");
    Completion(token)
}

/// How a re-executed test failed. Compare [`Failure::kind`]; the `Display` is for humans.
#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) kind: FailureKind,
    report: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    /// The process exited unsuccessfully: a panic, or a non-zero exit.
    Exited(ExitStatus),
    /// It exited 0 without the body ever starting: the filter matched no test.
    NeverStarted,
    /// It exited 0 after the body started but before it returned: the body exited the process.
    DidNotReturn,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.report)
    }
}

/// Reads what a process that has already exited wrote to a non-blocking pipe.
///
/// Stops at end of file or at `WouldBlock`, never waiting for EOF: another process can hold the
/// write end for as long as it lives, and every byte the exited process wrote is already there.
pub(crate) fn drain(token_read: &mut std::io::PipeReader) -> std::io::Result<Vec<u8>> {
    let flags = rustix::fs::fcntl_getfl(&*token_read).expect("read the token pipe's flags");
    debug_assert!(
        flags.contains(rustix::fs::OFlags::NONBLOCK),
        "the token pipe's read end must be nonblocking"
    );
    let mut token = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        match token_read.read(&mut chunk) {
            Ok(0) => return Ok(token),
            Ok(n) => token.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(token),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Re-executes this test binary to run only `test`, with `env` added, and reports how it went. `spawn`
/// forks the child.
pub(crate) fn run(test: &str, env: &[(&str, &str)], spawn: Spawn) -> Result<(), Failure> {
    let (mut token_read, token_write) = std::io::pipe().expect("create the completion pipe");
    // `drain` never waits for EOF, so a fork that inherits `token_write` before it is
    // close-on-exec (not every fork takes the lock) cannot delay the verdict.
    rustix::fs::fcntl_setfl(&token_read, rustix::fs::OFlags::NONBLOCK).expect("make the completion pipe non-blocking");
    // `try_clone` lands at fd 3 or above, out of reach of the child's stdio setup even when
    // the parent has fd 0-2 closed.
    let token_write = OwnedFd::from(token_write);
    let token_write = {
        let high = token_write
            .try_clone()
            .expect("move the completion pipe above the stdio slots");
        drop(token_write);
        high
    };
    let token_fd = token_write.as_raw_fd();
    let mut command = super::test_reexec::command(std::env::current_exe().expect("current_exe"));
    command
        .args(child_args(test))
        .env(ENV, format!("{}:{token_fd}:{test}", std::process::id()))
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only `fcntl` runs between fork and exec, which is async-signal-safe. The pipe
    // is close-on-exec, so this clears the flag in the child alone.
    unsafe {
        command.pre_exec(move || {
            // `token_fd` is the token pipe, open in this forked child.
            let fd = rustix::fd::BorrowedFd::borrow_raw(token_fd);
            rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty()).map_err(std::io::Error::from)
        });
    }
    // `spawn` already holds `spawn_lock` across the fork; do not take it here.
    let child = spawn(&mut command).expect("re-execute the test binary");
    drop(token_write);
    let output = child.wait_with_output().expect("wait for the isolated run");
    let token = drain(&mut token_read).expect("read the completion pipe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let (kind, why) = if !output.status.success() {
        (
            FailureKind::Exited(output.status),
            format!("it exited with {:?}", output.status),
        )
    } else if !token.starts_with(STARTED) {
        (FailureKind::NeverStarted, "the filter matched no test".to_string())
    } else if &token[STARTED.len()..] != RETURNED {
        (
            FailureKind::DidNotReturn,
            "the body exited the process without returning".to_string(),
        )
    } else {
        return Ok(());
    };
    Err(Failure {
        kind,
        report: format!(
            "test {test} did not pass in its own process: {why}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        ),
    })
}

pub(crate) use test_path;
