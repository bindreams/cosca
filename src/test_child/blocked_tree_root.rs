//! The root of [`foreign::blocked_tree`](super::foreign::blocked_tree), as a process of its own.
//!
//! The lib's test binary is also this root: its `main` calls [`run_if_requested`] before the test
//! runner starts, so the root is single-threaded. It spawns a `cat` on its own stdin, blocks
//! `SIGTERM`, prints the `cat`'s pid and waits for it. A `SIGTERM` sent to it stays pending, and
//! it is still pending once the `cat` has ended, however the two sends interleave with this wait.
//! It then prints how the `cat` ended, as a shell reports it (`128 + signal` or the exit code),
//! and if a `SIGTERM` arrived, it dies of it.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

const FLAG: &str = "--cosca-blocked-tree-root";

/// Runs the root and exits, if this process was started as one.
pub(crate) fn run_if_requested() {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).is_none_or(|a| a != FLAG) {
        return;
    }
    run();
    std::process::exit(0);
}

/// The argv (after the program name) that starts the root.
pub(crate) fn argv() -> [&'static str; 1] {
    [FLAG]
}

/// The status of the `cat` as a shell reports it: `128 + signal`, or the exit code.
fn shell_status(status: std::process::ExitStatus) -> i32 {
    status
        .signal()
        .map_or_else(|| status.code().expect("exited"), |s| 128 + s)
}

fn run() {
    // The `cat` is spawned first: a signal mask is inherited across `exec`, and the `cat` must
    // die of `SIGTERM`'s default disposition.
    #[allow(
        clippy::disallowed_methods,
        reason = "this process is single-threaded: nothing else forks, so there is no lock to hold"
    )]
    let mut cat = Command::new("cat")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .spawn()
        .expect("spawn the cat");
    let term = sigset_of_term();
    // SAFETY: `term` is an initialised set; the old mask is not wanted.
    let rc = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &term, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "block SIGTERM: {}", std::io::Error::last_os_error());

    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", cat.id()).expect("report the cat's pid");
    out.flush().expect("report the cat's pid");

    let status = cat.wait().expect("wait for the cat");
    writeln!(out, "{}", shell_status(status)).expect("report the cat's status");
    out.flush().expect("report the cat's status");

    // SAFETY: `sigpending` fills the set it is given.
    let (rc, pending) = unsafe {
        let mut pending = std::mem::zeroed();
        (libc::sigpending(&mut pending), pending)
    };
    assert_eq!(rc, 0, "sigpending: {}", std::io::Error::last_os_error());
    // SAFETY: `pending` is an initialised set.
    if unsafe { libc::sigismember(&pending, libc::SIGTERM) } == 1 {
        // SAFETY: restoring the default disposition, then unblocking the pending signal: it is
        // delivered before `sigprocmask` returns, and its default action ends this process.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            libc::sigprocmask(libc::SIG_UNBLOCK, &term, std::ptr::null_mut());
        }
        unreachable!("the pending SIGTERM kills this process");
    }
}

/// A set holding `SIGTERM` alone.
fn sigset_of_term() -> libc::sigset_t {
    // SAFETY: `sigemptyset` initialises the set it is given.
    unsafe {
        let mut set = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        set
    }
}
