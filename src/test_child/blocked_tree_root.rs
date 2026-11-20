//! The root of [`foreign::blocked_tree`](super::foreign::blocked_tree), as a process of its own: the
//! lib's test binary re-run as [`ROLE`], dispatched from `main` before the runner starts, so it is
//! single-threaded. It spawns a `cat` on its own stdin and prints the `cat`'s
//! pid, then how the `cat` ended (`128 + signal` or the exit code, as a shell reports it). It blocks
//! `SIGTERM` so a send stays pending however it interleaves with the wait on the `cat`, and dies of it
//! at the end.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use super::fixture_role::FixtureRole;

pub(crate) const ROLE: FixtureRole = FixtureRole::new("--cosca-blocked-tree-root", run);

fn shell_status(status: std::process::ExitStatus) -> i32 {
    status
        .signal()
        .map_or_else(|| status.code().expect("exited"), |s| 128 + s)
}

fn run(_: &[OsString]) -> ! {
    #[allow(
        clippy::disallowed_methods,
        reason = "this process runs no thread but its main one: nothing else forks, so there is no lock to hold"
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

    // SAFETY: a zeroed `sigset_t` is a valid out-parameter for `sigpending`.
    let (rc, pending) = unsafe {
        let mut pending = std::mem::zeroed();
        (libc::sigpending(&mut pending), pending)
    };
    assert_eq!(rc, 0, "sigpending: {}", std::io::Error::last_os_error());
    if unsafe { libc::sigismember(&pending, libc::SIGTERM) } == 1 {
        // SAFETY: plain libc calls. Unblocking delivers the pending SIGTERM before `sigprocmask`
        // returns.
        let (handler, rc) = unsafe {
            (
                libc::signal(libc::SIGTERM, libc::SIG_DFL),
                libc::sigprocmask(libc::SIG_UNBLOCK, &term, std::ptr::null_mut()),
            )
        };
        assert_ne!(
            handler,
            libc::SIG_ERR,
            "reset SIGTERM: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(rc, 0, "unblock SIGTERM: {}", std::io::Error::last_os_error());
        unreachable!("the pending SIGTERM kills this process");
    }
    std::process::exit(0)
}

fn sigset_of_term() -> libc::sigset_t {
    // SAFETY: `sigemptyset` initialises the set it is given.
    unsafe {
        let mut set = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        set
    }
}
