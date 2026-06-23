//! Unix process-group and session containment.
//!
//! Two mechanisms are available:
//! - **ProcessGroup** (`process_group(0)` / `setpgid`): the child becomes a
//!   process-group leader (pgid == pid). Teardown sends `killpg`. cgroup v2
//!   (Task 4) preempts this on Linux when available. macOS uses this for
//!   `ContainMode::Strongest`.
//! - **Session** (`setsid`): the child becomes a session leader *and*
//!   process-group leader in a new session, detached from any controlling
//!   terminal. Teardown is identical (`killpg` on the session's initial pgroup,
//!   which equals the leader's pid). Useful for daemon-like children.
//!
//! **Mutual exclusivity (S3):** `setsid` makes the child a session *and*
//! process-group leader simultaneously. Calling `setpgid`/`process_group(0)`
//! on a session leader fails with `EPERM`. Therefore Session mode applies
//! `setsid` *instead of* `process_group(0)` — never both.
//!
//! **Self-`setsid` escape:** a child that calls `setsid` itself exits the
//! parent's session/group; containment is then best-effort. This applies to
//! both mechanisms and is documented as a known limitation (not a sandbox).
//!
//! Parent-side signals use `nix` (not hand-rolled `libc`); see Global Constraints.
//!
//! # PGID-reuse caveat
//! `kill_tree` must run *before* the leader is reaped (`wait`): once reaped, the
//! kernel may recycle the leader's PID/PGID, so `killpg` could signal an
//! unrelated process group. The crate's `Drop` kills before it reaps, so the
//! common path is safe; an explicit `wait()` then `kill_tree()` is the unsafe
//! ordering. cgroup v2 and the identity-reverifying TreeWalk mechanism do not
//! have this hole — prefer them when the guarantee matters.

use std::io;

use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::Pid;

/// Apply pre-spawn group setup to `std_cmd` (root spawns only).
/// Must not be combined with `set_session` on the same command (S3).
pub(crate) fn set_process_group(std_cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    std_cmd.process_group(0); // leader: pgid == pid
}

/// Apply pre-spawn session setup to `std_cmd` via a `pre_exec` `setsid` call
/// (root spawns only, `ContainMode::Session`).
///
/// `setsid` makes the child a session leader *and* process-group leader (pgid
/// == sid == pid), detached from any controlling terminal. Because the child is
/// already a process-group leader after `setsid`, calling `setpgid` or
/// `process_group(0)` on it would return `EPERM` — do not call
/// `set_process_group` on the same command (S3 mutual exclusivity).
///
/// The `pre_exec` closure is async-signal-safe: it calls only raw `libc::setsid`
/// (no allocation, no unwinding). Failure of `setsid` aborts the spawn.
pub(crate) fn set_session(std_cmd: &mut std::process::Command) {
    // Safety: `pre_exec` runs post-fork, pre-exec. The closure is
    // async-signal-safe: `libc::setsid` is a raw syscall with no allocation.
    // A non-zero return means `setsid` failed (EPERM: already a session leader),
    // which we surface as an `io::Error` to abort the spawn.
    unsafe {
        use std::os::unix::process::CommandExt;
        std_cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Hard-kill the whole process group. ESRCH (gone) is success; EPERM falls
/// back to the leader directly (pgid == pid for a process-group root).
pub(crate) fn kill_group(pgid: i32) -> io::Result<()> {
    match killpg(Pid::from_raw(pgid), Signal::SIGKILL) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(nix::errno::Errno::EPERM) => kill_direct(pgid),
        Err(e) => Err(io::Error::from(e)),
    }
}

/// SIGTERM the group; ESRCH (gone) is success; EPERM falls back to the leader
/// directly (valid because pgid == pid — the sudo-wrapper case).
pub(crate) fn term_group(pgid: i32) -> io::Result<()> {
    match killpg(Pid::from_raw(pgid), Signal::SIGTERM) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(nix::errno::Errno::EPERM) => term_direct(pgid),
        Err(e) => Err(io::Error::from(e)),
    }
}

fn kill_direct(pid: i32) -> io::Result<()> {
    match kill(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => Err(io::Error::from(e)),
    }
}

fn term_direct(pid: i32) -> io::Result<()> {
    match kill(Pid::from_raw(pid), Signal::SIGTERM) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => Err(io::Error::from(e)),
    }
}

#[cfg(test)]
#[path = "unix_tests.rs"]
mod unix_tests;
