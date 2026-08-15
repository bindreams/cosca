//! Unix process-group and session containment.
//!
//! Two mechanisms are available:
//! - **ProcessGroup** (`process_group(0)` / `setpgid`): the child becomes a
//!   process-group leader (pgid == pid). Teardown sends `killpg`. cgroup v2
//!   preempts this on Linux when available. macOS uses this for
//!   `ContainMode::Strongest`.
//! - **Session** (`setsid`): the child becomes a session leader *and*
//!   process-group leader in a new session, detached from any controlling
//!   terminal. Teardown is identical (`killpg` on the session's initial pgroup,
//!   which equals the leader's pid). Useful for daemon-like children.
//!
//! **Mutual exclusivity:** `setsid` makes the child a session *and*
//! process-group leader simultaneously. Calling `setpgid`/`process_group(0)`
//! on a session leader fails with `EPERM`. Therefore Session mode applies
//! `setsid` *instead of* `process_group(0)` — never both.
//!
//! **Self-`setsid` escape:** a child that calls `setsid` itself exits the
//! parent's session/group; containment is then best-effort. This applies to
//! both mechanisms and is documented as a known limitation (not a sandbox).
//!
//! Parent-side signals use `nix` (not hand-rolled `libc`).
//!
//! # What `killpg` does and does not report
//! Its return value says only whether *at least one* member took the signal. A
//! group holding both a member we may signal and one we may not reports plain
//! success while the second keeps running, on both Unixes. macOS additionally
//! reports `EPERM` for a group whose survivors are all zombies, because xnu
//! excludes zombies from the pgrp iteration before counting. And on Linux even
//! `ESRCH` is not trustworthy as "definitely empty": `__kill_pgrp_info` keeps
//! overwriting its return value with each member's error until one succeeds, so
//! a departed member processed after a live refuser can leave the group's
//! overall `ESRCH` hiding that refuser. None of `killpg`'s three outcomes can be
//! trusted alone on either platform, so teardown always confirms itself against
//! the group's actual membership — see the `group` submodule.
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

use crate::error::Error;

/// Apply pre-spawn group setup to `std_cmd` (root spawns only).
/// Must not be combined with `set_session` on the same command.
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
/// `set_process_group` on the same command.
///
/// The `pre_exec` closure is async-signal-safe: it calls only raw `libc::setsid`
/// (no allocation, no unwinding). Failure of `setsid` aborts the spawn.
pub(crate) fn set_session(std_cmd: &mut std::process::Command) {
    // Safety: `pre_exec` runs post-fork, pre-exec. The closure is
    // async-signal-safe: `libc::setsid` is a raw syscall with no allocation.
    // A non-zero return means `setsid` failed (EPERM: already a session leader),
    // surfaced as an `io::Error` to abort the spawn.
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

/// Hard-kill the whole process group, then confirm the group actually came
/// down. See [`signal_group`]. `Ok(())` means every member the ONE listing pass saw was
/// either reached or already gone — not an atomic, ongoing guarantee: a member that forks a
/// new process into the group after that listing (an ordinary respawning supervisor, not
/// only an adversarial fork-bomb) is never seen, never signalled, and does not affect the
/// verdict. `Attached::Cgroup` (Linux cgroup v2, `cgroup.kill`) is fork-proof where this
/// mechanism structurally cannot be; prefer it when that atomicity matters.
pub(crate) fn kill_group(pgid: i32) -> Result<(), Error> {
    signal_group(pgid, Signal::SIGKILL)
}

/// Send the graceful signal to the whole process group, then confirm no live
/// member refused it. See [`signal_group`].
pub(crate) fn term_group(pgid: i32) -> Result<(), Error> {
    signal_group(pgid, Signal::SIGTERM)
}

/// Signal the group and report what was actually achieved. `killpg`'s return value is a
/// best-effort first delivery attempt, never the final verdict — see the module docs and
/// `verify` for why none of `Ok`/`ESRCH`/`EPERM` can be trusted alone on either platform.
///
/// **The `pgid` guard lives HERE, before any signal is sent — not only in `group::state`.**
/// An earlier draft of this fix placed the `pgid <= 0` rejection inside `group::state`,
/// downstream of this function's own `killpg`/`signal_direct` calls — meaning a `pgid` of `0`
/// (which signals the CALLER's own process group, per POSIX) or a negative one (the
/// broadcast/double-negation hazard this file's Background measures) would already have been
/// signalled for real before the "guard" ever ran. A check placed after the dangerous syscall
/// it claims to guard is not a guard.
fn signal_group(pgid: i32, signal: Signal) -> Result<(), Error> {
    // NOT a debug_assert!: unlike the reaped-root precondition in `Child::kill_tree`/
    // `terminate_tree` (Task 5, below), an invalid `pgid` reaching this function is a directly
    // and deliberately TESTED, ordinary input-validation outcome, not a "should never happen"
    // internal contract — `kill_group_and_term_group_reject_non_positive_pgid` (this file)
    // calls this path with `0`/`-1`/`i32::MIN` on purpose and asserts a plain `Err`, not a
    // panic. A `debug_assert!` here would turn that legitimate, always-possible defensive
    // check into a test-build panic and break that test outright — the two are not the same
    // kind of precondition, even though both guard "this input should not reach the syscall
    // below."
    if pgid <= 0 {
        return Err(Error::Unassessable {
            detail: format!(
                "process group {pgid} is not a valid group id to signal (0 addresses this \
                 process's own group; negative wraps to a broadcast or double-negation hazard)"
            ),
            source: None,
        });
    }
    match killpg(Pid::from_raw(pgid), signal) {
        Ok(()) => {}
        // NOT trusted as "definitely empty": Linux's __kill_pgrp_info returns the LAST
        // per-member error once none succeed, so ESRCH can mean "empty" or "a departed member
        // processed after a live refuser" indistinguishably. `verify` below re-lists and
        // settles it either way.
        Err(nix::errno::Errno::ESRCH) => {}
        // Preserved exactly as before this fix: the pgid == pid direct-to-leader fallback
        // for the sudo-wrapper case (sibling #54 territory — do not remove or reshape).
        Err(nix::errno::Errno::EPERM) => {
            let _ = signal_direct(pgid, signal);
        }
        Err(e) => return Err(Error::Io(io::Error::from(e))),
    }
    verify(pgid, signal)
}

/// Turn the group's actual membership into a contract answer — the single source of truth
/// regardless of what `killpg` reported. See `group`'s module docs for the listing and
/// signal-delivery design (one pass; `SIGKILL` resends for real, `SIGTERM` only probes).
fn verify(pgid: i32, signal: Signal) -> Result<(), Error> {
    match group::state(pgid, signal) {
        group::GroupState::Cleared => Ok(()),
        group::GroupState::Refused { refused, unassessable } => {
            let list = |pids: &[u32]| pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
            let mut detail = format!(
                "{signal} did not clear {n} member(s) of process group {pgid} (pid {list}); the \
                 tree is still up and this process cannot bring it down",
                n = refused.len(),
                list = list(&refused),
            );
            if !unassessable.is_empty() {
                // The group's true state may be WORSE than `refused` alone says — these
                // members were never confirmed either way, not confirmed clear.
                detail.push_str(&format!(
                    "; additionally, {n} member(s) could not be assessed at all (pid {list})",
                    n = unassessable.len(),
                    list = list(&unassessable),
                ));
            }
            Err(Error::Containment { detail })
        }
        group::GroupState::Unlistable { detail, source } => Err(Error::Unassessable { detail, source }),
    }
}

/// Signal `pid` directly. Already-gone is success. Kept, unmodified, because sibling #54
/// explicitly forbids touching this fallback — but the two signals it guards need opposite
/// framing, worked out fully rather than left as one general "unclear":
///
/// - **`kill_group` (`SIGKILL`)**: redundant for a member `converge` actually reaches, NOT
///   provably redundant overall. `converge` only resends to a member it has classified
///   `Liveness::Alive` AND successfully re-verified (`classify_member`/`check_or_signal`);
///   any member whose liveness or identity the OS refuses to confirm (`Liveness::Unknown` /
///   `Resolved::Unknown`) is never signalled by `converge` at all — for THOSE, this direct
///   call is the only delivery attempt, not a duplicate. It is also not the same check: this
///   call signals a bare `pid` number with NO identity verification, while `converge` refuses
///   to signal a pid whose token no longer matches — under the #54 pgid-recycle hazard the two
///   calls can have different, divergent targets. Kept because #54 forbids removing it, not
///   because it is proven safe or proven duplicative.
/// - **`term_group` (`SIGTERM`)**: NOT redundant — the only real one. `converge`'s `SIGTERM`
///   path deliberately never resends (Task 4's design: only probes, to avoid tripping a
///   program's own double-signal escalation convention), so this is the ONLY actual `SIGTERM`
///   delivery attempt to the leader after `killpg` reports `EPERM`. Do not remove or reframe
///   this arm as optional for the graceful path.
///
/// Its failure is intentionally NOT propagated (best-effort; `verify`'s listing decides the
/// contract answer either way), but is now logged rather than silently discarded, so a
/// genuine `SIGTERM` delivery failure here — the one case that matters — leaves a trace.
fn signal_direct(pid: i32, signal: Signal) -> io::Result<()> {
    match kill(Pid::from_raw(pid), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => {
            log::debug!("containment::unix::signal_direct: kill({pid}, {signal}) failed: {e}");
            Err(io::Error::from(e))
        }
    }
}

#[path = "unix/group.rs"]
mod group;

#[cfg(test)]
#[path = "unix_tests.rs"]
mod unix_tests;
