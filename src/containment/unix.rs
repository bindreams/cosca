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
//! Once the leader is reaped its PID/PGID may be reissued, and `killpg` would then signal that
//! process's group. On Linux 6.9+ the group's signal goes through the root's pidfd instead, which
//! names the group exactly. Every send by the group's number (the `killpg` where the kernel refuses
//! that, and the leader's signal) runs right after its own check of the root ([`GroupRoot::check`]:
//! on 6.9+ whether the pidfd's group still has a member). On Linux a member's `SIGKILL` resend pins
//! the member by a pidfd its identity check vouches for, then checks the root, then sends through
//! that pidfd. A member's `SIGTERM` probe, and a resend by the member's pid, checks the root, then
//! the member's identity right before it. Nothing is sent once a check fails; the residual window
//! between a check and its send is documented on `Child::kill_tree`. cgroup v2 names no pid and has
//! no such hole.

use std::io;

use nix::sys::signal::Signal;

use crate::containment::GroupRoot;
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
pub(crate) fn kill_group(pgid: i32, root: &GroupRoot<'_>) -> Result<(), Error> {
    #[cfg(test)]
    if let Some(outcome) = fault::intercept_kill_group(pgid) {
        return outcome;
    }
    signal_group(pgid, Signal::SIGKILL, root)
}

/// Test seam for [`kill_group`]. Thread-local, with an RAII reset.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::{Cell, RefCell};

    #[cfg(target_os = "linux")]
    pub(crate) use super::group::fault::{list_instead, refuse_probes, set_after_listing};

    type OnSend = Box<dyn FnMut(i32)>;

    thread_local! {
        static TERMED: RefCell<Option<Vec<i32>>> = const { RefCell::new(None) };
        static KILLED: RefCell<Option<Vec<i32>>> = const { RefCell::new(None) };
        static FAIL: Cell<bool> = const { Cell::new(false) };
        static ON_TERM: RefCell<Option<OnSend>> = const { RefCell::new(None) };
        static ON_KILL: RefCell<Option<OnSend>> = const { RefCell::new(None) };
        static REFUSE_GROUP: Cell<bool> = const { Cell::new(false) };
        static REFUSE_FLAG: Cell<bool> = const { Cell::new(false) };
        static GROUP_PROBE_ERRNO: Cell<Option<i32>> = const { Cell::new(None) };
    }

    /// While the guard lives, every send to a whole group on THIS thread (the `killpg`, or the
    /// group send through the root's pidfd) is refused with `EPERM` and not sent, as the kernel
    /// refuses a group whose every member belongs to another user. The leader's signal and the
    /// members' resends after it are sent for real.
    pub(crate) fn refuse_group_sends() -> Refused {
        REFUSE_GROUP.with(|r| r.set(true));
        Refused(())
    }

    /// While the guard lives, the group send through the root's pidfd on THIS thread fails with
    /// `EINVAL` and is not sent, as a kernel before 6.9 refuses `PIDFD_SIGNAL_PROCESS_GROUP`.
    #[cfg(target_os = "linux")]
    pub(crate) fn refuse_pidfd_group_flag() -> Refused {
        REFUSE_FLAG.with(|r| r.set(true));
        Refused(())
    }

    /// While the guard lives, the signal-0 send through a root's pidfd that asks whether its group
    /// has a member fails with `errno` on THIS thread, and is not made.
    #[cfg(target_os = "linux")]
    pub(crate) fn answer_group_probes_with(errno: i32) -> Refused {
        GROUP_PROBE_ERRNO.with(|e| e.set(Some(errno)));
        Refused(())
    }

    #[must_use = "the sends go out again as soon as the guard is dropped"]
    pub(crate) struct Refused(());

    impl Drop for Refused {
        fn drop(&mut self) {
            REFUSE_GROUP.with(|r| r.set(false));
            REFUSE_FLAG.with(|r| r.set(false));
            GROUP_PROBE_ERRNO.with(|e| e.set(None));
        }
    }

    pub(super) fn group_sends_refused() -> bool {
        REFUSE_GROUP.with(Cell::get)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn group_probe_errno() -> Option<i32> {
        GROUP_PROBE_ERRNO.with(Cell::get)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only Linux has the flag"))]
    pub(super) fn pidfd_group_flag_refused() -> bool {
        REFUSE_FLAG.with(Cell::get)
    }

    /// Runs `slot`'s hook, if any, on `pgid`, with the slot free while it runs.
    fn fire(slot: &'static std::thread::LocalKey<RefCell<Option<OnSend>>>, pgid: i32) {
        let Some(mut hook) = slot.with(|h| h.borrow_mut().take()) else {
            return;
        };
        hook(pgid);
        slot.with(|h| *h.borrow_mut() = Some(hook));
    }

    /// From now on `kill_group` on THIS thread records its group and sends nothing, so a test can
    /// assert a kill was not issued without a real `killpg` ever reaching a recyclable number.
    pub(crate) fn record_kill_group() -> KillGroupRecorder {
        KILLED.with(|k| *k.borrow_mut() = Some(Vec::new()));
        KillGroupRecorder(())
    }

    /// From now on `term_group` on THIS thread records its group and sends nothing.
    pub(crate) fn record_term_group() -> TermGroupRecorder {
        TERMED.with(|t| *t.borrow_mut() = Some(Vec::new()));
        TermGroupRecorder(())
    }

    #[must_use = "recording stops as soon as the recorder is dropped"]
    pub(crate) struct TermGroupRecorder(());

    impl TermGroupRecorder {
        /// The groups `term_group` was asked to signal since the recorder was made.
        pub(crate) fn termed(&self) -> Vec<i32> {
            TERMED.with(|t| t.borrow().clone().expect("the recorder is live"))
        }

        /// Runs `hook` at each recorded send, given its group.
        pub(crate) fn on_send(&self, hook: impl FnMut(i32) + 'static) {
            ON_TERM.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        }
    }

    impl Drop for TermGroupRecorder {
        fn drop(&mut self) {
            TERMED.with(|t| *t.borrow_mut() = None);
            ON_TERM.with(|h| *h.borrow_mut() = None);
        }
    }

    pub(super) fn intercept_term_group(pgid: i32) -> bool {
        let recorded = TERMED.with(|t| t.borrow_mut().as_mut().map(|termed| termed.push(pgid)).is_some());
        if recorded {
            fire(&ON_TERM, pgid);
        }
        recorded
    }

    #[must_use = "recording stops as soon as the recorder is dropped"]
    pub(crate) struct KillGroupRecorder(());

    impl KillGroupRecorder {
        /// From now on the intercepted `kill_group` reports the ordinary `Unassessable` refusal of a
        /// group it could not fully assess, as a live member that refuses the signal would cause.
        pub(crate) fn fail_with_unassessable(&self) {
            FAIL.with(|f| f.set(true));
        }

        /// The groups `kill_group` was asked to kill since the recorder was made.
        pub(crate) fn killed(&self) -> Vec<i32> {
            KILLED.with(|k| k.borrow().clone().expect("the recorder is live"))
        }

        /// Runs `hook` at each recorded send, given its group.
        pub(crate) fn on_send(&self, hook: impl FnMut(i32) + 'static) {
            ON_KILL.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        }

        /// Asserts `pgid` was killed, and nothing else was. More than once is fine: a macOS fd
        /// marker's sweep re-sends `killpg` on a later pass while a holder still confirms the group.
        #[track_caller]
        pub(crate) fn assert_killed_only(&self, pgid: i32) {
            let killed = self.killed();
            assert!(
                !killed.is_empty() && killed.iter().all(|g| *g == pgid),
                "expected only killpg({pgid}), at least once, got {killed:?}"
            );
        }
    }

    impl Drop for KillGroupRecorder {
        fn drop(&mut self) {
            KILLED.with(|k| *k.borrow_mut() = None);
            FAIL.with(|f| f.set(false));
            ON_KILL.with(|h| *h.borrow_mut() = None);
        }
    }

    pub(super) fn intercept_kill_group(pgid: i32) -> Option<Result<(), crate::error::Error>> {
        let recorded = KILLED.with(|k| k.borrow_mut().as_mut().map(|killed| killed.push(pgid)).is_some());
        if !recorded {
            return None;
        }
        fire(&ON_KILL, pgid);
        Some(if FAIL.with(|f| f.get()) {
            Err(crate::error::Error::Unassessable {
                detail: "forced by a test".into(),
                source: None,
            })
        } else {
            Ok(())
        })
    }
}

/// Send the graceful signal to the whole process group, then confirm no live
/// member refused it. See [`signal_group`].
pub(crate) fn term_group(pgid: i32, root: &GroupRoot<'_>) -> Result<(), Error> {
    #[cfg(test)]
    if fault::intercept_term_group(pgid) {
        return Ok(());
    }
    signal_group(pgid, Signal::SIGTERM, root)
}

/// Signal the group and report what was actually achieved. `killpg`'s return value is a
/// best-effort first delivery attempt, never the final verdict — see the module docs and
/// `verify` for why none of `Ok`/`ESRCH`/`EPERM` can be trusted alone on either platform.
///
/// **The `pgid` guard lives HERE, before any signal is sent — not only in `group::state`.**
/// A `pgid` of `0` signals the CALLER's own process group (per POSIX); a negative one risks
/// the broadcast/double-negation hazard this file's Background measures. A check placed after
/// the dangerous syscall it claims to guard is not a guard.
fn signal_group(pgid: i32, signal: Signal, root: &GroupRoot<'_>) -> Result<(), Error> {
    // NOT a debug_assert!: an invalid `pgid` reaching this function is a directly and deliberately
    // TESTED, ordinary input-validation outcome, not a "should never happen" internal contract —
    // `kill_group_and_term_group_reject_non_positive_pgid` (this file) calls this path with
    // `0`/`-1`/`i32::MIN` on purpose and asserts a plain `Err`, not a panic.
    if pgid <= 0 {
        return Err(Error::Unassessable {
            detail: format!(
                "process group {pgid} is not a valid group id to signal (0 addresses this \
                 process's own group; negative wraps to a broadcast or double-negation hazard)"
            ),
            source: None,
        });
    }
    match send_to_group(pgid, signal, root)? {
        Ok(()) => {}
        // NOT trusted as "definitely empty": Linux's __kill_pgrp_info returns the LAST
        // per-member error once none succeed, so ESRCH can mean "empty" or "a departed member
        // processed after a live refuser" indistinguishably. `verify` below re-lists and
        // settles it either way.
        Err(nix::errno::Errno::ESRCH) => {}
        // Preserved exactly as before this fix: the pgid == pid direct-to-leader fallback
        // for the sudo-wrapper case (sibling #54 territory — do not remove or reshape).
        Err(nix::errno::Errno::EPERM) => {
            _ = signal_direct(pgid, signal, root);
        }
        Err(e) => return Err(Error::Io(io::Error::from(e))),
    }
    verify(pgid, signal, root)
}

/// The send to the whole group, and the kernel's answer to it. On Linux it goes through the root's
/// pidfd with `PIDFD_SIGNAL_PROCESS_GROUP`, which names the group exactly: the kernel resolves it
/// from the pidfd's process, not from a number. Only when the kernel refuses the flag (`EINVAL`,
/// before Linux 6.9), or the root has no pidfd, and always on macOS, it goes by the group's number,
/// right after the root's check. A failed check sends nothing and is the call's error.
///
/// The check and the `killpg` are two syscalls: a reaper elsewhere in the process can reap the root
/// between them, and the number can then name another group. That window is a standing property of
/// process-group containment without the flag; a program with such a reaper should use cgroup
/// containment, whose kill names no pid.
fn send_to_group(pgid: i32, signal: Signal, root: &GroupRoot<'_>) -> Result<Result<(), nix::errno::Errno>, Error> {
    #[cfg(target_os = "linux")]
    if let Some(pidfd) = root.pidfd() {
        match pidfd_signal(pidfd, signal, Through::Group) {
            Err(nix::errno::Errno::EINVAL) => log::debug!(
                "containment::unix: the kernel refused PIDFD_SIGNAL_PROCESS_GROUP (before Linux 6.9), so process group {pgid} is signalled by its number"
            ),
            sent => return Ok(sent),
        }
    }
    root.check().map_err(|why| Error::Unassessable {
        detail: format!(
            "process group {pgid}: {why}, so its number may name another group, and {signal} was not sent by it"
        ),
        source: None,
    })?;
    Ok(send_signal(Target::Group, Sys::Group(pgid), signal))
}

/// What a send through [`send_signal`] reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code, reason = "only a test build records it"))]
pub(crate) enum Target {
    /// A whole process group.
    Group,
    /// A group's leader alone, after the group's send was refused.
    Leader,
    /// A listed member of a group, by its pid.
    Member(u32),
}

/// The syscall [`send_signal`] makes.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only Linux sends through a pidfd")
)]
pub(crate) enum Sys<'a> {
    /// `pidfd_send_signal` through a pidfd, with its flags.
    Pidfd(std::os::fd::BorrowedFd<'a>, libc::c_uint),
    /// `killpg` of a group's number.
    Group(i32),
    /// `kill` of a pid.
    Process(i32),
}

/// Sends `signal` to `target` by `sys`, and gives the kernel's answer. Every send to a process
/// group, its leader or a member goes through here, and makes its syscall here, so a test build
/// records it ([`GroupStep`](crate::send_log::GroupStep)) once the syscall returned, with the
/// signal it was given: a send that is skipped leaves no record. In a test build a seam may answer
/// in place of the kernel for a whole group: `EINVAL` for the pidfd flag, `EPERM` for a refused
/// group.
pub(crate) fn send_signal(target: Target, sys: Sys<'_>, signal: Signal) -> nix::Result<()> {
    let signo = signal as libc::c_int;
    #[cfg(test)]
    let seam = match (target, sys) {
        (Target::Group, Sys::Pidfd(..)) if fault::pidfd_group_flag_refused() => Some(nix::errno::Errno::EINVAL),
        (Target::Group, _) if fault::group_sends_refused() => Some(nix::errno::Errno::EPERM),
        _ => None,
    };
    #[cfg(not(test))]
    let seam: Option<nix::errno::Errno> = None;
    let sent = match (seam, sys) {
        (Some(errno), _) => Err(errno),
        #[cfg(target_os = "linux")]
        (None, Sys::Pidfd(pidfd, flags)) => pidfd_send_syscall(pidfd, signo, flags),
        #[cfg(not(target_os = "linux"))]
        (None, Sys::Pidfd(..)) => unreachable!("only Linux sends through a pidfd"),
        // SAFETY: plain syscalls on numbers; each caller checked the number right before.
        (None, Sys::Group(pgid)) => nix::errno::Errno::result(unsafe { libc::killpg(pgid, signo) }).map(drop),
        // SAFETY: as above.
        (None, Sys::Process(pid)) => nix::errno::Errno::result(unsafe { libc::kill(pid, signo) }).map(drop),
    };
    #[cfg(test)]
    {
        use crate::send_log::{GroupStep, Route};
        let route = match sys {
            Sys::Pidfd(..) => Route::Pidfd,
            Sys::Group(_) | Sys::Process(_) => Route::Number,
        };
        crate::send_log::record_group(match target {
            Target::Group => GroupStep::Group(route, signo),
            Target::Leader => GroupStep::Leader(route, signo),
            Target::Member(pid) => GroupStep::Member(route, pid, signo),
        });
    }
    #[cfg(not(test))]
    let _ = target;
    sent
}

/// `signal` to the process group `pidfd`'s process leads, through `pidfd` (a pidfd, or a
/// `/proc/<pid>` directory, which the kernel takes as one): exact, as [`send_to_group`]'s. `EINVAL`
/// is a kernel before 6.9, which refuses the flag.
#[cfg(target_os = "linux")]
pub(crate) fn pidfd_signal_group(pidfd: std::os::fd::BorrowedFd<'_>, signal: Signal) -> Result<(), nix::errno::Errno> {
    pidfd_signal(pidfd, signal, Through::Group)
}

/// What a send through the root's pidfd reaches.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Through {
    /// The root's whole process group (`PIDFD_SIGNAL_PROCESS_GROUP`).
    Group,
    /// The root alone.
    Leader,
}

/// Whether the process group `pidfd`'s process leads still has a member, zombies included, from a
/// signal-0 send with `PIDFD_SIGNAL_PROCESS_GROUP`, which names the group exactly. While it has one,
/// the group's number is still its own: the kernel does not reissue a pid that is any process's
/// group id. `None` where the kernel refuses the flag (before Linux 6.9), or gives an answer that
/// says neither. `EPERM` is one of those: the kernel gives it for a group whose every member is
/// another user's, and a seccomp filter may give it for any group, one that took the number
/// included.
#[cfg(target_os = "linux")]
pub(crate) fn pidfd_group_has_member(pidfd: std::os::fd::BorrowedFd<'_>) -> Option<bool> {
    #[cfg(test)]
    let answer = if fault::pidfd_group_flag_refused() {
        Err(nix::errno::Errno::EINVAL)
    } else if let Some(errno) = fault::group_probe_errno() {
        Err(nix::errno::Errno::from_raw(errno))
    } else {
        pidfd_send_syscall(pidfd, 0, libc::PIDFD_SIGNAL_PROCESS_GROUP)
    };
    #[cfg(not(test))]
    let answer = pidfd_send_syscall(pidfd, 0, libc::PIDFD_SIGNAL_PROCESS_GROUP);
    match answer {
        Ok(()) => Some(true),
        Err(nix::errno::Errno::ESRCH) => Some(false),
        Err(nix::errno::Errno::EINVAL) => None,
        Err(e) => {
            log::debug!("containment::unix: a signal-0 send to a process group through its root's pidfd answered {e}");
            None
        }
    }
}

/// `signal` through `pidfd`, to what `through` names. The kernel's errno is the answer: `EINVAL`
/// for a flag it does not know.
#[cfg(target_os = "linux")]
fn pidfd_signal(pidfd: std::os::fd::BorrowedFd<'_>, signal: Signal, through: Through) -> Result<(), nix::errno::Errno> {
    let (target, flags) = match through {
        Through::Group => (Target::Group, libc::PIDFD_SIGNAL_PROCESS_GROUP),
        Through::Leader => (Target::Leader, 0),
    };
    send_signal(target, Sys::Pidfd(pidfd, flags), signal)
}

/// `pidfd_send_signal(pidfd, signo, NULL, flags)`. The kernel's errno is the answer.
#[cfg(target_os = "linux")]
pub(crate) fn pidfd_send_syscall(
    pidfd: std::os::fd::BorrowedFd<'_>,
    signo: libc::c_int,
    flags: libc::c_uint,
) -> Result<(), nix::errno::Errno> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `pidfd` is a live pidfd for the call's duration, and a null `siginfo_t` asks the kernel
    // to fill in the defaults, as `kill(2)` does.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signo,
            std::ptr::null::<libc::siginfo_t>(),
            flags,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(nix::errno::Errno::last())
    }
}

/// Turn the group's actual membership into a contract answer — the single source of truth
/// regardless of what `killpg` reported. See `group`'s module docs for the listing and
/// signal-delivery design (one pass; `SIGKILL` resends for real, `SIGTERM` only probes).
fn verify(pgid: i32, signal: Signal, root: &GroupRoot<'_>) -> Result<(), Error> {
    match group::state(pgid, signal, root) {
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
        // A listing that can never work here (no `openat2`) is the platform's `Unsupported`, as
        // from a wait or a spawn, not an unassessable group.
        group::GroupState::Unlistable {
            source: Some(source), ..
        } if source.kind() == io::ErrorKind::Unsupported => Err(Error::Unsupported {
            op: format!("listing process group {pgid}"),
            platform: std::env::consts::OS,
            detail: source.to_string(),
        }),
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
///   call checks the root itself, while `converge` checks each member's token as well. Kept
///   because #54 forbids removing it, not because it is proven duplicative.
/// - **`term_group` (`SIGTERM`)**: NOT redundant — the only real one. `converge`'s `SIGTERM`
///   path deliberately never resends — only probes, to avoid tripping a program's own
///   double-signal escalation convention — so this is the ONLY actual `SIGTERM`
///   delivery attempt to the leader after `killpg` reports `EPERM`. Do not remove or reframe
///   this arm as optional for the graceful path.
///
/// Its failure is intentionally NOT propagated (best-effort; `verify`'s listing decides the
/// contract answer either way), but is now logged rather than silently discarded, so a
/// genuine `SIGTERM` delivery failure here — the one case that matters — leaves a trace.
///
/// On Linux it goes through the root's pidfd when it has one, which names the leader exactly;
/// otherwise by `pid`, right after the root's own check, and not at all if that fails.
fn signal_direct(pid: i32, signal: Signal, root: &GroupRoot<'_>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    let sent = root.pidfd().map(|pidfd| pidfd_signal(pidfd, signal, Through::Leader));
    #[cfg(not(target_os = "linux"))]
    let sent = None;
    let sent = match sent {
        Some(sent) => sent,
        None => {
            if let Err(why) = root.check() {
                log::debug!("containment::unix::signal_direct: {why}, so {signal} was not sent to pid {pid}");
                return Err(io::Error::other(why.to_string()));
            }
            send_signal(Target::Leader, Sys::Process(pid), signal)
        }
    };
    match sent {
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

#[cfg(test)]
#[path = "unix_send_tests.rs"]
mod unix_send_tests;
