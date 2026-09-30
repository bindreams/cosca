//! Linux: what an `EPERM` from a signal syscall means.
//!
//! The kernel refuses a signal for a permission reason only by `check_kill_permission`: the
//! sender's real or effective uid equals the target's real or saved uid, or the sender holds
//! `CAP_KILL` in the target's user namespace. (It also refuses `SIGCONT` across sessions, which no
//! caller here sends.) So an `EPERM` that rule would not have produced came from a filter: seccomp
//! or an LSM. Before asking, the target is checked for having exited: the same rule refuses a
//! signal to a root-owned zombie.

use std::os::fd::{AsFd as _, BorrowedFd};

use rustix::process::{waitid, WaitId, WaitIdOptions};

use crate::error::Error;
use crate::identity::{Liveness, ProcDir, ProcessId};

use super::{TargetState, Verdict};

/// The signal call whose `EPERM` is being classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalCall {
    /// `kill(2)` with `SIGKILL`, through `std`: `Child::kill` on an owned child.
    Kill,
    /// `pidfd_send_signal(2)` with `SIGKILL`: `Process::kill`.
    PidfdKill,
    /// `pidfd_send_signal(2)` with `SIGTERM`: `Child::terminate`, `Process::terminate`.
    PidfdTerminate,
}

impl SignalCall {
    /// The `Error::Unsupported` for this call refused by a filter, in the shape every refused
    /// syscall has (the crate root's "Platform requirements"); `op` is the public operation.
    pub(crate) fn unsupported(self) -> Error {
        let (op, requirement, syscall) = match self {
            SignalCall::Kill => ("kill a child process", "kill", "kill"),
            SignalCall::PidfdKill => ("kill a process", "pidfd_send_signal (Linux ≥ 5.1)", "pidfd_send_signal"),
            SignalCall::PidfdTerminate => (
                "terminate a process",
                "pidfd_send_signal (Linux ≥ 5.1)",
                "pidfd_send_signal",
            ),
        };
        Error::Unsupported {
            op: op.into(),
            platform: "linux",
            detail: format!("cosca requires {requirement}, refused here: {syscall} answered EPERM"),
        }
    }
}

// The kernel's rule =====

/// The calling thread's credentials, as `check_kill_permission` reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sender {
    pub(super) ruid: u32,
    pub(super) euid: u32,
    pub(super) cap_kill: bool,
}

/// The target credentials the rule reads: real and saved uid. Its effective uid is not in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Target {
    pub(super) ruid: u32,
    pub(super) suid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rule {
    /// The sender holds `CAP_KILL`.
    Permitted,
    Refused,
    /// The sender's uid matched the target's ruid or suid. That is a match unless the uid is the
    /// overflow uid, which stands for every unmapped uid: two different unmapped uids read alike.
    MatchedAt(u32),
}

/// `kill_ok_by_cred`.
pub(super) fn evaluate(sender: Sender, target: Target) -> Rule {
    if sender.cap_kill {
        return Rule::Permitted;
    }
    match [sender.euid, sender.ruid]
        .into_iter()
        .find(|s| *s == target.ruid || *s == target.suid)
    {
        None => Rule::Refused,
        Some(uid) => Rule::MatchedAt(uid),
    }
}

/// The `Uid:` line of `/proc/<pid>/status`: real, effective, saved, filesystem.
pub(super) fn parse_status_uids(status: &str) -> Option<[u32; 4]> {
    let fields = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    let mut uids = fields.split_whitespace().map(|f| f.parse::<u32>());
    let parsed = [
        uids.next()?.ok()?,
        uids.next()?.ok()?,
        uids.next()?.ok()?,
        uids.next()?.ok()?,
    ];
    uids.next().is_none().then_some(parsed)
}

// Has the target exited? =====

/// Whether the process behind `pidfd` has exited (is a zombie or gone), without reaping it.
///
/// `waitid(P_PIDFD, WEXITED | WNOHANG | WNOWAIT)` answers exactly for our own child. For a process
/// that is not our child it answers `ECHILD`, and the answer is its `/proc` state instead.
pub(super) fn has_exited(id: ProcessId, pidfd: BorrowedFd<'_>) -> Result<bool, Error> {
    match waitid(
        WaitId::PidFd(pidfd),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(status) => Ok(status.is_some()),
        Err(rustix::io::Errno::CHILD) => {
            let proc_dir = open_proc_dir(id)?;
            match id.is_alive_in(&proc_dir) {
                Liveness::Dead => Ok(true),
                Liveness::Alive => Ok(false),
                Liveness::Unknown => Err(unassessable(id, "its /proc state could not be read", None)),
            }
        }
        Err(errno) => Err(Error::Io(crate::error::io_context(
            "waitid",
            std::io::Error::from(errno),
        ))),
    }
}

// Classification =====

/// Classify the `EPERM` of `call`, sent to `id` through a fresh, identity-verified pidfd.
pub(crate) fn classify_kill(id: ProcessId) -> Result<Verdict, Error> {
    let Some(pidfd) = crate::wait::backend::open_verified(id, crate::wait::backend::PidfdOp::Kill)? else {
        return Ok(Verdict::Exited);
    };
    classify_pidfd(id, pidfd.as_fd(), SignalCall::Kill)
}

/// Classify the `EPERM` of `call`, sent to the process `pidfd` names (which `id` describes).
pub(crate) fn classify_pidfd(id: ProcessId, pidfd: BorrowedFd<'_>, call: SignalCall) -> Result<Verdict, Error> {
    if has_exited(id, pidfd)? {
        return Ok(Verdict::Exited);
    }
    let proc_dir = open_proc_dir(id)?;
    // The `/proc` must describe this pid namespace's `id`: the pidfd names the process and its
    // fdinfo `Pid:` is the number this `/proc` gives it.
    match crate::identity::pidfd_pid_in_view(&proc_dir, pidfd) {
        Ok(crate::identity::PidfdTarget::Pid(pid)) if pid == id.pid() => {}
        Ok(crate::identity::PidfdTarget::Reaped) => return Ok(Verdict::Exited),
        Ok(crate::identity::PidfdTarget::Pid(pid)) => {
            return Err(unassessable(
                id,
                &format!(
                    "the mounted /proc numbers the target {pid} (0 = invisible), so it is an outer pid namespace's"
                ),
                None,
            ))
        }
        Err(why) => return Err(unassessable(id, &why.reason, why.source)),
    }
    let status = proc_dir
        .read_to_string(&format!("{}/status", id.pid()))
        .map_err(|e| unassessable(id, "its /proc status could not be read", Some(e)))?;
    let [ruid, _euid, suid, _fsuid] = parse_status_uids(&status)
        .ok_or_else(|| unassessable(id, "its /proc status has no well-formed Uid line", None))?;
    let sender = current_sender()?;
    let target = Target { ruid, suid };
    let permitted = match evaluate(sender, target) {
        Rule::Permitted => true,
        Rule::Refused => false,
        Rule::MatchedAt(uid) => match_stands(
            uid,
            || overflow_uid(id),
            || every_uid_mapped(id, &proc_dir),
            || shares_user_ns(id, |path| proc_dir.read_link(path)),
            || {
                unassessable(
                    id,
                    "its uid is unmapped in this user namespace, so it cannot be compared with the caller's",
                    None,
                )
            },
        )?,
    };
    Ok(if permitted {
        Verdict::Filter(call)
    } else {
        Verdict::Privilege(TargetState::Running)
    })
}

/// Whether a uid match stands. It does unless the uid is the overflow uid, which also stands for
/// every unmapped uid. There it stands if every uid is mapped in this user namespace (none is
/// unmapped, as in the initial namespace and any container without a user namespace), or if the
/// target shares this namespace (so its uids are mapped); otherwise the comparison is undecidable
/// and `undecidable` is the error. Each question is asked only when the answer can change the
/// result.
pub(super) fn match_stands(
    uid: u32,
    overflow: impl FnOnce() -> Result<u32, Error>,
    every_uid_mapped: impl FnOnce() -> Result<bool, Error>,
    shares_user_ns: impl FnOnce() -> Result<bool, Error>,
    undecidable: impl FnOnce() -> Error,
) -> Result<bool, Error> {
    if uid != overflow()? || every_uid_mapped()? || shares_user_ns()? {
        Ok(true)
    } else {
        Err(undecidable())
    }
}

/// This thread's credentials. The kernel checks the calling thread's, so a thread-directed query.
fn current_sender() -> Result<Sender, Error> {
    let sets = rustix::thread::capabilities(None)
        .map_err(|e| Error::Io(crate::error::io_context("capget", std::io::Error::from(e))))?;
    Ok(Sender {
        ruid: rustix::process::getuid().as_raw(),
        euid: rustix::process::geteuid().as_raw(),
        cap_kill: sets.effective.contains(rustix::thread::CapabilitySet::KILL),
    })
}

/// This user namespace's overflow uid, the sysctl `/proc/sys/kernel/overflowuid`. Read by path,
/// not through the checked view: it says nothing about any process, and `/proc/sys` is commonly a
/// separate mount there (a container's read-only bind), which the checked view refuses to cross.
fn overflow_uid(id: ProcessId) -> Result<u32, Error> {
    std::fs::read_to_string("/proc/sys/kernel/overflowuid")
        .map_err(|e| unassessable(id, "the overflow uid could not be read", Some(e)))?
        .trim()
        .parse()
        .map_err(|_| unassessable(id, "the overflow uid is not a number", None))
}

/// Whether this user namespace maps every uid: `/proc/self/uid_map` has the line `0 0 4294967295`
/// the initial namespace has.
fn every_uid_mapped(id: ProcessId, proc_dir: &ProcDir) -> Result<bool, Error> {
    let map = proc_dir
        .read_to_string("self/uid_map")
        .map_err(|e| unassessable(id, "this process's uid map could not be read", Some(e)))?;
    Ok(maps_every_uid(&map))
}

/// Whether the `uid_map` text has a range starting at 0 that covers every uid.
pub(super) fn maps_every_uid(uid_map: &str) -> bool {
    uid_map.lines().any(|line| {
        let mut fields = line.split_whitespace().map(|f| f.parse::<u64>());
        matches!((fields.next(), fields.next(), fields.next()), (Some(Ok(0)), Some(Ok(_)), Some(Ok(count))) if count >= u64::from(u32::MAX))
    })
}

/// Whether `id`'s process is in this process's user namespace, comparing the two `ns/user` links
/// `read_link` reads (a path under `/proc`).
pub(super) fn shares_user_ns(
    id: ProcessId,
    read_link: impl Fn(&str) -> std::io::Result<Vec<u8>>,
) -> Result<bool, Error> {
    let theirs = read_link(&format!("{}/ns/user", id.pid()))
        .map_err(|e| unassessable(id, "its user namespace could not be read", Some(e)))?;
    let ours = read_link("self/ns/user")
        .map_err(|e| unassessable(id, "this process's user namespace could not be read", Some(e)))?;
    Ok(theirs == ours)
}

fn open_proc_dir(id: ProcessId) -> Result<ProcDir, Error> {
    ProcDir::open().map_err(|why| unassessable(id, &why.reason, why.source))
}

fn unassessable(id: ProcessId, why: &str, source: Option<std::io::Error>) -> Error {
    let mut detail = format!("pid {} could not be classified after a refused signal: {why}", id.pid());
    if let Some(source) = &source {
        detail.push_str(&format!(": {source}"));
    }
    log::warn!("refusal: {detail}");
    Error::Unassessable { detail, source }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;
