//! The root of a tree, as a mechanism that reaches its tree through the root's pid needs it: a
//! process group, and a macOS fd marker's group.

#[cfg(unix)]
use crate::identity::RawPid;
#[cfg(unix)]
use crate::signal::RootState;

/// The root of a tree, asked right before each send by its pid: the answer serves that send alone,
/// so no checked pid outlives the send it was checked for. Every call that takes one takes
/// `Option<&dyn Root>`; `None` for a caller whose mechanism names no group, which never sends by
/// the root's pid.
///
/// Implemented by `ReapHold` (Unix) and, on macOS, by the late spawn's hold over its
/// `exit_only::Target`. Nothing implements it on Windows, where no mechanism
/// sends by a pid.
pub(crate) trait Root {
    #[cfg_attr(not(unix), allow(dead_code, reason = "only Unix sends by the root's pid"))]
    fn pid(&self) -> u32;

    /// What the root's own handle shows now ([`RootState`]), read live. Unix only: a Windows
    /// process handle pins its process, so nothing there asks.
    #[cfg(unix)]
    fn state(&self) -> RootState;

    /// Linux: the root's pidfd, if it has one. A send through it with `PIDFD_SIGNAL_PROCESS_GROUP`
    /// names the group exactly: the kernel resolves it from the pidfd's process, never from a number.
    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>>;
}

/// Linux 6.9+: whether the root's group still has a member, zombies included, asked through the
/// root's pidfd, which names the group exactly whoever reaped the root. `None` without a root or a
/// pidfd, or where the kernel cannot say
/// ([`pidfd_group_has_member`](crate::containment::unix::pidfd_group_has_member)).
#[cfg(target_os = "linux")]
pub(crate) fn group_has_member(root: Option<&dyn Root>) -> Option<bool> {
    root.and_then(Root::pidfd)
        .and_then(crate::containment::unix::pidfd_group_has_member)
}

/// Whether the root's pid still names its group, read now. Called right before each send by that
/// number, and its answer serves that send alone: where a pid check cannot be made atomic with its
/// send, the two are back to back.
///
/// On Linux 6.9+ the root's pidfd answers ([`group_has_member`]): while the group has a member its
/// number is its own, whoever reaped the root, and once it has none it is [`NotItsGroup::Empty`].
/// Elsewhere the root's [`state`](Root::state) answers ([`number_holds`]).
#[cfg(unix)]
pub(crate) fn check_number(root: Option<&dyn Root>) -> Result<(), NotItsGroup> {
    #[cfg(test)]
    crate::send_log::record_group(crate::send_log::GroupStep::Check);
    #[cfg(target_os = "linux")]
    match group_has_member(root) {
        Some(true) => return Ok(()),
        Some(false) => return Err(NotItsGroup::Empty),
        None => {}
    }
    match root {
        Some(root) => number_holds(root.pid(), root.state()).map_err(NotItsGroup::Unproven),
        None => {
            debug_assert!(false, "a send by the root's number was given no root to check");
            Err(NotItsGroup::Unproven("no root was given to check".to_owned()))
        }
    }
}

/// Why a send by the root's pid is skipped after this handle's own reap, while the pid names no
/// process: it may be taken once the root's group has no member.
#[cfg(unix)]
pub(crate) fn reaped_pid_names_no_process(pid: u32) -> String {
    format!("this handle reaped the root, and its pid ({pid}) names no process")
}

/// Whether the root's pid, `pid`, still names its process group, from `state`: the root's own
/// handle's answer ([`check_number`], as [`Child::kill_tree`](crate::Child::kill_tree) says). `Ok`
/// only while the root is unreaped, as
/// [`root_number`](crate::child::tree_call::root_number) decides. `Err` says why not.
#[cfg(unix)]
pub(crate) fn number_holds(pid: RawPid, state: RootState) -> Result<(), String> {
    use crate::identity::Resolved;
    match state {
        RootState::Unreaped => Ok(()),
        RootState::Reaped { own: true } => match crate::child::root_identity_now(pid) {
            Resolved::Gone => Err(reaped_pid_names_no_process(pid)),
            Resolved::Found(_) => Err(format!(
                "this handle reaped the root, and another process holds its pid ({pid})"
            )),
            Resolved::Unknown => Err(format!(
                "this handle reaped the root, and its pid ({pid}) could not be read"
            )),
        },
        RootState::Reaped { own: false } => Err(format!("the root (pid {pid}) was reaped elsewhere")),
        RootState::Unknown(e) => Err(format!(
            "the root's own handle could not say whether it (pid {pid}) was reaped ({e})"
        )),
        RootState::Unpinned => Err(format!("the root (pid {pid}) is not pinned by this process")),
    }
}

/// Why [`check_number`] refused a send by the group's number.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotItsGroup {
    /// Linux 6.9+: the root's pidfd shows the group has no member left, so it can gain none: a
    /// process listed by its number is in another group that took the number.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only Linux has a pidfd"))]
    Empty,
    /// Nothing shows the number is still the group's, for this reason.
    Unproven(String),
}

#[cfg(unix)]
impl std::fmt::Display for NotItsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotItsGroup::Empty => f.write_str("the root's process group has no member left"),
            NotItsGroup::Unproven(why) => f.write_str(why),
        }
    }
}

#[cfg(all(test, unix))]
#[path = "root_tests.rs"]
mod root_tests;
