//! The root of a tree whose mechanism sends by the root's pid (a process group, a macOS fd marker's
//! group), and what such a mechanism does about the number from one look at it.

use crate::identity::RawPid;
#[cfg(unix)]
use crate::signal::RootState;

/// The root of a tree, asked right before each send by its pid: the answer serves that send alone,
/// so no checked pid outlives the send it was checked for. Every call that takes one takes
/// `Option<&dyn Root>`; `None` for a caller whose mechanism names no group, which never sends by
/// the root's pid.
pub(crate) trait Root {
    #[cfg_attr(not(unix), allow(dead_code, reason = "only Unix sends by the root's pid"))]
    fn pid(&self) -> u32;

    /// What the root's own handle shows now ([`RootState`]), read live.
    #[cfg(unix)]
    fn state(&self) -> RootState;

    /// Linux: the root's pidfd, if it has one. A send through it with `PIDFD_SIGNAL_PROCESS_GROUP`
    /// names the group exactly: the kernel resolves it from the pidfd's process, never from a number.
    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>>;
}

/// A root whose first [`state`](Root::state) is a look already taken (a drop's, which reads the
/// root's state once, for its own view, before it kills), so one look decides both. Every later
/// read, and every other question, is the root's own.
#[cfg(unix)]
pub(crate) struct Looked<'a> {
    root: &'a dyn Root,
    first: std::cell::Cell<Option<RootState>>,
}

#[cfg(unix)]
impl<'a> Looked<'a> {
    pub(crate) fn new(root: &'a dyn Root, look: RootState) -> Looked<'a> {
        Looked {
            root,
            first: std::cell::Cell::new(Some(look)),
        }
    }
}

#[cfg(unix)]
impl Root for Looked<'_> {
    fn pid(&self) -> u32 {
        self.root.pid()
    }

    fn state(&self) -> RootState {
        self.first.take().unwrap_or_else(|| self.root.state())
    }

    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.root.pidfd()
    }
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

/// Whether the root's pid still names its process group, read now. Called right before each send by
/// that number, and its answer serves that send alone: where a pid check cannot be made atomic with
/// its send, the two are back to back.
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
            Err(NotItsGroup::NoRoot)
        }
    }
}

/// Why the root's pid may not be taken to name the root's group: what the root's own handle and the
/// pid's own read together show. The one verdict every reader of the root's number asks, with its
/// text worded here.
#[derive(Debug)]
#[cfg_attr(not(unix), allow(dead_code, reason = "only Unix sends by the root's pid"))]
pub(crate) enum Refusal {
    /// This handle reaped the root, and its pid names no process: it may be taken, and lead a
    /// group, once the root's group has no member.
    ReapedPidGone(RawPid),
    /// This handle reaped the root, and another process holds its pid.
    ReapedPidTaken(RawPid),
    /// This handle reaped the root, and its pid could not be read.
    ReapedPidUnread(RawPid),
    /// Something else reaped the root.
    ReapedElsewhere(RawPid),
    /// The root's handle could not say whether it was reaped.
    Unsure(RawPid, std::io::Error),
    /// This process does not pin the root (macOS: launchd holds its zombie).
    Unpinned(RawPid),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::ReapedPidGone(pid) => {
                write!(f, "this handle reaped the root, and its pid ({pid}) names no process")
            }
            Refusal::ReapedPidTaken(pid) => write!(
                f,
                "this handle reaped the root, and another process holds its pid ({pid})"
            ),
            Refusal::ReapedPidUnread(pid) => {
                write!(f, "this handle reaped the root, and its pid ({pid}) could not be read")
            }
            Refusal::ReapedElsewhere(pid) => write!(f, "the root (pid {pid}) was reaped elsewhere"),
            Refusal::Unsure(pid, e) => write!(
                f,
                "the root's own handle could not say whether it (pid {pid}) was reaped ({e})"
            ),
            Refusal::Unpinned(pid) => write!(f, "the root (pid {pid}) is not pinned by this process"),
        }
    }
}

/// Whether the root's pid, `pid`, still names its process group, from `state`, the root's own
/// handle's answer, and for a root this handle reaped, the pid's own read. `Ok` only while the root
/// is unreaped.
#[cfg(unix)]
pub(crate) fn number_holds(pid: RawPid, state: RootState) -> Result<(), Refusal> {
    use crate::identity::Resolved;
    match state {
        RootState::Unreaped => Ok(()),
        RootState::Reaped { own: true } => Err(match crate::child::root_identity_now(pid) {
            Resolved::Gone => Refusal::ReapedPidGone(pid),
            Resolved::Found(_) => Refusal::ReapedPidTaken(pid),
            Resolved::Unknown => Refusal::ReapedPidUnread(pid),
        }),
        RootState::Reaped { own: false } => Err(Refusal::ReapedElsewhere(pid)),
        RootState::Unknown(e) => Err(Refusal::Unsure(pid, e)),
        RootState::Unpinned => Err(Refusal::Unpinned(pid)),
    }
}

/// What a mechanism that names (part of) its tree by the root's number sends, from one look at the
/// root ([`look`]).
#[cfg(unix)]
pub(crate) enum NumberLook {
    /// As far as the look shows, the number names the root: everything is sent.
    Trusted,
    /// macOS: the root is `Unpinned` or `Unknown`, so only what names the tree by identity is sent.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code, reason = "only macOS reports it"))]
    Untrusted(RootState),
    /// This handle reaped the root, and its group is empty or it had none: another process holds
    /// the pid, and the kernel does not reissue a pid while it is some group's id, or the pid of a
    /// group-less fd marker's root names nothing. Only the marker holders, if any, are signalled.
    Empty,
    /// The pid may name another process, for `refusal`'s reason. `exact_root` (Linux): the root's
    /// handle still reaches the root exactly, if it reaches it at all.
    MayNameAnother { refusal: Refusal, exact_root: bool },
    /// Linux 6.9+: the root is reaped, and its pidfd shows its group has no member left, so there is
    /// no tree to signal and nothing is sent.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only Linux has a pidfd"))]
    GroupGone,
}

/// [`NumberLook`] from one read of `root`'s state. `has_group`: the mechanism names a process group
/// by the number (an fd marker's mode may make none). A pid another process holds, after this
/// handle's own reap, means the group is empty; a pid that names no process may be taken once the
/// group has no member, so nothing is sent by it, except that a marker with no group has none to
/// skip. A group whose root's pid may name another process is decided again by the root's pidfd
/// on Linux 6.9+ ([`through_the_pidfd`]).
#[cfg(unix)]
pub(crate) fn look(root: &dyn Root, has_group: bool) -> NumberLook {
    let state = root.state();
    #[cfg(target_os = "macos")]
    if matches!(state, RootState::Unpinned | RootState::Unknown(_)) {
        return NumberLook::Untrusted(state);
    }
    let handle_unsure = matches!(state, RootState::Unknown(_));
    match number_holds(root.pid(), state) {
        Ok(()) => NumberLook::Trusted,
        Err(Refusal::ReapedPidTaken(_)) => NumberLook::Empty,
        Err(Refusal::ReapedPidGone(_)) if !has_group => NumberLook::Empty,
        Err(refusal) => {
            debug_assert!(
                cfg!(target_os = "macos") || !matches!(refusal, Refusal::Unpinned(_)),
                "only macOS reports an unpinned root, and it is answered above"
            );
            NumberLook::MayNameAnother {
                refusal,
                exact_root: handle_unsure && cfg!(target_os = "linux"),
            }
        }
    }
}

/// Linux 6.9+: `look` for a process group whose root's pid may name another process, decided again
/// by the root's pidfd, which names the group exactly whoever reaped the root. While the group has a
/// member it is signalled as usual: the group's own signal goes through the pidfd, and each send by
/// its number is checked the same way ([`check_number`]). A reaped root's group with no member left
/// is [`NumberLook::GroupGone`]. A root its handle cannot answer for keeps its look, as does a
/// kernel that cannot say.
#[cfg(target_os = "linux")]
pub(crate) fn through_the_pidfd(look: NumberLook, root: &dyn Root) -> NumberLook {
    let NumberLook::MayNameAnother { refusal, exact_root } = &look else {
        return look;
    };
    match group_has_member(Some(root)) {
        Some(true) => {
            log::debug!(
                "{refusal}, but its pidfd names its process group exactly, which still has a member: it is signalled"
            );
            NumberLook::Trusted
        }
        Some(false) if !*exact_root => NumberLook::GroupGone,
        _ => look,
    }
}

/// Why [`check_number`] refused a send by the group's number.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum NotItsGroup {
    /// Linux 6.9+: the root's pidfd shows the group has no member left, so it can gain none: a
    /// process listed by its number is in another group that took the number.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only Linux has a pidfd"))]
    Empty,
    /// Nothing shows the number is still the group's, for this reason.
    Unproven(Refusal),
    /// The send was given no root to check.
    NoRoot,
}

#[cfg(unix)]
impl std::fmt::Display for NotItsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotItsGroup::Empty => f.write_str("the root's process group has no member left"),
            NotItsGroup::Unproven(why) => std::fmt::Display::fmt(why, f),
            NotItsGroup::NoRoot => f.write_str("no root was given to check"),
        }
    }
}

#[cfg(all(test, unix))]
#[path = "root_tests.rs"]
mod root_tests;
