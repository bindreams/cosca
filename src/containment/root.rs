//! The root of a tree whose mechanism sends by the root's pid (a process group, a macOS fd marker's
//! group), and what such a mechanism does about the number from one look at it.

use crate::error::Error;
use crate::identity::RawPid;
#[cfg(unix)]
use crate::signal::RootState;
use crate::signal::{Sent, Sig};

/// The root of a tree, asked right before each send by its pid: the answer serves that send alone,
/// so no checked pid outlives the send it was checked for. Every call that takes one takes
/// `Option<&dyn Root>`; `None` for a caller whose mechanism names neither a group nor a walk, which
/// never sends by the root's pid or to the root itself. A tree call and a drop alike get the same
/// answer for the same root.
pub(crate) trait Root {
    fn pid(&self) -> u32;

    /// Send `sig` to the root through the handle that holds it, the one route a walk sends the root
    /// its own signal by, with no second open of its identity. [`Sent::Gone`] when the root is no
    /// longer the process held.
    fn signal(&self, sig: Sig) -> Result<Sent, Error>;

    /// What the root's own handle shows now ([`RootState`]), read live: right before each send by
    /// the root's pid.
    #[cfg(unix)]
    fn state(&self) -> RootState;

    /// The state a mechanism decides what to send on, asked once per call ([`look`]). It is
    /// [`state`](Root::state), unless the caller took the look first, to word its report from it
    /// ([`Seen`]).
    #[cfg(unix)]
    fn look_state(&self) -> RootState {
        self.state()
    }

    /// Linux: the root's pidfd, if it has one. A send through it with `PIDFD_SIGNAL_PROCESS_GROUP`
    /// names the group exactly: the kernel resolves it from the pidfd's process, never from a number.
    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>>;
}

/// A root whose [`look_state`](Root::look_state) is a look its caller already took (a drop's, which
/// words its report from the same look), so the one look decides the kill and the report. Each send
/// by the pid still reads the root's own [`state`](Root::state).
#[cfg(unix)]
pub(crate) struct Seen<'a> {
    root: &'a dyn Root,
    look: RootState,
}

#[cfg(unix)]
impl<'a> Seen<'a> {
    pub(crate) fn new(root: &'a dyn Root, look: RootState) -> Seen<'a> {
        Seen { root, look }
    }
}

#[cfg(unix)]
impl Root for Seen<'_> {
    fn pid(&self) -> u32 {
        self.root.pid()
    }

    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        self.root.signal(sig)
    }

    fn state(&self) -> RootState {
        self.root.state()
    }

    fn look_state(&self) -> RootState {
        self.look.clone()
    }

    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.root.pidfd()
    }
}

/// Linux 6.9+: whether the root's group still has a member, zombies included, asked through the
/// root's pidfd, which names the group exactly whoever reaped the root. `Ok(None)` without a root or
/// a pidfd, or where the kernel cannot say; `Err` is the errno of a probe that failed
/// ([`pidfd_group_has_member`](crate::containment::unix::pidfd_group_has_member)).
#[cfg(target_os = "linux")]
pub(crate) fn group_has_member(root: Option<&dyn Root>) -> Result<Option<bool>, nix::errno::Errno> {
    match root.and_then(Root::pidfd) {
        Some(pidfd) => crate::containment::unix::pidfd_group_has_member(pidfd),
        None => Ok(None),
    }
}

/// Whether the root's pid still names its process group, read now. Called right before each send by
/// that number, and its answer serves that send alone: where a pid check cannot be made atomic with
/// its send, the two are back to back.
///
/// On Linux 6.9+ the root's pidfd answers ([`group_has_member`]): while the group has a member its
/// number is its own, whoever reaped the root, and once it has none it is [`NotItsGroup::Empty`].
/// Elsewhere the root's [`state`](Root::state) answers ([`number_holds`]), as it does when the pidfd's
/// probe failed; a refusal then carries the probe's errno ([`NotItsGroup::Unproven`]).
#[cfg(unix)]
pub(crate) fn check_number(root: Option<&dyn Root>) -> Result<(), NotItsGroup> {
    #[cfg(test)]
    crate::send_log::record_group(crate::send_log::GroupStep::Check);
    let (has_member, probe) = probe_group(root, "the root's state decides");
    match has_member {
        Some(true) => return Ok(()),
        Some(false) => return Err(NotItsGroup::Empty),
        None => {}
    }
    match root {
        Some(root) => number_holds(root.pid(), root.state()).map_err(|refusal| NotItsGroup::unproven(refusal, probe)),
        None => {
            debug_assert!(false, "a send by the root's number was given no root to check");
            Err(NotItsGroup::NoRoot)
        }
    }
}

/// Linux 6.9+: whether the root's group has a member, by [`group_has_member`], and the errno of a
/// probe that failed, which leaves the answer to the root's state. A failed probe is logged once at
/// debug; `then` names what decided it instead. Both are `None` elsewhere.
#[cfg(target_os = "linux")]
fn probe_group(root: Option<&dyn Root>, then: &str) -> (Option<bool>, Option<i32>) {
    match group_has_member(root) {
        Ok(has_member) => (has_member, None),
        Err(errno) => {
            log::debug!(
                "a signal-0 send to a process group through its root's pidfd answered {report}, so {then}",
                report = crate::error::Report(&errno)
            );
            (None, Some(errno as i32))
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn probe_group(_root: Option<&dyn Root>, _then: &str) -> (Option<bool>, Option<i32>) {
    (None, None)
}

/// The error of a group probe through the root's pidfd that failed with the raw errno `errno`.
#[cfg(unix)]
fn probe_error(errno: i32) -> Error {
    Error::Unassessable {
        detail: "a signal-0 send to the root's process group through its pidfd failed".to_owned(),
        source: Some(Error::io_cause(std::io::Error::from_raw_os_error(errno))),
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
    /// This handle reaped the root, and its pid could not be read; carries the read's error when it
    /// names one.
    ReapedPidUnread(RawPid, Option<std::sync::Arc<Error>>),
    /// Something else reaped the root.
    ReapedElsewhere(RawPid),
    /// The root's handle could not say whether it was reaped.
    Unsure(RawPid, std::sync::Arc<std::io::Error>),
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
            Refusal::ReapedPidUnread(pid, _) => {
                write!(f, "this handle reaped the root, and its pid ({pid}) could not be read")
            }
            Refusal::ReapedElsewhere(pid) => write!(f, "the root (pid {pid}) was reaped elsewhere"),
            Refusal::Unsure(pid, _) => write!(
                f,
                "the root's own handle could not say whether it (pid {pid}) was reaped"
            ),
            Refusal::Unpinned(pid) => write!(f, "the root (pid {pid}) is not pinned by this process"),
        }
    }
}

impl std::error::Error for Refusal {
    /// The error of a handle that could not say, or of a pid that could not be read.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Refusal::Unsure(_, e) => Some(&**e),
            Refusal::ReapedPidUnread(_, read) => read.as_deref().map(|e| e as &(dyn std::error::Error + 'static)),
            _ => None,
        }
    }
}

#[cfg(unix)]
impl Refusal {
    /// The handle's error, shared ([`crate::error::shared_io`]), or the pid read's.
    pub(crate) fn cause(&self) -> Option<std::sync::Arc<crate::error::Error>> {
        match self {
            Refusal::Unsure(_, e) => Some(crate::error::shared_io_cause(e)),
            Refusal::ReapedPidUnread(_, read) => read.clone(),
            _ => None,
        }
    }

    /// The causes of a refusal that follows a group probe that failed with `probe` (Linux 6.9+): its
    /// own, if it has any, then the probe's error, as an [`Error::Several`] when that is two or more.
    /// `probe` is the raw errno. The carriers of a failed probe ([`NumberLook::MayNameAnother`],
    /// [`Why::MayNameAnother`](crate::containment::skip::Why::MayNameAnother),
    /// [`NotItsGroup::Unproven`]) hold only the refusal and that errno, and their `cause` is this.
    pub(crate) fn cause_after(&self, probe: Option<i32>) -> Option<std::sync::Arc<Error>> {
        match probe {
            None => self.cause(),
            Some(errno) => Some(Error::joined_cause(
                self.cause(),
                [std::sync::Arc::new(probe_error(errno))],
            )),
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
            (Resolved::Gone, _) => Refusal::ReapedPidGone(pid),
            (Resolved::Found(_), _) => Refusal::ReapedPidTaken(pid),
            (Resolved::Unknown, cause) => {
                Refusal::ReapedPidUnread(pid, cause.into_error(&format!("pid {pid}")).map(std::sync::Arc::new))
            }
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
    /// handle still reaches the root exactly, if it reaches it at all. `probe` (Linux 6.9+): the errno
    /// of the group probe that failed and left the look to the refusal, a cause beside the refusal's
    /// own ([`Refusal::cause_after`]).
    MayNameAnother {
        refusal: Refusal,
        exact_root: bool,
        probe: Option<i32>,
    },
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
    let state = root.look_state();
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
                probe: None,
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
    let NumberLook::MayNameAnother {
        refusal,
        exact_root,
        probe,
    } = look
    else {
        return look;
    };
    let (has_member, failed) = probe_group(Some(root), "the look keeps its refusal");
    match has_member {
        Some(true) => {
            log::debug!(
                "{refusal}, but its pidfd names its process group exactly, which still has a member: it is signalled",
                refusal = crate::error::Report(&refusal)
            );
            return NumberLook::Trusted;
        }
        Some(false) if !exact_root => return NumberLook::GroupGone,
        _ => {}
    }
    NumberLook::MayNameAnother {
        refusal,
        exact_root,
        probe: failed.or(probe),
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
    /// Nothing shows the number is still the group's, for this reason. The second is the errno of
    /// the group probe that failed before it, if one did ([`Refusal::cause_after`]). The third holds
    /// the causes joined from the two, once, for [`source`](std::error::Error::source) to lend.
    Unproven(Refusal, Option<i32>, std::sync::OnceLock<Option<std::sync::Arc<Error>>>),
    /// The send was given no root to check.
    NoRoot,
}

#[cfg(unix)]
impl std::fmt::Display for NotItsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotItsGroup::Empty => f.write_str("the root's process group has no member left"),
            NotItsGroup::Unproven(why, ..) => std::fmt::Display::fmt(why, f),
            NotItsGroup::NoRoot => f.write_str("no root was given to check"),
        }
    }
}

#[cfg(unix)]
impl std::error::Error for NotItsGroup {
    /// The refusal says its own words; the source is the refusal's cause, joined with a failed
    /// probe's error when there is one. This layer adds no words.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NotItsGroup::Unproven(why, None, _) => std::error::Error::source(why),
            NotItsGroup::Unproven(..) => self
                .joined()
                .map(|cause| &**cause as &(dyn std::error::Error + 'static)),
            NotItsGroup::Empty | NotItsGroup::NoRoot => None,
        }
    }
}

#[cfg(unix)]
impl NotItsGroup {
    /// [`Unproven`](NotItsGroup::Unproven) for `refusal`, after the group probe that failed with
    /// `probe`, if one did.
    pub(crate) fn unproven(refusal: Refusal, probe: Option<i32>) -> NotItsGroup {
        NotItsGroup::Unproven(refusal, probe, std::sync::OnceLock::new())
    }

    /// The error behind this refusal, as the `source` of an error that says it
    /// ([`Refusal::cause_after`] states what it holds).
    pub(crate) fn cause(&self) -> Option<std::sync::Arc<Error>> {
        self.joined().cloned()
    }

    /// The refusal's causes joined with the failed probe's, computed on first use.
    fn joined(&self) -> Option<&std::sync::Arc<Error>> {
        match self {
            NotItsGroup::Unproven(why, probe, joined) => joined.get_or_init(|| why.cause_after(*probe)).as_ref(),
            NotItsGroup::Empty | NotItsGroup::NoRoot => None,
        }
    }
}

#[cfg(all(test, unix))]
#[path = "root_tests.rs"]
mod root_tests;
