//! The process backend behind an async [`Child`](super::Child): tokio's own `process::Child`, or
//! (Windows) a raw `CreateProcessW` child that tokio's `Command` cannot express. `Child` forwards
//! its wait/kill/stream operations here so it stays backend-blind.

use std::process::ExitStatus;

#[cfg(unix)]
use crate::child::drop_report::Forgot;
use crate::child::owned::teardown::HandleTeardown;
#[cfg(target_os = "linux")]
use crate::child::owned::teardown::{Disposition, Past};
#[cfg(target_os = "linux")]
use crate::child::owned::OwnedChild;
#[cfg(target_os = "linux")]
use crate::child::spawn::held_teardown::{tear_down_held, tear_down_pidfd, HeldTeardown};
use crate::child::spawn::Diagnosis;
use crate::containment::dispatch::TeardownCaller;
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::os_process::OsProcess;
#[cfg(unix)]
use crate::signal::RootState;
use crate::signal::{Sent, Sig};
#[cfg(target_os = "linux")]
use crate::wait::teardown_warn::Due;

/// How [`ProcSource::wait_and_reap`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waited {
    /// The child exited and is still ours to reap.
    Exited,
    /// Something else reaped it: it must not be reaped by pid. The caller forgets it with
    /// [`ProcSource::forget_foreign`].
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    Foreign,
    /// macOS: launchd holds its zombie, and may reap it at any time. The caller forgets it as for
    /// [`Waited::Foreign`].
    #[cfg(target_os = "macos")]
    Orphaned,
    /// It cannot be shown to be ours, or the wait failed (macOS: no unique id or a failed peek;
    /// Windows: a failed wait on its handle). On Unix it must not be reaped by pid, and the caller
    /// forgets it as for [`Waited::Foreign`].
    Unverified,
}

#[cfg(unix)]
impl Waited {
    /// What a backend forgotten on this wait knows of its child; `None` for a child that exited and
    /// is still ours.
    fn forgotten(self) -> Option<Forgotten> {
        match self {
            Waited::Exited => None,
            Waited::Foreign => Some(Forgotten::ReapedElsewhere),
            #[cfg(target_os = "macos")]
            Waited::Orphaned => Some(Forgotten::Unpinned),
            Waited::Unverified => Some(Forgotten::Unproven),
        }
    }
}

/// What a forgotten backend knew of its child when it forgot it.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Forgotten {
    /// Shown reaped by someone else.
    ReapedElsewhere,
    /// launchd holds its zombie (`RootState::Unpinned`, macOS only), and may reap it at any time.
    Unpinned,
    /// Not shown to be ours: it may still be running.
    Unproven,
}

#[cfg(unix)]
impl Forgotten {
    /// What forgetting on `state`, the handle's own answer, knows.
    fn of(state: &RootState) -> Forgotten {
        match state {
            RootState::Unknown(_) => Forgotten::Unproven,
            RootState::Unpinned => Forgotten::Unpinned,
            RootState::Unreaped | RootState::Reaped { .. } => {
                // Every caller takes the state from `elsewhere`, which excludes `Unreaped`.
                debug_assert!(
                    !matches!(state, RootState::Unreaped),
                    "a child its handle shows ours is forgotten"
                );
                Forgotten::ReapedElsewhere
            }
        }
    }

    /// Whether the child is gone to its fate: reaped elsewhere, or an exited zombie launchd holds.
    fn gone(self) -> bool {
        self != Forgotten::Unproven
    }

    /// Completes "the child ...".
    fn why(self) -> &'static str {
        match self {
            Forgotten::ReapedElsewhere => "was reaped by someone else",
            Forgotten::Unpinned => "is a zombie launchd holds",
            Forgotten::Unproven => "cannot be shown to be ours",
        }
    }
}

/// The process backend behind an async [`Child`](super::Child). Each variant's `pid` is the number
/// the child had at spawn, stored when the backend was built because tokio forgets its own once it
/// has reaped the child; it does not say the process still holds it.
// The `Tokio` arm carries `::tokio::process::Child` inline — the common (and, on Unix, only)
// variant, and previously a plain `Child` field, so keeping it inline is no regression. Boxing it
// to shrink the rare Windows-only `Raw` variant would add a heap allocation + indirection to every
// async spawn, so the size difference is accepted deliberately.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing Raw to shrink it would add an allocation to every async spawn on the common Tokio path"
)]
#[derive(Debug)]
pub(crate) enum ProcSource {
    /// A `::tokio::process::Child` (the default path), with what names the process for good.
    Tokio {
        /// tokio's `Child`, held so that nothing but [`ProcSource::release`] hands it to its own
        /// drop, which reaps by pid (see [`Held`]). The paths that have verified the child is ours
        /// release it, every other path forgets it, and dropping the backend with neither done
        /// (an unwind) does whichever is safe.
        child: Held,
        pid: u32,
        /// The streams tokio had not handed out when the backend was built. They live here, not
        /// in `child`, so that dropping the backend closes this process's ends whatever becomes
        /// of tokio's `Child`. Always `None` since the async spawn makes every pipe itself
        /// (`Child::os.pipes`); deleted with `ProcSource`.
        #[cfg_attr(
            windows,
            allow(dead_code, reason = "only the Unix forget moves them out; held to close")
        )]
        stdin: Option<::tokio::process::ChildStdin>,
        #[cfg_attr(
            windows,
            allow(dead_code, reason = "only the Unix forget moves them out; held to close")
        )]
        stdout: Option<::tokio::process::ChildStdout>,
        #[cfg_attr(
            windows,
            allow(dead_code, reason = "only the Unix forget moves them out; held to close")
        )]
        stderr: Option<::tokio::process::ChildStderr>,
        /// The pidfd the spawn handshake opened while the child was held before `exec`. It names
        /// this process for good, so a signal through it cannot reach a process that later reuses
        /// the pid.
        #[cfg(target_os = "linux")]
        pidfd: PinnedPidfd,
        /// The child's unique id (see `child::spawn::unique_report`): the only identity a by-pid
        /// signal on macOS is checked against. `None`: no id is held, so the pid is acted on never.
        #[cfg(target_os = "macos")]
        identity: Option<u64>,
    },
    /// A child something else reaped, or one that cannot be shown to be ours (macOS: no unique id,
    /// or a peek that failed): tokio's `Child` is forgotten, and the streams it had not yet handed
    /// out remain. Always `None` since the async spawn makes every pipe itself; deleted with
    /// `ProcSource`.
    #[cfg(unix)]
    Foreign {
        #[allow(dead_code, reason = "only tests read them; held to close")]
        stdin: Option<::tokio::process::ChildStdin>,
        #[allow(dead_code, reason = "only tests read them; held to close")]
        stdout: Option<::tokio::process::ChildStdout>,
        #[allow(dead_code, reason = "only tests read them; held to close")]
        stderr: Option<::tokio::process::ChildStderr>,
        /// What became of the child, as far as the forget knew.
        fate: Forgotten,
        pid: u32,
        /// The `Tokio` backend's pidfd, which names the child exactly whatever the forget knew.
        /// Closed with the backend.
        #[cfg(target_os = "linux")]
        pidfd: PinnedPidfd,
    },
    /// A raw `CreateProcessW` child owning its process handle directly — the executable/argv[0]
    /// independence (and, later, arbitrary descriptors) that tokio's `Command` cannot express.
    #[cfg(windows)]
    Raw(crate::tokio::spawn::windows_raw::RawAsyncChild),
}

/// The backend's pidfd. A [`ProcSource`] has a `Drop`, so a field cannot be moved out of it; this
/// lets a teardown take the original (never a duplicate, which can fail at the fd limit) and hand
/// it on. Held from the spawn until [`take`](PinnedPidfd::take), which a forget (`hand_off`, from
/// the backend's replacement by a `Foreign` one) and a teardown that consumes the backend call.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct PinnedPidfd(Option<std::os::fd::OwnedFd>);

/// Why a [`PinnedPidfd`] can be empty: its use after this is a contract breach.
#[cfg(target_os = "linux")]
const PIDFD_TAKEN: &str = "the pidfd was taken by a teardown that consumes the backend";

#[cfg(target_os = "linux")]
impl PinnedPidfd {
    fn take(&mut self) -> std::os::fd::OwnedFd {
        self.0.take().expect(PIDFD_TAKEN)
    }

    /// Moves the pidfd into a new `PinnedPidfd`.
    fn hand_off(&mut self) -> PinnedPidfd {
        PinnedPidfd(Some(self.take()))
    }
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for PinnedPidfd {
    type Target = std::os::fd::OwnedFd;
    fn deref(&self) -> &std::os::fd::OwnedFd {
        self.0.as_ref().expect(PIDFD_TAKEN)
    }
}

#[cfg(target_os = "linux")]
impl std::os::fd::AsRawFd for PinnedPidfd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&**self)
    }
}

#[cfg(target_os = "linux")]
impl std::os::fd::AsFd for PinnedPidfd {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&**self)
    }
}

/// Why a child is forgotten by [`ProcSource::forget_foreign`], completing "child N ...".
#[cfg(all(unix, test))]
const FORGET_FOREIGN: &str = "was reaped by someone else, or cannot be shown to be ours";

/// Why a child its handle shows gone, not pinned, or unanswerable is forgotten, completing "child N ...".
#[cfg(unix)]
fn foreign_why(state: &RootState) -> String {
    match state {
        RootState::Unknown(e) => format!("cannot be shown to be ours (RootState::Unknown: {e})"),
        RootState::Unpinned => format!(
            "is not pinned by this process (RootState::Unpinned: {})",
            crate::signal::UNPINNED_WHY
        ),
        RootState::Unreaped | RootState::Reaped { .. } => {
            // Every caller takes the state from `elsewhere`, which excludes `Unreaped`.
            debug_assert!(
                !matches!(state, RootState::Unreaped),
                "a child its handle shows ours is forgotten"
            );
            "was reaped by someone else, or cannot be shown to be ours".to_owned()
        }
    }
}

/// What the second teardown of a child whose first kill was refused did, as its
/// [`HandleTeardown`]'s outcome says, plus what forgetting tokio's handle for it leaked, for the
/// caller's one warn. Only Linux tears a refused kill's child down again through its pidfd.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only Linux tears a child down again through its pidfd")
)]
struct TornDown {
    torn: HandleTeardown,
    /// What the forget leaked; `None` if the backend was forgotten before, so nothing more leaked
    /// (and its warn says so).
    leak: Option<&'static str>,
    /// Why the refused kill's own look forgot the child, completing "the child ...", if it did.
    why: Option<String>,
}

/// What forgetting tokio's handle for a child its handle does not show ours did, for the caller's
/// one warn.
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "only Unix forgets a child the handle cannot answer for")
)]
struct Forgetting {
    /// What the forget leaks.
    leak: &'static str,
    /// Why the child was forgotten.
    why: String,
    /// `Gone` if the child was shown reaped by someone else or held by launchd, `Running` with the
    /// identity the caller read, if it cannot be shown to be ours.
    fate: ChildFate,
}

/// What became of a child whose teardown kill was refused (a setuid child answers `EPERM`): the
/// exclusive states of [`ProcSource::after_refused_kill`].
enum Refused {
    /// Tokio's handle was forgotten for a child it shows gone; no second teardown ran. (Linux: a
    /// child it merely cannot show ours is torn down, see below.)
    Forgotten(Forgetting),
    /// The child torn down again through its pidfd, after tokio's handle was forgotten for it.
    /// Linux only.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only Linux tears a child down again through its pidfd")
    )]
    TornDown(TornDown),
    /// Tokio's handle was released, and nothing else was done to the child. macOS: tokio's drop queues
    /// a child still running on the runtime's orphan queue. Windows: the raw backend is dropped, and
    /// nothing waits for the child. Not Linux, which tears every child not shown gone down again.
    #[cfg_attr(
        target_os = "linux",
        allow(dead_code, reason = "only macOS and Windows release a child after a refused kill")
    )]
    Released,
}

/// What the one warning for a refused teardown kill says: the kill's error, then what became of the
/// child. A forgotten one says why and what the forget leaked; a torn-down one, if its look forgot it,
/// why, then what the forget leaked and the clause of its second teardown's outcome, whatever the
/// level; a released one where it went.
fn refused_kill_warning(pid: u32, e: &Error, after: &Refused) -> String {
    let mut text = format!("teardown kill of child {pid} failed ({e})");
    match after {
        Refused::Forgotten(forgotten) => text.push_str(&format!(
            "; the child {}; forgetting tokio's handle for it leaks {}",
            forgotten.why, forgotten.leak
        )),
        Refused::TornDown(torn_down) => {
            if let Some(why) = &torn_down.why {
                text.push_str(&format!("; the child {why}"));
            }
            match torn_down.leak {
                Some(leak) => text.push_str(&format!("; forgetting tokio's handle for it leaks {leak}")),
                None => text.push_str("; tokio's handle for it was already forgotten"),
            }
            if let Some(said) = torn_down.torn.outcome.said() {
                text.push_str(&format!("; {}", said.text()));
            }
        }
        Refused::Released => {
            #[cfg(target_os = "linux")]
            debug_assert!(false, "Linux tears every child not shown gone down again");
            #[cfg(target_os = "macos")]
            text.push_str(&format!("; it is {HANDED_TO_ORPHAN_REAPER}"));
            #[cfg(windows)]
            text.push_str(crate::child::owned::teardown::Disposition::Leave.suffix(true));
        }
    }
    text
}

/// What a warning says of a child that tokio's `Child` drop queued on the runtime's orphan queue,
/// after the child's name.
#[cfg(target_os = "macos")]
pub(crate) const HANDED_TO_ORPHAN_REAPER: &str = "handed to tokio's orphan reaper, which reaps it once it exits";

/// tokio's `Child`, which on Unix reaps by pid on drop, when the pid may name another process by
/// now. It is dropped only through [`ProcSource::release`], leaked only through
/// [`ProcSource::forget`], and dropping the backend with neither done is [`ProcSource`]'s own
/// `Drop`. On Windows the process handle pins the process, so none of this changes what it does.
#[derive(Debug)]
pub(crate) struct Held(Option<::tokio::process::Child>);

impl Held {
    fn take(&mut self) -> Option<::tokio::process::Child> {
        self.0.take()
    }
}

impl std::ops::Deref for Held {
    type Target = ::tokio::process::Child;
    fn deref(&self) -> &::tokio::process::Child {
        self.0
            .as_ref()
            .expect("the backend's tokio child was released or forgotten")
    }
}

impl std::ops::DerefMut for Held {
    fn deref_mut(&mut self) -> &mut ::tokio::process::Child {
        self.0
            .as_mut()
            .expect("the backend's tokio child was released or forgotten")
    }
}

/// Split tokio's untaken streams off `child`, so they outlive whatever becomes of it.
fn hold(
    mut child: ::tokio::process::Child,
) -> (
    Held,
    Option<::tokio::process::ChildStdin>,
    Option<::tokio::process::ChildStdout>,
    Option<::tokio::process::ChildStderr>,
) {
    let streams = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    (Held(Some(child)), streams.0, streams.1, streams.2)
}

/// `child`, counted when it is actually dropped (tests: `fault::count_backend_drops`), so a release
/// that does not drop it is not counted either.
#[cfg(test)]
fn counted(child: ::tokio::process::Child) -> super::fault::CountedDrop {
    super::fault::CountedDrop { _child: child }
}
#[cfg(not(test))]
fn counted(child: ::tokio::process::Child) -> ::tokio::process::Child {
    child
}

/// Dropping a backend that nothing released or forgot (an unwind out of a caller does this) does
/// the one safe thing: the untaken streams close with the fields, and tokio's `Child` goes to its
/// own drop only if [`ProcSource::state`] shows it ours, else it is forgotten. It is quiet where
/// it matters: no `log` call while unwinding, since a logger that panics there aborts.
///
/// Nothing is killed: the backend does not know whether the handle was armed.
#[cfg(unix)]
impl Drop for ProcSource {
    fn drop(&mut self) {
        let ProcSource::Tokio { child, .. } = self else {
            return;
        };
        let Some(child) = child.take() else {
            return;
        };
        // A child tokio already reaped has nothing left to drop wrongly.
        if child.id().is_none() || matches!(self.state_of(), RootState::Unreaped) {
            drop(counted(child));
        } else {
            std::mem::forget(child);
            #[cfg(test)]
            super::drop_fault::note_forget();
            if !std::thread::panicking() {
                log::debug!("a backend dropped without a release was forgotten: its child is not shown to be ours");
            }
        }
    }
}

/// What waiting on a forgotten child answers: nothing of ours is left to wait for.
#[cfg(unix)]
fn gone() -> Error {
    Error::Io(std::io::Error::from_raw_os_error(libc::ECHILD))
}

impl ProcSource {
    /// A tokio child that `pidfd`, opened by the spawn handshake, names.
    #[cfg(target_os = "linux")]
    pub(crate) fn new(child: ::tokio::process::Child, pid: u32, pidfd: std::os::fd::OwnedFd) -> ProcSource {
        let (child, stdin, stdout, stderr) = hold(child);
        ProcSource::Tokio {
            child,
            pid,
            stdin,
            stdout,
            stderr,
            pidfd: PinnedPidfd(Some(pidfd)),
        }
    }

    /// A tokio child whose unique id was read as `identity`.
    #[cfg(target_os = "macos")]
    pub(crate) fn new(child: ::tokio::process::Child, pid: u32, identity: Option<u64>) -> ProcSource {
        let (child, stdin, stdout, stderr) = hold(child);
        ProcSource::Tokio {
            child,
            pid,
            stdin,
            stdout,
            stderr,
            identity,
        }
    }

    /// A tokio child on Windows, where tokio's own process handle is the one that names it.
    #[cfg(windows)]
    pub(crate) fn new(child: ::tokio::process::Child, pid: u32) -> ProcSource {
        let (child, stdin, stdout, stderr) = hold(child);
        ProcSource::Tokio {
            child,
            pid,
            stdin,
            stdout,
            stderr,
        }
    }

    /// The pid the child had at spawn; see [`ProcSource`].
    pub(crate) fn pid(&self) -> u32 {
        match self {
            ProcSource::Tokio { pid, .. } => *pid,
            #[cfg(unix)]
            ProcSource::Foreign { pid, .. } => *pid,
            #[cfg(windows)]
            ProcSource::Raw(raw) => raw.pid(),
        }
    }

    /// The handle that names the child, for a check that must not go by pid alone. Linux: the pidfd.
    /// macOS: the pid with its unique id, while both are known. Windows: tokio's process handle.
    /// `None` when there is nothing to check a pid against: a forgotten child, a raw Windows child,
    /// or (macOS) one whose unique id or pid is unknown. On Linux a live backend always has its pidfd.
    pub(crate) fn target(&self) -> Option<crate::wait::exit_only::Target<'_>> {
        use crate::wait::exit_only::Target;
        match self {
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { pidfd, .. } => Some(Target::PidFd(std::os::fd::AsFd::as_fd(pidfd))),
            #[cfg(target_os = "macos")]
            ProcSource::Tokio {
                child, pid, identity, ..
            } => {
                // A child tokio has reaped has nothing to be checked against.
                child.id()?;
                Some(Target::pid(*pid, Some((*identity)?)))
            }
            #[cfg(windows)]
            ProcSource::Tokio { child, .. } => {
                let handle = child.raw_handle()?;
                // SAFETY: tokio owns the live process handle while `raw_handle` is `Some`, and the
                // borrow lasts no longer than `self`.
                Some(Target::Handle(unsafe {
                    std::os::windows::io::BorrowedHandle::borrow_raw(handle)
                }))
            }
            #[cfg(unix)]
            ProcSource::Foreign { .. } => None,
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }

    /// The process handle, borrowed from `self`. `None` once tokio has reaped the child and closed it.
    #[cfg(windows)]
    pub(crate) fn raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
        match self {
            ProcSource::Tokio { child, .. } => child.raw_handle(),
            ProcSource::Raw(raw) => Some(raw.raw_handle()),
        }
    }

    /// The child as its spawn holds it, with the handshake pidfd. `None` for a forgotten backend.
    #[cfg(target_os = "linux")]
    pub(crate) fn child_handle(&self, pid: u32) -> Option<crate::containment::ChildHandle<'_>> {
        let crate::wait::exit_only::Target::PidFd(pidfd) = self.target()?;
        Some(crate::containment::ChildHandle { pid, pidfd })
    }

    /// Wait until the child exits, returning its status.
    ///
    /// tokio's own `wait` and `try_wait` are a `waitpid` by pid, so on Unix the status is collected
    /// only by [`reap_on_events`](ProcSource::reap_on_events), right after a look through the handle
    /// shows the exit (Linux: through the pidfd; macOS: by pid, checked against the unique id read
    /// at spawn). A child reaped elsewhere is forgotten and answers `ECHILD`. A child the handle
    /// cannot answer for (a failed peek, or macOS without a readable unique id) answers
    /// [`Error::Unassessable`], since it may well be running; it is not forgotten.
    pub(crate) async fn wait(&mut self) -> Result<ExitStatus, Error> {
        match self {
            ProcSource::Tokio { .. } => {
                #[cfg(unix)]
                {
                    // Checked before the watch too, so a child already reaped elsewhere is not
                    // watched.
                    self.gate()?;
                    match self.reap_on_events().await {
                        Ok(status) => Ok(status),
                        Err(Halt::State(state)) => Err(self.refuse(state)),
                        Err(Halt::ReapedBetween(why)) => {
                            self.forget_as(
                                &format!("was reaped by someone else ({why})"),
                                Forgotten::ReapedElsewhere,
                            );
                            Err(gone())
                        }
                        Err(Halt::ReapFailed(e)) => Err(Error::Io(e)),
                        Err(Halt::Watch(e)) => Err(e),
                    }
                }
                #[cfg(windows)]
                {
                    let ProcSource::Tokio { child: c, .. } = self else {
                        unreachable!("matched above")
                    };
                    c.wait().await.map_err(Error::Io)
                }
            }
            #[cfg(unix)]
            ProcSource::Foreign { .. } => Err(gone()),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.wait().await,
        }
    }

    /// Exit status if the child has already exited (non-blocking).
    ///
    /// On Unix tokio's `try_wait` is a `waitpid` by pid, so it runs only for a child the handle
    /// shows ours: one reaped elsewhere is forgotten and answers `ECHILD`, and one it cannot answer
    /// for answers [`Error::Unassessable`] (see [`wait`](ProcSource::wait)).
    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        #[cfg(unix)]
        self.gate()?;
        match self {
            ProcSource::Tokio { child: c, .. } => c.try_wait().map_err(Error::Io),
            #[cfg(unix)]
            ProcSource::Foreign { .. } => Err(gone()),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.try_wait(),
        }
    }

    /// `Ok` for a child the handle shows ours, or that tokio already reaped. Otherwise
    /// [`refuse`](ProcSource::refuse)'s answer.
    #[cfg(unix)]
    fn gate(&mut self) -> Result<(), Error> {
        let ProcSource::Tokio { child, .. } = &*self else {
            return Ok(());
        };
        if child.id().is_none() {
            return Ok(());
        }
        match self.state_of() {
            RootState::Unreaped => Ok(()),
            state => Err(self.refuse(state)),
        }
    }

    /// The answer to a wait whose look found `state`, not `Unreaped`. Reaped elsewhere: the child is
    /// forgotten and the answer is `ECHILD`. Not shown either way: `Unassessable`, with the child
    /// left in place, so a later call can still answer and a `Drop` forgets it.
    #[cfg(unix)]
    fn refuse(&mut self, state: RootState) -> Error {
        let pid = self.pid();
        match state {
            RootState::Unreaped => unreachable!("a wait refused a child its handle shows ours"),
            RootState::Reaped { .. } => {
                self.forget_as("was reaped by someone else", Forgotten::ReapedElsewhere);
                gone()
            }
            RootState::Unknown(failed) => Error::Unassessable {
                detail: format!("pid {pid}: the child cannot be shown to be ours; it was not waited on"),
                source: Some(failed),
            },
            RootState::Unpinned => Error::Unassessable {
                detail: format!(
                    "pid {pid}: the child cannot be shown to be ours ({}); it was not waited on",
                    crate::signal::UNPINNED_WHY
                ),
                source: None,
            },
        }
    }

    /// Whether the child has exited by the time `grace` is over, read only through its pidfd: nothing
    /// is reaped and no state is read. A child forgotten as reaped elsewhere has exited.
    #[cfg(target_os = "linux")]
    pub(crate) async fn exited_within(&self, grace: std::time::Duration) -> Result<bool, Error> {
        match self {
            ProcSource::Foreign { fate, .. } if fate.gone() => Ok(true),
            ProcSource::Tokio { pidfd, .. } | ProcSource::Foreign { pidfd, .. } => {
                crate::tokio::wait::pidfd_exited_within(std::os::fd::AsFd::as_fd(pidfd), grace).await
            }
        }
    }

    /// The held handle read as an [`OsProcess`], to watch the child's exit through without reaping it
    /// or looking its pid up. `None`: nothing is left to watch, because the child is reaped, by tokio
    /// or by someone else, and has exited.
    ///
    /// - **Linux:** a duplicate of the pidfd, which names the child whatever the forget knew.
    /// - **macOS:** an exit watch armed on the pid, checked against the unique id read at spawn. A
    ///   child forgotten as not shown to be ours has nothing here to name it: `Unassessable`.
    /// - **Windows:** a duplicate of the process handle.
    ///
    /// A duplicate can fail (`EMFILE`, `ENFILE`, a handle-table limit): `Io`, which a watch reports as
    /// a watch failure.
    pub(crate) fn held_os_process(&self) -> Result<Option<Box<dyn OsProcess>>, Error> {
        let pid = self.pid();
        #[cfg(target_os = "linux")]
        {
            let pidfd = match self {
                ProcSource::Foreign { fate, .. } if fate.gone() => return Ok(None),
                ProcSource::Tokio { child, .. } if child.id().is_none() => return Ok(None),
                ProcSource::Tokio { pidfd, .. } | ProcSource::Foreign { pidfd, .. } => pidfd,
            };
            let held = std::os::fd::AsFd::as_fd(pidfd)
                .try_clone_to_owned()
                .map_err(Error::Io)?;
            Ok(Some(Box::new(crate::os_process::linux::LinuxProcess::new(
                Some(pid),
                held,
            ))))
        }
        #[cfg(target_os = "macos")]
        {
            match self {
                ProcSource::Foreign { fate, .. } if fate.gone() => Ok(None),
                ProcSource::Foreign { .. } => Err(Error::Unassessable {
                    detail: "the child cannot be shown to be ours, and its exit cannot be watched".to_owned(),
                    source: None,
                }),
                ProcSource::Tokio { child, .. } if child.id().is_none() => Ok(None),
                ProcSource::Tokio {
                    identity: Some(unique), ..
                } => {
                    let watched = crate::os_process::macos::child::MacChild::new(pid, *unique)?;
                    // The watch was armed on whatever held the pid by now. The spawn's unique id
                    // read after arming proves it was the child: a unique id is never reused.
                    let after = crate::os_process::macos::read_for_open(
                        pid,
                        "graceful shutdown",
                        "the graceful signal was sent, but the child's exit cannot be watched",
                    )?;
                    Ok(after
                        .filter(|now| now.unique_id == *unique)
                        .map(|_| Box::new(watched) as Box<dyn OsProcess>))
                }
                ProcSource::Tokio { identity: None, .. } => {
                    debug_assert!(false, "a spawn that left a child with no unique id fails");
                    Err(Error::Unassessable {
                        detail: "the child has no unique id, and its exit cannot be watched".to_owned(),
                        source: None,
                    })
                }
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::BorrowedHandle;

            let Some(raw) = self.raw_handle() else {
                return Ok(None);
            };
            // SAFETY: the backend owns the process handle live while `raw_handle` is `Some`, and the
            // borrow ends with the duplicate below.
            let held = unsafe { BorrowedHandle::borrow_raw(raw) }
                .try_clone_to_owned()
                .map_err(Error::Io)?;
            // Both backends' handles come from `CreateProcess`, which grants every right.
            Ok(Some(Box::new(crate::os_process::windows::WindowsProcess::for_child(
                held, pid,
            ))))
        }
    }

    /// Whether the backend still holds something that pins the child's pid against reuse.
    /// tokio's `Child` replaces its inner state the moment `wait`/`try_wait` observes the exit,
    /// dropping the guard that holds the process handle (`id()` goes `None` with it); the raw
    /// backend owns its handle for the child's whole life and never unpins.
    #[cfg(windows)]
    pub(crate) fn pins_pid(&self) -> bool {
        match self {
            ProcSource::Tokio { child: c, .. } => c.id().is_some(),
            ProcSource::Raw(_) => true,
        }
    }

    /// Send `sig` to the child. Does not reap. [`Sent::Gone`] means nothing was delivered because
    /// the child is already gone (reaped by tokio or by someone else); for [`Sent::Unverified`], see
    /// there. Neither is an error.
    ///
    /// - **Linux:** `pidfd_send_signal` on the handshake pidfd, never by pid, so a foreign reap
    ///   followed by a pid reuse cannot redirect it. A child forgotten as not shown to be ours is
    ///   still signalled through it.
    /// - **macOS:** by audit token, after a read that the pid still has the unique id read at spawn.
    ///   The kernel checks the pid's `p_idversion` and signals while it holds a reference, so a reap
    ///   by another reaper and a pid reuse cannot redirect it; only the documented 2^32 version
    ///   wrap is left. A child that has exited and is not reaped is [`Sent::Delivered`].
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        match self {
            #[cfg(target_os = "linux")]
            ProcSource::Foreign {
                fate: Forgotten::Unproven,
                pidfd,
                pid,
                ..
            } => crate::signal::via_pidfd(Some(std::os::fd::AsFd::as_fd(pidfd)), *pid, sig).map_err(Error::Io),
            #[cfg(unix)]
            ProcSource::Foreign { fate, .. } => {
                log::debug!("the child {}; {sig:?} not sent", fate.why());
                Ok(if fate.gone() { Sent::Gone } else { Sent::Unverified })
            }
            #[cfg(unix)]
            ProcSource::Tokio { child, .. } if child.id().is_none() => {
                log::debug!("the child is already reaped; {sig:?} not sent");
                Ok(Sent::Gone)
            }
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { pid, pidfd, .. } => {
                crate::signal::via_pidfd(Some(std::os::fd::AsFd::as_fd(pidfd)), *pid, sig).map_err(Error::Io)
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { pid, identity, .. } => {
                crate::signal::via_audit_token(*pid, *identity, sig).map_err(Error::Io)
            }
            #[cfg(windows)]
            ProcSource::Tokio { child, .. } => {
                let Sig::Kill = sig;
                // tokio drops its handle once it has reaped the child.
                let Some(h) = child.raw_handle() else {
                    return Ok(Sent::Gone);
                };
                // SAFETY of the handle: tokio owns it live while `raw_handle` is `Some`.
                // tokio's own child, made by `CreateProcess`.
                terminate_unreaped(
                    windows::Win32::Foundation::HANDLE(h),
                    crate::os_process::windows::CREATE_PROCESS_ACCESS,
                )
            }
            #[cfg(windows)]
            ProcSource::Raw(r) => {
                let Sig::Kill = sig;
                r.start_kill().map(|()| Sent::Delivered)
            }
        }
    }

    /// Whether the root is still this backend's child to act on, from its own handle; see
    /// [`RootState`]. Nothing is logged: it may run during an unwind.
    ///
    /// - **Linux:** a peek through the pidfd. Exact, with no start token to collide.
    /// - **macOS:** a peek that checks the pid's unique id, including that a running child's id can
    ///   be read ([`exit_only::peek_verified`](crate::wait::exit_only)). A child with no unique id
    ///   (a spawn whose unique id was not adopted, see `adopted_id`) is `Unknown`: its unique-id
    ///   read was refused, and nothing shows the pid still names it.
    ///
    /// A child tokio reaped (`id()` is `None`), and a backend forgotten as reaped elsewhere, are
    /// `Reaped`. A backend forgotten because launchd holds the child's zombie is `Unpinned`. One
    /// forgotten because the child could not be shown to be ours is `Unknown`: the child may still
    /// be running.
    #[cfg(unix)]
    pub(crate) fn state(&self) -> RootState {
        match self {
            ProcSource::Foreign { fate, .. } => match fate {
                Forgotten::ReapedElsewhere => RootState::Reaped { own: false },
                Forgotten::Unpinned => RootState::Unpinned,
                Forgotten::Unproven => RootState::Unknown(std::io::Error::other(
                    "its handle was forgotten because it could not be shown to be ours, so it may still be running",
                )),
            },
            ProcSource::Tokio { child, .. } if child.id().is_none() => RootState::Reaped { own: true },
            ProcSource::Tokio { .. } => self.state_of(),
        }
    }

    /// [`state`](ProcSource::state) of a `Tokio` backend whose `child` may already be taken out of
    /// it (the drop does that), for a child tokio has not reaped.
    #[cfg(unix)]
    fn state_of(&self) -> RootState {
        let ProcSource::Tokio { .. } = self else {
            return RootState::Reaped { own: false };
        };
        #[cfg(target_os = "linux")]
        let peeked = {
            let ProcSource::Tokio { pidfd, .. } = self else {
                unreachable!("checked above")
            };
            crate::wait::exit_only::peek(&crate::wait::exit_only::Target::PidFd(std::os::fd::AsFd::as_fd(pidfd)))
        };
        #[cfg(target_os = "macos")]
        let peeked = {
            let ProcSource::Tokio { pid, identity, .. } = self else {
                unreachable!("checked above")
            };
            let Some(identity) = *identity else {
                return RootState::Unknown(std::io::Error::other(
                    "the child's unique id is unknown, so nothing shows its pid still names it",
                ));
            };
            crate::wait::exit_only::peek_verified(&crate::wait::exit_only::Target::pid(*pid, Some(identity)))
        };
        RootState::of_peek(peeked)
    }

    /// The pid and non-`Unreaped` state of a child tokio has not reaped, if its handle shows one.
    #[cfg(unix)]
    fn elsewhere(&self) -> Option<(u32, RootState)> {
        let ProcSource::Tokio { child, .. } = self else {
            return None;
        };
        child.id()?;
        match self.state_of() {
            RootState::Unreaped => None,
            state => Some((self.pid(), state)),
        }
    }

    /// Forget the child: tokio's `Child` is leaked, never dropped, because its drop would reap by
    /// pid, and the pid may name another process by now. The untaken streams close, and so does
    /// cosca's own pidfd, unless the caller moved it out first. What leaks is tokio's own: on Linux
    /// its pidfd and its reactor registration, on macOS its `SIGCHLD` watch.
    #[cfg(unix)]
    pub(crate) fn forget(mut self) {
        if let ProcSource::Tokio { child, .. } = &mut self {
            if let Some(child) = child.take() {
                std::mem::forget(child);
            }
        }
    }

    /// Hand tokio's `Child` to its own drop, which `try_wait`s once and queues a still-running
    /// child on the runtime's orphan queue. Only for a child verified to be ours: that drop reaps
    /// by pid.
    pub(crate) fn release(mut self) {
        if let ProcSource::Tokio { child, .. } = &mut self {
            drop(child.take().map(counted));
        }
    }

    /// The pidfd naming the child, if the backend holds one (Linux, forgotten or not).
    #[cfg(unix)]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        #[cfg(target_os = "linux")]
        if let ProcSource::Foreign { pidfd, .. } = self {
            return Some(std::os::fd::AsFd::as_fd(pidfd));
        }
        match self.target()? {
            #[cfg(target_os = "linux")]
            crate::wait::exit_only::Target::PidFd(fd) => Some(fd),
            #[allow(unreachable_patterns, reason = "a Linux backend's target is always its pidfd")]
            _ => None,
        }
    }

    /// Whether the child is still running, read without reaping it: `false` once it is reaped, by
    /// tokio or by someone else, or has exited. On Linux a backend forgotten as not shown to be ours
    /// asks its kept pidfd, which names the child whoever reaped it. On macOS a child with no unique
    /// id cannot be read.
    #[cfg(unix)]
    pub(crate) fn is_running(&self) -> std::io::Result<bool> {
        #[cfg(target_os = "linux")]
        if let ProcSource::Foreign {
            fate: Forgotten::Unproven,
            pidfd,
            ..
        } = self
        {
            let target = crate::wait::exit_only::Target::PidFd(std::os::fd::AsFd::as_fd(pidfd));
            return Ok(matches!(
                crate::wait::exit_only::peek(&target)?,
                crate::os_process::child::PeekOutcome::Running
            ));
        }
        if self.is_reaped() {
            return Ok(false);
        }
        let Some(target) = self.target() else {
            return Err(std::io::Error::other(
                "the child's unique id is unknown, so nothing shows its pid still names it",
            ));
        };
        Ok(matches!(
            crate::wait::exit_only::peek(&target)?,
            crate::os_process::child::PeekOutcome::Running
        ))
    }

    /// Whether the child has exited, from its exit edge and not from the reap record, which a
    /// zombie only its tracer sees lacks. Linux: the pidfd's readability, whoever reaped. macOS: the
    /// peek, and then the zombie the exit is withheld as, read on the unique id.
    #[cfg(unix)]
    fn has_exited(&self) -> std::io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let pidfd = self.pidfd().expect("a Linux backend always has its pidfd");
            crate::os_process::poll::is_readable(pidfd)
        }
        #[cfg(target_os = "macos")]
        {
            if !self.is_running()? {
                return Ok(true);
            }
            let ProcSource::Tokio {
                pid,
                identity: Some(unique),
                ..
            } = self
            else {
                unreachable!("`is_running` read a running child by its unique id");
            };
            crate::identity::has_exited(*pid, *unique, crate::identity::ReadPurpose::Running)
                .map_err(|errno| crate::identity::has_exited_error(*pid, errno))
        }
    }

    /// Whether the child is still running, read through the backend's own handle without reaping it:
    /// `Dead` once it is reaped, by tokio or by someone else, or has exited. `Unknown` when the
    /// handle cannot say, and (macOS) for a backend forgotten as not shown to be ours, which may still
    /// run. A recycled pid never reads as alive.
    pub(crate) fn liveness(&self) -> crate::identity::Liveness {
        use crate::identity::Liveness;

        #[cfg(unix)]
        {
            #[cfg(target_os = "macos")]
            if self.forgot_unproven() {
                return Liveness::Unknown;
            }
            match self.has_exited() {
                Ok(true) => Liveness::Dead,
                Ok(false) => Liveness::Alive,
                Err(e) => {
                    log::debug!("child {}: its liveness could not be read ({e})", self.pid());
                    Liveness::Unknown
                }
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::BorrowedHandle;

            use crate::os_process::child::PeekOutcome;

            // `None`: tokio has collected the child and closed its handle.
            let Some(raw) = self.raw_handle() else {
                return Liveness::Dead;
            };
            if self.is_reaped() {
                return Liveness::Dead;
            }
            // SAFETY: the backend owns the process handle live while `raw_handle` is `Some`, and the
            // borrow ends with the look.
            let handle = unsafe { BorrowedHandle::borrow_raw(raw) };
            match crate::wait::exit_only::peek(&crate::wait::exit_only::Target::Handle(handle)) {
                Ok(PeekOutcome::Running) => Liveness::Alive,
                Ok(PeekOutcome::Exit(_) | PeekOutcome::Foreign(_)) => Liveness::Dead,
                Err(e) => {
                    log::debug!("child {}: its liveness could not be read ({e})", self.pid());
                    Liveness::Unknown
                }
            }
        }
    }

    /// `true` once the backend has collected the child's status, so no reap remains.
    pub(crate) fn is_reaped(&self) -> bool {
        match self {
            ProcSource::Tokio { child: c, .. } => c.id().is_none(),
            #[cfg(unix)]
            ProcSource::Foreign { .. } => true,
            #[cfg(windows)]
            ProcSource::Raw(r) => r.is_reaped(),
        }
    }

    /// Block until the child has exited, then let the backend reap it. **Never kills** — the
    /// caller's own successful kill is what bounds the wait.
    /// **Invariant:** no `wait()` future for this child is in flight when this runs.
    ///
    /// The caller's child was never awaited, so one tokio has already reaped is a broken
    /// precondition, asserted in debug.
    ///
    /// - **Linux:** `waitid(P_PIDFD, WEXITED | WNOWAIT)` on the kept pidfd, so tokio's own
    ///   field-drop reaps the zombie. `ECHILD` is [`Waited::Foreign`]. So is any other failure (a
    ///   contract breach, asserted in debug): without proof the child is ours, tokio's by-pid reap
    ///   must not run.
    /// - **macOS:** the sync child's verified-id wait (a kqueue plus peeks that check the pid's
    ///   unique id), which never reaps. A child a tracer holds is waited for until the tracer
    ///   hands it back. A foreign reap and a pid with another unique id are [`Waited::Foreign`], and
    ///   a launchd-held zombie is [`Waited::Orphaned`]. What cannot be shown to be ours or reaped is [`Waited::Unverified`]: a
    ///   refused read, a failed peek or kqueue (warned), and a child with no unique id (a
    ///   spawn whose unique id was not adopted, see `adopted_id`), which is not waited on at all. A
    ///   foreign reap between the verified exit and tokio's reap is not seen: if another child of
    ///   ours has taken the number, tokio's reap collects it.
    /// - **Windows:** waits on tokio's process handle, which pins the child.
    ///
    /// On anything but [`Waited::Exited`] the caller calls
    /// [`forget_foreign`](ProcSource::forget_foreign).
    #[cfg(any(windows, test))]
    pub(crate) fn wait_and_reap(&mut self, pid: u32) -> Waited {
        self.wait_and_reap_at(pid, log::Level::Warn)
    }

    /// [`wait_and_reap`](ProcSource::wait_and_reap), logging what it finds that is not an exit at
    /// `level`: for a caller that reports a [`Waited::Foreign`] itself, in its one warn.
    #[cfg(any(windows, test))]
    pub(crate) fn wait_and_reap_at(&mut self, pid: u32, level: log::Level) -> Waited {
        self.wait_and_reap_caused(pid, level).0
    }

    /// [`wait_and_reap_at`](ProcSource::wait_and_reap_at), and why a [`Waited::Foreign`] was found:
    /// the wait's error, or why the child is not ours.
    pub(crate) fn wait_and_reap_caused(
        &mut self,
        pid: u32,
        #[cfg_attr(
            windows,
            allow(unused_variables, reason = "a process handle pins its process: nothing to log")
        )]
        level: log::Level,
    ) -> (Waited, Option<String>) {
        crate::bounded::assert_may_block("wait_and_reap");
        match self {
            // Already forgotten, with no fresh evidence of what became of it.
            #[cfg(unix)]
            ProcSource::Foreign { .. } => (Waited::Unverified, None),
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { child, pidfd, .. } => {
                if !still_ours(child) {
                    return (Waited::Exited, None);
                }
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                wait_on_pidfd(pid, pidfd, level)
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child, identity, .. } => {
                if !still_ours(child) {
                    return (Waited::Exited, None);
                }
                // No unique id is held, so nothing shows the pid names this child: it is never waited
                // on.
                let Some(identity) = identity else {
                    return (
                        Waited::Unverified,
                        Some("no unique id is held, so nothing shows its pid names it".to_owned()),
                    );
                };
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                wait_reapable(pid, *identity, level)
            }
            #[cfg(windows)]
            ProcSource::Tokio { child, .. } => {
                if !still_ours(child) {
                    return (Waited::Exited, None);
                }
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                (wait_on_handle(child, pid), None)
            }
            #[cfg(windows)]
            ProcSource::Raw(_) => unreachable!("the raw backend tears its own spawn failures down"),
        }
    }

    /// [`wait_and_reap_caused`](ProcSource::wait_and_reap_caused) for an `async fn`, without
    /// blocking: [`reap_on_events`](ProcSource::reap_on_events). What it finds instead of a status
    /// is returned, not acted on or logged: the caller forgets the child and reports it. `Err` when
    /// the exit cannot be watched, so nothing was collected: the caller reaps by other means.
    /// **Never kills.**
    #[cfg(unix)]
    pub(crate) async fn wait_and_reap_awaiting(&mut self) -> Result<(Waited, Option<String>), Error> {
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        #[cfg(test)]
        if super::fault::take_pend_awaited_reap() {
            std::future::pending::<()>().await;
        }
        Ok(match self.reap_on_events().await {
            Ok(_) => (Waited::Exited, None),
            Err(Halt::State(state)) => verdict_of(state),
            Err(Halt::ReapedBetween(why)) => (Waited::Foreign, Some(why)),
            Err(Halt::ReapFailed(e)) => (Waited::Unverified, Some(format!("tokio's try_wait failed: {e}"))),
            Err(Halt::Watch(e)) => return Err(e),
        })
    }

    /// Collect the child's status once it has exited, without blocking. tokio's `try_wait` is a
    /// `waitpid` by pid, so it runs only right after a look through the child's handle shows the
    /// exit, and every attempt has its own look. Between attempts the reap waits for an event on
    /// the handle (see [`event_reap`]): a zombie a foreign tracer holds shows no exit until the
    /// tracer hands it back. A foreign reap between a look and its `try_wait` is not seen: if
    /// another child of ours has taken the number, `try_wait` collects it.
    #[cfg(unix)]
    async fn reap_on_events(&mut self) -> Result<ExitStatus, Halt> {
        #[cfg(target_os = "linux")]
        use crate::wait::exit_only::{self, Target};

        if !matches!(self, ProcSource::Tokio { .. }) {
            return Err(Halt::State(self.state()));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd as _;

            let ProcSource::Tokio { child, pidfd, .. } = self else {
                unreachable!("checked above")
            };
            if child.id().is_none() {
                return collected(child);
            }
            let target = Target::PidFd(pidfd.as_fd());
            let watch = event_reap::PidfdWatch::arm(pidfd.as_fd()).map_err(Halt::Watch)?;
            loop {
                let ready = watch.ready().await.map_err(Halt::Watch)?;
                if let Some(status) = reap_after_look(child, exit_only::peek(&target))? {
                    return Ok(status);
                }
                #[cfg(test)]
                super::fault::run_reap_parked();
                ready.seen();
            }
        }
        #[cfg(target_os = "macos")]
        {
            let ProcSource::Tokio {
                child, pid, identity, ..
            } = self
            else {
                unreachable!("checked above")
            };
            if child.id().is_none() {
                return collected(child);
            }
            let Some(identity) = *identity else {
                return Err(Halt::State(RootState::Unknown(std::io::Error::other(
                    "the child's unique id is unknown, so nothing shows its pid still names it",
                ))));
            };
            look_on_events(*pid, identity, |looked| reap_after_look(child, looked)).await
        }
    }

    /// Block until the child's exit is visible to this process, or until `until`, and say which
    /// came first. For a message only: [`wait_and_reap_caused`](ProcSource::wait_and_reap_caused),
    /// which the caller runs next either way, is the wait that decides. Anything this cannot read
    /// (a failed peek, a child it cannot show to be ours, a foreign reap) answers `true`, and is
    /// left to that wait. On Linux a failed poll is not one of them: the peeks decide, and a child
    /// still running at `until` answers `false`.
    ///
    /// - **Linux:** [`crate::wait::pidfd_exit_visible_by`].
    /// - **macOS:** the verified-id kqueue wait, with `until` as its deadline.
    /// - **Windows:** [`handle_signaled_by`](crate::wait::teardown_warn::handle_signaled_by) on the
    ///   process handle.
    pub(crate) fn exit_visible_by(&self, pid: u32, until: std::time::Instant) -> bool {
        crate::bounded::assert_may_block("exit_visible_by");
        #[cfg(windows)]
        {
            let _ = pid;
            let ProcSource::Tokio { child, .. } = self else {
                return true;
            };
            // `None` once tokio has collected the child: the wait answers at once.
            child.raw_handle().is_none_or(|handle| {
                crate::wait::teardown_warn::handle_signaled_by(windows::Win32::Foundation::HANDLE(handle), until)
            })
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd as _;

            let _ = pid;
            let ProcSource::Tokio { pidfd, .. } = self else {
                return true;
            };
            crate::wait::pidfd_exit_visible_by(pidfd.as_fd(), until)
        }
        #[cfg(target_os = "macos")]
        {
            use crate::wait::macos::{await_reapable, Waited as Awaited};
            let ProcSource::Tokio {
                identity: Some(identity),
                ..
            } = self
            else {
                return true;
            };
            match await_reapable(pid, Some(*identity), Some(until)) {
                Ok(waited) => waited != Awaited::DeadlinePassed,
                Err(e) => {
                    log::debug!("child {pid}: a look at its exit failed ({e}); the wait that follows decides");
                    true
                }
            }
        }
    }

    /// Give up a child something else reaped, or that cannot be shown to be ours
    /// ([`Waited::Foreign`]): tokio's `Child` is forgotten, never dropped, because its drop
    /// would reap by pid, and the pid may name another process by now. The untaken
    /// streams are kept, and the backend is [`reaped`](ProcSource::is_reaped) from here on.
    ///
    /// Forgetting leaks what tokio's `Child` holds — on Linux its pidfd and its reactor
    /// registration, on macOS its `SIGCHLD` watch — so it is logged at `warn`, naming the pid.
    /// Returns what the forget leaks, or `None` if the backend was already forgotten.
    #[cfg(all(unix, test))]
    pub(crate) fn forget_foreign(&mut self) -> Option<&'static str> {
        self.forget_noting(FORGET_FOREIGN, Forgotten::Unproven, &mut Diagnosis::default())
    }

    /// [`forget_foreign`](ProcSource::forget_foreign) for any reason: `why` completes "child N ...",
    /// so the warning says what actually happened. A reap by someone else is not claimed: use
    /// [`forget_as`](ProcSource::forget_as) for a child shown reaped elsewhere.
    #[cfg(target_os = "macos")]
    pub(crate) fn forget_because(&mut self, why: &str) -> Option<&'static str> {
        self.forget_as(why, Forgotten::Unproven)
    }

    /// Whether the backend forgot a child not shown to be ours, which may still run.
    #[cfg(unix)]
    pub(crate) fn forgot_unproven(&self) -> bool {
        matches!(
            self,
            ProcSource::Foreign {
                fate: Forgotten::Unproven,
                ..
            }
        )
    }

    /// The fate recorded by the forgetting; `None` if not forgotten (see `forget_if_foreign`).
    #[cfg(unix)]
    pub(crate) fn forgotten_fate(&self, id: Option<ProcessId>) -> Option<ChildFate> {
        match self {
            ProcSource::Foreign { fate, .. } => Some(if fate.gone() {
                ChildFate::Gone
            } else {
                ChildFate::Running { id }
            }),
            _ => None,
        }
    }

    /// [`forget_because`](ProcSource::forget_because), recording what became of the child.
    #[cfg(unix)]
    pub(crate) fn forget_as(&mut self, why: &str, fate: Forgotten) -> Option<&'static str> {
        self.forget_noting(why, fate, &mut Diagnosis::default())
    }

    /// [`forget_noting`](ProcSource::forget_noting) that logs nothing: the forget is owed to `owed`,
    /// for a caller whose teardown warns next and carries it.
    #[cfg(target_os = "linux")]
    fn forget_deferring(&mut self, why: &str, fate: Forgotten, owed: &mut Diagnosis) -> Option<&'static str> {
        let (pid, leak) = self.forget_quietly(fate)?;
        owed.add(format!(
            "child {pid} {why}; forgetting tokio's handle for it leaks {leak}"
        ));
        Some(leak)
    }

    /// [`forget_as`](ProcSource::forget_as) for a spawn whose identity check found `diagnosis`: the
    /// forget's one warn carries it.
    #[cfg(unix)]
    pub(crate) fn forget_noting(
        &mut self,
        why: &str,
        fate: Forgotten,
        diagnosis: &mut Diagnosis,
    ) -> Option<&'static str> {
        let (pid, leak) = self.forget_quietly(fate)?;
        log::warn!(
            "{}",
            diagnosis.fold(format!(
                "child {pid} {why}; forgetting tokio's handle for it leaks {leak}"
            ))
        );
        Some(leak)
    }

    /// Forget tokio's `Child` without logging, for a caller that reports the forget in its own one
    /// warn. Returns the child's pid and what the forget leaks, or `None` if the backend was
    /// already forgotten (or never held a child): nothing was forgotten, so nothing leaked.
    /// `fate`: what became of the child, as far as the caller knows.
    #[cfg(unix)]
    fn forget_quietly(&mut self, fate: Forgotten) -> Option<(String, &'static str)> {
        let leak = if cfg!(target_os = "linux") {
            "tokio's pidfd and its reactor registration"
        } else {
            "tokio's SIGCHLD watch"
        };
        let ProcSource::Tokio {
            pid,
            stdin,
            stdout,
            stderr,
            #[cfg(target_os = "linux")]
            pidfd,
            ..
        } = self
        else {
            return None;
        };
        let pid = *pid;
        let foreign = ProcSource::Foreign {
            stdin: stdin.take(),
            stdout: stdout.take(),
            stderr: stderr.take(),
            fate,
            pid,
            // Moved, not duplicated: a duplicate can fail at the fd limit.
            #[cfg(target_os = "linux")]
            pidfd: pidfd.hand_off(),
        };
        std::mem::replace(self, foreign).forget();
        #[cfg(test)]
        super::drop_fault::note_forget();
        Some((pid.to_string(), leak))
    }

    /// Forget tokio's `Child` where `view` shows the drop must not leave it to tokio's own drop,
    /// which reaps by pid. One policy for every drop and cleanup, and a quiet one: the caller's one
    /// warn carries what was forgotten.
    /// - a root the view shows reaped is forgotten on that evidence;
    /// - any other only if a second look shows it gone, not pinned, or unanswerable.
    ///
    /// `None` if nothing was forgotten: tokio already reaped the child, it is already forgotten, or
    /// the second look shows it ours.
    #[cfg(unix)]
    pub(crate) fn forget_for(&mut self, view: &crate::containment::DropView) -> Option<Forgot> {
        use crate::containment::dispatch::RootView;
        let now = match view.root {
            RootView::Reaped => {
                if !self.holds_unreaped_child() {
                    return None;
                }
                None
            }
            RootView::Unknown(_) | RootView::Unpinned | RootView::Trusted => Some(self.elsewhere()?.1),
        };
        let fate = now.as_ref().map_or(Forgotten::ReapedElsewhere, Forgotten::of);
        let (_, leak) = self.forget_quietly(fate)?;
        Some(Forgot { leak, now, cause: None })
    }

    /// Forget tokio's `Child` after a wait found it foreign for `cause`, quietly.
    #[cfg(unix)]
    pub(crate) fn forget_for_wait(&mut self, waited: Waited, cause: Option<String>) -> Option<Forgot> {
        let (_, leak) = self.forget_quietly(waited.forgotten()?)?;
        Some(Forgot { leak, now: None, cause })
    }

    /// Whether tokio's `Child` is still held and has not reaped its child.
    #[cfg(unix)]
    fn holds_unreaped_child(&self) -> bool {
        matches!(self, ProcSource::Tokio { child, .. } if child.id().is_some())
    }

    /// [`forget_foreign`](ProcSource::forget_foreign), but only on evidence, for the places that
    /// release the backend without waiting: the handle shows the child reaped elsewhere, not
    /// pinned, or cannot be asked. One warn, naming the error when the handle could not say.
    /// Returns what the forget leaks, if it forgot.
    #[cfg(unix)]
    pub(crate) fn forget_if_foreign(&mut self) -> Option<&'static str> {
        self.forget_if_foreign_noting(&mut Diagnosis::default())
    }

    /// [`forget_if_foreign`](ProcSource::forget_if_foreign) for a spawn whose identity check found
    /// `diagnosis`.
    #[cfg(unix)]
    fn forget_if_foreign_noting(&mut self, diagnosis: &mut Diagnosis) -> Option<&'static str> {
        let (_, state) = self.elsewhere()?;
        self.forget_noting(&foreign_why(&state), Forgotten::of(&state), diagnosis)
    }

    /// [`forget_if_foreign`](ProcSource::forget_if_foreign) without the warn, for a caller whose
    /// one warn carries it: what the forget leaks, why the child was forgotten, and what became of
    /// it (`Gone` if it was shown reaped by someone else or held by launchd, `Running` with `id`, the
    /// child's identity if the caller has read one, if it cannot be shown to be ours).
    #[cfg(unix)]
    fn forget_if_foreign_quietly(&mut self, id: Option<ProcessId>) -> Option<Forgetting> {
        let (_, state) = self.elsewhere()?;
        let (_, leak) = self.forget_quietly(Forgotten::of(&state))?;
        let fate = if Forgotten::of(&state).gone() {
            ChildFate::Gone
        } else {
            ChildFate::Running { id }
        };
        Some(Forgetting {
            leak,
            why: foreign_why(&state),
            fate,
        })
    }

    /// Guaranteed synchronous teardown for a spawn that failed after the fork: kill the child
    /// through its handle (Linux: the pidfd; macOS: the pid, only while it has the child's unique
    /// id; a child with none is neither signalled nor waited on), then block until it has exited. A
    /// child something else reaped, or one that cannot be shown to be ours, is forgotten
    /// ([`forget_foreign`](ProcSource::forget_foreign)) instead, with a warning naming it. The kill
    /// is what bounds the wait, so a caller that has ALREADY killed uses
    /// [`wait_and_reap`](ProcSource::wait_and_reap) instead.
    ///
    /// A refused kill is not waited on here. Linux: the child is torn down again through its pidfd
    /// (another kill, then a reap through the pidfd; a child still running is left, warned) and
    /// tokio's `Child` is forgotten. Elsewhere: a child its handle does not show reaped elsewhere is released to the
    /// runtime's orphan reaper. A child shown reaped elsewhere is forgotten either way. Consumes the
    /// backend, so every path ends in [`release`](ProcSource::release) or
    /// [`forget`](ProcSource::forget). **Invariant:** no `wait()` future for this child is in flight
    /// when this runs.
    ///
    /// `id` is the child's identity, if the spawn had read one.
    #[cfg(any(unix, test))]
    pub(crate) fn reap_now(self, pid: u32, id: Option<ProcessId>) -> ChildFate {
        self.reap_now_noting(pid, id, &mut Diagnosis::default())
    }

    /// [`reap_now`](ProcSource::reap_now) for a spawn whose identity check found `why`: the
    /// teardown's one warn carries it.
    pub(crate) fn reap_now_noting(mut self, pid: u32, id: Option<ProcessId>, why: &mut Diagnosis) -> ChildFate {
        crate::bounded::assert_may_block("reap_now");
        let killed = self.teardown_kill();
        if let Err(e) = &killed {
            return self.after_refused_kill(pid, id, e, why);
        }
        // Only the wait's evidence says the child was reaped elsewhere: a kill that found it gone may
        // have sent nothing at all (a macOS child with no unique id). A child the wait cannot show
        // to be ours is dead or dying if the kill was delivered, and may be running if it was not.
        // The wait logs at `debug`: the forget's one warn carries its cause.
        #[cfg(unix)]
        let (waited, cause) = self.wait_warning(pid, |proc| proc.wait_and_reap_caused(pid, log::Level::Debug));
        #[cfg(not(unix))]
        let waited = self.wait_warning(pid, |proc| proc.wait_and_reap(pid));
        let fate = match waited {
            Waited::Exited => self.collect_exit(id),
            Waited::Unverified => match killed {
                Ok(Sent::Delivered) => ChildFate::Killed,
                _ => ChildFate::Running { id },
            },
            // Reaped elsewhere, or (macOS) a zombie launchd holds.
            _ => Foreign::Gone.fate(matches!(killed, Ok(Sent::Delivered))),
        };
        #[cfg(unix)]
        if let Some(fate) = waited.forgotten() {
            let cause = cause.map_or_else(String::new, |c| format!(" ({c})"));
            self.forget_noting(
                &format!("was reaped by someone else, or cannot be shown to be ours{cause}"),
                fate,
                why,
            );
        }
        self.release();
        fate
    }

    /// macOS: tears down a child whose unique id `unique` arrived only after its spawn returned, and
    /// its tree through `prepared` (see `kill_and_reap_unreported`). Tokio's `Child` is forgotten,
    /// never dropped, because its drop would `waitpid` a number already collected; the event's one
    /// warn says what that leaks. A child its kill did not end (a setuid child refuses the kill) is
    /// released instead, to tokio's orphan reaper, which reaps it once it exits: forgetting it would
    /// leave a zombie nothing collects.
    ///
    /// The wait for the killed child's exit blocks this thread in place, as the spawn's other waits do
    /// (principle 2), on every runtime: tokio's `block_in_place` panics inside a `LocalSet`, even on a
    /// multi-thread runtime, and cannot be asked beforehand. It logs one `warn` naming the child once it
    /// passes [`slow_teardown_after`](super::slow_teardown_after), and goes on waiting.
    /// Consumes the backend. **Invariant:** no `wait()` future for this child is in flight.
    #[cfg(target_os = "macos")]
    pub(crate) fn reap_unreported(
        mut self,
        pid: u32,
        unique: u64,
        prepared: crate::containment::Prepared,
    ) -> ChildFate {
        crate::bounded::assert_may_block("reap_unreported");
        let done = crate::child::spawn::kill_and_reap_unreported(pid, unique, prepared, super::slow_teardown_after());
        if matches!(done.fate, ChildFate::Running { .. }) {
            self.release();
            return done.warn(pid, Some(&format!("it is {HANDED_TO_ORPHAN_REAPER}")));
        }
        let tail = self
            .forget_quietly(Forgotten::Unproven)
            .map(|(_, leak)| format!("forgetting tokio's handle for it leaks {leak}"));
        done.warn(pid, tail.as_deref())
    }

    /// macOS: an elevation front whose id came late is sent nothing: tokio's `Child` is forgotten, and
    /// the event's one warn says so.
    #[cfg(target_os = "macos")]
    pub(crate) fn leave_late_front(mut self, pid: u32) {
        let tail = self
            .forget_quietly(Forgotten::Unproven)
            .map(|(_, leak)| format!("forgetting tokio's handle for it leaks {leak}"));
        crate::child::spawn::warn_late_front(pid, tail.as_deref());
    }

    /// Collects the exit status of a child [`wait_and_reap`](ProcSource::wait_and_reap) saw exit and
    /// showed ours, so that `Reaped` is said of a status that was collected: the wait only
    /// observes the exit, and tokio would otherwise collect it when the backend is released.
    pub(crate) fn collect_exit(&mut self, id: Option<ProcessId>) -> ChildFate {
        #[cfg(test)]
        let pid = self.pid();
        let ProcSource::Tokio { child, .. } = self else {
            unreachable!("only a tokio backend's wait answers `Exited`")
        };
        let looked = child.try_wait();
        // So a test that released its fixture at the kill can assert how the root died.
        #[cfg(test)]
        if let Ok(Some(status)) = &looked {
            crate::child::spawn::fault::record_teardown_reap(pid, *status);
        }
        crate::child::spawn::fate_of_a_look(looked.map_err(|e| e.raw_os_error()), id)
    }

    /// [`reap_now_noting`](ProcSource::reap_now_noting) for an elevation front (see
    /// [`crate::elevation::front`]): it is sent nothing, and tokio's `Child` is forgotten, never
    /// handed to a reaper. A spawn whose identity check found `why`: the forget's one warn carries
    /// it. Answers `error` with what became of the front noted, and the child's fate. **Invariant:** no `wait()` future for this
    /// child is in flight.
    #[cfg(target_os = "linux")]
    pub(crate) fn leave_front_noting(
        mut self,
        pid: u32,
        id: Option<ProcessId>,
        subtree: Option<&crate::containment::cgroup::Subtree>,
        why: &mut Diagnosis,
        error: Error,
        front: crate::elevation::front::Front,
    ) -> (Error, ChildFate) {
        use crate::child::spawn::FrontFate;

        // The forgets are owed to the one warn of the teardown below, not logged on their own. A
        // front reaped elsewhere, or one its handle cannot answer for, is neither signalled nor
        // waited on, as the sync teardown leaves it: the forget's warn goes out when `why` is
        // dropped.
        if let Some((_, state)) = self.elsewhere() {
            self.forget_deferring(&foreign_why(&state), Forgotten::of(&state), why);
            let fate = match state {
                RootState::Unknown(_) => ChildFate::Unknown,
                _ => ChildFate::Gone,
            };
            return (FrontFate::Unaccounted.note(error, Some(front), Some(pid)), fate);
        }
        if !matches!(self, ProcSource::Tokio { .. }) {
            // `elsewhere` answers for every backend but a forgotten one, and a spawn's backend is
            // forgotten only above.
            debug_assert!(
                false,
                "{}: a spawn's backend is forgotten before its teardown",
                crate::elevation::front::front_named(Some(pid))
            );
            return (
                FrontFate::Unaccounted.note(error, Some(front), Some(pid)),
                ChildFate::Unknown,
            );
        }
        self.forget_deferring("is an elevation front, sent nothing", Forgotten::Unproven, why);
        // Nothing is handed back: tokio's `Running` has no `Unreaped` yet.
        let child = OwnedChild::new(Box::new(crate::os_process::linux::LinuxProcess::new(
            Some(pid),
            self.take_forgotten_pidfd(),
        )));
        let how = HeldTeardown {
            front: Some(front),
            id,
            subtree,
            disposition: Disposition::Leave,
            due: Due::in_(super::slow_teardown_after()),
        };
        let (error, fate, _) = tear_down_held(child, how, why, error);
        (error, fate)
    }

    /// Runs `wait` on this backend: a failed spawn's teardown wait for the child `pid` it killed,
    /// which warns once, naming it, if its exit is not visible within
    /// [`slow_teardown_after`](super::slow_teardown_after)
    /// ([`wait_warning`](crate::wait::teardown_warn::wait_warning)).
    pub(crate) fn wait_warning<R>(&mut self, pid: u32, wait: impl FnOnce(&mut Self) -> R) -> R {
        crate::wait::teardown_warn::wait_warning(
            self,
            crate::wait::teardown_warn::Due::in_(super::slow_teardown_after()),
            |proc, until| proc.exit_visible_by(pid, until),
            |after| crate::child::spawn::warn_still_waiting(Some(pid), after),
            wait,
        )
    }

    /// The teardown's kill: [`Sig::Kill`] through the handle, or (tests) the forced refusal of the
    /// seam's "leave it alive" form, which replaces the kill so the child is really left alone.
    fn teardown_kill(&self) -> Result<Sent, Error> {
        #[cfg(test)]
        if let Some((marker, kind)) = crate::child::spawn::fault::take_force_kill_failure() {
            return Err(Error::Io(std::io::Error::new(kind, marker)));
        }
        self.signal(Sig::Kill)
    }

    /// A child whose teardown kill was refused (a setuid child answers `EPERM`) and that is not
    /// shown reaped elsewhere: tokio's `Child` is forgotten, never dropped or released, because
    /// tokio would reap it later with `waitpid(pid)` from its orphan queue, when the number may
    /// name another process. The child goes to the teardown every `OwnedChild` has, through its own
    /// pidfd, moved out of the backend: another kill, then a reap through the pidfd, or, if that kill
    /// is refused too, one look: a child still running is left. Answers what the teardown did, what
    /// the forget leaked, and what the teardown could not do, quietly: the caller's one warn
    /// carries them.
    ///
    /// `forgot`: the refused kill's own look forgot the child just now, so a look on its pidfd
    /// failed, and says why and what leaked. `None`: the look showed the child ours, so the backend
    /// is still tokio's and is forgotten here, or it was forgotten before and holds its pidfd
    /// already.
    #[cfg(target_os = "linux")]
    fn tear_down_forgotten(mut self, pid: u32, id: Option<ProcessId>, forgot: Option<Forgetting>) -> TornDown {
        let (past, leak, why) = match forgot {
            Some(forgot) => (Past::WaitMayFail, Some(forgot.leak), Some(forgot.why)),
            None => match self.forget_quietly(Forgotten::Unproven) {
                Some((_, leak)) => (Past::Clean, Some(leak), None),
                // Forgotten before ([`reap_now`](ProcSource::reap_now) takes any backend): whatever
                // look did it says nothing of a wait on the pidfd, and nothing more leaks.
                None => (Past::WaitMayFail, None, None),
            },
        };
        // The original, moved out: a duplicate could fail at the fd limit and strand the child.
        let torn = tear_down_pidfd(
            Some(pid),
            self.take_forgotten_pidfd(),
            id,
            past,
            Due::in_(super::slow_teardown_after()),
        );
        TornDown { torn, leak, why }
    }

    /// What a refused teardown kill (`e`; a setuid child answers `EPERM`) leaves to do, for
    /// [`reap_now`](ProcSource::reap_now): forget tokio's handle for a
    /// child it shows reaped elsewhere or cannot answer for, since its drop reaps by pid; tear down
    /// again every child not shown gone (Linux: [`tear_down_forgotten`](ProcSource::tear_down_forgotten);
    /// elsewhere: release the rest to tokio's orphan queue); and warn once, with `why`, what became
    /// of it. The child is torn down before the warn and the assertions: a panic from either must
    /// not strand a child that is ours. Consumes the backend, which is a spawn's own, tokio's still.
    #[cfg_attr(not(unix), allow(unused_mut, reason = "only Unix forgets through `&mut self`"))]
    fn after_refused_kill(mut self, pid: u32, id: Option<ProcessId>, e: &Error, why: &mut Diagnosis) -> ChildFate {
        #[cfg(unix)]
        let forgotten = self.forget_if_foreign_quietly(id);
        #[cfg(not(unix))]
        let forgotten: Option<Forgetting> = None;
        let after = match forgotten {
            // Linux tears down every child not shown gone through its pidfd, which pins it whatever
            // the handle can say: one forgotten here included.
            #[cfg(target_os = "linux")]
            Some(forgot) if !matches!(forgot.fate, ChildFate::Gone) => {
                Refused::TornDown(self.tear_down_forgotten(pid, id, Some(forgot)))
            }
            Some(forgotten) => Refused::Forgotten(forgotten),
            #[cfg(target_os = "linux")]
            None => Refused::TornDown(self.tear_down_forgotten(pid, id, None)),
            #[cfg(not(target_os = "linux"))]
            None => {
                self.release();
                Refused::Released
            }
        };
        let line = format!(
            "{}: {}",
            TeardownCaller::FailedSpawn.label(),
            why.fold(refused_kill_warning(pid, e, &after))
        );
        match &after {
            Refused::TornDown(torn_down) => torn_down.torn.warn(Some(&line)),
            _ => log::warn!("{line}"),
        }
        // `EPERM` is a setuid child refusing the kill, reachable without a bug: it alone is not
        // asserted.
        debug_assert!(
            matches!(e, Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied),
            "the teardown kill of an owned child failed: {e}"
        );
        refused_kill_answer(&after, id)
    }

    /// The pidfd of a backend forgotten (by the caller just now, or before), moved out of it for
    /// good: for a caller that consumes the backend. On Linux a backend is `Tokio` or `Foreign`, and
    /// forgetting turns the first into the second, so it holds the pidfd after any forget attempt;
    /// calling this on a `Tokio` backend that was not forgotten is a contract breach.
    #[cfg(target_os = "linux")]
    fn take_forgotten_pidfd(&mut self) -> std::os::fd::OwnedFd {
        let ProcSource::Foreign { pidfd, .. } = self else {
            unreachable!("called on a backend that is not forgotten")
        };
        pidfd.take()
    }

    /// Install the per-instance test wait observer (raw backend only). Panics on a Tokio child —
    /// the observer seam exists solely for the raw async wait path.
    #[cfg(all(test, windows))]
    pub(crate) fn install_wait_observer(
        &mut self,
        started: ::tokio::sync::oneshot::Sender<()>,
        outcome: ::tokio::sync::oneshot::Sender<crate::child::spawn::windows_raw::WaitOutcome>,
    ) {
        match self {
            ProcSource::Raw(r) => r.set_observer(started, outcome),
            ProcSource::Tokio { .. } => panic!("wait observer requires the raw CreateProcessW backend"),
        }
    }
}

/// What became of a child whose teardown kill was refused (a setuid child answers `EPERM`), by
/// `after`: its second teardown's fate, the forgetting's (a child not shown to be ours), or, one
/// released, running. `id` is its identity, if the spawn had read one.
fn refused_kill_answer(after: &Refused, id: Option<ProcessId>) -> ChildFate {
    match after {
        Refused::Forgotten(forgotten) => forgotten.fate,
        Refused::TornDown(torn_down) => torn_down.torn.outcome.fate(),
        Refused::Released => {
            #[cfg(target_os = "linux")]
            debug_assert!(false, "Linux tears every child not shown gone down again");
            ChildFate::Running { id }
        }
    }
}

/// Why [`ProcSource::reap_on_events`] stopped without a status.
#[cfg(unix)]
#[derive(Debug)]
enum Halt {
    /// A look showed the child not this backend's to reap (never `Unreaped`).
    State(RootState),
    /// The `try_wait` right after a look that showed the exit found no record, or `ECHILD`:
    /// something else reaped the child in between. What showed it.
    ReapedBetween(String),
    /// The `try_wait` right after a look that showed the exit failed otherwise.
    ReapFailed(std::io::Error),
    /// The exit cannot be watched; nothing was collected.
    Watch(Error),
}

/// What a wait whose look found `state`, not `Unreaped`, says: the verdict, and why.
#[cfg(unix)]
fn verdict_of(state: RootState) -> (Waited, Option<String>) {
    match state {
        RootState::Unreaped => unreachable!("a wait's look halted on a child its handle shows ours"),
        RootState::Reaped { .. } => (
            Waited::Foreign,
            Some("its handle shows it reaped by someone else".to_owned()),
        ),
        #[cfg(target_os = "macos")]
        RootState::Unpinned => (Waited::Orphaned, Some(crate::signal::UNPINNED_WHY.to_owned())),
        #[cfg(not(target_os = "macos"))]
        RootState::Unpinned => (Waited::Unverified, Some(crate::signal::UNPINNED_WHY.to_owned())),
        RootState::Unknown(e) => (
            Waited::Unverified,
            Some(format!("its handle cannot show it is ours ({e})")),
        ),
    }
}

/// The status tokio already collected.
#[cfg(unix)]
fn collected(child: &mut ::tokio::process::Child) -> Result<ExitStatus, Halt> {
    match child.try_wait() {
        Ok(Some(status)) => Ok(status),
        Ok(None) => unreachable!("tokio answers its collected status once it has reaped"),
        Err(e) => Err(Halt::ReapFailed(e)),
    }
}

/// macOS: the looks of [`ProcSource::reap_on_events`] at `pid`, checked against the unique id
/// `identity`. Each look goes to `on_look`, which ends the reap with `Some` or an error. Between
/// looks it waits on [`event_reap::KqueueWatch`]; a look that finds a tracer holding the child also
/// watches the tracer chain.
#[cfg(target_os = "macos")]
async fn look_on_events<T>(
    pid: u32,
    identity: u64,
    mut on_look: impl FnMut(std::io::Result<crate::os_process::child::PeekOutcome>) -> Result<Option<T>, Halt>,
) -> Result<T, Halt> {
    use crate::wait::exit_only::{self, Target};
    let target = Target::pid(pid, Some(identity));
    let mut watch = event_reap::KqueueWatch::arm(pid).map_err(Halt::Watch)?;
    loop {
        // A `NOTE_REAP` means something else reaped it: no look by its pid may follow.
        if watch.reaped().map_err(Halt::Watch)? {
            return Err(Halt::State(RootState::Reaped { own: false }));
        }
        let (looked, holder) = match exit_only::peek_verified_traced(&target) {
            Ok((peeked, holder)) => (Ok(peeked), holder),
            Err(e) => (Err(e), None),
        };
        if let Some(found) = on_look(looked)? {
            return Ok(found);
        }
        // A tracer whose identity cannot be read leaves the child's state unknown, as a refused peek
        // does. A refused registration leaves it unwatched: the caller waits by other means.
        if let Some(holder) = holder {
            use crate::wait::macos::WalkError;
            match watch.held_by(holder) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(WalkError::Identity(e)) => return Err(Halt::State(RootState::Unknown(e))),
                Err(WalkError::Watch(e)) => return Err(Halt::Watch(Error::Io(e))),
            }
        }
        #[cfg(test)]
        super::fault::run_reap_parked();
        watch.next().await.map_err(Halt::Watch)?;
    }
}

/// Act on one look at the child: on an exit, collect it with tokio's `try_wait` at once; `None`
/// while there is nothing to reap.
#[cfg(unix)]
fn reap_after_look(
    child: &mut ::tokio::process::Child,
    looked: std::io::Result<crate::os_process::child::PeekOutcome>,
) -> Result<Option<ExitStatus>, Halt> {
    use crate::os_process::child::PeekOutcome;
    match looked {
        Ok(PeekOutcome::Exit(_)) => match child.try_wait() {
            Ok(Some(status)) => Ok(Some(status)),
            Ok(None) => Err(Halt::ReapedBetween(
                "waitpid found no exit record after its handle showed one".to_owned(),
            )),
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => Err(Halt::ReapedBetween(
                "waitpid answered ECHILD after its handle showed its exit".to_owned(),
            )),
            Err(e) => Err(Halt::ReapFailed(e)),
        },
        Ok(PeekOutcome::Running) => Ok(None),
        other => Err(Halt::State(RootState::of_peek(other))),
    }
}

/// Whether tokio still holds the child, so its pid is pinned. Once tokio is `Done` (a prior
/// `wait()` reaped it) the pid may be recycled and nothing may wait on it.
fn still_ours(child: &::tokio::process::Child) -> bool {
    let ours = child.id().is_some();
    debug_assert!(
        ours,
        "wait_and_reap found an already-reaped child where one was impossible"
    );
    ours
}

/// Linux: waits until the exit is visible to this process, through the child's own pidfd. What it
/// finds that is not an exit is logged at `level` and returned as the cause.
#[cfg(target_os = "linux")]
fn wait_on_pidfd(pid: u32, pidfd: &std::os::fd::OwnedFd, level: log::Level) -> (Waited, Option<String>) {
    use std::os::fd::AsFd;

    use crate::os_process::child::PeekOutcome;
    use crate::wait::exit_only::{self, Target};

    match exit_only::wait_visible_exit(&Target::PidFd(pidfd.as_fd())) {
        Ok(PeekOutcome::Exit(_record)) => {
            #[cfg(test)]
            if let crate::os_process::child::ExitRecord::Status(status) = _record {
                crate::child::spawn::fault::record_teardown_reap(pid, status);
            }
            (Waited::Exited, None)
        }
        Ok(PeekOutcome::Foreign(_)) => (
            Waited::Foreign,
            Some("waitid on its pidfd found it reaped by someone else (ECHILD)".to_owned()),
        ),
        // A blocking wait that returns without an exit is a contract breach, like an errno that
        // is not `ECHILD`. Without proof the child is ours, tokio's by-pid reap must not run.
        Ok(PeekOutcome::Running) => {
            log::log!(
                level,
                "wait_and_reap: waitid on child {pid}'s pidfd returned without an exit"
            );
            debug_assert!(false, "a blocking waitid on a pidfd returned without an exit");
            (
                Waited::Unverified,
                Some("waitid on its pidfd returned without an exit".to_owned()),
            )
        }
        Err(e) => {
            log::log!(level, "wait_and_reap: waitid on child {pid}'s pidfd failed: {e}");
            debug_assert!(false, "waitid on a child's own pidfd failed: {e}");
            (Waited::Unverified, Some(format!("waitid on its pidfd failed: {e}")))
        }
    }
}

/// macOS: waits, through the same verified-id wait the sync child uses, until the child is a zombie
/// this process can reap. It never reaps: tokio's field-drop does. A child a tracer holds answers
/// `ECHILD` to `waitid` and is still running, so the wait goes on until the tracer hands it back.
/// A foreign reap is [`Waited::Foreign`]; anything else that cannot be shown to be ours is
/// [`Waited::Unverified`] (see [`ProcSource::wait_and_reap`]), logged at `level` and returned as the
/// cause.
#[cfg(target_os = "macos")]
fn wait_reapable(pid: u32, identity: u64, level: log::Level) -> (Waited, Option<String>) {
    use crate::wait::macos::{await_reapable, Waited as Awaited};
    match await_reapable(pid, Some(identity), None) {
        Ok(Awaited::Reapable) => {
            #[cfg(test)]
            if let Ok(crate::os_process::child::PeekOutcome::Exit(crate::os_process::child::ExitRecord::Status(
                status,
            ))) = crate::wait::exit_only::peek(&crate::wait::exit_only::Target::pid(pid, Some(identity)))
            {
                crate::child::spawn::fault::record_teardown_reap(pid, status);
            }
            (Waited::Exited, None)
        }
        Ok(Awaited::Gone) => (
            Waited::Foreign,
            Some("its pid is gone, or names another process".to_owned()),
        ),
        // Exited, and not ours to reap, like a foreign reap.
        Ok(Awaited::Orphaned) => {
            log::log!(
                level,
                "wait_and_reap: child {pid} is not ours to reap (launchd holds its zombie, because its tracer died)"
            );
            (Waited::Orphaned, Some(crate::signal::UNPINNED_WHY.to_owned()))
        }
        // Unbounded, so the deadline cannot pass: a contract breach.
        Ok(Awaited::DeadlinePassed) => {
            log::log!(
                level,
                "wait_and_reap: the unbounded wait on child {pid} reported a passed deadline"
            );
            debug_assert!(false, "an unbounded wait reported a passed deadline");
            (
                Waited::Unverified,
                Some("the unbounded wait reported a passed deadline".to_owned()),
            )
        }
        // Without proof the child is ours, tokio's by-pid reap must not run.
        Err(e) => {
            log::log!(level, "wait_and_reap: waiting on child {pid} failed: {e}");
            (Waited::Unverified, Some(format!("waiting on it failed: {e}")))
        }
    }
}

/// Windows: hard-kill the not-yet-reaped child whose live process handle is `h`, through
/// [`windows_terminate_held`](crate::identity::windows_terminate_held), `granted` the access it holds.
/// Never blocks.
#[cfg(windows)]
pub(super) fn terminate_unreaped(
    h: windows::Win32::Foundation::HANDLE,
    granted: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
) -> Result<Sent, Error> {
    use crate::identity::{windows_terminate_held, Termination};
    // `h` is a live process handle the caller owns.
    match windows_terminate_held(h, granted) {
        Termination::Terminated | Termination::Exited => Ok(Sent::Delivered),
        Termination::Failed(e) => Err(Error::Io(crate::error::win32_io_error(e))),
    }
}

/// Windows: waits on tokio's process handle, which pins the child.
#[cfg(windows)]
fn wait_on_handle(child: &::tokio::process::Child, pid: u32) -> Waited {
    let h = child.raw_handle().expect("tokio owns the handle while id() is Some");
    // Tests: a wait on a handle that cannot be waited on, made to fail without being made.
    #[cfg(test)]
    let forced = super::fault::take_fail_handle_wait();
    #[cfg(not(test))]
    let forced = false;
    let waited = if forced {
        wait_failed(pid, windows::Win32::Foundation::WAIT_FAILED)
    } else {
        // SAFETY: tokio owns and (on its field-drop) closes the handle; we only wait on it.
        wait_for_exit(windows::Win32::Foundation::HANDLE(h), pid)
    };
    debug_assert!(
        forced || matches!(waited, Waited::Exited),
        "wait_and_reap did not observe the child's exit"
    );
    waited
}

/// Windows: blocks until the process `h` names has exited. `Unverified` when the wait fails, as one
/// on a handle without `SYNCHRONIZE` does. INFINITE is bounded by the kill the caller already issued.
///
/// `h` is a live process handle the caller keeps open.
#[cfg(windows)]
pub(super) fn wait_for_exit(h: windows::Win32::Foundation::HANDLE, pid: u32) -> Waited {
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
    // SAFETY: the caller's live process handle.
    let waited = unsafe { WaitForSingleObject(h, INFINITE) };
    if waited != WAIT_OBJECT_0 {
        return wait_failed(pid, waited);
    }
    #[cfg(test)]
    {
        use std::os::windows::process::ExitStatusExt as _;
        let mut code = 0u32;
        // SAFETY: `h` is a live process handle and `code` a valid out-parameter.
        unsafe { windows::Win32::System::Threading::GetExitCodeProcess(h, &mut code) }
            .expect("GetExitCodeProcess on an exited child");
        crate::child::spawn::fault::record_teardown_reap(pid, std::process::ExitStatus::from_raw(code));
    }
    Waited::Exited
}

#[cfg(windows)]
fn wait_failed(pid: u32, waited: windows::Win32::Foundation::WAIT_EVENT) -> Waited {
    log::warn!("wait_and_reap: the wait on child {pid}'s handle failed: {waited:?}");
    Waited::Unverified
}

#[cfg(unix)]
#[path = "proc_source/event_reap.rs"]
mod event_reap;

#[cfg(test)]
#[path = "proc_source_tests.rs"]
mod proc_source_tests;
