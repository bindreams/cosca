//! Signalling a child whose tracked process an elevation wrapper chose: a *front*.
//!
//! `sudo` and `doas` without a pty, and macOS `osascript`, leave cosca tracking a process that runs
//! as the caller and outlives the elevated program it launched. A `SIGKILL` to that front is
//! allowed, and orphans the program instead of ending it. With direct exec (`!use_pty`,
//! `!pam_session`, or doas without PAM) the tracked process is the root program itself, whose
//! signal is refused. Which of the two cosca holds is not known at spawn.
//!
//! So a forced kill never signals a live front. It goes through a cgroup whose `cgroup.kill`
//! reaches the tracked process whatever its credentials, and nothing is signalled after it. Whether
//! the kill reached the tracked process is read after the write ([`cgroup_kill_reached`]): a front
//! that left the cgroup in between was not killed. Without a cgroup, nothing is sent and the answer
//! is `Unkillable`.
//!
//! Left alone, a wrapper front exits only after its program, so `wait()` returns once the program
//! is gone. A cgroup kill is asynchronous, though: `wait()` then returns once the front is reaped,
//! and a program stuck in uninterruptible sleep can outlive it. Only `wait_tree()` observes the
//! program's own end.
//!
//! A `SIGTERM` is gated only for osascript, which would end and leave the program running, so
//! `terminate()` on it is refused like a kill. A sudo or doas front relays it to the program; with
//! direct exec the tracked process is the root program itself, which refuses it (`EPERM`).
//!
//! pkexec, a UAC child and an already-elevated child track the program itself and are signalled
//! like any child.

use std::io;

use crate::child::owned::teardown::Reach;
use crate::child::owned::OwnedChild;
use crate::error::{ElevationErrorKind, Error, Failures};
use crate::os_process::child::PeekOutcome;
use crate::signal::{Sent, Sig};

/// How a message names the elevation front `pid` (`None`: not known).
pub(crate) fn front_named(pid: Option<u32>) -> String {
    pid.map_or_else(
        || "the elevation front (pid unknown)".to_owned(),
        |pid| format!("elevation front pid {pid}"),
    )
}

/// Who the process an [`OwnedChild`] tracks is, as the spawn left it. The box holds it, and its
/// [`kill_root`](OwnedChild::kill_root) and [`terminate_by`](OwnedChild::terminate_by) apply the
/// rule this module states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrackedKind {
    /// This process's own child: a plain spawn, an already-elevated parent's child.
    Own,
    /// The program, running as another user (pkexec, UAC): a refused signal is `Unkillable`.
    AnotherUser,
    /// A front (sudo, doas, osascript): a wrapper that may outlive the program.
    Front(Front),
}

impl TrackedKind {
    /// The front this is, for the wording of a message and for the paths that end a child without
    /// a box. No kill is decided from it.
    pub(crate) fn front(self) -> Option<Front> {
        match self {
            TrackedKind::Front(front) => Some(front),
            TrackedKind::Own | TrackedKind::AnotherUser => None,
        }
    }

    /// Whether a signal to the tracked process may be refused because it runs as another user, so
    /// the refusal is `Unkillable`: the program (pkexec, UAC), or a front that may be the program
    /// itself (direct exec).
    fn runs_as_another_user(self) -> bool {
        match self {
            TrackedKind::Own => false,
            TrackedKind::AnotherUser => true,
            TrackedKind::Front(front) => front.may_be_the_program(),
        }
    }

    /// A refused signal to the tracked process, as the error the caller gets: `EPERM` (POSIX) and
    /// `ACCESS_DENIED` (Windows) both read `PermissionDenied`; anything else stays `Io`.
    fn refusal(self, err: io::Error) -> Error {
        if self.runs_as_another_user() && err.kind() == io::ErrorKind::PermissionDenied {
            Error::Elevation {
                kind: ElevationErrorKind::Unkillable,
                detail: "could not signal the elevated child".into(),
                source: Some(Error::io_cause(err)),
            }
        } else {
            Error::Io(err)
        }
    }
}

/// What the root is when the rule lets its own kill follow the caller's step
/// ([`OwnedChild::kill_root`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillNeed {
    /// Not a front: its kill is sent as any child's.
    ThenRoot,
    /// A front that has exited: a refused kill of it is `Ok`.
    Exited,
}

/// What the caller's step did, for a root the rule leaves to its containment: a live front in a
/// cgroup the containment kill reaches. That kill is then the only kill, and nothing is sent to the
/// root after it ([`OwnedChild::kill_root`]).
pub(crate) enum AloneStep<K, A> {
    /// The containment kill completed (`Ok`) or failed (`Err`, how). The rule reads after it whether
    /// it reached the front.
    Killed { result: Result<(), Error>, carry: K },
    /// No containment kill completed: the rule answers that the front's cgroup was not killed.
    NotKilled(K),
    /// The caller answered: nothing is read or sent.
    Answered(A),
}

/// What the caller's step did, for a root the rule lets its own kill follow ([`KillNeed`]).
pub(crate) enum RootStep<R, A> {
    /// The root's own kill follows.
    ThenRoot(R),
    /// The caller answered, or sends the root's kill itself: nothing is sent.
    Answered(A),
}

/// What [`OwnedChild::kill_root`] came to, by which step it called.
pub(crate) enum KillRootOutcome<K, R, A> {
    /// The rule refused before any step (a live front nothing reaches).
    Refused(Error),
    /// An [`AloneStep`] other than `Answered`, and the rule's read after it: `Ok` if the kill
    /// reached the front, else the refusal.
    Contained { reached: Result<(), Error>, carry: K },
    /// A [`RootStep::ThenRoot`], and the root's own kill's answer.
    Root { sent: Result<Sent, Error>, carry: R },
    /// The step answered: nothing was sent to the root.
    Answered(A),
}

impl OwnedChild {
    /// The forced kill, with the rule applied. `reach` says where a containment kill lands (`None`: no
    /// containment that holds the root): the rule reads it before the kill to choose between a
    /// containment-only kill and a refusal, and after a containment-only kill to read whether it
    /// reached the front. At most one step is called, before anything is sent to the root: `alone`
    /// for a live front in a cgroup (given the front), `then_root` otherwise.
    pub(crate) fn kill_root<K, R, A>(
        &self,
        reach: Option<&dyn Reach>,
        alone: impl FnOnce(Front) -> AloneStep<K, A>,
        then_root: impl FnOnce(KillNeed) -> RootStep<R, A>,
    ) -> KillRootOutcome<K, R, A> {
        let pid = self.pid();
        let placed = || reach.map_or(Ok(false), |reach| reach.would_reach(self));
        let need = match kill_gate(self.tracked_kind().front(), pid, || self.running(), placed) {
            Gate::Closed(refusal) => return KillRootOutcome::Refused(refusal),
            Gate::CgroupOnly(front) => {
                // Nothing is signalled after the cgroup kill: it could only be refused. Whether the
                // kill landed is read through the front's place, not through `Reach::reached`: a front
                // the kill ended and another thread reaped has no place left, and has exited.
                let (reached, carry) = match alone(front) {
                    AloneStep::Answered(answer) => return KillRootOutcome::Answered(answer),
                    AloneStep::Killed { result: Ok(()), carry } => (
                        cgroup_kill_reached(front, pid, || self.running().map(|running| !running), placed),
                        carry,
                    ),
                    AloneStep::Killed { result: Err(e), carry } => (Err(cgroup_kill_failed(front, pid, e)), carry),
                    AloneStep::NotKilled(carry) => (Err(cgroup_not_killed(front, pid)), carry),
                };
                return KillRootOutcome::Contained { reached, carry };
            }
            Gate::Open => KillNeed::ThenRoot,
            Gate::Exited => KillNeed::Exited,
        };
        match then_root(need) {
            RootStep::Answered(answer) => KillRootOutcome::Answered(answer),
            RootStep::ThenRoot(carry) => KillRootOutcome::Root {
                sent: self.send_kill(need == KillNeed::Exited),
                carry,
            },
        }
    }

    /// [`kill_root`](Self::kill_root) for a caller with no containment kill to make: the root's own
    /// kill, unless the rule refuses it. A live front in a cgroup is refused too, for this call kills
    /// through none.
    #[cfg(any(target_os = "linux", not(unix)))]
    pub(crate) fn kill_root_only(&self, reach: Option<&dyn Reach>) -> Result<Sent, Error> {
        let pid = self.pid();
        let killed = self.kill_root(
            reach,
            |front| {
                AloneStep::<std::convert::Infallible, _>::Answered(refused(
                    front,
                    pid,
                    Signal::Kill,
                    Some(Reason::words("this call kills through no cgroup")),
                ))
            },
            |_| RootStep::ThenRoot(()),
        );
        match killed {
            KillRootOutcome::Refused(refusal) | KillRootOutcome::Answered(refusal) => Err(refusal),
            KillRootOutcome::Root { sent, .. } => sent,
            KillRootOutcome::Contained { carry, .. } => match carry {},
        }
    }

    /// A `SIGTERM` sent by the caller's `send` (a group or console signal the box does not hold),
    /// unless the rule refuses it: a live osascript front is refused, and nothing is sent.
    pub(crate) fn terminate_by<T>(&self, send: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        match terminate_gate(self.tracked_kind().front(), self.pid(), || self.running()) {
            Gate::Closed(refusal) => Err(refusal),
            Gate::Open | Gate::Exited => send(),
            Gate::CgroupOnly(_) => {
                debug_assert!(false, "a SIGTERM's gate never leaves a front to a cgroup kill");
                send()
            }
        }
    }

    /// Whether the root runs, read without reaping it.
    fn running(&self) -> io::Result<bool> {
        let peeked = self.peek().map_err(Error::into_io)?;
        Ok(matches!(peeked, PeekOutcome::Running))
    }

    /// The root's own kill through its handle: `Sent::Gone` once it has exited or been reaped, a
    /// refusal mapped as the tracked kind says. An exited front's refusal is `Ok`: an exit is
    /// permanent, so a refused signal to it changes nothing.
    fn send_kill(&self, exited_front: bool) -> Result<Sent, Error> {
        match self.signal(Sig::Kill).map_err(Error::into_io) {
            Ok(sent) => Ok(sent),
            Err(e) if exited_front && e.kind() == io::ErrorKind::PermissionDenied => {
                log::debug!(
                    "the kill of the exited {} was refused ({report})",
                    front_named(self.pid()),
                    report = crate::error::Report(&e)
                );
                Ok(Sent::Delivered)
            }
            Err(e) if exited_front => Err(Error::Io(e)),
            Err(e) => Err(self.tracked_kind().refusal(e)),
        }
    }
}

/// How a signal to a child may go.
#[derive(Debug)]
enum Gate {
    /// Not a front: signal it like any child.
    Open,
    /// A front that has exited. A kill answers `Ok`, as for any exited child, even where the
    /// signal to it would be refused (a root zombie keeps its credentials). `Ok` then means only
    /// that the front has exited: a front something else killed (the OOM killer, or this user) may
    /// have left its program running.
    Exited,
    /// A live front in a cgroup: kill the cgroup, and signal nothing after it.
    CgroupOnly(Front),
    /// A live front that nothing reaches past: send nothing, and answer this `Unkillable`.
    Closed(Error),
}

/// A front, and what a signal to it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Front {
    Sudo,
    Doas,
    Osascript,
}

impl Front {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Front::Sudo => "sudo",
            Front::Doas => "doas",
            Front::Osascript => "osascript",
        }
    }

    /// The tracked process may be the program itself (direct exec), not the wrapper.
    fn may_be_the_program(self) -> bool {
        !matches!(self, Front::Osascript)
    }

    /// A `SIGTERM` to the front reaches the program.
    fn relays_term(self) -> bool {
        !matches!(self, Front::Osascript)
    }
}

/// The gate for a forced kill of the child `pid`, the `front` its spawn launched (if any).
/// `running` reads, without reaping, whether the tracked process still runs; `in_cgroup` whether it
/// is in a cgroup whose kill reaches it. Both are asked only about a front, and `in_cgroup` only
/// about one that may run: one that cannot be read is taken to run. A front `in_cgroup` cannot
/// place is asked `running` again: one that exited meanwhile, and that another thread's `wait`
/// reaped, has no cgroup left to read.
fn kill_gate(
    front: Option<Front>,
    pid: impl Into<Option<u32>>,
    running: impl Fn() -> io::Result<bool>,
    in_cgroup: impl FnOnce() -> Result<bool, Error>,
) -> Gate {
    let pid = pid.into();
    let Some(front) = front else {
        return Gate::Open;
    };
    let mut unread = Unread::new();
    match running() {
        Ok(false) => return Gate::Exited,
        Ok(true) => {}
        Err(e) => unread.push(("whether it had exited could not be read", Error::Io(e))),
    }
    let placed = in_cgroup();
    if !matches!(placed, Ok(true)) && matches!(running(), Ok(false)) {
        return Gate::Exited;
    }
    match placed {
        Ok(true) => Gate::CgroupOnly(front),
        Ok(false) => Gate::Closed(refused(front, pid, Signal::Kill, unread_reason(unread))),
        Err(e) => {
            unread.push(("whether its cgroup kill reaches it could not be read", e));
            Gate::Closed(refused(front, pid, Signal::Kill, unread_reason(unread)))
        }
    }
}

/// Failed reads of a gate.
type Unread = Vec<(&'static str, Error)>;

/// A refusal's reason: its words and, if any, its cause.
struct Reason {
    words: String,
    cause: Option<std::sync::Arc<Error>>,
}

impl Reason {
    fn words(words: impl Into<String>) -> Reason {
        Reason {
            words: words.into(),
            cause: None,
        }
    }
}

/// What the failed reads were of, as the refusal's words, and the reads' errors as its cause: the
/// one failure, or a [`Error::Several`] of them in the order they failed.
fn unread_reason(unread: Unread) -> Option<Reason> {
    let words = unread.iter().map(|(what, _)| *what).collect::<Vec<_>>().join("; ");
    let cause = Failures::collect(unread.into_iter().map(|(_, e)| std::sync::Arc::new(e)))?.into_cause();
    Some(Reason {
        words,
        cause: Some(cause),
    })
}

/// Whether a cgroup kill, just written, reached the tracked process `pid`, the `front` its spawn
/// launched. The kill and a move out of the cgroup are serialised by the kernel (both writes take
/// `cgroup_mutex`), so what holds after the write says which came first:
///
/// - `exited`: it has exited, so nothing of it is left to kill.
/// - `under_leaf`: its cgroup is the leaf or one under it (see `containment::cgroup::Subtree::holds`).
///
/// A front `under_leaf` does not place is asked `exited` again: one the kill ended meanwhile, and
/// that another thread's `wait` reaped, has no cgroup left to read, and has exited.
///
/// A front none of these places in the leaf left it before the kill, as pam_systemd moves sudo into
/// a session scope: it was not killed, and the answer is `Unkillable`, so nothing waits for it. So
/// is one whose place cannot be read: nothing shows the kill reached it. A front killed and then
/// moved before it exited reads the same (see [`Command::contain`](crate::Command::contain)).
fn cgroup_kill_reached(
    front: Front,
    pid: impl Into<Option<u32>>,
    exited: impl Fn() -> io::Result<bool>,
    under_leaf: impl FnOnce() -> Result<bool, Error>,
) -> Result<(), Error> {
    let pid = pid.into();
    let mut unread = Unread::new();
    match exited() {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => unread.push(("whether it had exited could not be read", Error::Io(e))),
    }
    let placed = under_leaf();
    if !matches!(placed, Ok(true)) && matches!(exited(), Ok(true)) {
        return Ok(());
    }
    let why = match placed {
        Ok(true) => return Ok(()),
        Ok(false) => "it reads as having left the cgroup before its kill, which did not reach it".to_owned(),
        Err(e) => {
            unread.push(("its cgroup could not be read", e));
            "nothing shows the cgroup kill reached it".to_owned()
        }
    };
    let reason = match unread_reason(unread) {
        None => Reason::words(why),
        Some(Reason { words, cause }) => Reason {
            words: format!("{why} ({words})"),
            cause,
        },
    };
    Err(refused(front, pid, Signal::Kill, Some(reason)))
}

/// The refusal of a kill of the front `pid` whose cgroup kill failed with `error`: nothing else was
/// sent, since a kill of the front itself would orphan its elevated program.
fn cgroup_kill_failed(front: Front, pid: impl Into<Option<u32>>, error: Error) -> Error {
    let reason = Reason {
        words: "its cgroup kill failed".to_owned(),
        cause: Some(std::sync::Arc::new(error)),
    };
    refused(front, pid, Signal::Kill, Some(reason))
}

/// The refusal alone, without the tree's failure; use [`cgroup_kill_failed`] where the failure is
/// the cause.
fn cgroup_not_killed(front: Front, pid: impl Into<Option<u32>>) -> Error {
    refused(
        front,
        pid,
        Signal::Kill,
        Some(Reason::words("its cgroup was not killed")),
    )
}

/// The gate for a `SIGTERM` to the child `pid`, the `front` its spawn launched (if any): closed only
/// for a live front that does not relay it. `running` is asked only about such a front.
fn terminate_gate(
    front: Option<Front>,
    pid: impl Into<Option<u32>>,
    running: impl FnOnce() -> io::Result<bool>,
) -> Gate {
    let pid = pid.into();
    let Some(front) = front.filter(|f| !f.relays_term()) else {
        return Gate::Open;
    };
    match running() {
        Ok(false) => Gate::Open,
        Ok(true) => Gate::Closed(refused(front, pid, Signal::Term, None)),
        Err(e) => Gate::Closed(refused(
            front,
            pid,
            Signal::Term,
            unread_reason(vec![("whether it had exited could not be read", Error::Io(e))]),
        )),
    }
}

/// What a front's detail names, for the child `pid` (unknown: `None`).
pub(crate) fn describe(front: Front, pid: impl Into<Option<u32>>) -> String {
    let subject = pid
        .into()
        .map_or_else(|| "the spawned child".to_owned(), |pid| format!("pid {pid}"));
    if front.may_be_the_program() {
        format!(
            "{subject} is what {name} left this process tracking: {name} itself, which runs as this user and \
             outlives the elevated program it launched, so a kill would orphan the program, or, with direct exec, \
             the root program itself, whose kill is refused",
            name = front.name()
        )
    } else {
        format!(
            "{subject} is {name}, which runs as this user and outlives the elevated program it launched, so a signal \
             would end {name} and orphan the program",
            name = front.name()
        )
    }
}

#[derive(Clone, Copy)]
enum Signal {
    Kill,
    Term,
}

fn refused(front: Front, pid: impl Into<Option<u32>>, signal: Signal, why: Option<Reason>) -> Error {
    let what = match signal {
        Signal::Kill => "no kill",
        Signal::Term => "no SIGTERM",
    };
    let mut detail = format!("{}; {what} was sent.", describe(front, pid));
    // Only Linux has a cgroup to reach the program through; osascript runs on macOS.
    if matches!(signal, Signal::Kill) && !matches!(front, Front::Osascript) {
        detail.push_str(" Only a cgroup (Linux containment) that holds it reaches the program.");
    }
    let mut source = None;
    if let Some(Reason { words, cause }) = why {
        detail.push_str(&format!(" ({words})"));
        source = cause;
    }
    Error::Elevation {
        kind: ElevationErrorKind::Unkillable,
        detail,
        source,
    }
}

#[cfg(test)]
#[path = "front_tests.rs"]
mod front_tests;
