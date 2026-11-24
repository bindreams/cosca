//! [`StopTarget`]: what a stop action acts on, and the record a prepared send leaves for the call
//! that ran the action.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::child::Child;
use crate::containment::treewalk::WalkToken;
use crate::containment::{Root, SendAnswer, TerminateOutcome, TreeStop, UnsentKind};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::signal::Sig;
use crate::stop::{SendOutcome, StopError, StopWaits};

/// What a stop action acts on: a child's process, or its whole tree, and what the spawn recorded about
/// the child.
///
/// A [`Child`] hands its stop action a target that stands for the root for [`terminate`] and
/// [`graceful_shutdown`], and one that stands for the contained tree for [`terminate_tree`] and
/// [`graceful_shutdown_tree`] ([`covers_tree`](Self::covers_tree)). The prepared functions of
/// [`stop`](crate::stop) honour the difference; an action of the caller's own reads it.
///
/// A target is the borrow of one call of the child: it is made by the call, or from a child with `From`.
///
/// [`terminate`]: Child::terminate
/// [`graceful_shutdown`]: Child::graceful_shutdown
/// [`terminate_tree`]: Child::terminate_tree
/// [`graceful_shutdown_tree`]: Child::graceful_shutdown_tree
pub struct StopTarget<'a> {
    child: &'a Child,
    scope: Scope<'a>,
    /// What the last prepared send of a call on the root did ([`RootRecord`]), and of a call on the
    /// tree ([`TreeRecord`]); only the cell of the target's scope is ever written. Cells that are
    /// `Sync`, so a shared borrow of the target is `Send` and an action may be written over it
    /// asynchronously.
    root_record: Mutex<Option<RootRecord>>,
    tree_record: Mutex<Option<TreeRecord>>,
    /// When the waits cosca makes inside the call end (`None`: no bound). Only the target reads it: it knows
    /// the deadline's clock.
    deadline: Option<Deadline>,
    /// Whether the call's deadline cut a wait of the action ([`timed_out`](Self::timed_out) sets it). Written while
    /// the action runs, read once it has returned.
    deadline_cut: AtomicBool,
}

/// A call's deadline: the instant its waits end by, and the clock it is read on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline {
    at: Instant,
    clock: ClockKind,
}

/// Which clock a [`Deadline`]'s instant is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClockKind {
    /// The real clock ([`crate::wait::now`]), which a sync call's waits are measured on.
    Real,
    /// Tokio's clock ([`crate::tokio::wait::tokio_now`]), for an async call; OS-timed waits are on the real
    /// clock (see `StopTarget::deadline`).
    #[cfg(feature = "tokio")]
    Tokio,
}

impl ClockKind {
    /// The clock an async wait on a process is measured on: tokio's timer on Unix, and on Windows the OS's own
    /// registered wait, which runs on the real clock.
    #[cfg(feature = "tokio")]
    pub(crate) const ASYNC_PROCESS_WAIT: ClockKind = if cfg!(unix) { ClockKind::Tokio } else { ClockKind::Real };

    /// Now, on this clock.
    fn now(self) -> Instant {
        match self {
            ClockKind::Real => crate::wait::now(),
            #[cfg(feature = "tokio")]
            ClockKind::Tokio => crate::tokio::wait::tokio_now(),
        }
    }
}

impl Deadline {
    /// `timeout` from now on the real clock, for a sync call; `None` (no bound) for one too large for the clock.
    pub(crate) fn real(timeout: Duration) -> Option<Deadline> {
        crate::wait::deadline_from(timeout).map(|at| Deadline {
            at,
            clock: ClockKind::Real,
        })
    }

    /// `timeout` from now on tokio's clock, for an async call; `None` (no bound) for one too large for the clock.
    #[cfg(feature = "tokio")]
    pub(crate) fn tokio(timeout: Duration) -> Option<Deadline> {
        crate::tokio::wait::deadline_from(timeout).map(|at| Deadline {
            at,
            clock: ClockKind::Tokio,
        })
    }

    /// This deadline's instant on `clock`, for a wait measured on it: the instant itself on its own clock,
    /// else what is left now, re-expressed on `clock`. `None` (no bound) for one too large for it.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(unused_variables, reason = "without tokio there is one clock")
    )]
    pub(crate) fn at_on(&self, clock: ClockKind) -> Option<Instant> {
        #[cfg(feature = "tokio")]
        if clock != self.clock {
            return crate::tokio::wait::to_real_clock_at(Some(self.at), self.clock.now(), clock.now());
        }
        Some(self.at)
    }

    /// `grace` from now on this deadline's clock, as a deadline on it; `None` for one too large for the clock.
    fn after(&self, grace: Duration) -> Option<Deadline> {
        crate::wait::deadline_at(self.clock.now(), grace).map(|at| Deadline { at, clock: self.clock })
    }

    /// A wait of up to `grace`, cut to `deadline` (`None`: no bound): the instant it ends by, on the deadline's
    /// own clock, and which bound that is (a tie is the deadline's). `None` with no deadline: the wait is the
    /// grace alone.
    pub(crate) fn cut(deadline: Option<Deadline>, grace: Duration) -> Option<(Deadline, Bound)> {
        let deadline = deadline?;
        Some(match deadline.after(grace) {
            Some(by) if by.at < deadline.at => (by, Bound::Grace),
            _ => (deadline, Bound::Deadline),
        })
    }

    /// The instant a wait of up to `grace` ends by, cut to `deadline` ([`cut`](Self::cut)), on `clock`, for a wait
    /// that arms from an instant on that clock. `None` (no bound) for a grace too large for the clock, with no
    /// deadline.
    pub(crate) fn grace_end(deadline: Option<Deadline>, grace: Duration, clock: ClockKind) -> Option<Instant> {
        match Deadline::cut(deadline, grace) {
            Some((by, _)) => by.at_on(clock),
            None => crate::wait::deadline_at(clock.now(), grace),
        }
    }
}

/// What ends a wait that [`Deadline::cut`] cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bound {
    /// The caller's grace: the wait ending with the root running says the grace is over.
    Grace,
    /// The call's deadline: the wait ending with the root running says the call's timeout ran out.
    Deadline,
}

/// What a [`StopTarget`] stands for.
#[derive(Clone, Copy)]
pub(crate) enum Scope<'a> {
    Root,
    Tree(TreeCall<'a>),
}

/// Which tree call runs the action, which decides what a prepared send answers and records.
#[derive(Clone, Copy)]
pub(crate) enum TreeCall<'a> {
    /// `terminate_tree`: the send is the whole call.
    SignalOnly,
    /// `graceful_shutdown_tree`: the call goes on to wait and sweep from what the send left. The token
    /// is this call's own, which its complete walk's listing is held under.
    Shutdown(&'a WalkToken),
}

/// What the last prepared send of a call on the root did, for the call to go on from, and what
/// `terminate` answers when the action fails ([`outcome`](RootRecord::outcome)). Only a record of a send that
/// went out, or may have, names a stop: a later error says that stop was sent before it.
pub(crate) enum RootRecord {
    /// The stop went out, by name (`TreeStop::name`), which the lone shutdown words what a refused kill after
    /// it says was sent from.
    Sent(&'static str),
    /// The stop may have gone out, and the answer cannot say ([`SendOutcome::Unknown`]).
    #[cfg_attr(
        not(windows),
        allow(dead_code, reason = "only the Windows proxy's answer is unknown")
    )]
    Unknown(&'static str),
    /// Nothing was sent, and the kind says which outcome that is. `Some`: a refusal, with its error's report,
    /// for the call to log if the action goes on regardless. `None`: there was nothing to send to (the root
    /// had exited, or the handle found it gone), which is no refusal.
    NotSent(Option<String>, UnsentKind),
}

/// What the last prepared send of a call on the tree did, for the call to go on from.
pub(crate) enum TreeRecord {
    /// A send to the tree was made, whoever it reached, or found nothing to send: the grace, the sweep and
    /// the reap follow. `earlier` names what the sweep's error says was sent before it; `walk` is the token
    /// of this call's complete walk, which the sweep may stand on. `outcome` is how the send went: `Sent`, or
    /// `Unknown`, or `NotSent` when the call goes on though nothing went out (the send reached no process:
    /// an empty group or leaf, every member gone or refusing it; the root had exited; or the tree was already
    /// killed).
    Sent {
        earlier: Option<String>,
        walk: Option<WalkToken>,
        outcome: SendOutcome,
    },
    /// The send was refused, or found nothing that names the tree, and answered an error (its report):
    /// the call ends with it unless the action went on regardless. The kind says which outcome that is.
    NotSent(String, UnsentKind),
    /// Linux: the root is reachable only through its pidfd, and the signal went to it through it (the
    /// answer of that send); the call waits the grace, and kills through the pidfd if the root outlived
    /// it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only Linux has a pidfd"))]
    RootThroughPidfd(crate::containment::Skip, Result<crate::signal::Sent, Error>, Sig),
    /// macOS: an fd marker's holders alone were sent the signal ([`Skip::outcome`](crate::containment::Skip::outcome) says whether it reached one); the
    /// call waits the grace and kills any left.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix mechanism skips by the root's number")
    )]
    HoldersOnly(crate::containment::Skip, Sig),
}

impl RootRecord {
    /// How the send this record is of went.
    pub(crate) fn outcome(&self) -> SendOutcome {
        match self {
            RootRecord::Sent(_) => SendOutcome::Sent,
            RootRecord::Unknown(_) => SendOutcome::Unknown,
            RootRecord::NotSent(_, kind) => kind.outcome(),
        }
    }
}

/// How a signal sent through a root's handle went: delivered, or not (the root was gone, or the OS refused).
pub(super) fn signal_outcome(sent: &Result<crate::signal::Sent, Error>) -> SendOutcome {
    match sent {
        Ok(crate::signal::Sent::Delivered) => SendOutcome::Sent,
        Ok(_) | Err(_) => SendOutcome::NotSent,
    }
}

impl TreeRecord {
    /// How the send this record is of went.
    pub(crate) fn outcome(&self) -> SendOutcome {
        match self {
            TreeRecord::Sent { outcome, .. } => *outcome,
            TreeRecord::NotSent(_, kind) => kind.outcome(),
            TreeRecord::RootThroughPidfd(_, sent, _) => signal_outcome(sent),
            TreeRecord::HoldersOnly(skip, _) => skip.outcome(),
        }
    }

    /// The record of a send after which the call goes on from nothing the send found (no earlier stop,
    /// no listing), and which went as `outcome`.
    fn bare(outcome: SendOutcome) -> TreeRecord {
        TreeRecord::Sent {
            earlier: None,
            walk: None,
            outcome,
        }
    }

    /// A send that answered `refusal`.
    fn not_sent(refusal: &Error, kind: UnsentKind) -> TreeRecord {
        TreeRecord::NotSent(crate::error::Report(refusal).to_string(), kind)
    }

    /// The record of the send that came to `answer`, for a call that reads only how it went.
    fn of(answer: &SendAnswer) -> TreeRecord {
        TreeRecord::bare(answer.outcome())
    }
}

impl<'a> StopTarget<'a> {
    /// The target of a call on the root alone.
    pub(crate) fn root(child: &'a Child) -> StopTarget<'a> {
        StopTarget {
            child,
            scope: Scope::Root,
            root_record: Mutex::new(None),
            tree_record: Mutex::new(None),
            deadline: None,
            deadline_cut: AtomicBool::new(false),
        }
    }

    /// The target of the tree call `call`.
    pub(crate) fn tree(child: &'a Child, call: TreeCall<'a>) -> StopTarget<'a> {
        StopTarget {
            child,
            scope: Scope::Tree(call),
            root_record: Mutex::new(None),
            tree_record: Mutex::new(None),
            deadline: None,
            deadline_cut: AtomicBool::new(false),
        }
    }

    /// This target, with the waits cosca makes inside its call ending by `deadline` (`None`: no bound).
    pub(crate) fn with_deadline(mut self, deadline: Option<Deadline>) -> StopTarget<'a> {
        self.deadline = deadline;
        self
    }

    /// Windows: the call's deadline on the real clock, for the proxy's wait, which the OS measures on it.
    /// `None`: no bound, or one too large for the clock (a tokio-clock deadline that cannot be re-expressed
    /// on the real clock).
    #[cfg(windows)]
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline?.at_on(ClockKind::Real)
    }

    /// Windows: whether the call's deadline has passed, now on its own clock, for the refusal before a proxy
    /// start.
    #[cfg(windows)]
    pub(crate) fn deadline_passed(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| deadline.clock.now() >= deadline.at)
    }

    /// The [`Error::TimedOut`] of a wait of the action that the call's deadline cut, with no source; the target
    /// keeps that the deadline cut it, for a graceful shutdown to go on to the kill
    /// ([`ran_into_deadline`](Self::ran_into_deadline)).
    pub(crate) fn timed_out(&self, detail: String, members: Vec<ProcessId>) -> Error {
        self.deadline_cut.store(true, Ordering::Relaxed);
        Error::TimedOut {
            detail,
            members,
            source: None,
        }
    }

    /// Whether `error`, which the action answered, is the action running into the call's deadline: an
    /// [`Error::TimedOut`] once the deadline has cut one of the action's waits ([`timed_out`](Self::timed_out)),
    /// whichever call of the action made it. The rule is
    /// [`graceful_shutdown_timeout`](Child::graceful_shutdown_timeout)'s.
    pub(crate) fn ran_into_deadline(&self, error: &Error) -> bool {
        matches!(error, Error::TimedOut { .. }) && self.deadline_cut.load(Ordering::Relaxed)
    }

    /// `wait_exit`'s answer for a wait that `bound` ended; [`wait_exit_with`] is its only caller.
    fn exit_answer(&self, exited: bool, bound: Bound) -> Result<bool, Error> {
        match (exited, bound) {
            (true, _) => Ok(true),
            (false, Bound::Grace) => Ok(false),
            (false, Bound::Deadline) => {
                let pid = self.pid();
                Err(self.timed_out(
                    format!("the call was waiting for the child (pid {pid}) to exit"),
                    self.id().into_iter().collect(),
                ))
            }
        }
    }

    pub(crate) fn child(&self) -> &'a Child {
        self.child
    }

    pub(crate) fn scope(&self) -> Scope<'a> {
        self.scope
    }

    /// Leaves a send of the stop `name` to the root that went out as what the last send did, whatever it
    /// answered: an answer that is an error but cannot say the stop did not arrive is not a refusal.
    pub(crate) fn note_root_sent(&self, name: &'static str) {
        self.note_root(RootRecord::Sent(name));
    }

    /// Leaves a send of the stop `name` to the root that may have gone out, and whose answer cannot say, as
    /// what the last send did.
    #[cfg_attr(
        not(windows),
        allow(dead_code, reason = "only the Windows proxy's answer is unknown")
    )]
    pub(crate) fn note_root_unknown(&self, name: &'static str) {
        self.note_root(RootRecord::Unknown(name));
    }

    /// Windows: leaves the stop `name` as a send that may have gone out, for either kind of target, before a
    /// send that may never answer (the proxy's: its future can be dropped while the proxy runs). The send's
    /// end replaces it with what the send came to.
    #[cfg(windows)]
    pub(crate) fn note_may_have_sent(&self, name: &'static str) {
        match self.scope {
            Scope::Root => self.note_root_unknown(name),
            Scope::Tree(_) => self.note_tree(TreeRecord::Sent {
                earlier: Some(crate::containment::earlier_of(name)),
                walk: None,
                outcome: SendOutcome::Unknown,
            }),
        }
    }

    /// Leaves a send that found no root to send to (`NotSent(None)`) as what the last send did: nothing was
    /// sent, no stop is named, and no refusal is reported.
    pub(crate) fn note_root_gone(&self) {
        self.note_root(RootRecord::NotSent(None, UnsentKind::NotSent));
    }

    fn note_root(&self, record: RootRecord) {
        debug_assert!(!self.covers_tree(), "a tree target records its sends as tree records");
        *lock(&self.root_record) = Some(record);
    }

    /// Leaves a send that sent nothing (a rule's refusal, an early refusal of a prepared function, or the
    /// proxy's answer that the child is not yet ready) as what the last send did, for either kind of target.
    /// A call that ends at its send ([`TreeCall::SignalOnly`]) keeps only that nothing was sent: only a call
    /// that goes on from it reads the report.
    pub(crate) fn note_not_sent(&self, refusal: &Error, kind: UnsentKind) {
        match self.scope {
            Scope::Root => self.note_root(RootRecord::NotSent(
                Some(crate::error::Report(refusal).to_string()),
                kind,
            )),
            Scope::Tree(TreeCall::SignalOnly) => self.note_tree(TreeRecord::bare(kind.outcome())),
            Scope::Tree(TreeCall::Shutdown(_)) => self.note_tree(TreeRecord::not_sent(refusal, kind)),
        }
    }

    fn note_tree(&self, record: TreeRecord) {
        debug_assert!(self.covers_tree(), "a root target records its sends as root records");
        *lock(&self.tree_record) = Some(record);
    }

    /// What the last prepared send of a call on the root did; `None` when the action sent none.
    pub(crate) fn into_root_record(self) -> Option<RootRecord> {
        debug_assert!(!self.covers_tree(), "a tree target holds a tree record");
        self.root_record
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What the last prepared send of a call on the tree did; `None` when the action sent none.
    pub(crate) fn into_tree_record(self) -> Option<TreeRecord> {
        debug_assert!(self.covers_tree(), "a root target holds a root record");
        self.tree_record
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What `terminate` or `terminate_tree` answers once the action has returned `acted`: `Ok` as it is, an
    /// error with how the action's last prepared send went. An action that made no prepared send and
    /// failed is [`Unknown`](SendOutcome::Unknown).
    pub(crate) fn into_stop_result(self, acted: Result<(), Error>) -> Result<(), StopError> {
        acted.map_err(|error| {
            let recorded = match self.scope {
                Scope::Root => self.into_root_record().map(|record| record.outcome()),
                Scope::Tree(_) => self.into_tree_record().map(|record| record.outcome()),
            };
            StopError::new(error, recorded.unwrap_or(SendOutcome::Unknown))
        })
    }

    /// The child's pid, as [`Child::pid`].
    pub fn pid(&self) -> u32 {
        self.child.pid()
    }

    /// The child's identity, as [`Child::id`].
    pub fn id(&self) -> Option<ProcessId> {
        self.child.id()
    }

    /// Whether the target stands for the child's whole contained tree (`terminate_tree`,
    /// `graceful_shutdown_tree`) and not for the root alone.
    pub fn covers_tree(&self) -> bool {
        matches!(self.scope, Scope::Tree(_))
    }

    /// Waits up to `grace` for the root to exit, and whether it did, through the child's handle. The
    /// wait reaps nothing: the child's pid stays pinned, and a later wait of the child still gets its
    /// exit status. The same for both kinds of target: a tree target waits for the root too.
    ///
    /// `grace` is the caller's own bound: the wait ends when the root has exited, or when `grace` is
    /// over, whichever comes first, and answers `false` for a root still running then. `Duration::ZERO`
    /// is one look. In a call given a timeout the wait also ends by the call's deadline, and for a root still
    /// running then it answers
    /// [`Error::TimedOut`] (naming the root) instead of `false`: `false` says the grace is over, and it is
    /// not. The grace is the bound only when it is strictly shorter than what is left before the deadline: a
    /// tie is the deadline's. An action that goes on with `?` therefore ends at the deadline, with that
    /// error.
    ///
    /// The error's `members` lists the root when it has an identity ([`id`](Self::id)); a root with none is
    /// not listed, and `detail` names what was waited for, with its pid.
    ///
    /// This blocks the calling thread for up to `grace`. An async action awaits
    /// `cosca::tokio::stop::wait_exit` (feature `tokio`) instead.
    pub fn wait_exit(&self, grace: Duration) -> Result<bool, Error> {
        crate::child::graceful::shutdown::run_ready(wait_exit_with(
            &crate::child::graceful::shutdown::BlockingDriver(self.child),
            self,
            grace,
        ))
    }

    /// Windows: which program a send through the proxy starts, as the child's command set it.
    #[cfg(windows)]
    pub(crate) fn ctrl_proxy(&self) -> &crate::stop::proxy::CtrlProxy {
        &self.child.ctrl_proxy
    }

    /// Windows: whether the spawn recorded that a console event addressed to the child's process
    /// group is delivered from this process: the child was created with the group flag and none of
    /// `DETACHED_PROCESS`, `CREATE_NEW_CONSOLE` and `CREATE_NO_WINDOW`, and this process had a console
    /// when it created it.
    ///
    /// A fact fixed at the child's creation, not a delivery guarantee: a program with a GUI subsystem
    /// never attaches to its creator's console whatever the flags say, and a child may free or attach a
    /// console after it starts. See `stop::send_ctrl_break_to_group`.
    #[cfg(windows)]
    pub fn leads_group_on_our_console(&self) -> bool {
        self.child.console.group && self.created_on_our_console()
    }

    /// Windows: whether the spawn recorded that the child was created on this process's console: none of
    /// `DETACHED_PROCESS`, `CREATE_NEW_CONSOLE` and `CREATE_NO_WINDOW`, and this process had a console when
    /// it created it. A child cosca did not create (a UAC elevation's) records no console, so it was not.
    #[cfg(windows)]
    pub(crate) fn created_on_our_console(&self) -> bool {
        let console = self.child.console;
        !console.own_console_flags && console.caller_had_console
    }

    /// The mechanism's own cooperative route, sent the stop `how`, answering what the tree call that runs
    /// the action answers for the route's outcome, and recording what the call goes on from. The prepared
    /// sends of a tree target are this route with their own stop.
    ///
    /// A send whose outcome only the call can finish (the root through its pidfd, an fd marker's holders)
    /// answers `Ok` and records the outcome for the call. For the outcome where nothing names the tree
    /// the send answers what the call answers for it: an error (nothing was sent, and the call ends), or
    /// `Ok` for a tree this handle already killed.
    pub(crate) fn send_tree(&self, call: TreeCall<'_>, how: TreeStop) -> Result<(), Error> {
        let child = self.child;
        let root_handle = child.proc.hold(child.pid());
        let root: Option<&dyn Root> = Some(&root_handle);
        let token = match call {
            TreeCall::SignalOnly => None,
            TreeCall::Shutdown(token) => Some(token),
        };
        // What the answers read of the stop is taken before the route consumes it.
        let name = how.name();
        #[cfg(unix)]
        let sig = how.sig();
        let (outcome, walk) = child.tree.terminate(child.pid(), root, token, how);
        match call {
            TreeCall::SignalOnly => self.signal_only_answer(
                outcome,
                #[cfg(unix)]
                sig,
            ),
            TreeCall::Shutdown(_) => self.shutdown_answer(
                outcome,
                walk,
                name,
                #[cfg(unix)]
                sig,
            ),
        }
    }

    /// `terminate_tree`'s answer to the route's `outcome`: what the signals reached is all it says, and
    /// nothing is waited for. A send to the root through its pidfd is gated as any send of the action's is,
    /// in front of the route. The record is only what the call reads back for how the send went.
    fn signal_only_answer(&self, outcome: TerminateOutcome, #[cfg(unix)] sig: Sig) -> Result<(), Error> {
        match outcome {
            // A signal settles nothing, so nothing is killed again and nothing waited for.
            #[cfg(unix)]
            TerminateOutcome::End(skip) => {
                let call = self.child.skip_call("terminate_tree", sig, None);
                self.note_tree(TreeRecord::bare(SendOutcome::NotSent));
                call.answer(&self.child.tree, skip, None).answer
            }
            #[cfg(unix)]
            TerminateOutcome::HoldersOnly(skip) => {
                let call = self.child.skip_call("terminate_tree", sig, None);
                self.note_tree(TreeRecord::bare(skip.outcome()));
                call.answer(&self.child.tree, skip, None).answer
            }
            #[cfg(unix)]
            TerminateOutcome::RootThroughPidfd(skip) => {
                let call = self.child.skip_call("terminate_tree", sig, None);
                let sent = self.child.proc.signal(sig);
                self.note_tree(TreeRecord::bare(signal_outcome(&sent)));
                call.answer(&self.child.tree, skip, Some(sent)).answer
            }
            #[cfg(not(unix))]
            TerminateOutcome::End(_) | TerminateOutcome::HoldersOnly(..) | TerminateOutcome::RootThroughPidfd(_) => {
                unreachable!("only a Unix mechanism skips by the root's number")
            }
            sent => {
                let answer = sent.into_answer();
                self.note_tree(TreeRecord::of(&answer));
                answer.into_tree_result()
            }
        }
    }

    /// `graceful_shutdown_tree`'s answer to the route's `outcome`: what the signal did, as the call
    /// that goes on to wait and sweep reads it, and the record it goes on from.
    fn shutdown_answer(
        &self,
        outcome: TerminateOutcome,
        walk: Option<WalkToken>,
        name: &str,
        #[cfg(unix)] sig: Sig,
    ) -> Result<(), Error> {
        match outcome {
            TerminateOutcome::Sent { result, earlier } => {
                self.note_tree(TreeRecord::Sent {
                    earlier,
                    walk,
                    outcome: SendOutcome::Sent,
                });
                result
            }
            // The send may have gone out: the call goes on to the grace and the sweep with the error as
            // its cooperative error, as for one that did.
            TerminateOutcome::Unknown { error, earlier } => {
                self.note_tree(TreeRecord::Sent {
                    earlier,
                    walk,
                    outcome: SendOutcome::Unknown,
                });
                Err(error)
            }
            // The send went to no process, whatever the check after it found: the call goes on as after a send,
            // and no later error says a stop was sent before it.
            TerminateOutcome::NoneReached { result } => {
                self.note_tree(TreeRecord::Sent {
                    earlier: None,
                    walk,
                    outcome: SendOutcome::NotSent,
                });
                result
            }
            TerminateOutcome::NotSent(not_sent, kind) => {
                self.note_tree(TreeRecord::not_sent(&not_sent, kind));
                Err(not_sent)
            }
            TerminateOutcome::RootExited(exited) => {
                log::debug!(
                    "graceful_shutdown_tree({}): sent no {name}: {report}",
                    self.child.pid(),
                    report = crate::error::Report(&exited)
                );
                self.note_tree(TreeRecord::bare(SendOutcome::NotSent));
                Ok(())
            }
            // `Err`: nothing sent. `Ok`: the tree was already killed, and nothing was sent either.
            #[cfg(unix)]
            TerminateOutcome::End(skip) => {
                let call = self.child.skip_call("graceful_shutdown_tree", sig, None);
                let answer = call.answer(&self.child.tree, skip, None).answer;
                self.note_tree(match &answer {
                    Ok(()) => TreeRecord::bare(SendOutcome::NotSent),
                    Err(refusal) => TreeRecord::not_sent(refusal, UnsentKind::NotSent),
                });
                answer
            }
            // The root alone, through its pidfd, sent the stop's own signal: the gate in front of every
            // send of the action has let it through.
            #[cfg(target_os = "linux")]
            TerminateOutcome::RootThroughPidfd(skip) => {
                self.note_tree(TreeRecord::RootThroughPidfd(skip, self.child.proc.signal(sig), sig));
                Ok(())
            }
            #[cfg(all(unix, not(target_os = "linux")))]
            TerminateOutcome::RootThroughPidfd(_) => unreachable!("only a Linux pidfd names the root exactly"),
            // A tree this handle already killed leaves nothing for the grace and the kill of the holders
            // to do: the sweep that follows answers as the tree calls do.
            #[cfg(unix)]
            TerminateOutcome::HoldersOnly(mut skip) if skip.is_moot(&self.child.tree) => {
                log::debug!(
                    "graceful_shutdown_tree({}): this handle already killed the tree, so the holders' grace is skipped",
                    self.child.pid()
                );
                self.note_tree(TreeRecord::bare(skip.outcome()));
                // The holders' signal was sent: a failure of it is the call's.
                skip.holders.take().unwrap_or(Ok(()))
            }
            #[cfg(unix)]
            TerminateOutcome::HoldersOnly(skip) => {
                self.note_tree(TreeRecord::HoldersOnly(skip, sig));
                Ok(())
            }
            #[cfg(not(unix))]
            TerminateOutcome::End(_) | TerminateOutcome::RootThroughPidfd(_) | TerminateOutcome::HoldersOnly(..) => {
                unreachable!("only a Unix mechanism skips by the root's number")
            }
        }
    }
}

fn lock<T>(cell: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<'a> From<&'a Child> for StopTarget<'a> {
    /// The target that stands for `child`'s root, for a prepared function to be called on its own.
    fn from(child: &'a Child) -> StopTarget<'a> {
        StopTarget::root(child)
    }
}

#[cfg(feature = "tokio")]
impl<'a> From<&'a crate::tokio::Child> for StopTarget<'a> {
    /// The target that stands for `child`'s root, for a prepared function to be called on its own.
    fn from(child: &'a crate::tokio::Child) -> StopTarget<'a> {
        StopTarget::root(&child.inner)
    }
}

impl std::fmt::Debug for StopTarget<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StopTarget")
            .field("pid", &self.pid())
            .field("covers_tree", &self.covers_tree())
            .finish_non_exhaustive()
    }
}

/// The one body of [`StopTarget::wait_exit`], shared by the blocking and the awaiting driver.
pub(crate) async fn wait_exit_with<D: StopWaits>(
    driver: &D,
    target: &StopTarget<'_>,
    grace: Duration,
) -> Result<bool, Error> {
    let (exited, bound) = root_exited_within(driver, target.deadline, grace).await?;
    target.exit_answer(exited, bound)
}

/// Whether the root has exited within `grace`, a wait cut to `deadline` ([`Deadline::cut`]), and which bound
/// ended the wait: the one wait of the root's exit that `wait_exit` and the graceful shutdowns' grace share.
pub(crate) async fn root_exited_within<D: StopWaits>(
    driver: &D,
    deadline: Option<Deadline>,
    grace: Duration,
) -> Result<(bool, Bound), Error> {
    let cut = Deadline::cut(deadline, grace);
    let exited = match cut {
        Some((by, _)) => driver.root_exited_by(by).await?,
        None => driver.root_exited(grace).await?,
    };
    Ok((exited, cut.map_or(Bound::Grace, |(_, bound)| bound)))
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod target_tests;
