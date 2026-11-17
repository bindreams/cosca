//! [`StopTarget`]: what a stop action acts on, and the record a prepared send leaves for the call
//! that ran the action.

use std::sync::Mutex;
use std::time::Duration;

use crate::child::Child;
use crate::containment::treewalk::WalkToken;
use crate::containment::{Root, TerminateOutcome, TreeStop};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::signal::Sig;

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

/// What the last prepared send of a call on the root did, for the call to go on from.
pub(crate) enum RootRecord {
    /// The send went out; the stop it sent, by name (`TreeStop::name`). The lone shutdown words what a
    /// refused kill after it says was sent from this.
    Sent(&'static str),
    /// The send was refused: the error's report, for the call to log if the action goes on regardless.
    Refused(String),
}

/// What the last prepared send of a call on the tree did, for the call to go on from.
pub(crate) enum TreeRecord {
    /// A send to the tree went out, or found nothing to send: the grace, the sweep and the reap follow.
    /// `earlier` names what the sweep's error says was sent before it; `walk` is the token of this
    /// call's complete walk, which the sweep may stand on.
    Sent {
        earlier: Option<String>,
        walk: Option<WalkToken>,
    },
    /// The send was refused, or found nothing that names the tree, and answered an error (its report):
    /// the call ends with it unless the action went on regardless.
    NotSent(String),
    /// Linux: the root is reachable only through its pidfd, and the signal went to it through it (the
    /// answer of that send); the call waits the grace, and kills through the pidfd if the root outlived
    /// it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only Linux has a pidfd"))]
    RootThroughPidfd(crate::containment::Skip, Result<crate::signal::Sent, Error>, Sig),
    /// macOS: an fd marker's holders alone were sent the signal; the call waits the grace and kills any
    /// left.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "only a Unix mechanism skips by the root's number")
    )]
    HoldersOnly(crate::containment::Skip, Sig),
}

impl TreeRecord {
    /// A send that answered `refusal`.
    fn not_sent(refusal: &Error) -> TreeRecord {
        TreeRecord::NotSent(crate::error::Report(refusal).to_string())
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
        }
    }

    /// The target of the tree call `call`.
    pub(crate) fn tree(child: &'a Child, call: TreeCall<'a>) -> StopTarget<'a> {
        StopTarget {
            child,
            scope: Scope::Tree(call),
            root_record: Mutex::new(None),
            tree_record: Mutex::new(None),
        }
    }

    pub(crate) fn child(&self) -> &'a Child {
        self.child
    }

    pub(crate) fn scope(&self) -> Scope<'a> {
        self.scope
    }

    /// Leaves a send of the stop `name` to the root that went out, or may have, as what the last send
    /// did, whatever it answered: an answer that is an error but cannot say the stop did not arrive
    /// is not a refusal.
    pub(crate) fn note_root_went_out(&self, name: &'static str) {
        debug_assert!(!self.covers_tree(), "a tree target records its sends as tree records");
        *lock(&self.root_record) = Some(RootRecord::Sent(name));
    }

    /// Leaves a send that was refused (a rule's refusal, or an early refusal of a prepared function) as
    /// what the last send did, for either kind of target.
    pub(crate) fn note_refused(&self, refusal: &Error) {
        match self.scope {
            Scope::Root => {
                *lock(&self.root_record) = Some(RootRecord::Refused(crate::error::Report(refusal).to_string()));
            }
            Scope::Tree(_) => self.note_tree(TreeRecord::not_sent(refusal)),
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
    /// over, whichever comes first. `Duration::ZERO` is one look.
    pub fn wait_exit(&self, grace: Duration) -> Result<bool, Error> {
        self.child.proc.exited_by(crate::wait::deadline_from(grace))
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
        let console = self.child.console;
        console.group && !console.own_console_flags && console.caller_had_console
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
    /// in front of the route.
    fn signal_only_answer(&self, outcome: TerminateOutcome, #[cfg(unix)] sig: Sig) -> Result<(), Error> {
        match outcome {
            TerminateOutcome::Sent { result, .. } => result,
            TerminateOutcome::NotSent(not_sent) | TerminateOutcome::RootExited(not_sent) => Err(not_sent),
            // A signal settles nothing, so nothing is killed again and nothing waited for.
            #[cfg(unix)]
            TerminateOutcome::End(skip) | TerminateOutcome::HoldersOnly(skip) => {
                let call = self.child.skip_call("terminate_tree", sig, None);
                call.answer(&self.child.tree, skip, None).answer
            }
            #[cfg(unix)]
            TerminateOutcome::RootThroughPidfd(skip) => {
                let call = self.child.skip_call("terminate_tree", sig, None);
                let sent = self.child.proc.signal(sig);
                call.answer(&self.child.tree, skip, Some(sent)).answer
            }
            #[cfg(not(unix))]
            TerminateOutcome::End(_) | TerminateOutcome::HoldersOnly(_) | TerminateOutcome::RootThroughPidfd(_) => {
                unreachable!("only a Unix mechanism skips by the root's number")
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
                self.note_tree(TreeRecord::Sent { earlier, walk });
                result
            }
            TerminateOutcome::NotSent(not_sent) => {
                self.note_tree(TreeRecord::not_sent(&not_sent));
                Err(not_sent)
            }
            TerminateOutcome::RootExited(exited) => {
                log::debug!(
                    "graceful_shutdown_tree({}): sent no {name}: {report}",
                    self.child.pid(),
                    report = crate::error::Report(&exited)
                );
                self.note_tree(TreeRecord::Sent {
                    earlier: None,
                    walk: None,
                });
                Ok(())
            }
            // `Err`: nothing sent. `Ok`: the tree was already killed.
            #[cfg(unix)]
            TerminateOutcome::End(skip) => {
                let call = self.child.skip_call("graceful_shutdown_tree", sig, None);
                let answer = call.answer(&self.child.tree, skip, None).answer;
                self.note_tree(match &answer {
                    Ok(()) => TreeRecord::Sent {
                        earlier: None,
                        walk: None,
                    },
                    Err(refusal) => TreeRecord::not_sent(refusal),
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
                self.note_tree(TreeRecord::Sent {
                    earlier: None,
                    walk: None,
                });
                // The holders' signal was sent: a failure of it is the call's.
                skip.holders.take().unwrap_or(Ok(()))
            }
            #[cfg(unix)]
            TerminateOutcome::HoldersOnly(skip) => {
                self.note_tree(TreeRecord::HoldersOnly(skip, sig));
                Ok(())
            }
            #[cfg(not(unix))]
            TerminateOutcome::End(_) | TerminateOutcome::RootThroughPidfd(_) | TerminateOutcome::HoldersOnly(_) => {
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

impl std::fmt::Debug for StopTarget<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StopTarget")
            .field("pid", &self.pid())
            .field("covers_tree", &self.covers_tree())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod target_tests;
