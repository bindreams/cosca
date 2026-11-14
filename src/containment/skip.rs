//! What a mechanism that names its tree by the root's number did not send, as the mechanism says it
//! ([`Skip`], in the outcome of its kill and of its terminate), and how a tree call words it
//! ([`SkipCall`]).

use crate::containment::root::Refusal;
use crate::error::Error;

/// What a kill or a terminate skipped because the root's number may not name the root.
#[derive(Debug)]
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "only a Unix mechanism skips by the root's number")
)]
pub(crate) struct Skip {
    /// What the skip left undone, as an action ("kill its process group (pgid 7)").
    pub(crate) action: String,
    pub(crate) why: Why,
    /// Linux: the root's handle still reaches the root exactly, so the caller sends the call's signal
    /// to the root alone, through its hold.
    pub(crate) root_alone: bool,
    /// macOS: the sweep by identity a fd marker still makes of its holders, which no reuse of a pid
    /// redirects. `None`: the mechanism has none.
    pub(crate) holders: Option<Result<(), Error>>,
}

#[cfg(unix)]
impl Skip {
    /// Whether this handle's own reap is why the root's pid names no process or cannot be read, and
    /// the handle already killed the tree: there is nothing left for the skip to leave undone.
    pub(crate) fn is_moot(&self, tree: &crate::containment::Tree) -> bool {
        tree.is_killed()
            && matches!(
                &self.why,
                Why::MayNameAnother(Refusal::ReapedPidGone(_) | Refusal::ReapedPidUnread(..), _)
            )
    }

    /// The error of a sweep that skipped what the root's number names: the holders' sweep's own
    /// error when it failed, else `Unassessable`, with the error behind [`why`](Skip::why) as its
    /// `source`, or a peer of the holders' error's own.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS's late sweep skips a root it cannot show ours")
    )]
    pub(crate) fn sweep_error(self) -> Error {
        match self.holders {
            Some(Err(e)) => e.with_peers(self.why.cause()),
            _ => Error::Unassessable {
                detail: format!(
                    "the root could not be shown to be ours, so its tree did not {}",
                    self.action
                ),
                source: self.why.cause(),
            },
        }
    }
}

/// Why the root's number was not used.
#[derive(Debug)]
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "only a Unix mechanism skips by the root's number")
)]
pub(crate) enum Why {
    /// macOS: the root is `Unpinned` or `Unknown`; `why` says which, and `cause` is the error of an
    /// `Unknown`, shared with the state it came from.
    Untrusted {
        why: String,
        cause: Option<std::sync::Arc<std::io::Error>>,
    },
    /// The pid may name another process, for this reason. The second is the errno of the group probe
    /// that failed before it, if one did, raw ([`Refusal::cause_after`]).
    MayNameAnother(Refusal, Option<i32>),
}

#[cfg(unix)]
impl Why {
    /// [`Why::Untrusted`] for `state`, the root's own handle's answer.
    pub(crate) fn untrusted(state: &crate::signal::RootState) -> Why {
        Why::Untrusted {
            why: crate::signal::why_untrusted(state),
            cause: match state {
                crate::signal::RootState::Unknown(e) => Some(std::sync::Arc::clone(e)),
                _ => None,
            },
        }
    }

    /// The error behind this reason, shared ([`crate::error::shared_io`]).
    pub(crate) fn cause(&self) -> Option<std::sync::Arc<Error>> {
        match self {
            Why::Untrusted { cause, .. } => cause.as_ref().map(crate::error::shared_io_cause),
            Why::MayNameAnother(refusal, probe) => refusal.cause_after(*probe),
        }
    }

    /// The one `warn` of a skipped call: `detail`, then the chain of the error behind this reason.
    pub(crate) fn warn(&self, detail: &str) {
        match self.cause() {
            Some(cause) => log::warn!("{detail}: {}", crate::error::Report(&*cause)),
            None => log::warn!("{detail}"),
        }
    }
}

/// What a mechanism's cooperative signal to its tree did, from one look at the root. A tree call that
/// goes on to wait and sweep (`graceful_shutdown_tree`) acts on it.
#[derive(Debug)]
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "only a Unix mechanism skips by the root's number")
)]
pub(crate) enum TerminateOutcome {
    /// The signal went out, as usual or to what names the tree by identity, and `result` is what the
    /// check after it found. `earlier` names what a later sweep's error says was sent before it.
    Sent {
        result: Result<(), Error>,
        earlier: Option<&'static str>,
    },
    /// Nothing was sent: the call ends with this error.
    NotSent(Error),
    /// Nothing was sent: the root has exited and the walk found no member, so its children were
    /// reparented at its exit.
    #[cfg_attr(not(unix), allow(dead_code, reason = "only a Unix walk finds its root exited"))]
    RootExited(Error),
    /// Nothing is sent by the root's number, and nothing else names the tree: the call ends now.
    End(Skip),
    /// Linux: the root's number may name another process, but its handle names it exactly: the caller
    /// shuts the root alone down through the handle, and the call ends.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only Linux has a pidfd"))]
    RootThroughPidfd(Skip),
    /// macOS: an fd marker's holders alone were signalled, by the pipe they hold (the result is in
    /// [`Skip::holders`]): the caller waits the grace and kills any left, and the call ends.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only a macOS fd marker names its tree by identity")
    )]
    HoldersOnly(Skip),
}

impl TerminateOutcome {
    /// The outcome of a send that answered as `sent`: the outer `Err` is a send that did not go out
    /// ([`NotSent`](Self::NotSent)), the `Ok` what the check after the send found
    /// ([`Sent`](Self::Sent)).
    pub(crate) fn of(sent: Result<Result<(), Error>, Error>, earlier: Option<&'static str>) -> TerminateOutcome {
        match sent {
            Ok(result) => TerminateOutcome::Sent { result, earlier },
            Err(not_sent) => TerminateOutcome::NotSent(not_sent),
        }
    }
}

#[cfg(all(test, unix))]
#[path = "skip_tests.rs"]
mod skip_tests;

#[cfg(unix)]
pub(crate) use call::SkipCall;

#[cfg(unix)]
mod call {
    use super::{Skip, Why};
    use crate::containment::dispatch::{Retry, Settled, TreeKillOutcome, TreeSignal, Unkilled};
    use crate::containment::root::Refusal;
    use crate::containment::Tree;
    use crate::error::Error;
    use crate::signal::Sent;
    use std::sync::Arc;

    /// A tree call that skipped what the root's number names: which call (`op`, with `earlier`, what
    /// the same operation sent before it, so an error never claims it sent nothing), on which root
    /// (`pid`), sending which signal.
    pub(crate) struct SkipCall<'a> {
        pub(crate) op: &'a str,
        pub(crate) pid: u32,
        pub(crate) signal: TreeSignal,
        pub(crate) earlier: Option<&'a str>,
    }

    impl SkipCall<'_> {
        /// The call's answer to `skip`: its kill, or its terminate that ended there. A `Kill` is
        /// settled into the handle's state through [`Tree::settle`], the only writer of it, and a
        /// `Term` never is.
        ///
        /// Nothing was sent by the root's number, and what names the tree by identity (a macOS fd
        /// marker's holders) was signalled by the mechanism. `root`: the signal to the root through
        /// its handle, if the caller sent one ([`Skip::root_alone`]). One `warn` names what was
        /// skipped and what was sent. The error is the holders' sweep's, the root signal's, or
        /// `Unassessable`, with each other failure of the call, and the error behind the skip's
        /// reason, below its variant ([`Error::with_peers`]); a root signal that failed with an
        /// [`Error::Io`], a leaf with no slot, goes below the `Unassessable`, after the reason. `Ok`
        /// only after this handle's own reap, when it already killed the tree.
        pub(crate) fn answer(
            &self,
            tree: &Tree,
            skip: Skip,
            root: Option<Result<Sent, Error>>,
        ) -> Settled<Result<(), Error>> {
            let mut skip = match skip {
                Skip {
                    why: Why::Untrusted { why, cause },
                    action,
                    holders,
                    ..
                } => {
                    let error = self.untrusted(&action, &why, cause, holders);
                    return match self.signal {
                        TreeSignal::Kill => tree.settle_for_kill_tree(
                            TreeKillOutcome::Ran(Err(Unkilled::from(error))),
                            false,
                            Retry::Follows,
                        ),
                        TreeSignal::Term => Settled::of(Err(error)),
                    };
                }
                skip => skip,
            };
            let Why::MayNameAnother(refusal, _) = &skip.why else {
                unreachable!("an untrusted skip is answered above")
            };
            if skip.is_moot(tree) {
                log::debug!(
                    "{}({}): {refusal}, and this handle already killed the tree, so it does not {}",
                    self.op,
                    self.pid,
                    skip.action,
                    refusal = crate::error::Report(refusal)
                );
                return match self.signal {
                    TreeSignal::Kill => {
                        tree.settle_for_kill_tree(TreeKillOutcome::Skipped(skip), false, Retry::Follows)
                    }
                    TreeSignal::Term => Settled::of(skip.holders.take().unwrap_or(Ok(()))),
                };
            }
            let (sent_root, failed_root) = match self.signal {
                TreeSignal::Kill => (
                    "killed the root through its pidfd, which names it exactly, and sent nothing else",
                    "the kill of the root",
                ),
                TreeSignal::Term => (
                    "sent the SIGTERM to the root through its pidfd, which names it exactly, and sent nothing else",
                    "the SIGTERM to the root",
                ),
            };
            // The warn says each failure in full; the returned `Unassessable` says only that it
            // failed, for the failure is a peer or a cause of the answer.
            let sent = |with_errors: bool| match (&skip.holders, &root) {
                (Some(Ok(())), _) => "signalled only the marker holders".to_owned(),
                (Some(Err(e)), _) if with_errors => format!(
                    "signalled only the marker holders, which failed ({})",
                    crate::error::Report(e)
                ),
                (Some(Err(_)), _) => "signalled only the marker holders, which failed".to_owned(),
                (None, None) => "sent nothing".to_owned(),
                (None, Some(Ok(Sent::Delivered))) => sent_root.to_owned(),
                (None, Some(Ok(Sent::Gone))) => "sent nothing: the root's pidfd shows it is gone".to_owned(),
                (None, Some(Ok(_))) => "sent nothing: the root's handle no longer reaches it".to_owned(),
                (None, Some(Err(e))) if with_errors => format!(
                    "sent nothing: {failed_root} through its pidfd failed ({})",
                    crate::error::Report(e)
                ),
                (None, Some(Err(_))) => format!("sent nothing: {failed_root} through its pidfd failed"),
            };
            let detail = self.skipped_detail(&skip, &sent(false));
            let cause = skip.why.cause();
            skip.why.warn(&self.skipped_detail(&skip, &sent(true)));
            let swept = skip.holders.is_some();
            let mut killed_again = Vec::new();
            let holders = match self.signal {
                TreeSignal::Kill => {
                    let settled = tree.settle_for_kill_tree(TreeKillOutcome::Skipped(skip), false, Retry::Follows);
                    killed_again = settled.killed_again;
                    let settled = settled.answer;
                    debug_assert!(
                        swept || settled.is_ok(),
                        "a skipped kill that swept nothing leaves nothing to report: {settled:?}"
                    );
                    swept.then_some(settled)
                }
                TreeSignal::Term => skip.holders.take(),
            };
            // The other failures of the call join the one it returns, and the warn above still says
            // each in one line.
            let answer = match (holders, root.and_then(Result::err)) {
                (Some(Err(held)), root) => held.with_peers(root.map(Arc::new).into_iter().chain(cause)),
                // An `Io` is a leaf with no slot: it goes below the call's `Unassessable`.
                (None, Some(root)) => root.with_peers_or_unassessable(|| detail, cause, []),
                (_, root) => Error::Unassessable { detail, source: cause }.with_peers(root.map(Arc::new)),
            };
            Settled {
                answer: Err(answer),
                killed_again,
            }
        }

        /// The error of a call that skipped what the root's number names, `skipped`, because the root
        /// is `Unpinned` or `Unknown` (macOS), `why`, with the error of an `Unknown` as `cause`: no
        /// `warn`, only a debug line when holders were signalled.
        fn untrusted(
            &self,
            skipped: &str,
            why: &str,
            cause: Option<std::sync::Arc<std::io::Error>>,
            holders: Option<Result<(), Error>>,
        ) -> Error {
            let (root_pid, op) = (self.pid, self.op);
            let earlier = self
                .earlier
                .map_or_else(String::new, |sent| format!(", though {sent} was sent before it"));
            let said = cause.as_ref().map_or_else(
                || why.to_owned(),
                |cause| format!("{why}: {}", crate::error::Report(&**cause)),
            );
            let unassessable = |sent: &str, because: &str| Error::Unassessable {
                detail: format!("pid {root_pid}: {why}; {op} {sent}{earlier}: {because}it did not {skipped}"),
                source: cause.as_ref().map(crate::error::shared_io_cause),
            };
            match holders {
                None => unassessable("sent nothing", "its signals are all named by the root's number, so "),
                Some(swept) => {
                    log::debug!("{op}: {said}, so it does not {skipped}; it signals the marker holders");
                    match swept {
                        // The holders are not the tree: a kill that skipped the rest is not `Ok`.
                        Ok(()) => unassessable("signalled only the marker holders", ""),
                        // The root's state is why nothing else was sent: its error is a peer.
                        Err(e) => e.with_peers(cause.as_ref().map(crate::error::shared_io_cause)),
                    }
                }
            }
        }

        /// The one line that says the call skipped what names the tree by the root's number. After
        /// this handle's own reap, with a pid that names no process, it ends with how to end the
        /// descendants the reaped root left.
        pub(crate) fn skipped_detail(&self, skip: &Skip, sent: &str) -> String {
            let Why::MayNameAnother(refusal, _) = &skip.why else {
                unreachable!("only a skip that may name another process is worded here")
            };
            let remedy = match refusal {
                Refusal::ReapedPidGone(_) => format!(
                    "; descendants that outlived the reaped root are not ended by it: {}",
                    crate::child::drop_report::END_THEM_BEFORE_WAIT
                ),
                _ => String::new(),
            };
            let earlier = self
                .earlier
                .map_or_else(String::new, |sent| format!(", though {sent} was sent before it"));
            format!(
                "{}(): {refusal}, so its number may name another process; it did not {}, and {sent}{earlier}{remedy}",
                self.op, skip.action
            )
        }

        /// macOS: the end of a call that signalled an fd marker's holders alone ([`Skip::holders`] of
        /// `skip` is their `SIGTERM`), after the grace: `kill` is the kill of any holder left, the
        /// mechanism's own with the same root. One `warn` names what was skipped. The kill's error, or
        /// `Unassessable`, with the `SIGTERM`'s failure and the refusal's reason below its variant.
        pub(crate) fn holders_settled(&self, tree: &Tree, skip: Skip, kill: TreeKillOutcome) -> Settled<Error> {
            let Settled {
                answer: settled,
                killed_again,
            } = tree.settle_for_kill_tree(kill, false, Retry::Follows);
            // The warn says each failure in full; the returned `Unassessable` says only that it
            // failed, for the failure is a peer of the answer.
            let sent = |with_errors: bool| {
                let said = |failure: Option<&Error>| match failure {
                    None => String::new(),
                    Some(e) if with_errors => format!(", which failed ({})", crate::error::Report(e)),
                    Some(_) => ", which failed".to_owned(),
                };
                let term = said(skip.holders.as_ref().and_then(|h| h.as_ref().err()));
                let kill_failed = said(settled.as_ref().err());
                format!("sent the SIGTERM only to the marker holders{term}, then killed any left after the grace{kill_failed}")
            };
            let detail = self.skipped_detail(&skip, &sent(false));
            skip.why.warn(&self.skipped_detail(&skip, &sent(true)));
            // The `SIGTERM`'s failure and the refusal's reason are peers of the kill's failure, as they
            // are of any answer of a skip.
            let cause = skip.why.cause();
            let term_failed = skip.holders.and_then(Result::err).map(Arc::new);
            let error = match settled {
                Err(e) => e.with_peers(term_failed.into_iter().chain(cause)),
                Ok(()) => Error::Unassessable { detail, source: cause }.with_peers(term_failed),
            };
            Settled {
                answer: error,
                killed_again,
            }
        }
    }
}
