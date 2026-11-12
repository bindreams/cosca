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
                Why::MayNameAnother(Refusal::ReapedPidGone(_) | Refusal::ReapedPidUnread(_))
            )
    }

    /// The error of a sweep that skipped what the root's number names: the holders' sweep's own
    /// error when it failed, else `Unassessable`, with the error behind [`why`](Skip::why) as its
    /// `source`.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS's late sweep skips a root it cannot show ours")
    )]
    pub(crate) fn sweep_error(self) -> Error {
        match self.holders {
            Some(Err(e)) => e,
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
    /// The pid may name another process, for this reason.
    MayNameAnother(Refusal),
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
            Why::MayNameAnother(refusal) => refusal.cause(),
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
    /// The signal went out, as usual or to what names the tree by identity, with `result`. `earlier`
    /// names what a later sweep's error says was sent before it.
    Sent {
        result: Result<(), Error>,
        earlier: Option<&'static str>,
    },
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

#[cfg(all(test, unix))]
#[path = "skip_tests.rs"]
mod skip_tests;

#[cfg(unix)]
pub(crate) use call::SkipCall;

#[cfg(unix)]
mod call {
    use super::{Skip, Why};
    use crate::containment::dispatch::{Settled, TreeKillOutcome, TreeSignal, Unkilled};
    use crate::containment::root::Refusal;
    use crate::containment::Tree;
    use crate::error::Error;
    use crate::signal::Sent;

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
        /// `Unassessable`; `Ok` only after this handle's own reap, when it already killed the tree.
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
                        TreeSignal::Kill => {
                            tree.settle_for_kill_tree(self.op, TreeKillOutcome::Ran(Err(Unkilled::from(error))), false)
                        }
                        TreeSignal::Term => Settled::of(Err(error)),
                    };
                }
                skip => skip,
            };
            let Why::MayNameAnother(refusal) = &skip.why else {
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
                    TreeSignal::Kill => tree.settle_for_kill_tree(self.op, TreeKillOutcome::Skipped(skip), false),
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
            let sent = match (&skip.holders, &root) {
                (Some(Ok(())), _) => "signalled only the marker holders".to_owned(),
                (Some(Err(e)), _) => format!(
                    "signalled only the marker holders, which failed ({})",
                    crate::error::Report(e)
                ),
                (None, None) => "sent nothing".to_owned(),
                (None, Some(Ok(Sent::Delivered))) => sent_root.to_owned(),
                (None, Some(Ok(Sent::Gone))) => "sent nothing: the root's pidfd shows it is gone".to_owned(),
                (None, Some(Ok(_))) => "sent nothing: the root's handle no longer reaches it".to_owned(),
                (None, Some(Err(e))) => format!(
                    "sent nothing: {failed_root} through its pidfd failed ({})",
                    crate::error::Report(e)
                ),
            };
            let detail = self.skipped_detail(&skip, &sent);
            let cause = skip.why.cause();
            skip.why.warn(&detail);
            let swept = skip.holders.is_some();
            let mut killed_again = Vec::new();
            let holders = match self.signal {
                TreeSignal::Kill => {
                    let settled = tree.settle_for_kill_tree(self.op, TreeKillOutcome::Skipped(skip), false);
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
            let answer = match (holders, root) {
                (Some(Err(e)), _) | (None, Some(Err(e))) => Err(e),
                _ => Err(Error::Unassessable { detail, source: cause }),
            };
            Settled { answer, killed_again }
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
                        Err(e) => e,
                    }
                }
            }
        }

        /// The one line that says the call skipped what names the tree by the root's number. After
        /// this handle's own reap, with a pid that names no process, it ends with how to end the
        /// descendants the reaped root left.
        pub(crate) fn skipped_detail(&self, skip: &Skip, sent: &str) -> String {
            let Why::MayNameAnother(refusal) = &skip.why else {
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

        /// A failed grace wait of a macOS fd marker's holders: they are killed now.
        pub(crate) fn holders_grace_failed(&self, e: &Error) {
            log::debug!(
                "{}({}): the marker holders' grace wait failed, so they are killed now: {report}",
                self.op,
                self.pid,
                report = crate::error::Report(e)
            );
        }

        /// macOS: the end of a call that signalled an fd marker's holders alone ([`Skip::holders`] of
        /// `skip` is their `SIGTERM`), after the grace: `kill` is the kill of any holder left, the
        /// mechanism's own with the same root. One `warn` names what was skipped. The kill's error, or
        /// `Unassessable`.
        pub(crate) fn holders_settled(&self, tree: &Tree, skip: &Skip, kill: TreeKillOutcome) -> Settled<Error> {
            let term = match &skip.holders {
                Some(Err(e)) => format!(", which failed ({})", crate::error::Report(e)),
                _ => String::new(),
            };
            let Settled {
                answer: settled,
                killed_again,
            } = tree.settle_for_kill_tree(self.op, kill, false);
            let kill_failed = match &settled {
                Ok(()) => String::new(),
                Err(e) => format!(", which failed ({})", crate::error::Report(e)),
            };
            let sent = format!(
                "sent the SIGTERM only to the marker holders{term}, then killed any left after the grace{kill_failed}"
            );
            let detail = self.skipped_detail(skip, &sent);
            skip.why.warn(&detail);
            let error = match settled {
                Err(e) => e,
                Ok(()) => Error::Unassessable {
                    detail,
                    source: skip.why.cause(),
                },
            };
            Settled {
                answer: error,
                killed_again,
            }
        }
    }
}
