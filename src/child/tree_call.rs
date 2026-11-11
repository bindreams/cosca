//! The tree paths' one look at the root, and what each sends by the root's number after it. Shared
//! by the sync and async `kill_tree`, `terminate_tree` and `graceful_shutdown_tree`.

use crate::child::drop_report::END_THEM_BEFORE_WAIT;
use crate::containment::dispatch::{TreeKillOutcome, TreeSignal, Unkilled};
use crate::containment::{reaped_pid_names_no_process, Attached, Root, TreeKilled};
use crate::error::Error;
use crate::identity::RawPid;
use crate::signal::{RootState, Sent};

/// What a tree path may send by the root's number, from one look at the root's state.
pub(crate) enum RootNumber {
    /// Everything: as far as the look shows, the number names the root.
    Trusted,
    /// macOS: the root is `Unpinned` or `Unknown`, so only what names the tree by identity is sent;
    /// see [`Attached::signal_tree_untrusted`](crate::containment::Attached::signal_tree_untrusted).
    #[cfg(target_os = "macos")]
    Untrusted(RootState),
    /// This handle reaped the root, and its group is empty or it had none: another process holds
    /// the pid, and the kernel does not reissue a pid while it is some group's id, or the pid of a
    /// pid-less fd marker's root names nothing. Only the marker holders, if any, are signalled.
    Empty,
    /// The pid may name another process, for the reason `why`. `exact_root` (Linux): the root's
    /// handle still reaches the root exactly, if it reaches it at all.
    MayNameAnother { why: String, exact_root: bool },
    /// Linux 6.9+: the root is reaped, and its pidfd shows its group has no member left, so there is
    /// no tree to signal and nothing is sent.
    #[cfg(target_os = "linux")]
    GroupGone,
}

/// [`RootNumber`] for `attached`'s tree, from one call of `state`: the root's own handle's answer. On
/// macOS it is always called; elsewhere only for a mechanism that reaches its tree through the root's number
/// ([`Attached::needs_root_check`](crate::containment::Attached::needs_root_check)). After this
/// handle's own reap, `own` decides a pid another process holds: the group is empty
/// ([`RootNumber::Empty`]). A pid that names no process (`Gone`) may be taken, and lead a group, once
/// the root's group has no member, so nothing is sent by it ([`RootNumber::MayNameAnother`]), except
/// that a macOS fd marker without a group has none to skip ([`RootNumber::Empty`]). Descendants the
/// reaped root left are then not ended by the call, as [`Child::kill_tree`](crate::Child::kill_tree)
/// says. No walk runs from the pid.
pub(crate) fn root_number(attached: &Attached, pid: RawPid, state: impl FnOnce() -> RootState) -> RootNumber {
    use crate::identity::Resolved;
    #[cfg(target_os = "macos")]
    let state = {
        let looked = state();
        if matches!(looked, RootState::Unpinned | RootState::Unknown(_)) {
            return RootNumber::Untrusted(looked);
        }
        move || looked
    };
    if !attached.needs_root_check() {
        return RootNumber::Trusted;
    }
    let mut exact_root = false;
    let why = match state() {
        RootState::Unreaped => return RootNumber::Trusted,
        RootState::Reaped { own: true } => match crate::child::root_identity_now(pid) {
            Resolved::Gone => {
                #[cfg(target_os = "macos")]
                if attached.fd_marker_has_group() == Some(false) {
                    return RootNumber::Empty;
                }
                reaped_pid_names_no_process(pid)
            }
            Resolved::Found(_) => return RootNumber::Empty,
            Resolved::Unknown => format!("this handle reaped the root, and its pid ({pid}) could not be read"),
        },
        RootState::Reaped { own: false } => format!("the root (pid {pid}) was reaped elsewhere"),
        RootState::Unknown(e) => {
            exact_root = cfg!(target_os = "linux");
            format!("the root's own handle could not say whether it (pid {pid}) was reaped ({e})")
        }
        RootState::Unpinned => {
            debug_assert!(false, "only macOS reports an unpinned root, and it is answered above");
            format!("the root (pid {pid}) is not pinned by this process")
        }
    };
    RootNumber::MayNameAnother { why, exact_root }
}

/// Linux 6.9+: `number` for a process group whose root's pid may name another process, decided again
/// by the root's pidfd (`root`), which names the group exactly whoever reaped the root. While the
/// group has a member it is signalled as usual: the group's own signal goes through the pidfd, and
/// each send by its number is checked the same way ([`check_number`](crate::containment::check_number)).
/// A reaped root's group with no member left is [`RootNumber::GroupGone`]. A root its handle cannot
/// answer for, whose group has no member, may have left the group alive, so it keeps `number`; so
/// does a kernel that cannot say.
/// A drop and a failed elevated spawn's cleanup take the same decision
/// ([`Attached::hard_kill_for_drop`](crate::containment::Attached::hard_kill_for_drop)).
#[cfg(target_os = "linux")]
pub(crate) fn through_the_pidfd(attached: &Attached, number: RootNumber, root: Option<&dyn Root>) -> RootNumber {
    let RootNumber::MayNameAnother { why, exact_root } = &number else {
        return number;
    };
    if !matches!(attached, Attached::ProcessGroup(_)) {
        return number;
    }
    match crate::containment::group_has_member(root) {
        Some(true) => {
            log::debug!(
                "{why}, but its pidfd names its process group exactly, which still has a member: it is signalled"
            );
            RootNumber::Trusted
        }
        Some(false) if !*exact_root => RootNumber::GroupGone,
        _ => number,
    }
}

/// One tree call: the tree of `attached`, whose root is `pid`, sent `signal` by the operation
/// `op`, which already sent `earlier` (so an error never claims the operation sent nothing).
/// A `Kill` that reached the whole tree is settled into `killed` ([`TreeCall::answered`]).
pub(crate) struct TreeCall<'a> {
    pub(crate) attached: &'a Attached,
    pub(crate) pid: RawPid,
    pub(crate) signal: TreeSignal,
    pub(crate) op: &'static str,
    pub(crate) earlier: Option<&'a str>,
    pub(crate) killed: &'a TreeKilled,
}

/// What `graceful_shutdown_tree` (sync and async) does after its one look at the root
/// ([`TreeCall::graceful`]).
pub(crate) enum Graceful {
    /// Signal the tree as usual, then the grace and the sweep.
    Signal,
    /// The cooperative signal went out already, with `result`; then the grace and the sweep, which
    /// says `earlier` was sent before it.
    Sent {
        result: Result<(), Error>,
        earlier: Option<&'static str>,
    },
    /// The call ends now, with this error.
    End(Error),
    /// Linux: the root's number may name another process (`why`), but its pidfd names it exactly:
    /// the root alone is shut down through it ([`PidfdShutdown`]), and the call ends.
    #[cfg(target_os = "linux")]
    RootThroughPidfd(String),
    /// macOS: the root's number may name another process (`why`): an fd marker's holders alone are
    /// shut down, by the pipe they hold ([`TreeCall::holders_term`]), and the call ends.
    #[cfg(target_os = "macos")]
    HoldersOnly(String),
}

impl TreeCall<'_> {
    /// The call's one look at the root ([`root_number`]), and on Linux 6.9+ at its group through
    /// `root`'s pidfd (`through_the_pidfd`).
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables, reason = "only Linux has a pidfd"))]
    pub(crate) fn root_number(&self, state: impl FnOnce() -> RootState, root: Option<&dyn Root>) -> RootNumber {
        let number = root_number(self.attached, self.pid, state);
        #[cfg(target_os = "linux")]
        let number = through_the_pidfd(self.attached, number, root);
        #[cfg(test)]
        crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterRootLook);
        number
    }

    /// What `kill_tree` and `terminate_tree` (sync and async) do instead of signalling a tree
    /// reached through the root's pid (a process group, or a macOS fd marker's group and walk) when
    /// that pid may name another process, decided on one look ([`root_number`]). `None`: signal it
    /// as usual.
    ///
    /// No walk from the root's pid runs here, and no `killpg`. What names the tree by identity still
    /// runs: a macOS fd marker's holders, named by the pipe they hold.
    ///
    /// Each answer a `Kill` gives of a tree that was reached is [`answered`](Self::answered), and
    /// one of a kill that skipped what the root's number names is settled by
    /// [`number_skipped`](Self::number_skipped).
    ///
    /// - `Untrusted` (macOS): `Attached::signal_tree_untrusted`.
    /// - `Empty`: the holders are signalled, and the call is their sweep's answer (`Ok` with no
    ///   holders channel).
    /// - `GroupGone` (Linux): nothing is sent, and the call is `Ok`.
    /// - `MayNameAnother`: [`number_skipped`](Self::number_skipped), after `signal_root` when the
    ///   handle still names the root exactly.
    ///
    /// `signal_root` sends the call's own signal to the root through its handle. `root` is the root
    /// a send to its group needs.
    pub(crate) fn root_checked(
        &self,
        state: impl FnOnce() -> RootState,
        signal_root: impl FnOnce() -> Result<Sent, Error>,
        root: Option<&dyn Root>,
    ) -> Option<Result<(), Error>> {
        match self.root_number(state, root) {
            RootNumber::Trusted => None,
            #[cfg(target_os = "macos")]
            RootNumber::Untrusted(root) => self.untrusted(&root),
            RootNumber::Empty => Some(self.answered(self.empty_group().unwrap_or(Ok(())))),
            #[cfg(target_os = "linux")]
            RootNumber::GroupGone => Some(self.group_gone()),
            RootNumber::MayNameAnother { why, exact_root } => {
                let root = exact_root.then(signal_root);
                Some(Err(self.number_skipped(&why, root)))
            }
        }
    }

    /// `graceful_shutdown_tree`'s decision on its one look at the root, for its `SIGTERM`: what
    /// [`root_checked`](Self::root_checked) decides, except that a root whose number may name
    /// another process is shut down through what still names it exactly, if anything does.
    pub(crate) fn graceful(&self, state: impl FnOnce() -> RootState, root: Option<&dyn Root>) -> Graceful {
        match self.root_number(state, root) {
            RootNumber::Trusted => Graceful::Signal,
            // By identity alone. With no channel by identity there is nothing to signal, wait for or
            // sweep, so the call ends here with nothing sent.
            #[cfg(target_os = "macos")]
            RootNumber::Untrusted(root) => match self.untrusted(&root) {
                Some(Err(e)) if !self.attached.names_tree_by_identity() => Graceful::End(e),
                None => Graceful::Signal,
                Some(result) => Graceful::Sent {
                    result,
                    earlier: Some("the SIGTERM"),
                },
            },
            // The group has no member left: nothing to signal, wait for or sweep but the root.
            #[cfg(target_os = "linux")]
            RootNumber::GroupGone => Graceful::Sent {
                result: self.group_gone(),
                earlier: None,
            },
            // The group is empty: nothing goes out by its number, only to the marker holders, if any.
            RootNumber::Empty => {
                let holders = self.empty_group();
                Graceful::Sent {
                    earlier: holders.is_some().then_some("the SIGTERM to any marker holders"),
                    result: self.answered(holders.unwrap_or(Ok(()))),
                }
            }
            // The pid may name another process. A macOS fd marker shuts its holders down by the pipe
            // they hold, and a Linux root its handle cannot answer for is shut down through its
            // pidfd; any other mechanism has nothing to send. Either way the call ends with one
            // warn: a sweep would warn again.
            RootNumber::MayNameAnother { why, exact_root } => {
                #[cfg(target_os = "linux")]
                if exact_root {
                    return Graceful::RootThroughPidfd(why);
                }
                #[cfg(not(target_os = "linux"))]
                let _ = exact_root;
                #[cfg(target_os = "macos")]
                if self.attached.names_tree_by_identity() {
                    return Graceful::HoldersOnly(why);
                }
                Graceful::End(self.number_skipped(&why, None))
            }
        }
    }

    /// This call's answer: a `Kill`'s is settled into the handle's state (it reaches no root of its
    /// own to end, so `root_ended` is false), through [`Attached::settle`](crate::containment::Attached::settle),
    /// the only writer of it. A `SIGTERM`'s is the answer as it is.
    fn answered(&self, result: Result<(), Error>) -> Result<(), Error> {
        match self.signal {
            TreeSignal::Kill => self.attached.settle_for_kill_tree(
                self.op,
                self.killed,
                TreeKillOutcome::Ran(result.map_err(Unkilled::from)),
                false,
            ),
            TreeSignal::Term => result,
        }
    }

    /// The signal for [`RootNumber::Untrusted`] (macOS).
    #[cfg(target_os = "macos")]
    fn untrusted(&self, root: &RootState) -> Option<Result<(), Error>> {
        self.attached
            .signal_tree_untrusted(self.signal, root, self.pid, self.op, self.earlier)
            .map(|result| self.answered(result))
    }

    /// [`RootNumber::GroupGone`]: nothing is sent, and the answer is `Ok`.
    #[cfg(target_os = "linux")]
    fn group_gone(&self) -> Result<(), Error> {
        log::debug!(
            "{}({}): the root is reaped, and its pidfd shows its process group has no member left, so nothing is sent",
            self.op,
            self.pid
        );
        self.answered(Ok(()))
    }

    /// The signal for [`RootNumber::Empty`]: nothing by the root's number, and a macOS fd marker's
    /// holders by the pipe they hold. `None` for a mechanism with no such channel. The caller
    /// [`answered`](Self::answered)s it.
    fn empty_group(&self) -> Option<Result<(), Error>> {
        log::debug!(
            "{}({}): this handle reaped the root, so its group is empty or it had none, a walk from its pid \
             would find none of the tree, and nothing is sent by it",
            self.op,
            self.pid
        );
        self.attached.signal_holders_only(self.signal)
    }

    /// The answer for [`RootNumber::MayNameAnother`], `why` its reason: nothing is sent by the
    /// root's number, a macOS fd marker's holders are signalled, and one `warn` names what was
    /// skipped and what was sent, `root` included: the signal to the root through its handle, if
    /// one was sent. The holders' sweep's error, the root signal's error, or `Unassessable`. A
    /// `Kill` is settled by what the sweep left ([`settle_skipped_kill`](Self::settle_skipped_kill)).
    pub(crate) fn number_skipped(&self, why: &str, root: Option<Result<Sent, Error>>) -> Error {
        let holders = self.attached.signal_holders_only(self.signal);
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
        let sent = match (&holders, &root) {
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
        let detail = self.skipped_detail(why, &sent);
        log::warn!("{detail}");
        let holders = match (holders, self.signal) {
            (Some(swept), TreeSignal::Kill) => Some(self.settle_skipped_kill(swept)),
            (None, TreeSignal::Kill) => {
                // Nothing was swept, so nothing is left to report.
                _ = self.settle_skipped_kill(Ok(()));
                None
            }
            (holders, TreeSignal::Term) => holders,
        };
        match (holders, root) {
            (Some(Err(e)), _) | (None, Some(Err(e))) => e,
            _ => Error::Unassessable { detail, source: None },
        }
    }

    /// A kill that skipped what names the tree by the root's number, settled into the handle's state
    /// by what its sweep of the marker holders left (`holders`, `Ok` where there is no such
    /// sweep), as a drop settles its skip. A failed sweep leaves the tree unvouched. The error is
    /// the settlement's report of it.
    fn settle_skipped_kill(&self, holders: Result<(), Error>) -> Result<(), Error> {
        let outcome = TreeKillOutcome::Skipped {
            action: self.skipped_action(),
            holders: holders.map_err(Unkilled::from),
        };
        self.attached.settle_for_kill_tree(self.op, self.killed, outcome, false)
    }

    /// What the call skipped, as an action.
    fn skipped_action(&self) -> String {
        let verb = self.signal.verb();
        self.attached
            .named_by_root_number(self.pid, verb)
            .unwrap_or_else(|| format!("{verb} its tree"))
    }

    /// The one line that says the call skipped what names the tree by the root's number. After this
    /// handle's own reap it ends with how to end the descendants the reaped root left.
    fn skipped_detail(&self, why: &str, sent: &str) -> String {
        let skipped = self.skipped_action();
        let remedy = if why == reaped_pid_names_no_process(self.pid) {
            format!("; descendants that outlived the reaped root are not ended by it: {END_THEM_BEFORE_WAIT}")
        } else {
            String::new()
        };
        let earlier = self
            .earlier
            .map_or_else(String::new, |sent| format!(", though {sent} was sent before it"));
        format!(
            "{}(): {why}, so its number may name another process; it did not {skipped}, and {sent}{earlier}{remedy}",
            self.op
        )
    }

    /// `signal` to the marker holders of a macOS fd marker, which names its tree by identity.
    #[cfg(target_os = "macos")]
    pub(crate) fn holders_only(&self, signal: TreeSignal) -> Result<(), Error> {
        self.attached.signal_holders_only(signal).unwrap_or_else(|| {
            debug_assert!(false, "only a mechanism that names its tree by identity gets here");
            Ok(())
        })
    }

    /// [`Graceful::HoldersOnly`]'s first step: the `SIGTERM` to the marker holders. The caller
    /// waits the grace, logs a failed wait with [`holders_grace_failed`](Self::holders_grace_failed),
    /// and ends with [`holders_shutdown_error`](Self::holders_shutdown_error).
    #[cfg(target_os = "macos")]
    pub(crate) fn holders_term(&self) -> Result<(), Error> {
        self.holders_only(TreeSignal::Term)
    }

    /// A failed grace wait of [`Graceful::HoldersOnly`]: the holders are killed now.
    #[cfg(target_os = "macos")]
    pub(crate) fn holders_grace_failed(&self, e: &Error) {
        log::debug!(
            "{}({}): the marker holders' grace wait failed, so they are killed now: {report}",
            self.op,
            self.pid,
            report = crate::error::Report(e)
        );
    }

    /// [`Graceful::HoldersOnly`]'s end, `why` its reason: a kill of any holders left, by the pipe
    /// they hold (a marker's drain wait never shows every member exited), after `term`. One `warn`
    /// names what was skipped. The kill, a skipped one, is settled as in
    /// [`number_skipped`](Self::number_skipped). The kill's error, or `Unassessable`.
    #[cfg(target_os = "macos")]
    pub(crate) fn holders_shutdown_error(&self, why: &str, term: Result<(), Error>) -> Error {
        let kill = self.holders_only(TreeSignal::Kill);
        let term = match &term {
            Ok(()) => String::new(),
            Err(e) => format!(", which failed ({e})"),
        };
        let kill_failed = match &kill {
            Ok(()) => String::new(),
            Err(e) => format!(", which failed ({})", crate::error::Report(e)),
        };
        let sent = format!(
            "sent the SIGTERM only to the marker holders{term}, then killed any left after the grace{kill_failed}"
        );
        let detail = self.skipped_detail(why, &sent);
        log::warn!("{detail}");
        match self.settle_skipped_kill(kill) {
            Err(e) => e,
            Ok(()) => Error::Unassessable { detail, source: None },
        }
    }
}

/// [`Graceful::RootThroughPidfd`] (Linux), sync and async: the `SIGTERM` through the root's pidfd,
/// the grace, then a kill through the pidfd if the root outlived it. Nothing goes out by the
/// number. A front that may not be signalled is refused, as for the tree paths.
///
/// The caller [`start`](Self::start)s it, waits the grace when [`needs_grace`](Self::needs_grace),
/// and [`finish`](Self::finish)es it with the wait's outcome.
#[cfg(target_os = "linux")]
pub(crate) struct PidfdShutdown {
    term: Result<Sent, Error>,
}

#[cfg(target_os = "linux")]
impl PidfdShutdown {
    /// The `SIGTERM`, sent by `term` unless `gate` refuses it; a refusal is the call's error.
    pub(crate) fn start(
        gate: crate::elevation::front::Gate,
        term: impl FnOnce() -> Result<Sent, Error>,
    ) -> Result<PidfdShutdown, Error> {
        if let crate::elevation::front::Gate::Closed(unkillable) = gate {
            return Err(unkillable);
        }
        Ok(PidfdShutdown { term: term() })
    }

    /// Whether the `SIGTERM` reached the root, so the grace is waited.
    pub(crate) fn needs_grace(&self) -> bool {
        matches!(self.term, Ok(Sent::Delivered))
    }

    /// The call's error, after `exited`, the grace wait's outcome (`None`: not waited): a root
    /// that did not exit within it, or whose wait failed, is killed by `kill` unless `kill_gate`
    /// refuses it. One `warn` names what was skipped and what was sent. The failed signal's error,
    /// or `Unassessable`.
    pub(crate) fn finish(
        self,
        call: &TreeCall<'_>,
        why: &str,
        exited: Option<Result<bool, impl std::error::Error + 'static>>,
        kill_gate: impl FnOnce() -> crate::elevation::front::Gate,
        kill: impl FnOnce() -> Result<Sent, Error>,
    ) -> Error {
        use crate::elevation::front::Gate;
        let kill = match exited {
            None | Some(Ok(true)) => None,
            Some(outcome) => {
                if let Err(e) = outcome {
                    log::debug!(
                        "{}({}): the root's grace wait failed, so it is killed now: {report}",
                        call.op,
                        call.pid,
                        report = crate::error::Report(&e)
                    );
                }
                Some(match kill_gate() {
                    Gate::Closed(unkillable) => Err(unkillable),
                    _ => kill(),
                })
            }
        };
        let termed = "sent the SIGTERM to the root through its pidfd, which names it exactly";
        let sent = match (&self.term, &kill) {
            (Err(e), _) => format!(
                "sent nothing: the SIGTERM to the root through its pidfd failed ({})",
                crate::error::Report(e)
            ),
            (Ok(Sent::Delivered), None) => format!("{termed}, and it exited within the grace; sent nothing else"),
            (Ok(Sent::Delivered), Some(Ok(Sent::Delivered))) => {
                format!("{termed}, then killed the root through its pidfd after the grace, and sent nothing else")
            }
            (Ok(Sent::Delivered), Some(Err(e))) => {
                format!(
                    "{termed}, then the kill of the root through its pidfd failed ({})",
                    crate::error::Report(e)
                )
            }
            (Ok(Sent::Delivered), Some(Ok(_))) => {
                format!("{termed}, and its pidfd showed it gone after the grace; sent nothing else")
            }
            (Ok(Sent::Gone), _) => "sent nothing: the root's pidfd shows it is gone".to_owned(),
            (Ok(_), _) => "sent nothing: the root's handle no longer reaches it".to_owned(),
        };
        let detail = call.skipped_detail(why, &sent);
        log::warn!("{detail}");
        match (self.term, kill) {
            (Err(e), _) | (_, Some(Err(e))) => e,
            _ => Error::Unassessable { detail, source: None },
        }
    }
}

/// `graceful_shutdown_tree`'s answer (sync and async) from the root's reap, `waited`, once the tree is
/// down. A root reaped elsewhere (`ECHILD`) leaves no exit status for this handle: that is
/// `Unassessable`, saying the tree is down, as for a root launchd holds. Any other answer stands.
pub(crate) fn status_unless_reaped_elsewhere(
    waited: Result<std::process::ExitStatus, Error>,
    pid: RawPid,
) -> Result<std::process::ExitStatus, Error> {
    match waited {
        Err(Error::Io(e)) if e.raw_os_error() == Some(libc::ECHILD) => {
            log::debug!("graceful_shutdown_tree({pid}): the tree is down, and the root was reaped elsewhere");
            Err(Error::Unassessable {
                detail: format!(
                    "pid {pid}: graceful_shutdown_tree brought the tree down, but its exit status cannot be \
                     collected: the root was reaped elsewhere"
                ),
                source: None,
            })
        }
        other => other,
    }
}

#[cfg(test)]
#[path = "tree_call_tests.rs"]
mod tree_call_tests;
