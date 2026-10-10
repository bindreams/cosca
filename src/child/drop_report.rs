//! The one warn of a drop or a failed-spawn cleanup.
//!
//! An event is the drop (or the cleanup) of one handle. Its steps only collect what they found:
//! the root's state, the kill they skipped, the forget of tokio's `Child`, a signal the OS refused.
//! [`DropReport`] composes all of it into a single `warn`, or none when nothing is worth one.

use crate::containment::dispatch::RootView;
use crate::containment::DropView;
use crate::error::Error;
use crate::signal::RootState;

/// What forgetting tokio's `Child` leaked, and what was seen when the child was asked again.
#[cfg_attr(
    not(feature = "tokio"),
    allow(dead_code, reason = "only the async child forgets tokio's `Child`")
)]
#[derive(Debug)]
pub(crate) struct Forgot {
    /// What the forget leaks (tokio's pidfd and reactor registration, or its `SIGCHLD` watch).
    pub(crate) leak: &'static str,
    /// What the handle said when it was asked again, if it was.
    pub(crate) now: Option<RootState>,
    /// Why the child had to be forgotten, when a wait found out (the wait's error, or why its
    /// zombie is not ours).
    pub(crate) cause: Option<String>,
}

impl Forgot {
    /// Whether the child was shown reaped by someone else (or held by launchd), rather than merely
    /// not shown to be ours, in which case it may still be running.
    pub(crate) fn reaped_elsewhere(&self) -> bool {
        self.now
            .as_ref()
            .is_none_or(|state| !matches!(state, RootState::Unknown(_)))
    }
}

/// What one drop or cleanup found, for its single `warn`.
pub(crate) struct DropReport<'a> {
    /// The caller, which prefixes the warn.
    pub(crate) label: &'a str,
    pub(crate) view: &'a DropView,
    /// The elevation front the event left running instead of signalling, and why.
    pub(crate) front: Option<&'a Error>,
    /// What the drop did not do because the root's number is untrusted
    /// ([`DropKill::skipped`](crate::containment::dispatch::DropKill)).
    pub(crate) skipped: Option<String>,
    /// What forgetting tokio's `Child` leaked, if the event forgot it.
    pub(crate) forgot: Option<Forgot>,
    /// What the signals could not do: a refused kill, a failed reap.
    pub(crate) left: Vec<String>,
}

impl<'a> DropReport<'a> {
    pub(crate) fn new(label: &'a str, view: &'a DropView) -> DropReport<'a> {
        DropReport {
            label,
            view,
            front: None,
            skipped: None,
            forgot: None,
            left: Vec::new(),
        }
    }

    /// Log the report: one `warn`, or nothing when there is nothing to report. `already_said`: an
    /// earlier step of this same event warned (a cleanup that left its handle armed, whose drop
    /// retries), so this one is a `debug` record. Returns whether it warned.
    pub(crate) fn emit(self, already_said: bool) -> bool {
        let Some(text) = self.compose() else {
            return false;
        };
        if already_said {
            log::debug!("{text}");
            return false;
        }
        log::warn!("{text}");
        true
    }

    fn compose(&self) -> Option<String> {
        let pid = self.view.root_pid;
        let reaped_now = matches!(
            self.forgot.as_ref().and_then(|f| f.now.as_ref()),
            Some(RootState::Reaped)
        );
        let reaped = reaped_now || matches!(self.view.root, RootView::Reaped);
        let mut parts: Vec<String> = Vec::new();

        if let Some(mut state) = self.state_text(pid, reaped_now) {
            if self.view.unsettled() && !reaped_now {
                if let Some(action) = &self.skipped {
                    state.push_str(&format!(
                        ", so it does not {action}, whose number may belong to an unrelated process"
                    ));
                }
            }
            if matches!(self.view.root, RootView::Unpinned) && !reaped_now {
                state.push_str("; the root itself is neither signalled nor waited on");
            }
            parts.push(state);
        }
        if let (RootView::Reaped, Some(action)) = (&self.view.root, &self.skipped) {
            parts.push(format!(
                "the root is already reaped, so this drop does not {action}, whose number may now belong to an \
                 unrelated process. Descendants that outlived the reaped root are not torn down by this drop; \
                 call kill_tree() before wait() to end them (https://github.com/bindreams/cosca/issues/382)"
            ));
        }
        if let Some(why) = self.front.filter(|_| !reaped) {
            parts.push(format!(
                "elevation front pid {pid}: {why}; the front is killed through its cgroup if it is still in it; \
                 cosca does not wait for it, and tokio reaps it once it exits"
            ));
        }
        parts.extend(self.left.iter().cloned());
        if let Some(forgot) = &self.forgot {
            if let Some(cause) = &forgot.cause {
                parts.push(format!("the wait found it foreign: {cause}"));
            }
            parts.push(format!("forgetting tokio's handle for it leaks {}", forgot.leak));
        }

        (!parts.is_empty()).then(|| format!("{}: {}", self.label, parts.join("; ")))
    }

    /// The root's state, when it is worth a warn: unsettled, or forgotten. A second look that
    /// shows the reap names it, rather than the first look's doubt.
    fn state_text(&self, pid: u32, reaped_now: bool) -> Option<String> {
        let first_doubt = match &self.view.root {
            RootView::Unknown(e) => Some(e.to_string()),
            RootView::Unpinned => Some(crate::signal::UNPINNED_WHY.to_owned()),
            RootView::Reaped | RootView::Trusted => None,
        };
        if let (true, Some(doubt)) = (reaped_now, &first_doubt) {
            return Some(format!(
                "RootState::Reaped: the root ({pid}) was reaped by someone else (its own handle first could not say: {doubt})"
            ));
        }
        match (&self.view.root, &self.forgot) {
            (RootView::Unpinned, _) => Some(format!(
                "RootState::Unpinned: the root ({pid}) is not pinned by this process ({})",
                crate::signal::UNPINNED_WHY
            )),
            (RootView::Unknown(e), _) => Some(format!(
                "RootState::Unknown: the root's ({pid}) own handle could not say whether it was reaped ({e})"
            )),
            (RootView::Reaped | RootView::Trusted, Some(forgot)) => Some(match &forgot.now {
                Some(RootState::Unknown(e)) => {
                    format!("child {pid} cannot be shown to be ours (RootState::Unknown: {e})")
                }
                Some(RootState::Unpinned) => format!(
                    "child {pid} is not pinned by this process (RootState::Unpinned: {})",
                    crate::signal::UNPINNED_WHY
                ),
                Some(RootState::Reaped | RootState::Unreaped) | None => {
                    format!("child {pid} was reaped by someone else, or cannot be shown to be ours")
                }
            }),
            (RootView::Reaped | RootView::Trusted, None) => None,
        }
    }
}
