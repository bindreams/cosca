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
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only the async child forgets tokio's `Child`")
    )]
    /// Whether the child was shown reaped by someone else (or held by launchd), rather than merely
    /// not shown to be ours, in which case it may still be running.
    pub(crate) fn reaped_elsewhere(&self) -> bool {
        self.now
            .as_ref()
            .is_none_or(|state| !matches!(state, RootState::Unknown(_)))
    }
}

/// What kind of thing a part of a report says, to tell a repeat of what an earlier step of the same
/// event reported from something new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PartKey {
    /// The root's condition and what was therefore skipped, left or forgotten: the same event
    /// described again, whatever its wording.
    Described,
    /// The contained tree's teardown failure.
    Tree,
    /// A failure of the signals, by its text: a different one is new.
    Left(String),
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
    /// The contained tree's teardown failure, if it failed.
    pub(crate) tree: Option<String>,
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
            tree: None,
            left: Vec::new(),
        }
    }

    /// Log the report: one `warn`, or nothing when there is nothing to report. `reported`: what an
    /// earlier step of this same event warned of (a cleanup that left its handle armed, whose drop
    /// retries). A report that only repeats it is a `debug` record; one with anything new warns.
    /// Returns the kinds of part it warned of, none when it did not warn.
    pub(crate) fn emit(self, reported: &[PartKey]) -> Vec<PartKey> {
        let parts = self.parts();
        if parts.is_empty() {
            return Vec::new();
        }
        let text = format!(
            "{}: {}",
            self.label,
            parts
                .iter()
                .map(|(_, text)| text.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
        if parts.iter().all(|(key, _)| reported.contains(key)) {
            log::debug!("{text}");
            return Vec::new();
        }
        log::warn!("{text}");
        parts.into_iter().map(|(key, _)| key).collect()
    }

    fn parts(&self) -> Vec<(PartKey, String)> {
        let pid = self.view.root_pid;
        let reaped_now = matches!(
            self.forgot.as_ref().and_then(|f| f.now.as_ref()),
            Some(RootState::Reaped)
        );
        let reaped = reaped_now || matches!(self.view.root, RootView::Reaped);
        let mut parts: Vec<(PartKey, String)> = Vec::new();

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
            parts.push((PartKey::Described, state));
        }
        if let (RootView::Reaped, Some(action)) = (&self.view.root, &self.skipped) {
            parts.push((
                PartKey::Described,
                format!(
                    "the root is already reaped, so this drop does not {action}, whose number may now belong to an \
                 unrelated process. Descendants that outlived the reaped root are not torn down by this drop; \
                 call kill_tree() before wait() to end them (https://github.com/bindreams/cosca/issues/382)"
                ),
            ));
        }
        if let Some(why) = self.front.filter(|_| !reaped) {
            parts.push((
                PartKey::Described,
                format!(
                    "elevation front pid {pid}: {why}; the front is killed through its cgroup if it is still in it; \
                     cosca does not wait for it, and tokio reaps it once it exits"
                ),
            ));
        }
        parts.extend(self.tree.iter().map(|tree| (PartKey::Tree, tree.clone())));
        parts.extend(self.left.iter().map(|left| (PartKey::Left(left.clone()), left.clone())));
        if let Some(forgot) = &self.forgot {
            if let Some(cause) = &forgot.cause {
                parts.push((PartKey::Described, format!("the wait found it foreign: {cause}")));
            }
            parts.push((
                PartKey::Described,
                format!("forgetting tokio's handle for it leaks {}", forgot.leak),
            ));
        }

        parts
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
