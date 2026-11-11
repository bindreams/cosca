//! The one warn of a drop or a failed-spawn cleanup.
//!
//! An event is the drop (or the cleanup) of one handle. Its steps only collect what they found:
//! the root's state, the kill they skipped, a signal the OS refused.
//! [`DropReport`] composes all of it into a single `warn`, or none when nothing is worth one.

use crate::child::owned::teardown::{Remains, TeardownOutcome};
use crate::containment::dispatch::RootView;
use crate::containment::DropView;

/// The remedy for descendants that outlive a root this handle has reaped, in a drop's warn and in a
/// tree call's error.
pub(crate) const END_THEM_BEFORE_WAIT: &str =
    "call kill_tree() before wait() to end them (https://github.com/bindreams/cosca/issues/382)";

/// What kind of thing a part of a report says, to tell a repeat of what an earlier step of the same
/// event reported from something new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PartKey {
    /// The root's condition and what was therefore skipped, left or forgotten: the same event
    /// described again, whatever its wording.
    Described,
    /// The contained tree's teardown failure.
    Tree,
    /// The failure to watch a drain after a tree kill that landed: not a repeat of a later kill's
    /// failure.
    Drain,
    /// A failure of the signals, by its text: a different one is new.
    Left(String),
}

/// What one drop or cleanup found, for its single `warn`.
pub(crate) struct DropReport<'a> {
    /// The look at the root.
    pub(crate) view: &'a DropView,
    /// What the drop did not do because the root's number is untrusted
    /// ([`TreeKillOutcome::left_undone`](crate::containment::dispatch::TreeKillOutcome::left_undone)).
    pub(crate) skipped: Option<String>,
    /// The contained tree's teardown failure, if it failed.
    pub(crate) tree: Option<String>,
    /// The failure to watch the tree's drain after a kill that landed, if it failed.
    pub(crate) drain: Option<String>,
    /// What the signals could not do: a refused kill, a failed reap.
    pub(crate) left: Vec<String>,
}

impl<'a> DropReport<'a> {
    pub(crate) fn new(view: &'a DropView) -> DropReport<'a> {
        DropReport {
            view,
            skipped: None,
            tree: None,
            drain: None,
            left: Vec::new(),
        }
    }

    /// Takes `torn`'s clause into the report, led by the report's caller: a clause at warn becomes
    /// a part of the one warn, and a lower one is logged at its level, led by the same caller
    /// ([`TeardownOutcome::take_warn`]). What is left of `torn` is returned.
    pub(crate) fn fold_clause(&mut self, torn: TeardownOutcome) -> Remains {
        let (warn, remains) = torn.take_warn(self.view.caller.label());
        self.left.extend(warn);
        remains
    }

    /// Log the report: one `warn`, or nothing when there is nothing to report. `reported`: what an
    /// earlier step of this same event warned of (a failed spawn's cleanup, before its handle's
    /// drop). A report that only repeats it is a `debug` record; one with anything new warns.
    /// Returns the kinds of part it warned of, none when it did not warn.
    pub(crate) fn emit(self, reported: &[PartKey]) -> Vec<PartKey> {
        let parts = self.parts();
        if parts.is_empty() {
            return Vec::new();
        }
        let text = format!(
            "{}: {}",
            self.view.caller.label(),
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
        let mut parts: Vec<(PartKey, String)> = Vec::new();

        if let Some(mut state) = self.state_text(pid) {
            if self.view.unsettled() {
                if let Some(action) = &self.skipped {
                    state.push_str(&format!(
                        ", so it does not {action}, whose number may belong to an unrelated process"
                    ));
                }
            }
            if matches!(self.view.root, RootView::Unpinned) {
                state.push_str("; the root itself is neither signalled nor waited on");
            }
            parts.push((PartKey::Described, state));
        }
        if let (RootView::Reaped, Some(action)) = (&self.view.root, &self.skipped) {
            let this = self.view.caller.this_event();
            parts.push((
                PartKey::Described,
                format!(
                    "the root is already reaped, so {this} does not {action}, whose number may now belong to an \
                 unrelated process. Descendants that outlived the reaped root are not torn down by {this}; \
                 {END_THEM_BEFORE_WAIT}"
                ),
            ));
        }
        parts.extend(self.tree.iter().map(|tree| (PartKey::Tree, tree.clone())));
        parts.extend(self.drain.iter().map(|drain| (PartKey::Drain, drain.clone())));
        parts.extend(self.left.iter().map(|left| (PartKey::Left(left.clone()), left.clone())));

        parts
    }

    /// The root's state, when it is worth a warn: unsettled.
    fn state_text(&self, pid: u32) -> Option<String> {
        match &self.view.root {
            RootView::Unpinned => Some(format!(
                "RootState::Unpinned: the root ({pid}) is not pinned by this process ({})",
                crate::signal::UNPINNED_WHY
            )),
            RootView::Unknown(e) => Some(format!(
                "RootState::Unknown: the root's ({pid}) own handle could not say whether it was reaped ({})",
                crate::error::Report(e)
            )),
            RootView::Reaped | RootView::Trusted => None,
        }
    }
}
