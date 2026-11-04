//! What a parent learns about its child's exit: the vocabulary of `OsChild` and its callers.

use std::process::ExitStatus;

use crate::error::ChildFate;

/// A child's exit as its exit record states it. A peek sees one too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitRecord {
    Status(ExitStatus),
    /// A consuming `waitid` that should have handed back a zombie's exit record gave another
    /// `si_code`. A contract breach, but the zombie is consumed, so it is a cached outcome.
    #[cfg_attr(windows, allow(dead_code, reason = "Windows has no `waitid` records"))]
    Unreadable {
        si_code: i32,
    },
}

/// Why a child is not this process's to reap any more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    windows,
    allow(dead_code, reason = "a process handle pins its process: no foreign reap")
)]
pub(crate) enum Foreign {
    /// The OS answered `ECHILD`, or a by-pid consume found nothing: something else reaped it.
    Gone,
    /// The pid names another process now: its start time differs from the child's.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS reads a child by a pid that can be reused")
    )]
    Other,
    /// `ECHILD` for a pid that still names the child, held by launchd: its tracer died and XNU
    /// reparented it. It has exited and is not this process's to reap. Kept apart from `Gone` so
    /// that a log can say why.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS has a zombie launchd holds")
    )]
    Orphaned,
}

impl Foreign {
    /// The fate of a child that is not this process's to reap. Every path that maps a `Foreign` to a
    /// fate uses this:
    ///
    /// - `kill_delivered`: cosca's kill was delivered, so the child is [`Killed`](ChildFate::Killed):
    ///   dead or dying, its exit not collected by cosca.
    /// - Otherwise cosca delivered nothing, and the child is [`Gone`](ChildFate::Gone).
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    pub(crate) fn fate(self, kill_delivered: bool) -> ChildFate {
        // Every foreign verdict is the same situation for the fate: only the kill tells them apart.
        let _ = self;
        if kill_delivered {
            ChildFate::Killed
        } else {
            ChildFate::Gone
        }
    }
}

/// What a peek saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeekOutcome {
    /// An exit record, not consumed.
    Exit(ExitRecord),
    /// No exit record: still running, stopped under a tracer, or a zombie only its tracer sees.
    Running,
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    Foreign(Foreign),
}
