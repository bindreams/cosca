//! The pure part of the Unix "is this pid gone, or merely unreadable?" decision.
//!
//! Kept separate and free of syscalls so it is compiled and EXECUTED on every host,
//! including the Windows development machine — the Linux path would otherwise ship with
//! compile-only coverage.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::{RawPid, Resolved};

/// What `kill(pid, 0)` said about a pid whose `/proc` entry we could not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalProbe {
    /// `kill` returned 0: the process exists and we may signal it.
    Signalable,
    /// `ESRCH`: no such process.
    NoSuchProcess,
    /// `EPERM` (or any other errno): it exists, or we cannot tell.
    Denied,
    /// The value is not a single-process target at all, so no probe was issued.
    NotAPid,
}

/// The `kill(2)` target for `pid`, or `None` when `pid` is not a single-process target at
/// all. Rejecting those WITHOUT issuing the call is load-bearing: `kill(0, sig)` signals the
/// caller's own process group, and any value above `i32::MAX` wraps negative, where
/// `kill(-N, sig)` targets a whole group and `kill(-1, sig)` everything we may signal. All
/// of those succeed, so a leak here would fake a live process — or, at a real signal site,
/// SIGKILL the caller.
pub(crate) fn signal_target(pid: RawPid) -> Option<i32> {
    let p = i32::try_from(pid).ok()?;
    (p > 0).then_some(p)
}

/// `Resolved::Gone` only when the OS positively says "no such process". Everything else is
/// `Unknown`: an unreadable `/proc` entry is not evidence of death.
pub(crate) fn classify_unreadable(probe: SignalProbe) -> Resolved<()> {
    match probe {
        SignalProbe::NoSuchProcess | SignalProbe::NotAPid => Resolved::Gone,
        SignalProbe::Signalable | SignalProbe::Denied => Resolved::Unknown,
    }
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;
