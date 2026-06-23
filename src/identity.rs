//! Stable-across-time process identity.
//!
//! A bare PID is unsafe: the OS recycles PIDs, so the same number can name a
//! different process minutes later. [`ProcessId`] pairs the PID with a raw
//! kernel *start token* — a per-process value fixed at creation — so equality
//! distinguishes "the same process" from "a reused PID".
//!
//! The token is the RAW kernel value (Windows creation `FILETIME`, Linux
//! `/proc` `starttime` jiffies, macOS `proc_bsdinfo` start µs), compared
//! exactly. It is deliberately NOT a wall-clock time: deriving wall-clock from
//! boot time drifts under NTP and would silently break `Eq`/`Hash`. The
//! human-facing wall-clock lives in `created_at()` (Task 2), allowed to drift
//! and never used for identity.

pub(crate) mod stat_parse;

#[cfg_attr(windows, path = "identity/windows.rs")]
#[cfg_attr(target_os = "linux", path = "identity/linux.rs")]
#[cfg_attr(target_os = "macos", path = "identity/macos.rs")]
mod backend;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("subprocess::identity is implemented only for Windows, Linux, and macOS");

/// A process identifier as the OS knows it (matches `std::process::id`).
pub type RawPid = u32;

/// A raw, per-process kernel start value. Opaque: its only meaning is identity
/// (exact equality). Interpreted into a wall-clock time only by `created_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StartToken(u64);

impl StartToken {
    fn from_raw(v: u64) -> StartToken {
        StartToken(v)
    }

    fn raw(self) -> u64 {
        self.0
    }
}

/// A process identity that stays unique across time: `(pid, start_token)`.
/// `Eq`/`Hash` are over the pair, so a recycled PID never compares equal to the
/// original process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId {
    pid: RawPid,
    start: StartToken,
}

impl ProcessId {
    /// The raw OS process id. NOTE: a bare PID is not unique across time — use
    /// the whole `ProcessId` for identity, comparison, and map keys.
    pub fn pid(&self) -> RawPid {
        self.pid
    }

    /// The raw start token as a `u64`, for crate-internal ordering by creation
    /// time (the containment tree-walk keeps only descendants created at-or-after
    /// the root acquired its pid). Opaque outside identity ordering.
    pub(crate) fn start_token_raw(&self) -> u64 {
        self.start.raw()
    }

    /// Resolve the live identity of `pid`, or `None` if no such process is
    /// currently resolvable.
    pub fn of(pid: RawPid) -> Option<ProcessId> {
        let start = backend::start_token(pid)?;
        Some(ProcessId { pid, start })
    }

    /// Test-only constructor from raw parts, so sibling modules can build
    /// synthetic identities (with chosen pid/token) without a live process.
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(pid: RawPid, token: u64) -> ProcessId {
        ProcessId {
            pid,
            start: StartToken::from_raw(token),
        }
    }

    /// This process's own identity.
    pub fn current() -> ProcessId {
        let pid = std::process::id();
        ProcessId::of(pid).expect("the current process always has a resolvable identity")
    }

    /// Whether a process with this exact identity is still *resolvable* — the
    /// zombie-inclusive sense (matches psutil's `is_running`). Stays true for a
    /// not-yet-reaped Unix zombie and, on Windows, during the post-exit window
    /// while a process handle remains open. For "is it still running?", use
    /// [`ProcessId::is_alive`].
    pub fn exists(&self) -> bool {
        backend::start_token(self.pid) == Some(self.start)
    }

    /// Whether the process is currently *running* (has not exited). Authoritative
    /// and synchronously correct the instant the process exits — on Windows via
    /// the handle's signaled state, on Unix via process state / `/proc`
    /// presence. A reused PID (different start token) is never alive.
    pub fn is_alive(&self) -> bool {
        backend::is_running(self.pid, self.start)
    }

    /// Best-effort wall-clock creation time. Lazy and allowed to drift (NTP);
    /// NEVER used for identity. `None` if the process is gone or unavailable.
    pub fn created_at(&self) -> Option<std::time::SystemTime> {
        backend::created_at(self.start)
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
