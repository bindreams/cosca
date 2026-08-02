//! Stable-across-time process identity.
//!
//! A bare PID is unsafe: the OS recycles PIDs, so the same number can name a
//! different process minutes later. [`ProcessId`] pairs the PID with a raw
//! kernel *start token* — a per-process value fixed at creation — so equality
//! distinguishes "the same process" from "a reused PID".
//!
//! The token is the RAW kernel value (Windows creation `FILETIME`, Linux
//! `/proc` `starttime` jiffies, macOS `sysctl KERN_PROC` (`kinfo_proc`) start
//! µs), compared exactly. It is deliberately NOT a wall-clock time: deriving
//! wall-clock from boot time drifts under NTP and would silently break
//! `Eq`/`Hash`. The human-facing wall-clock lives in `created_at()`,
//! allowed to drift and never used for identity.

pub(crate) mod probe;
pub(crate) mod stat_parse;

#[path = "identity/state.rs"]
mod state;
pub use state::{Existence, Liveness, Resolved};

#[cfg_attr(windows, path = "identity/windows.rs")]
#[cfg_attr(target_os = "linux", path = "identity/linux.rs")]
#[cfg_attr(target_os = "macos", path = "identity/macos.rs")]
mod backend;

#[cfg(all(windows, test))]
#[path = "identity/windows_fixture.rs"]
pub(crate) mod windows_fixture;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("cosca::identity is implemented only for Windows, Linux, and macOS");

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

    /// Resolve the live identity of `pid`. [`Resolved::Gone`] means the OS reports no such
    /// process; [`Resolved::Unknown`] means it refused the question (typically an
    /// unprivileged caller querying a service) — the process may well be running.
    pub fn of(pid: RawPid) -> Resolved<ProcessId> {
        backend::start_token(pid).map(|start| ProcessId { pid, start })
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

    /// This process's own identity. Windows reads the current-process pseudo-handle, which
    /// performs no access check at all; Unix reads the caller's own entry by pid, which no
    /// `hidepid` mount or sandbox policy hides from the task itself. Either way it is
    /// resolvable even for a process whose own DACL would deny a foreign by-pid open.
    ///
    /// # Panics
    /// If the process cannot read its own start token: on Linux, if `/proc` is not mounted
    /// or its own `stat` record has no parseable `starttime` (both hard requirements of that
    /// backend); on Windows and macOS, if a self-directed `GetProcessTimes` / `proc_pidinfo`
    /// fails, which has no documented cause. Infallible by design — every caller, including
    /// `Process::current()`, relies on it.
    pub fn current() -> ProcessId {
        let start = backend::current_token()
            .found()
            .expect("a process must be able to read its own start token (Linux: /proc must be mounted)");
        ProcessId {
            pid: std::process::id(),
            start,
        }
    }

    /// Whether a process with this exact identity is still *resolvable* (the
    /// zombie-inclusive sense, matching psutil's `is_running`). [`Existence::Present`] for a
    /// not-yet-reaped zombie on every platform: Linux (`/proc` persists), macOS (`sysctl
    /// KERN_PROC` resolves zombies), and Windows (during the post-exit handle window).
    /// [`Existence::Unknown`] when the OS refuses the query — never `Gone`. For "is it still
    /// running?", use [`ProcessId::is_alive`].
    pub fn exists(&self) -> Existence {
        match backend::start_token(self.pid) {
            Resolved::Found(t) if t == self.start => Existence::Present,
            Resolved::Found(_) | Resolved::Gone => Existence::Gone,
            Resolved::Unknown => Existence::Unknown,
        }
    }

    /// Whether the process is currently *running* (has not exited). Authoritative and
    /// synchronously correct the instant the process exits — on Windows via the handle's
    /// signaled state, on Unix via process state / `/proc` presence. A reused PID (different
    /// start token) is never alive. [`Liveness::Unknown`] when the OS refuses the query, or
    /// answers ambiguously — never `Dead` on a process we could not assess.
    pub fn is_alive(&self) -> Liveness {
        backend::is_running(self.pid, self.start)
    }

    /// Best-effort wall-clock creation time. Lazy and allowed to drift (NTP);
    /// NEVER used for identity. `None` if the process is gone or unavailable.
    pub fn created_at(&self) -> Option<std::time::SystemTime> {
        backend::created_at(self.start)
    }
}

#[cfg(windows)]
pub(crate) use backend::{close as windows_close, open_classified as windows_open_classified, Opened};

/// What an ALREADY-OPEN Windows handle says about an identity. The held handle pins the
/// kernel object, so this is pid-reuse-safe (unlike re-resolving by raw pid).
#[cfg(windows)]
#[derive(Debug)]
pub(crate) enum HandleIdentity {
    /// The handle's creation token matches — it IS this process.
    Same,
    /// The token differs — the pid was recycled; the original is gone.
    Different,
    /// `GetProcessTimes` failed, so nothing was established. Never treat as "gone". Carries
    /// the failure for the same reason `Opened::Denied` does: by the time a caller wants to
    /// report it, `GetLastError` has been overwritten.
    Unreadable(windows::core::Error),
}

#[cfg(windows)]
pub(crate) fn windows_handle_identity(handle: windows::Win32::Foundation::HANDLE, id: ProcessId) -> HandleIdentity {
    match backend::creation_token_result(handle) {
        Ok(t) if t == id.start => HandleIdentity::Same,
        Ok(_) => HandleIdentity::Different,
        Err(e) => HandleIdentity::Unreadable(e),
    }
}

/// Build a `ProcessId` from an already-open Windows handle + its pid, reusing the
/// creation-token read (no second `OpenProcess`). Forwards to the private backend so
/// the runas launch can derive identity from the owned handle of a possibly-elevated
/// child without re-opening it by pid.
#[cfg(windows)]
pub(crate) fn windows_identity_from_handle(
    handle: windows::Win32::Foundation::HANDLE,
    pid: RawPid,
) -> Option<ProcessId> {
    backend::windows_identity_from_handle(handle, pid)
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
