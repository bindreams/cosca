//! Windows process-identity backend.
//!
//! - `start_token`: raw creation `FILETIME` (identity, NOT epoch-adjusted).
//! - `created_at`: that 100 ns-since-1601 value converted to `SystemTime`.
//! - `is_running`: authoritative "not exited" via `WaitForSingleObject(_, 0)`, which tests
//!   the process's *signaled state* — so it flips to dead the instant the process exits,
//!   without the object-teardown window that an existence check (`OpenProcess` succeeding)
//!   would have. Reading the signaled state needs `SYNCHRONIZE`; when only
//!   `PROCESS_QUERY_LIMITED_INFORMATION` is granted, `GetExitCodeProcess` can still prove an
//!   exit but not the absence of one.
//!
//! An `OpenProcess` failure is classified, never collapsed: `ERROR_INVALID_PARAMETER` is the
//! OS saying "no such pid" and is the ONLY failure that means absence. Everything else —
//! `ERROR_ACCESS_DENIED` above all — means we were not allowed to ask.

use std::time::{Duration, SystemTime};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, STILL_ACTIVE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_ACCESS_RIGHTS,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use super::{Liveness, RawPid, Resolved, StartToken};

/// 100 ns intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01 (Unix).
const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

/// The `OpenProcess` failure that means "no such pid". Derived, never hand-packed: this
/// constant is the crate's whole classification rule, and one wrong nibble in a literal
/// would silently reclassify every access-denied process as gone.
pub(crate) const ERROR_INVALID_PARAMETER_HRESULT: windows::core::HRESULT =
    windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER.0);

/// The outcome of a classified `OpenProcess`. `Denied` carries the failure because a caller
/// that has to report it cannot recover it afterwards: `GetLastError` is thread-global and
/// every intervening call overwrites it.
pub(crate) enum Opened {
    Found(HANDLE),
    /// `ERROR_INVALID_PARAMETER` — the OS's "no such pid". The ONLY failure meaning absence.
    Gone,
    /// Anything else, `ERROR_ACCESS_DENIED` above all: we were not allowed to ask.
    Denied(windows::core::Error),
}

/// `OpenProcess` with `mask`, classified. The crate's single rule. The caller closes the
/// handle.
pub(crate) fn open_classified(pid: RawPid, mask: PROCESS_ACCESS_RIGHTS) -> Opened {
    // SAFETY: OpenProcess tolerates any pid value (it returns Err).
    match unsafe { OpenProcess(mask, false, pid) } {
        Ok(h) => Opened::Found(h),
        Err(e) if e.code() == ERROR_INVALID_PARAMETER_HRESULT => Opened::Gone,
        // `debug`, not `warn`: the tree-walk calls this once per pid per sweep. The event is
        // reported at `warn` exactly once, by the call site that decided what the denial
        // means; this line is the per-call detail — which pid, which mask — that those
        // messages cannot carry.
        Err(e) => {
            log::debug!("OpenProcess({pid}, {mask:?}) failed: {e} — reporting Unknown, not absence");
            Opened::Denied(e)
        }
    }
}

pub(crate) fn close(handle: HANDLE) {
    // SAFETY: `handle` is an owned process handle.
    if let Err(e) = unsafe { CloseHandle(handle) } {
        log::warn!("CloseHandle of an owned process handle failed: {e}");
        debug_assert!(false, "CloseHandle of an owned process handle should not fail: {e}");
    }
}

/// Read the creation FILETIME of an open process handle as a raw token, preserving the
/// failure. `creation_token` is this with the error dropped.
// SAFETY: `handle` must be a live process handle with QUERY_LIMITED rights.
pub(crate) fn creation_token_result(handle: HANDLE) -> windows::core::Result<StartToken> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }?;
    let ft = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    Ok(StartToken::from_raw(ft))
}

pub(super) fn creation_token(handle: HANDLE) -> Option<StartToken> {
    creation_token_result(handle).ok()
}

/// Build a `ProcessId` from an already-open Windows process handle and its pid, reusing the
/// creation-token read. Avoids a second `OpenProcess` (which can fail and would otherwise
/// force dropping a live elevated child).
pub(crate) fn windows_identity_from_handle(handle: HANDLE, pid: RawPid) -> Option<crate::identity::ProcessId> {
    let start = creation_token(handle)?;
    Some(crate::identity::ProcessId { pid, start })
}

/// This process's own start token, read from the pseudo-handle. `GetCurrentProcess` performs
/// NO access check, so unlike a by-pid open this cannot be denied — which matters for a
/// process whose own DACL is restricted (AppContainer, low integrity).
pub(super) fn current_token() -> Resolved<StartToken> {
    // SAFETY: the pseudo-handle is always valid and must not be closed.
    match creation_token(unsafe { GetCurrentProcess() }) {
        Some(t) => Resolved::Found(t),
        // No log: `ProcessId::current()` turns this into a panic whose message says the same
        // thing, louder.
        None => Resolved::Unknown,
    }
}

pub(super) fn start_token(pid: RawPid) -> Resolved<StartToken> {
    // PROCESS_QUERY_LIMITED_INFORMATION is the weakest mask that can read the creation time,
    // and it is not universally granted to an unelevated caller — a failure here is
    // classified rather than treated as absence.
    let handle = match open_classified(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Opened::Found(h) => h,
        Opened::Gone => return Resolved::Gone,
        Opened::Denied(_) => return Resolved::Unknown,
    };
    let token = creation_token_result(handle);
    close(handle);
    match token {
        Ok(t) => Resolved::Found(t),
        // The open SUCCEEDED, so the process object exists. A GetProcessTimes failure is not
        // evidence of absence — and it is reachable when the process exits mid-query, so it
        // must not be an assertion.
        Err(e) => {
            log::debug!("GetProcessTimes failed on an opened handle for pid {pid}: {e}");
            Resolved::Unknown
        }
    }
}

pub(super) fn created_at(start: StartToken) -> Option<SystemTime> {
    let unix_100ns = start.raw().checked_sub(EPOCH_DIFF_100NS)?;
    let secs = unix_100ns / 10_000_000;
    let nanos = (unix_100ns % 10_000_000) * 100;
    Some(SystemTime::UNIX_EPOCH + Duration::new(secs, nanos as u32))
}

pub(super) fn is_running(pid: RawPid, start: StartToken) -> Liveness {
    // Fast path: one open for both rights. SYNCHRONIZE lets us WaitForSingleObject;
    // QUERY_LIMITED lets us read the creation time to reject a reused PID.
    let both = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    let handle = match open_classified(pid, both) {
        Opened::Found(h) => h,
        Opened::Gone => return Liveness::Dead,
        Opened::Denied(_) => return liveness_without_synchronize(pid, start),
    };
    let verdict = match creation_token_result(handle) {
        Ok(t) if t == start => {
            // SAFETY: `handle` is live; a 0 ms wait never blocks. (A `let` binding is
            // required: `unsafe { .. } == X` does not parse as a bare arm body.)
            let signaled = unsafe { WaitForSingleObject(handle, 0) };
            match signaled {
                WAIT_TIMEOUT => Liveness::Alive,
                WAIT_OBJECT_0 => Liveness::Dead,
                // WAIT_FAILED and anything undocumented: the wait never reported on the
                // process, so we learned nothing.
                other => {
                    log::debug!("WaitForSingleObject(pid {pid}, 0) returned {other:?}");
                    Liveness::Unknown
                }
            }
        }
        Ok(_) => Liveness::Dead, // reused PID: a different process holds it now
        Err(e) => {
            // Opened but unreadable — never claim Dead.
            log::debug!("GetProcessTimes failed on an opened handle for pid {pid}: {e}");
            Liveness::Unknown
        }
    };
    close(handle);
    verdict
}

/// The `SYNCHRONIZE`-denied path. `QUERY_LIMITED` alone still rejects a reused pid and still
/// lets `GetExitCodeProcess` PROVE an exit. It cannot prove the converse: a process that
/// exits with code 259 reports `STILL_ACTIVE` forever, so `STILL_ACTIVE` yields `Unknown`,
/// never `Alive`.
fn liveness_without_synchronize(pid: RawPid, start: StartToken) -> Liveness {
    let handle = match open_classified(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Opened::Found(h) => h,
        Opened::Gone => return Liveness::Dead,
        Opened::Denied(_) => return Liveness::Unknown,
    };
    // The identity check runs on the HELD handle, which pins the kernel object, so no
    // recycle can slip between the check and the exit-code read.
    let verdict = match creation_token_result(handle) {
        Err(e) => {
            log::debug!("GetProcessTimes failed on an opened handle for pid {pid}: {e}");
            Liveness::Unknown
        }
        Ok(t) if t != start => Liveness::Dead, // reused PID
        Ok(_) => {
            let mut code = 0u32;
            // SAFETY: `handle` is live and carries QUERY_LIMITED, which is what
            // GetExitCodeProcess requires.
            match unsafe { GetExitCodeProcess(handle, &mut code) } {
                Ok(()) if code != STILL_ACTIVE.0 as u32 => Liveness::Dead,
                Ok(()) => Liveness::Unknown,
                Err(e) => {
                    log::debug!("GetExitCodeProcess failed on an opened handle for pid {pid}: {e}");
                    Liveness::Unknown
                }
            }
        }
    };
    close(handle);
    verdict
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;

/// Windows creation `FILETIME` is an absolute count of 100 ns ticks since 1601-01-01 UTC:
/// recorded once, at creation, and unchanged by a reboot. There is nothing to scope it by.
pub(super) fn session_scope() -> Result<super::persist::Scope, super::persist::ScopeReadError> {
    Ok(super::persist::Scope::none())
}
