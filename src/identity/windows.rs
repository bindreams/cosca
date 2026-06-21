//! Windows process-identity backend.
//!
//! - `start_token`: raw creation `FILETIME` (identity, NOT epoch-adjusted).
//! - `created_at`: that 100 ns-since-1601 value converted to `SystemTime`.
//! - `is_running`: authoritative "not exited" via `WaitForSingleObject(_, 0)`,
//!   which tests the process's *signaled state* — so it flips to dead the
//!   instant the process exits, without the object-teardown window that an
//!   existence check (`OpenProcess` succeeding) would have.

use std::time::{Duration, SystemTime};

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use super::{RawPid, StartToken};

/// 100 ns intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01 (Unix).
const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

/// Read the creation FILETIME of an open process handle as a raw token.
// SAFETY: `handle` must be a live process handle with QUERY_LIMITED rights.
fn creation_token(handle: HANDLE) -> Option<StartToken> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let res = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    res.ok()?;
    let ft = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    Some(StartToken::from_raw(ft))
}

pub(super) fn start_token(pid: RawPid) -> Option<StartToken> {
    // PROCESS_QUERY_LIMITED_INFORMATION works without elevation for most
    // processes (incl. services). SAFETY: OpenProcess tolerates an invalid pid
    // (returns Err); the handle is closed before return.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let token = creation_token(handle);
    let closed = unsafe { CloseHandle(handle) };
    debug_assert!(closed.is_ok(), "CloseHandle of an owned process handle should not fail");
    token
}

pub(super) fn created_at(start: StartToken) -> Option<SystemTime> {
    let unix_100ns = start.raw().checked_sub(EPOCH_DIFF_100NS)?;
    let secs = unix_100ns / 10_000_000;
    let nanos = (unix_100ns % 10_000_000) * 100;
    Some(SystemTime::UNIX_EPOCH + Duration::new(secs, nanos as u32))
}

pub(super) fn is_running(pid: RawPid, start: StartToken) -> bool {
    // SYNCHRONIZE lets us WaitForSingleObject; QUERY_LIMITED lets us read the
    // creation time to reject a reused PID. SAFETY: OpenProcess tolerates an
    // invalid pid; the handle is closed before every return path.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) } {
        Ok(h) => h,
        Err(_) => return false, // gone (or unopenable) => not running
    };
    let running = match creation_token(handle) {
        // Same identity AND not signaled (WAIT_TIMEOUT) => still running.
        Some(t) if t == start => {
            // SAFETY: `handle` is live; a 0 ms wait never blocks. (A `let` binding
            // is required here: `unsafe { .. } == X` does not parse as a bare arm body.)
            let signaled = unsafe { WaitForSingleObject(handle, 0) };
            signaled == WAIT_TIMEOUT
        }
        _ => false, // reused PID (different creation time) or unreadable
    };
    let closed = unsafe { CloseHandle(handle) };
    debug_assert!(closed.is_ok(), "CloseHandle of an owned process handle should not fail");
    running
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
