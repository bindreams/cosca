//! Windows death-watch + kill. `OpenProcess` returns a HANDLE that pins the kernel
//! object, so a reused pid cannot fool it; we re-verify the start_token once at open.
//! No reaping concept on Windows.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CreateEventW, SetEvent, TerminateProcess, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

use crate::error::Error;
use crate::identity::{HandleIdentity, Liveness, Opened, ProcessId};

fn close(handle: HANDLE) {
    // Match identity/windows.rs: a failed CloseHandle of an owned handle is a contract
    // violation, asserted in debug.
    let closed = unsafe { CloseHandle(handle) };
    debug_assert!(closed.is_ok(), "CloseHandle of an owned process handle should not fail");
}

pub(crate) fn block_until_exit(id: ProcessId, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
    let handle = match crate::identity::windows_open_classified(
        id.pid(),
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
    ) {
        Opened::Found(h) => h,
        Opened::Gone => return Ok(true), // no such pid => exited
        // Denied on a LIVE process => a real failure: reporting "exited" would let a
        // supervisor conclude a healthy service had died. The error comes from the
        // classifier, not `last_os_error()`: `is_alive()` below runs a whole
        // open/query/wait cycle that would overwrite the thread-s last-error first.
        Opened::Denied(e) => {
            return match id.is_alive() {
                Liveness::Dead => Ok(true),
                Liveness::Alive | Liveness::Unknown => {
                    log::warn!(
                        "wait: pid {} could not be opened to watch for its exit ({e}) - reporting an error, not an exit",
                        id.pid()
                    );
                    Err(Error::Unassessable {
                        detail: format!("pid {} could not be opened to watch for its exit", id.pid()),
                        source: Some(e.into()),
                    })
                }
            }
        }
    };
    // The handle already in hand answers the recycle question with no race; a second by-pid
    // lookup would not.
    match crate::identity::windows_handle_identity(handle, id) {
        HandleIdentity::Same => {}
        HandleIdentity::Different => {
            close(handle);
            return Ok(true); // recycled before open - the original is gone
        }
        HandleIdentity::Unreadable(e) => {
            log::warn!(
                "wait: pid {} opened but its identity could not be verified ({e})",
                id.pid()
            );
            close(handle);
            return Err(Error::Unassessable {
                detail: format!("pid {} opened but its identity could not be verified", id.pid()),
                source: Some(e.into()),
            });
        }
    }
    let ms: u32 = match crate::wait::remaining(deadline) {
        None => INFINITE,
        Some(d) => d.as_millis().min((INFINITE - 1) as u128) as u32,
    };
    // SAFETY: `handle` is a live process handle held for the wait's duration.
    let waited = unsafe { WaitForSingleObject(handle, ms) };
    // A real wait call may legitimately reach here and still resolve at once: the
    // identity-verified handle can name an already-exited-but-not-yet-destroyed process
    // object, which is already signaled, so `WAIT_OBJECT_0` comes back promptly. Only
    // `WAIT_TIMEOUT` means the call genuinely spent its whole `ms` budget with nothing
    // signaled — see `real_wait_probe`'s own doc for why that, not mere entry, is what a test
    // must watch for.
    #[cfg(test)]
    if waited == WAIT_TIMEOUT {
        real_wait_probe::note_timeout(id);
    }
    // Capture BEFORE close(): CloseHandle would overwrite GetLastError.
    let wait_err = (waited != WAIT_OBJECT_0 && waited != WAIT_TIMEOUT).then(std::io::Error::last_os_error);
    close(handle);
    match wait_err {
        None => Ok(waited == WAIT_OBJECT_0), // exited, or WAIT_TIMEOUT => still alive
        Some(e) => Err(Error::Io(e)),
    }
}

/// An unnamed manual-reset event, initially unsignaled, for releasing
/// `block_until_exit_or_cancel` early. Signal with [`signal_cancel`]; `OwnedHandle` closes it.
// consumers: tokio::wait::grace_wait and the async raw backend (tokio::spawn::windows_raw).
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn new_cancel_event() -> Result<OwnedHandle, Error> {
    // SAFETY: creating an unnamed event has no preconditions; the handle is immediately
    // wrapped in an OwnedHandle, which closes it.
    let h = unsafe { CreateEventW(None, true, false, None) }.map_err(|e| Error::Io(e.into()))?;
    // SAFETY: `h` is a freshly created, owned event handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0 as _) })
}

// consumers: tokio::wait::grace_wait and the async raw backend (tokio::spawn::windows_raw).
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn signal_cancel(event: &OwnedHandle) {
    // SAFETY: `event` is a live event handle (the OwnedHandle keeps it open).
    let set = unsafe { SetEvent(HANDLE(event.as_raw_handle())) };
    // SetEvent on a live owned event has no documented failure mode; a silent failure would
    // degrade the cancellation contract to an unbounded park, so fail LOUD. Release builds
    // skip the assert during an unwind (the in-flight panic wins — never double-panic);
    // debug builds assert even then, an abort being an acceptable price for visibility there.
    debug_assert!(set.is_ok(), "SetEvent on an owned event handle failed: {set:?}");
    if !std::thread::panicking() {
        assert!(set.is_ok(), "SetEvent on an owned event handle failed: {set:?}");
    } else if let Err(e) = &set {
        // RELEASE unwind (a debug build already aborted above — visibility over grace,
        // the shipped policy): cannot assert while a panic is in flight, so leave the
        // loudest trace we can for the possible unbounded park.
        log::error!("SetEvent failed during unwind ({e}); a parked watcher may not release");
    }
}

/// `block_until_exit`, releasable early: returns `Ok(false)` as soon as `cancel` is signaled
/// (the process wins a tie — it is the lower wait index). `Ok(true)` = exited within `grace`;
/// `None` = unbounded.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))] // only consumer is tokio::wait::grace_wait
pub(crate) fn block_until_exit_or_cancel(
    id: ProcessId,
    grace: Option<Duration>,
    cancel: &OwnedHandle,
) -> Result<bool, Error> {
    let handle = match crate::identity::windows_open_classified(
        id.pid(),
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
    ) {
        Opened::Found(h) => h,
        Opened::Gone => return Ok(true), // no such pid => exited
        // Denied on a LIVE process => a real failure: reporting "exited" would let a
        // supervisor conclude a healthy service had died. The error comes from the
        // classifier, not `last_os_error()`: `is_alive()` below runs a whole
        // open/query/wait cycle that would overwrite the thread-s last-error first.
        Opened::Denied(e) => {
            return match id.is_alive() {
                Liveness::Dead => Ok(true),
                Liveness::Alive | Liveness::Unknown => {
                    log::warn!(
                        "wait: pid {} could not be opened to watch for its exit ({e}) - reporting an error, not an exit",
                        id.pid()
                    );
                    Err(Error::Unassessable {
                        detail: format!("pid {} could not be opened to watch for its exit", id.pid()),
                        source: Some(e.into()),
                    })
                }
            }
        }
    };
    // The handle already in hand answers the recycle question with no race; a second by-pid
    // lookup would not.
    match crate::identity::windows_handle_identity(handle, id) {
        HandleIdentity::Same => {}
        HandleIdentity::Different => {
            close(handle);
            return Ok(true); // recycled before open - the original is gone
        }
        HandleIdentity::Unreadable(e) => {
            log::warn!(
                "wait: pid {} opened but its identity could not be verified ({e})",
                id.pid()
            );
            close(handle);
            return Err(Error::Unassessable {
                detail: format!("pid {} opened but its identity could not be verified", id.pid()),
                source: Some(e.into()),
            });
        }
    }
    let ms = match grace {
        None => INFINITE,
        // Capped at INFINITE-1 (~49.7 days) — the cancel event releases large graces early;
        // a debug_assert flags the rare clamp.
        Some(d) => {
            let clamped = d.as_millis().min((INFINITE - 1) as u128) as u32;
            debug_assert!(
                d.as_millis() <= (INFINITE - 1) as u128,
                "Windows grace clamped to INFINITE-1 ms (~49.7 days): {}",
                d.as_secs()
            );
            clamped
        }
    };
    let handles = [handle, HANDLE(cancel.as_raw_handle())];
    // SAFETY: both handles are live for the wait's duration.
    let waited = unsafe { WaitForMultipleObjects(&handles, false, ms) };
    // A real wait call may legitimately reach here and still resolve at once: the
    // identity-verified handle can name an already-exited-but-not-yet-destroyed process
    // object, which is already signaled, so `WAIT_OBJECT_0` comes back promptly. Only
    // `WAIT_TIMEOUT` means the call genuinely spent its whole `ms` budget with nothing
    // signaled — see `real_wait_probe`'s own doc for why that, not mere entry, is what a test
    // must watch for.
    #[cfg(test)]
    if waited == WAIT_TIMEOUT {
        real_wait_probe::note_timeout(id);
    }
    // Capture BEFORE close(): CloseHandle would overwrite GetLastError.
    let wait_failed = (waited == WAIT_FAILED).then(std::io::Error::last_os_error);
    close(handle);
    if waited == WAIT_OBJECT_0 {
        Ok(true) // process exited
    } else if waited.0 == WAIT_OBJECT_0.0 + 1 || waited == WAIT_TIMEOUT {
        Ok(false) // released by cancel, or grace elapsed — still alive either way
    } else if let Some(e) = wait_failed {
        Err(Error::Io(e))
    } else {
        // Events cannot be abandoned (a mutex verdict); anything else is undocumented.
        // Report the raw verdict — GetLastError is only meaningful for WAIT_FAILED.
        debug_assert!(false, "unexpected WaitForMultipleObjects verdict: {waited:?}");
        Err(Error::Io(std::io::Error::other(format!(
            "unexpected WaitForMultipleObjects result: {waited:?}"
        ))))
    }
}

pub(crate) fn kill(id: ProcessId) -> Result<(), Error> {
    // Open for terminate AND query, so the SAME held handle both pins the kernel object
    // (pid-reuse-safe) and lets us re-verify identity before terminating.
    // SAFETY: OpenProcess tolerates an invalid pid; the handle is closed on every path below.
    let handle =
        match crate::identity::windows_open_classified(id.pid(), PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)
        {
            Opened::Found(h) => h,
            Opened::Gone => return Ok(()), // no such pid => already dead is success
            // Live-or-unassessable => Err. An Unknown liveness must NOT be reported as a
            // successful kill.
            Opened::Denied(e) => {
                return if id.is_alive() == Liveness::Dead {
                    Ok(())
                } else {
                    log::warn!(
                        "wait: pid {} could not be opened to terminate it ({e}) - reporting an error, not a kill",
                        id.pid()
                    );
                    Err(Error::Unassessable {
                        detail: format!("pid {} could not be opened to terminate it", id.pid()),
                        source: Some(e.into()),
                    })
                }
            }
        };
    // Re-verify identity on the HELD handle: a pid recycled before the open pins the NEW
    // process, whose creation token will not match. An UNREADABLE token is not proof the
    // target is gone, so it must not report a successful kill.
    match crate::identity::windows_handle_identity(handle, id) {
        HandleIdentity::Same => {}
        HandleIdentity::Different => {
            close(handle);
            return Ok(()); // pid recycled; the original is already gone
        }
        HandleIdentity::Unreadable(e) => {
            log::warn!(
                "wait: pid {} opened but its identity could not be verified ({e})",
                id.pid()
            );
            close(handle);
            return Err(Error::Unassessable {
                detail: format!("pid {} opened but its identity could not be verified", id.pid()),
                source: Some(e.into()),
            });
        }
    }
    // SAFETY: handle is live; close on every path.
    let res = unsafe { TerminateProcess(handle, 1) };
    // Re-check BEFORE close: the held handle pins the kernel object, so the by-pid resolve
    // inside `is_alive` cannot land on a recycled pid. After `close` it could. Windows denies
    // TerminateProcess on an already-exited process, so this arm is reached routinely on a
    // successful shutdown, and `is_alive` reads the SIGNALED STATE - unambiguous, unlike
    // GetExitCodeProcess, which cannot tell a live process from one that exited with 259.
    let verdict = res.is_err().then(|| id.is_alive());
    close(handle);
    match res {
        Ok(()) => Ok(()),
        Err(_) if verdict == Some(Liveness::Dead) => Ok(()),
        Err(e) => {
            log::warn!(
                "wait: TerminateProcess(pid {}) failed and the target is not provably dead ({e})",
                id.pid()
            );
            Err(Error::Io(e.into()))
        }
    }
}

pub(crate) fn terminate(id: ProcessId) -> Result<(), Error> {
    let _ = id;
    Err(Error::Unsupported {
        op: "graceful terminate (SIGTERM-equivalent)".into(),
        platform: "windows",
        detail: "Windows has no per-process graceful-termination signal; for a contained \
                 child use graceful_shutdown_tree (CTRL_BREAK to the group)"
            .into(),
    })
}

/// Test-only instrumentation proving whether `block_until_exit`/`block_until_exit_or_cancel`
/// genuinely spent a real wait's whole timeout budget with nothing signaled
/// (`WaitForSingleObject`/`WaitForMultipleObjects` returning `WAIT_TIMEOUT`), rather than
/// resolving promptly.
///
/// **Not "was the real wait call entered at all."** Measured on real Windows CI (see the PR that
/// introduced this module): the identity-verified handle can legitimately still name an
/// already-exited-but-not-yet-destroyed process object — the pid not yet recycled, `OpenProcess`
/// finding the SAME process, `HandleIdentity::Same` — and a real wait call on that handle then
/// returns `WAIT_OBJECT_0` near-instantly, because the target is already signaled. That is a
/// correct, common outcome, not the regression class this probe exists to catch, and an
/// entry-based counter flagged it as a false positive. `WAIT_TIMEOUT` is the unambiguous signal
/// that the call blocked for (approximately) its whole timeout with nothing becoming signaled —
/// the actual shape of "a root-only watch that waits out the grace."
///
/// Keyed by [`ProcessId`], not a single shared counter. `note_timeout`/`timeouts_for` run for
/// EVERY caller of `block_until_exit`/`block_until_exit_or_cancel` in the whole binary — the
/// sync API's own timed waits go through the same backend — so a process-wide counter, even
/// sampled as a before/after delta, can be ticked by an UNRELATED test's own live child on
/// another thread landing inside the narrow window between a test's two samples. That is not
/// hypothetical: `grace_wait_false_for_live_child_at_zero_grace`
/// (`src/tokio/wait_tests.rs`) deliberately drives a live child to a real `WAIT_TIMEOUT` at
/// `Duration::ZERO` as its own correct, expected outcome, and it can run concurrently with any
/// other test under plain `cargo test`'s shared-process model. Keying by the identity under
/// test makes that impossible: no other process can ever share a `ProcessId` — the same
/// anti-pid-reuse pairing (`identity.rs`) this crate already relies on everywhere else. A test
/// therefore reads its OWN child's count, which starts at zero (a freshly spawned test child's
/// `ProcessId` has never been seen before) and needs no before/after sampling at all.
///
/// Entries are never removed — append-only, like `log_capture.rs`'s records — negligible growth
/// over one test run, and removal would only reintroduce a cross-test race.
///
/// A GLOBAL `OnceLock`, not a `thread_local!` — the one place in this module that must be, and
/// this is the justification: both instrumented calls run inside a `spawn_blocking` closure
/// (`crate::tokio::wait::blocking_watch`), dispatched to a tokio blocking-pool thread distinct
/// from the async task that later asserts on the count. A thread-local counter would never be
/// visible there.
#[cfg(test)]
pub(crate) mod real_wait_probe {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use crate::identity::ProcessId;

    static REAL_WAIT_TIMEOUTS: OnceLock<Mutex<HashMap<ProcessId, u32>>> = OnceLock::new();

    fn map() -> &'static Mutex<HashMap<ProcessId, u32>> {
        REAL_WAIT_TIMEOUTS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(crate) fn note_timeout(id: ProcessId) {
        *map().lock().unwrap().entry(id).or_insert(0) += 1;
    }

    // The only consumer is the tokio TreeWalk fast-path test
    // (`windows_async_treewalk_grants_no_grace_window_once_the_backend_has_reaped`), so this is
    // dead code in a `--no-default-features` (no `tokio`) build — same shape as
    // `block_until_exit_or_cancel`'s own `allow(dead_code)` just above.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn timeouts_for(id: ProcessId) -> u32 {
        map().lock().unwrap().get(&id).copied().unwrap_or(0)
    }
}
