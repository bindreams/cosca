//! Windows death-watch + kill. `OpenProcess` returns a HANDLE that pins the kernel
//! object, so a reused pid cannot fool it; we re-verify the start_token once at open.
//! No reaping concept on Windows.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CreateEventW, SetEvent, TerminateProcess, WaitForMultipleObjects, WaitForSingleObject,
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
    // Armed in rounds: a `WAIT_TIMEOUT` is UNCONDITIONALLY rechecked against the real deadline
    // and re-armed rather than ever trusted outright. Per Microsoft's Wait Functions and
    // Time-out Intervals: "If the time-out interval is less than the resolution of the system
    // clock, the wait may time out in less than the specified length of time" — even an
    // un-clamped, correctly-ceiled `ms` can return early on real hardware, so the recheck below
    // is not conditional on whether `win32_timeout_ms`'s clamp (production: `INFINITE - 1`,
    // ~49.7 days; test: `wait_clamp_seam`) fired this round — that clamp is a second, much
    // larger-gap reason the same recheck is needed, not the only one. `remaining` is recomputed
    // FRESH every iteration (never hoisted above the loop) — see docs/principles.md #13.
    let waited = loop {
        let ms = crate::wait::win32_timeout_ms(crate::wait::remaining(deadline));
        // SAFETY: `handle` is a live process handle held for the wait's duration.
        let w = unsafe { WaitForSingleObject(handle, ms) };
        if w != WAIT_TIMEOUT || crate::wait::remaining(deadline) == Some(Duration::ZERO) {
            break w;
        }
    };
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
/// (the process wins a tie — it is the lower wait index). `Ok(true)` = exited within the
/// deadline; `None`/`Some(None)` = unbounded. `deadline` is an absolute `Instant` the caller
/// computed before ever reaching this function — every re-arm below recomputes its remaining
/// time against this SAME absolute instant (via `crate::wait::remaining_at`), so a caller that
/// hands this off through `spawn_blocking` (as `grace_wait` does) never starts the deadline
/// counting late just because the blocking pool was slow to pick up the task, and a re-arm
/// never resets the clock either.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))] // only consumer is tokio::wait::grace_wait
pub(crate) fn block_until_exit_or_cancel(
    id: ProcessId,
    deadline: Option<Option<Instant>>,
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
    // Test-only anchor: a sequence number fetched immediately after the real `OpenProcess`
    // syscall above returns — a fixed point a mutant that hoists the loop's `remaining` read
    // above this call cannot land after. A counter, not an `Instant`, so the ordering proof
    // below never depends on two clock reads happening to differ — see
    // `deadline_observer`'s own doc.
    #[cfg(test)]
    let before_identity_seq = deadline_observer::next_seq();
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
    // Test-only seam proving (immediately, not by elapsed time) that this wait is never
    // genuinely entered on a still-alive target — see `armed_probe`'s own doc for why it's
    // gated on `is_armed()`.
    #[cfg(test)]
    if armed_probe::is_armed() {
        // SAFETY: `handle` is a live, identity-verified process handle; ms=0 is a
        // non-blocking poll, never a wait.
        let already = unsafe { WaitForSingleObject(handle, 0) };
        if already == WAIT_FAILED {
            // Capture BEFORE anything else could overwrite GetLastError.
            let e = std::io::Error::last_os_error();
            // `handle` was identity-verified moments ago — a non-blocking poll on it failing
            // is a contract violation, not "not yet signalled" (the WAIT_TIMEOUT case below).
            // Must never reach `notify_armed_unsignalled`: folding an OS failure into "armed
            // on an unsignalled target" would false-flag a correct run as the very regression
            // this seam exists to catch.
            debug_assert!(
                false,
                "armed_probe: non-blocking poll of an identity-verified handle failed: {e}"
            );
        } else if already != WAIT_OBJECT_0 {
            armed_probe::notify_armed_unsignalled();
            // Force the real wait below to return at once instead of genuinely spending
            // `ms` — a bug this seam catches must fail fast, not hang out the grace.
            signal_cancel(cancel);
        }
    }
    let handles = [handle, HANDLE(cancel.as_raw_handle())];
    // Armed in rounds: a `WAIT_TIMEOUT` is UNCONDITIONALLY rechecked against the real deadline
    // and re-armed rather than ever trusted outright. Per Microsoft's Wait Functions and
    // Time-out Intervals: "If the time-out interval is less than the resolution of the system
    // clock, the wait may time out in less than the specified length of time" — even an
    // un-clamped, correctly-ceiled `ms` can return early on real hardware, so the recheck below
    // is not conditional on whether `win32_timeout_ms`'s clamp (production: `INFINITE - 1`,
    // ~49.7 days — the cancel event releases large graces early; test: `wait_clamp_seam`) fired
    // this round — that clamp is a second, much larger-gap reason the same recheck is needed,
    // not the only one; it is also why a grace longer than the clamp is still honored correctly
    // instead of being silently capped. `remaining` is recomputed FRESH every iteration (never
    // hoisted above the loop) — see docs/principles.md #13.
    let waited = loop {
        let reading = read_remaining(deadline);
        // Test-only: report what this call actually used. `reading` ties the remaining time to
        // the very `now` and sequence number taken with it, so a mutant that hoists the read
        // above `OpenProcess` carries all three with it.
        #[cfg(test)]
        deadline_observer::notify(id, deadline, &reading, before_identity_seq);
        let remaining = reading.remaining;
        let ms = crate::wait::win32_timeout_ms(remaining);
        // SAFETY: both handles are live for the wait's duration.
        let w = unsafe { WaitForMultipleObjects(&handles, false, ms) };
        if w != WAIT_TIMEOUT || crate::wait::remaining(deadline) == Some(Duration::ZERO) {
            break w;
        }
    };
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

/// Test-only seam proving a root-only watch on an already-reaped root never reaches a live
/// target — immediately, never by elapsed time. A `WAIT_TIMEOUT`-based counter could only ever
/// be told apart from correct code by how long the call ran, which would make elapsed time the
/// real assertion.
///
/// An already-reaped root does not pin down WHICH of `block_until_exit_or_cancel`'s three
/// outcomes it lands on (`Opened::Gone`, an already-signalled `HandleIdentity::Same`, or
/// `HandleIdentity::Different` — the last only if the OS recycles the pid in the window before
/// the watch opens it), so this alone does not deterministically prove the `Different` mutant is
/// caught. `grace_wait_resolves_immediately_on_an_identity_mismatch`
/// (`src/tokio/wait_tests.rs`) proves that one directly: a genuinely live child watched under an
/// identity naming the same pid but a wrong start token is `Different` on every run.
///
/// The call site (`block_until_exit_or_cancel`, just before the real wait) only polls and acts
/// when [`is_armed`] is true. `block_until_exit_or_cancel` is the SAME function every other
/// grace-wait test in the binary calls, several of them precisely to watch a genuinely
/// still-alive target run its real wait to completion (e.g.
/// `grace_wait_true_when_child_dies_mid_wait`); gating on `is_armed` is what keeps this seam
/// from force-releasing THEIR waits too. Only once armed does it do a non-blocking
/// `WaitForSingleObject(handle, 0)` on the TARGET — not `cancel` — the instant before the real
/// wait would be entered. If that target is not ALREADY signaled (the process has not already
/// exited), this is exactly the regression shape this test exists to catch: a real wait is
/// about to be genuinely entered on a live target. [`notify_armed_unsignalled`] fires, and the
/// call site immediately force-signals `cancel` so the real wait that follows returns at once
/// instead of genuinely spending the grace — a caught bug fails fast, not slow.
///
/// `thread_local!`, NOT a process-global slot — a global (even one gated by `is_armed`) is
/// still visible from every thread, so under plain `cargo test`'s shared-process, many-threads
/// model (which cosca must pass) a concurrent, unrelated test's `block_until_exit_or_cancel`
/// call on ANOTHER thread would see `is_armed() == true` while this test's guard is installed,
/// find ITS OWN target unsignalled, and get force-cancelled too — cross-test interference.
///
/// `block_until_exit_or_cancel` runs inside `tokio::task::spawn_blocking`'s closure, on a
/// blocking-pool thread distinct from the one that called `grace_wait` (the "arming" thread), so
/// a thread-local written there is not, by itself, visible on the blocking-pool thread.
/// `blocking_watch` (`src/tokio/wait.rs`) bridges the two threads: it reads [`current`] on the
/// arming thread before `spawn_blocking`, then re-[`install`]s the cloned sender on the
/// blocking-pool thread for that call's scope.
#[cfg(test)]
pub(crate) mod armed_probe {
    use std::cell::RefCell;
    use std::sync::mpsc::Sender;

    thread_local! {
        static ARMED_TX: RefCell<Option<Sender<()>>> = const { RefCell::new(None) };
    }

    /// Installs `tx` as the CURRENT thread's observer for the guard's lifetime, restoring
    /// whatever was there before (always `None` in every real use — this repo never nests two
    /// installs on one thread) on drop, even on unwind, so a panicking test or a reused
    /// blocking-pool thread never carries a stale observer forward.
    // Consumers are the tokio TreeWalk fast-path test
    // (`windows_async_treewalk_grants_no_grace_window_once_the_backend_has_reaped`) and
    // `grace_wait_resolves_immediately_on_an_identity_mismatch`, both `tokio`-only, so this is
    // dead code in a `--no-default-features` (no `tokio`) build — same shape as
    // `block_until_exit_or_cancel`'s own `allow(dead_code)` just above.
    //
    // `!Send`, via the `PhantomData<*const ()>` marker: the whole point is that dropping it
    // clears the thread-local slot IT WAS INSTALLED ON. A `Guard` sent to another thread and
    // dropped there would restore `self.0` into THAT thread's cell instead — corrupting an
    // unrelated thread's (possibly a live test's) observer state.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) struct Guard(Option<Sender<()>>, std::marker::PhantomData<*const ()>);

    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn install(tx: Sender<()>) -> Guard {
        let prev = ARMED_TX.with(|cell| cell.replace(Some(tx)));
        debug_assert!(prev.is_none(), "armed_probe::install nested on the same thread");
        Guard(prev, std::marker::PhantomData)
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            ARMED_TX.with(|cell| *cell.borrow_mut() = self.0.take());
        }
    }

    /// The CURRENT thread's installed observer, if any — read on the arming thread, before
    /// `spawn_blocking`, so `blocking_watch` can `move` it into that closure. Cloned, not
    /// taken: the arming thread's own installation must survive for its guard's whole
    /// lifetime, which may span more than one `blocking_watch` call (e.g. `wait_exit`'s retry
    /// loop).
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn current() -> Option<Sender<()>> {
        ARMED_TX.with(|cell| cell.borrow().clone())
    }

    /// Whether the CURRENT thread has an observer installed — gates the call site's poll and
    /// forced cancel so they run only for the one test that opted in, never for any other
    /// caller of `block_until_exit_or_cancel` in the same binary or on another thread.
    pub(crate) fn is_armed() -> bool {
        ARMED_TX.with(|cell| cell.borrow().is_some())
    }

    pub(crate) fn notify_armed_unsignalled() {
        ARMED_TX.with(|cell| {
            if let Some(tx) = cell.borrow().as_ref() {
                let _ = tx.send(());
            }
        });
    }
}

/// One read of the clock and the time remaining to `deadline` computed from that same reading,
/// so a test observer can prove which reading a wait was armed from.
pub(crate) struct Reading {
    #[cfg(test)]
    now: Instant,
    remaining: Option<Duration>,
    /// Test-only sequence number taken with the read, later than every number handed out before.
    #[cfg(test)]
    seq: u64,
}

fn read_remaining(deadline: Option<Option<Instant>>) -> Reading {
    let now = crate::wait::now();
    Reading {
        remaining: crate::wait::remaining_at(deadline, now),
        #[cfg(test)]
        now,
        #[cfg(test)]
        seq: deadline_observer::next_seq(),
    }
}

/// Deliberate test scaffolding: reports what `block_until_exit_or_cancel` actually used at the
/// FIRST `remaining` read inside its retry loop — on a channel the TEST owns exclusively,
/// keyed by the target `ProcessId` (not one shared global slot) so tests running concurrently
/// in the SAME process under plain `cargo test` — nextest's one-process-per-test isolation is
/// not guaranteed here — can never cross-feed each other's notifications. [`install`] returns
/// an [`InstallGuard`] that removes the entry on drop, so a finished test's sender cannot
/// linger and answer a LATER test that happens to reuse the same pid.
///
/// Two things a test can check, both required to prove principle 13 ("never late by cosca's
/// own choice"):
/// - `Used::deadline` vs `crate::tokio::wait::grace_wait_armed_observer`'s report: paired,
///   for EXACT equality, to prove the wait is armed from the single deadline `grace_wait`
///   computed before ever calling `spawn_blocking`, never a value re-derived after crossing
///   the blocking-pool boundary. Made deterministic (not a clock-resolution bet) by the
///   `armed` side using `crate::wait::deadline_from_override_seam` to force a made-up instant:
///   a callee that only threads the value through reports that same made-up instant back; one
///   that re-derives it (on a different thread, where the override does not apply) reports a
///   real, later instant instead — always unequal.
/// - `Used::used_seq` vs `Used::before_identity_seq`: `used_seq` is fetched where `remaining`
///   is actually read (first loop iteration); `before_identity_seq`, right after the real
///   `OpenProcess` syscall, before identity verification. A correct call always has
///   `used_seq > before_identity_seq` — the sequence counter, not an `Instant`, is what makes
///   this exact: a mutant that hoists the `remaining` read above `windows_open_classified`
///   fetches `used_seq` before `before_identity_seq` exists, giving `used_seq < before_identity_seq`
///   deterministically, not merely "probably, unless two clock reads tie."
#[cfg(test)]
pub(crate) mod deadline_observer {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::Sender;
    use std::sync::Mutex;
    use std::time::Instant;

    use crate::identity::ProcessId;

    /// What a single `block_until_exit_or_cancel` call reported — see this module's own doc.
    /// Only ever READ from `crate::tokio::wait_tests` (the `tokio`-feature test that pairs
    /// this observer with `grace_wait_armed_observer`) — its fields are otherwise dead under
    /// a `tokio`-less build, even though `notify` below still WRITES them unconditionally.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) struct Used {
        pub(crate) deadline: Option<Option<Instant>>,
        pub(crate) used_at: Instant,
        pub(crate) before_identity_seq: u64,
        pub(crate) used_seq: u64,
    }

    static TX: Mutex<Option<HashMap<ProcessId, Sender<Used>>>> = Mutex::new(None);
    // Global, not per-`ProcessId`: sequence ORDER only needs to be unambiguous within one
    // `block_until_exit_or_cancel` call, and a single call always runs on a single thread —
    // a shared counter across calls/threads costs nothing and keeps the anchor/read pairing
    // trivially correct even if two calls happened to race on the same counter.
    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// The next sequence number, guaranteed distinct from and greater than every number handed
    /// out before it (process-wide, not per-thread) — used instead of comparing two
    /// `Instant::now()` reads so the ordering proof never depends on clock resolution.
    pub(crate) fn next_seq() -> u64 {
        SEQ.fetch_add(1, Ordering::Relaxed)
    }

    /// Removes its `ProcessId`'s entry from the registry on drop, so a finished test's sender
    /// cannot linger and answer a later test that happens to reuse the same pid. Returned by
    /// [`install`]; the test just needs to keep it alive for the test's duration.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) struct InstallGuard {
        id: ProcessId,
    }

    impl Drop for InstallGuard {
        fn drop(&mut self) {
            if let Some(map) = TX.lock().unwrap().as_mut() {
                map.remove(&self.id);
            }
        }
    }

    // Only caller is `crate::tokio::wait_tests` (the `tokio`-feature test that pairs this
    // observer with `grace_wait_armed_observer`): dead under a `tokio`-less build.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn install(id: ProcessId, tx: Sender<Used>) -> InstallGuard {
        TX.lock().unwrap().get_or_insert_with(HashMap::new).insert(id, tx);
        InstallGuard { id }
    }

    pub(crate) fn notify(
        id: ProcessId,
        deadline: Option<Option<Instant>>,
        reading: &super::Reading,
        before_identity_seq: u64,
    ) {
        let guard = TX.lock().unwrap();
        let Some(tx) = guard.as_ref().and_then(|map| map.get(&id)) else {
            return;
        };
        let _ = tx.send(Used {
            deadline,
            used_at: reading.now,
            before_identity_seq,
            used_seq: reading.seq,
        });
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
