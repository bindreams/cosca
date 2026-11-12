//! A future that resolves when a waitable handle (a process, an event) is signalled or a timeout
//! has passed, with no thread of ours parked on it and no tokio timer: the Windows exit waits of
//! the async API. tokio's own child wait (`process/windows.rs`) has this shape.
//! `RegisterWaitForSingleObject` queues the handle with the OS's wait threads, which watch up to 63
//! handles each, and the callback completes a oneshot. The timeout is the registration's own, on
//! the real clock, so the wait needs neither tokio's time driver nor its clock (a paused clock does
//! not advance it).

use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ::tokio::sync::oneshot;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Threading::{
    RegisterWaitForSingleObject, UnregisterWaitEx, WT_EXECUTEINWAITTHREAD, WT_EXECUTEONLYONCE,
};

use crate::error::win32_io_error;

/// What ended a registered wait: the OS's `TimerOrWaitFired`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Woke {
    /// The handle was signalled.
    Signalled,
    /// The timeout passed first. The OS may count it a little short (see
    /// [`win32_timeout_ms`](crate::wait::win32_timeout_ms)), so it is no proof the deadline passed.
    TimedOut,
}

/// A wait for a handle to be signalled or a timeout to pass, registered when this is made, and
/// unregistered when it is dropped, whether it was polled or not. It resolves once, and is not
/// polled again after.
///
/// The wait owns a duplicate of the handle and its own heap callback state; the OS reaches nothing
/// the caller owns, so forgetting a wait (`mem::forget`) leaks a registration and a handle but
/// touches nothing freed. Dropping it unregisters, blocking until a running callback has returned,
/// so no callback runs after the drop.
#[must_use = "futures do nothing unless polled"]
pub(crate) struct RegisteredWait {
    rx: oneshot::Receiver<Woke>,
    wait_object: HANDLE,
    /// The callback's state: owned here, freed only after the unregistration.
    complete: *mut Option<oneshot::Sender<Woke>>,
    /// The duplicate the OS waits on. A field, so it drops after [`Drop::drop`] has unregistered.
    _handle: OwnedHandle,
}

// SAFETY: the raw pointer is the callback's state, which the callback reaches from an OS thread and
// which only `Drop` frees, after the unregistration. A wait handle is not tied to a thread.
unsafe impl Send for RegisteredWait {}

impl RegisteredWait {
    /// Register a wait for `handle`, for at most `remaining` (`None` = no timeout; a finite one is
    /// rounded up to whole milliseconds, as [`win32_timeout_ms`](crate::wait::win32_timeout_ms)
    /// does for every Win32 wait). An error is the duplication's or the registration's failure, with
    /// its Win32 code.
    pub(crate) fn register(handle: BorrowedHandle<'_>, remaining: Option<Duration>) -> io::Result<Self> {
        let handle = handle.try_clone_to_owned()?;
        let (tx, rx) = oneshot::channel();
        let complete = Box::into_raw(Box::new(Some(tx)));
        let mut wait_object = HANDLE::default();
        // SAFETY: `handle` is open and moves into the wait, which closes it after `Drop`'s
        // unregistration; `complete` is freed only after that. The callback is `extern "system"`
        // and never unwinds.
        let registered = unsafe {
            RegisterWaitForSingleObject(
                &mut wait_object,
                HANDLE(handle.as_raw_handle()),
                Some(callback),
                Some(complete.cast_const().cast()),
                crate::wait::win32_timeout_ms(remaining),
                WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE,
            )
        };
        if let Err(e) = registered {
            // SAFETY: the registration failed, so no callback can see `complete`.
            drop(unsafe { Box::from_raw(complete) });
            return Err(win32_io_error(e));
        }
        Ok(Self {
            rx,
            wait_object,
            complete,
            _handle: handle,
        })
    }
}

impl Future for RegisteredWait {
    type Output = Woke;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Woke> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Pending => Poll::Pending,
            // The sender is dropped only with this wait's state, after the last poll, so it is never
            // dropped unsent: a lost value is a bug, not a wake to answer.
            Poll::Ready(sent) => Poll::Ready(sent.expect("a registered wait's sender is dropped only with its state")),
        }
    }
}

impl Drop for RegisteredWait {
    fn drop(&mut self) {
        // SAFETY: `wait_object` is this wait's registration. `INVALID_HANDLE_VALUE` blocks until a
        // callback that is running has returned, so none can touch `complete` after this.
        let unregistered = unsafe { UnregisterWaitEx(self.wait_object, Some(INVALID_HANDLE_VALUE)) };
        match unregistered {
            // SAFETY: `complete` came from `Box::into_raw`, and nothing uses it now.
            Ok(()) => drop(unsafe { Box::from_raw(self.complete) }),
            // A callback may still run, so its state is left allocated.
            Err(e) => {
                let e = win32_io_error(e);
                log::warn!(
                    "UnregisterWaitEx failed ({report}); the wait's callback state is leaked",
                    report = crate::error::Report(&e)
                );
                debug_assert!(false, "UnregisterWaitEx failed: {e}");
            }
        }
    }
}

/// Runs on an OS wait thread, in place of a thread of ours: completes the oneshot. Does nothing
/// else, since it holds the wait thread (and so the `Drop` that unregisters) while it runs.
unsafe extern "system" fn callback(context: *mut c_void, timer_fired: bool) {
    // SAFETY: `context` is the wait's `complete`, which outlives the callback (`Drop` unregisters
    // with a blocking wait before freeing it).
    let complete = unsafe { &mut *context.cast::<Option<oneshot::Sender<Woke>>>() };
    if let Some(tx) = complete.take() {
        _ = tx.send(if timer_fired { Woke::TimedOut } else { Woke::Signalled });
    }
}

/// Resolve with what ended the first of `waits`. `waits` is not empty.
async fn first_woken(waits: &mut [RegisteredWait]) -> Woke {
    debug_assert!(!waits.is_empty(), "no wait to be the first of");
    std::future::poll_fn(|cx| {
        for wait in waits.iter_mut() {
            if let Poll::Ready(woke) = Pin::new(wait).poll(cx) {
                return Poll::Ready(woke);
            }
        }
        Poll::Pending
    })
    .await
}

/// Resolve when any of `handles` (not empty) is signalled, or when the real-clock `deadline` has
/// passed (`None` = never): [`Woke::TimedOut`] only once [`crate::wait::remaining`] says so. A
/// timeout the OS counted short registers the handles again for the time that is left, as every
/// other Win32 wait of the crate does ([`crate::wait::wait_until`]). The waits are registered with
/// the OS, so none holds a thread, and are unregistered when this is dropped.
pub(crate) async fn wait_any<'h>(
    handles: impl Iterator<Item = BorrowedHandle<'h>> + Clone,
    deadline: Option<Instant>,
) -> io::Result<Woke> {
    loop {
        let remaining = crate::wait::remaining(deadline);
        let mut waits = handles
            .clone()
            .map(|handle| RegisteredWait::register(handle, remaining))
            .collect::<io::Result<Vec<_>>>()?;
        match first_woken(&mut waits).await {
            Woke::TimedOut if crate::wait::remaining(deadline) != Some(Duration::ZERO) => {}
            woke => return Ok(woke),
        }
    }
}

#[cfg(test)]
#[path = "registered_wait_tests.rs"]
mod registered_wait_tests;
