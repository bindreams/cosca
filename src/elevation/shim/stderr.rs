//! The shim's lines on its own stderr, written so that a closed pipe cannot raise `SIGPIPE`.
//!
//! The shim catches `SIGPIPE` like any other signal that would end it, and a caught one stops the
//! program, so a front that has dropped its stderr must not cause one.

use std::fmt::Arguments;
use std::io::Write;

/// Writes `cosca-elevation-shim: <args>` and a newline to stderr. A failure is ignored: whether the
/// front's stderr still exists is not the shim's to decide.
///
/// `SIGPIPE` is blocked in this thread for the write. Linux raises it at this thread before the write
/// returns `EPIPE`, so it is pending when the write failed that way, and it is taken off the queue
/// here, whatever the signal's disposition.
pub(crate) fn line(args: Arguments<'_>) {
    // SAFETY: all-zero sets are valid out-parameters; `sigemptyset` and `sigaddset` initialise `pipe`.
    let (pipe, previous) = unsafe {
        let mut pipe: libc::sigset_t = std::mem::zeroed();
        let mut previous: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut pipe);
        libc::sigaddset(&mut pipe, libc::SIGPIPE);
        let blocked = libc::pthread_sigmask(libc::SIG_BLOCK, &pipe, &mut previous);
        debug_assert_eq!(blocked, 0, "pthread_sigmask(SIG_BLOCK)");
        (pipe, previous)
    };
    let written = writeln!(std::io::stderr(), "cosca-elevation-shim: {args}");
    if written.is_err_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) {
        take_pending_sigpipe(&pipe);
    }
    // SAFETY: `previous` is the mask `pthread_sigmask` just returned.
    let restored = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
    debug_assert_eq!(restored, 0, "pthread_sigmask(SIG_SETMASK)");
}

/// Removes the `SIGPIPE` the failed write raised at this thread. It is pending already, and `SIGPIPE`
/// is blocked, so `sigwait` returns at once rather than waiting.
fn take_pending_sigpipe(pipe: &libc::sigset_t) {
    // SAFETY: an all-zero set is a valid out-parameter, and `pending` is valid for the call.
    let pending = unsafe {
        let mut pending: libc::sigset_t = std::mem::zeroed();
        let queried = libc::sigpending(&mut pending);
        debug_assert_eq!(queried, 0, "sigpending");
        pending
    };
    // SAFETY: `pending` is a valid set.
    if unsafe { libc::sigismember(&pending, libc::SIGPIPE) } != 1 {
        return;
    }
    let mut signal = 0;
    // SAFETY: `pipe` is a valid set containing only a blocked, pending signal, and `signal` is valid.
    let waited = unsafe { libc::sigwait(pipe, &mut signal) };
    debug_assert_eq!(waited, 0, "sigwait");
}

#[cfg(test)]
#[path = "stderr_tests.rs"]
mod stderr_tests;
