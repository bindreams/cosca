//! What the two roles a host program is re-executed in share: the elevation shim (Unix) and the
//! console-event proxy ([`init`](crate::init) starts either by `argv[1]`).
//!
//! Neutral on purpose: the roles' protocol modules import it, and [`init`](crate::init), which exits
//! the process, is not for them to import.

use std::fmt::Arguments;
use std::io::Write;

/// The name the elevation shim's stderr lines carry.
#[cfg(unix)]
pub(crate) const SHIM: &str = "cosca-elevation-shim";
/// The name the console-event proxy's stderr lines carry.
pub(crate) const PROXY: &str = "cosca-ctrl-proxy";

/// Decimal digits only: no sign, no whitespace, no leading zero, so a number has one encoding. The
/// argv of both roles carries numbers this way.
pub(crate) fn decimal<T: std::str::FromStr>(a: &[u8]) -> Option<T> {
    if a.is_empty() || !a.iter().all(u8::is_ascii_digit) || (a.len() > 1 && a[0] == b'0') {
        return None;
    }
    std::str::from_utf8(a).ok()?.parse().ok()
}

/// Writes `<role>: <args>` and a newline to stderr, `role` being [`SHIM`] or [`PROXY`]. A failure
/// is ignored: whether the caller's stderr still exists is not the role's to decide.
///
/// On Unix a closed pipe must not raise `SIGPIPE`: the shim catches the signals that would end it,
/// and a caught one stops the program. `SIGPIPE` is blocked in this thread for the write. Linux
/// raises it at this thread before the write returns `EPIPE`, so it is pending when the write failed
/// that way, and it is taken off the queue here, whatever the signal's disposition. Windows has no
/// such signal.
#[cfg(unix)]
pub(crate) fn line(role: &str, args: Arguments<'_>) {
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
    let written = writeln!(std::io::stderr(), "{role}: {args}");
    if written.is_err_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) {
        take_pending_sigpipe(&pipe);
    }
    // SAFETY: `previous` is the mask `pthread_sigmask` just returned.
    let restored = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
    debug_assert_eq!(restored, 0, "pthread_sigmask(SIG_SETMASK)");
}

#[cfg(not(unix))]
pub(crate) fn line(role: &str, args: Arguments<'_>) {
    _ = writeln!(std::io::stderr(), "{role}: {args}");
}

/// Removes the `SIGPIPE` the failed write raised at this thread. It is pending already, and `SIGPIPE`
/// is blocked, so `sigwait` returns at once rather than waiting.
#[cfg(unix)]
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

#[cfg(all(test, unix))]
#[path = "role_tests.rs"]
mod role_tests;
