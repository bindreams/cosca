//! What the helper roles a host program is started in share: the elevation shim (Unix) and the
//! console-event proxy. A process is started in a role when [`init_helpers`](crate::init_helpers) finds
//! [`HELPER_ENV`] set, or, for the shim on Unix, its first argument (the tools that start the shim
//! reset the environment).
//!
//! Neutral on purpose: the roles' protocol modules import it, and [`init_helpers`](crate::init_helpers),
//! which exits the process, is not for them to import.

use std::fmt::Arguments;
use std::io::Write;

/// The environment variable that says a process was started as a helper. Cosca sets it on the helper's
/// command; nothing else does. A process that finds it set never runs as the host program.
pub(crate) const HELPER_ENV: &str = "__COSCA_HELPER";
/// The value of [`HELPER_ENV`] that makes the process the console-event proxy; the process's arguments
/// are then the proxy's data.
pub(crate) const CTRL_PROXY: &str = "ctrl-proxy";
/// What a process exits with when [`HELPER_ENV`] names a role this build does not have. It is below the
/// elevation shim's codes (112 to 125), which are below 126 so that no shell reads one as a signal death,
/// and outside the proxy's answers (150 to 159) and its cause codes (bit 29 set), so no protocol reads it
/// as an answer.
pub(crate) const UNKNOWN_HELPER_ROLE: i32 = 100;

/// The name the elevation shim's stderr lines carry.
#[cfg(unix)]
pub(crate) const SHIM: &str = "cosca-elevation-shim";
/// The name the console-event proxy's stderr lines carry.
pub(crate) const PROXY: &str = "cosca-ctrl-proxy";
/// The name a stderr line carries when the role is not known.
pub(crate) const HELPER: &str = "cosca-helper";

/// How a refusal says what made the process a helper: `started with __COSCA_HELPER=<value>`. Every refusal
/// line begins with it. The value is escaped (a newline is `\n`), so a refusal is always one line.
pub(crate) fn started_with(value: &std::ffi::OsStr) -> String {
    format!("started with {HELPER_ENV}={}", value.to_string_lossy().escape_debug())
}

/// Decimal digits only: no sign, no whitespace, no leading zero, so a number has one encoding. The
/// argv of both roles carries numbers this way.
pub(crate) fn decimal<T: std::str::FromStr>(a: &[u8]) -> Option<T> {
    if a.is_empty() || !a.iter().all(u8::is_ascii_digit) || (a.len() > 1 && a[0] == b'0') {
        return None;
    }
    std::str::from_utf8(a).ok()?.parse().ok()
}

/// Writes `<role>: <args>` and a newline to stderr, `role` being [`SHIM`], [`PROXY`] or [`HELPER`]. A failure
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
