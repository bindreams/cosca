//! Signal dispositions (plan F, D1, D1b, D8d).
//!
//! - A signal the shim inherited ignored stays ignored, in the shim and in the program. SIGPIPE is
//!   the exception for the program: a Rust runtime starts with it ignored, and the program never
//!   starts that way (D1b).
//! - Every other signal whose default action terminates the process is caught, real-time signals
//!   included: its arrival stops the program instead of leaving it unsupervised (D8d). The
//!   exceptions are SIGKILL, which cannot be caught, and the seven synchronous fault signals: a
//!   fault is a crash.
//! - SIGTSTP, SIGTTIN and SIGTTOU are caught and do nothing: the shim never stops with a control
//!   byte unserved.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

/// The synchronous fault signals. A no-op handler on one returns to the faulting instruction for
/// ever, so they stay at `SIG_DFL`.
pub(super) const FAULTS: [libc::c_int; 7] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGABRT,
    libc::SIGTRAP,
    libc::SIGSYS,
];

/// The signals a terminal or a supervisor sends to end a process politely. The child records one that
/// arrives before its `exec` and reports it (D3).
pub(super) const TERMINATIONS: [libc::c_int; 4] = [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM];

const STOPS: [libc::c_int; 3] = [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];
/// Default action is to ignore (SIGCHLD, SIGURG, SIGWINCH) or to continue (SIGCONT).
const NOT_TERMINATING: [libc::c_int; 4] = [libc::SIGCHLD, libc::SIGURG, libc::SIGWINCH, libc::SIGCONT];

/// Which signals the shim started with ignored, and the highest signal number.
pub(super) struct Inherited {
    pub(super) max: libc::c_int,
    /// Indexed by signal number; index 0 is unused.
    ignored: Vec<bool>,
}

impl Inherited {
    /// Reads every signal's disposition. A signal `sigaction` refuses (glibc keeps two for itself)
    /// is not the shim's to handle.
    pub(super) fn read() -> Inherited {
        let max = libc::SIGRTMAX();
        let mut ignored = vec![false; max as usize + 1];
        for signal in 1..=max {
            // SAFETY: an all-zero `sigaction` is valid; a null `act` only queries.
            let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: `current` is valid for the call.
            if unsafe { libc::sigaction(signal, std::ptr::null(), &mut current) } == 0 {
                ignored[signal as usize] = current.sa_sigaction == libc::SIG_IGN;
            }
        }
        Inherited { max, ignored }
    }

    pub(super) fn was_ignored(&self, signal: libc::c_int) -> bool {
        self.ignored.get(signal as usize).copied().unwrap_or(false)
    }

    /// Raw pointer view for the child, which must not index with a bounds-check panic path.
    pub(super) fn ignored_ptr(&self) -> *const bool {
        self.ignored.as_ptr()
    }
}

static WAKE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_terminating_signal(signal: libc::c_int) {
    let fd = WAKE.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: `__errno_location` is async-signal-safe and the write is one byte from a local.
        unsafe {
            let saved = *libc::__errno_location();
            let byte = signal as u8;
            libc::write(fd, (&byte as *const u8).cast(), 1);
            *libc::__errno_location() = saved;
        }
    }
}

extern "C" fn on_stop_signal(_: libc::c_int) {}

/// Installs the shim's handlers for what it inherited at `SIG_DFL` (D8d). `wake` is the nonblocking
/// write end of the pipe the loop reads: a terminating signal writes its number to it.
pub(super) fn install(inherited: &Inherited, wake: RawFd) {
    WAKE.store(wake, Ordering::Relaxed);
    for signal in 1..=inherited.max {
        let skip = signal == libc::SIGKILL
            || signal == libc::SIGSTOP
            || FAULTS.contains(&signal)
            || NOT_TERMINATING.contains(&signal)
            || inherited.was_ignored(signal);
        if skip {
            continue;
        }
        let handler: extern "C" fn(libc::c_int) = if STOPS.contains(&signal) {
            on_stop_signal
        } else {
            on_terminating_signal
        };
        // SAFETY: an all-zero `sigaction` is valid; the handler is async-signal-safe.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handler as usize;
        action.sa_flags = libc::SA_RESTART;
        // SAFETY: `action.sa_mask` is a valid out-parameter.
        unsafe { libc::sigfillset(&mut action.sa_mask) };
        // SAFETY: `action` is valid. EINVAL is glibc's own signals.
        unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
    }
}

/// D1: the program does not inherit a `SIGCHLD` the shim's caller ignored, because an ignored
/// `SIGCHLD` makes the kernel reap children without telling their parent.
pub(super) fn reset_sigchld() {
    // SAFETY: an all-zero `sigaction` is valid.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    // SAFETY: `action` is valid.
    unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) };
}

/// Blocks every signal, returning the mask it replaced.
pub(super) fn block_all() -> libc::sigset_t {
    // SAFETY: all-zero sets are valid out-parameters; `sigfillset` initialises `all`.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old);
        old
    }
}

pub(super) fn restore(mask: &libc::sigset_t) {
    // SAFETY: `mask` is a valid set.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, mask, std::ptr::null_mut()) };
}

/// SIGPIPE's disposition at entry, for the seam log.
pub(super) fn sigpipe_state() -> &'static str {
    // SAFETY: an all-zero `sigaction` is valid; a null `act` only queries.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: `current` is valid for the call.
    unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut current) };
    if current.sa_sigaction == libc::SIG_IGN {
        "ignored"
    } else {
        "default-or-caught"
    }
}
