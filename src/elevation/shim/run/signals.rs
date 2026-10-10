//! Signal dispositions.
//!
//! - A signal the shim inherited ignored stays ignored, in the shim and in the program. SIGPIPE is
//!   the exception, in both: a Rust runtime starts with it ignored, so the shim cannot see the
//!   caller's disposition, and the program never starts with it ignored.
//! - Every other signal whose default action terminates the process is caught, real-time signals
//!   included, from before hello on: its arrival stops the program instead of leaving it
//!   unsupervised, and cannot kill the shim while cosca believes a start is under way. The
//!   exceptions are SIGKILL, which cannot be caught, and the seven synchronous fault signals: a
//!   fault is a crash.
//! - SIGTSTP, SIGTTIN and SIGTTOU are caught and do nothing: the shim never stops with a control
//!   byte unserved.
//! - A signal `sigaction` refuses is the platform's own (glibc keeps two real-time signals for
//!   itself): not the shim's to handle, found out by asking up front.

use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

use rustix::io::Errno;

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
/// arrives before its `exec` and reports it.
pub(super) const TERMINATIONS: [libc::c_int; 4] = [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM];

const STOPS: [libc::c_int; 3] = [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];
/// Default action is to ignore (SIGCHLD, SIGURG, SIGWINCH) or to continue (SIGCONT).
const NOT_TERMINATING: [libc::c_int; 4] = [libc::SIGCHLD, libc::SIGURG, libc::SIGWINCH, libc::SIGCONT];

/// Which signals the shim started with ignored, which of them `sigaction` accepts, and the highest
/// signal number.
pub(super) struct Inherited {
    pub(super) max: libc::c_int,
    /// Indexed by signal number; index 0 is unused.
    ignored: Vec<bool>,
    /// Indexed by signal number: the platform lets a process set the signal's action.
    handleable: Vec<bool>,
}

impl Inherited {
    /// Reads every signal's disposition.
    pub(super) fn read() -> Inherited {
        let max = libc::SIGRTMAX();
        let mut ignored = vec![false; max as usize + 1];
        let mut handleable = vec![false; max as usize + 1];
        for signal in 1..=max {
            // SAFETY: an all-zero `sigaction` is valid; a null `act` only queries.
            let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: `current` is valid for the call.
            if unsafe { libc::sigaction(signal, std::ptr::null(), &mut current) } == 0 {
                ignored[signal as usize] = current.sa_sigaction == libc::SIG_IGN;
                handleable[signal as usize] = true;
            } else {
                // The platform's own signals only: glibc's `SIGCANCEL` and `SIGSETXID`, musl's three.
                debug_assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINVAL),
                    "sigaction({signal}) query"
                );
            }
        }
        Inherited {
            max,
            ignored,
            handleable,
        }
    }

    pub(super) fn was_ignored(&self, signal: libc::c_int) -> bool {
        self.ignored.get(signal as usize).copied().unwrap_or(false)
    }

    /// Raw pointer view for the child, which must not index with a bounds-check panic path.
    pub(super) fn ignored_ptr(&self) -> *const bool {
        self.ignored.as_ptr()
    }

    /// Raw pointer view of which signals the child may set the action of.
    pub(super) fn handleable_ptr(&self) -> *const bool {
        self.handleable.as_ptr()
    }

    fn is_handleable(&self, signal: libc::c_int) -> bool {
        self.handleable.get(signal as usize).copied().unwrap_or(false)
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

/// The pipe the shim's handlers write to: a terminating signal writes its number to `tx`.
pub(super) struct Wake {
    pub(super) rx: OwnedFd,
    pub(super) tx: OwnedFd,
}

impl Wake {
    /// A pipe, both ends non-blocking and close-on-exec.
    pub(super) fn new() -> io::Result<Wake> {
        let (rx, tx) = std::io::pipe()?;
        let (rx, tx): (OwnedFd, OwnedFd) = (rx.into(), tx.into());
        for end in [&rx, &tx] {
            let flags = rustix::fs::fcntl_getfl(end)?;
            rustix::fs::fcntl_setfl(end, flags | rustix::fs::OFlags::NONBLOCK)?;
        }
        Ok(Wake { rx, tx })
    }
}

/// Installs the shim's handlers for what it inherited at `SIG_DFL`. `wake` is the nonblocking write
/// end of the pipe the loop reads.
pub(super) fn install(inherited: &Inherited, wake: RawFd) {
    WAKE.store(wake, Ordering::Relaxed);
    for signal in 1..=inherited.max {
        let skip = signal == libc::SIGKILL
            || signal == libc::SIGSTOP
            || !inherited.is_handleable(signal)
            || FAULTS.contains(&signal)
            || NOT_TERMINATING.contains(&signal)
            || (inherited.was_ignored(signal) && signal != libc::SIGPIPE);
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
        action.sa_sigaction = handler as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        // SAFETY: `action.sa_mask` is a valid out-parameter.
        let filled = unsafe { libc::sigfillset(&mut action.sa_mask) };
        debug_assert_eq!(filled, 0, "sigfillset");
        // SAFETY: `action` is valid.
        let set = unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
        debug_assert_eq!(set, 0, "sigaction({signal}): {}", Errno::from_raw_os_error(errno()));
    }
}

/// The program does not inherit a `SIGCHLD` the shim's caller ignored, because an ignored `SIGCHLD`
/// makes the kernel reap children without telling their parent.
pub(super) fn reset_sigchld() {
    // SAFETY: an all-zero `sigaction` is valid.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    // SAFETY: `action` is valid.
    let set = unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) };
    debug_assert_eq!(set, 0, "sigaction(SIGCHLD): {}", Errno::from_raw_os_error(errno()));
}

/// Blocks every signal, returning the mask it replaced.
pub(super) fn block_all() -> libc::sigset_t {
    // SAFETY: all-zero sets are valid out-parameters; `sigfillset` initialises `all`.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        let filled = libc::sigfillset(&mut all);
        debug_assert_eq!(filled, 0, "sigfillset");
        let blocked = libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old);
        debug_assert_eq!(blocked, 0, "pthread_sigmask(SIG_BLOCK)");
        old
    }
}

pub(super) fn restore(mask: &libc::sigset_t) {
    // SAFETY: `mask` is a valid set.
    let restored = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, mask, std::ptr::null_mut()) };
    debug_assert_eq!(restored, 0, "pthread_sigmask(SIG_SETMASK)");
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
