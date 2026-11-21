//! Creating the program's process, Linux.
//!
//! The child is made by the spawn core ([`fork_exec`](crate::child::spawn::fork_exec)), on
//! [`fork_with_pidfd`](crate::os_process::linux::fork::fork_with_pidfd); every signal and reap
//! afterwards goes through its pidfd. The clone is [`CloneKind::Plain`]: the child waits on the shim
//! (the release pipe below), which a vfork child must never do.
//!
//! **The child makes raw system calls only, from the clone to `execve`.** The core's contract
//! binds [`steps`]: it allocates nothing, formats nothing, calls no `getenv`, no std I/O and nothing
//! that reads libc's cached thread id (`raise`, `abort`, `pthread_*`), and it neither panics nor
//! debug-asserts. Everything it uses is prepared before the clone: [`Prepared`].
//!
//! The child is held before it arms anything: after its handlers are set up it blocks reading the
//! release pipe, and the shim lets it go only once it has checked, with the child already created,
//! that cosca is still there. A shim that died instead closes the pipe the same way, and the child
//! finds that out when it arms `PDEATHSIG` and looks at its parent.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use super::signals::{Inherited, FAULTS, TERMINATIONS};
use crate::child::spawn::fork_exec::{self, Failure, Program, SpawnError, Spawned, StepFailure};
use crate::elevation::shim::protocol::{Errno, NotExecuted, Signal};
use crate::elevation::shim::step::ToChild;
use crate::os_process::linux::fork::{CloneKind, ForkFn, NewChild};

/// A termination that reached the child before its `exec` (the first one).
static TERMINATED: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_termination(signal: libc::c_int) {
    // A failed exchange means an earlier one is already recorded.
    _ = TERMINATED.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

extern "C" fn nothing(_: libc::c_int) {}

const LOG_AT_GATE: &[u8] = b"child: waiting at gate (handlers ready)\n";
const LOG_NO_PARENT: &[u8] = b"child: the shim is gone before exec; exit 119\n";

/// What the child's steps need, built before the clone.
pub(in crate::elevation::shim) struct Prepared {
    max_signal: libc::c_int,
    ignored: *const bool,
    handleable: *const bool,
    // Keeps the tables `ignored` and `handleable` point into alive.
    _inherited: Inherited,
    saved_mask: libc::sigset_t,
    all_signals: libc::sigset_t,
    shim_pid: libc::pid_t,
    /// The release pipe: the child reads, the shim closes its end to let the child go.
    release_read: RawFd,
    release_write: RawFd,
    log_fd: RawFd,
    gate: Option<std::ffi::CString>,
    fault: bool,
    /// The signal the child asks to receive when the shim dies: `SIGKILL`.
    parent_death_signal: libc::c_ulong,
}

impl Prepared {
    pub(in crate::elevation::shim) fn new(
        inherited: Inherited,
        saved_mask: libc::sigset_t,
        release: (RawFd, RawFd),
        log_fd: Option<RawFd>,
        gate: Option<&std::ffi::OsStr>,
        fault: bool,
        setup_fails: bool,
    ) -> Prepared {
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: an all-zero set is a valid out-parameter; `sigfillset` initialises it.
        let all_signals = unsafe {
            let mut all: libc::sigset_t = std::mem::zeroed();
            libc::sigfillset(&mut all);
            all
        };
        Prepared {
            max_signal: inherited.max,
            ignored: inherited.ignored_ptr(),
            handleable: inherited.handleable_ptr(),
            _inherited: inherited,
            saved_mask,
            all_signals,
            shim_pid: rustix::process::getpid().as_raw_nonzero().get(),
            release_read: release.0,
            release_write: release.1,
            log_fd: log_fd.unwrap_or(-1),
            gate: gate.map(|g| std::ffi::CString::new(g.as_bytes()).expect("a gate path carries no NUL")),
            fault,
            // A test seam makes the request fail, as the kernel would refuse a signal it has not got.
            parent_death_signal: if setup_fails {
                1000
            } else {
                libc::SIGKILL as libc::c_ulong
            },
        }
    }
}

/// Creates the child with the core, by `fork`. The caller holds `spawn_lock`. `Err` means the program never ran.
pub(in crate::elevation::shim) fn spawn(
    prepared: &Prepared,
    program: &Program,
    fork: ForkFn,
) -> Result<Spawned, SpawnError> {
    // SAFETY: the caller holds `spawn_lock`, and `steps` makes raw system calls only; it runs in the
    // child, for which `prepared` was built.
    unsafe {
        fork_exec::spawn(
            CloneKind::Plain,
            fork,
            program,
            &[],
            &mut |_| steps(prepared),
            crate::elevation::shim::codes::NOT_EXECUTED,
        )
    }
}

/// What a spawn that made no child says: the report, what failed, and the errno.
pub(in crate::elevation::shim) fn not_spawned(error: SpawnError) -> (NotExecuted, &'static str, i32) {
    match error {
        SpawnError::Pipe(errno) => (NotExecuted::SetupFailed(Errno(errno)), "cannot create a pipe", errno),
        SpawnError::Unsupported(refusal) => (
            NotExecuted::Unsupported(Errno(refusal.errno())),
            "the kernel cannot make a child with a pidfd",
            refusal.errno(),
        ),
        SpawnError::Fork(errno) => (NotExecuted::ForkFailed(Errno(errno)), "fork", errno),
    }
}

/// What a child that ended before its ready record says: the channel ended with no record, so no
/// `execve` ran. `status` is its wait status, when someone reaped it. A signal is reported as the
/// child's termination; a plain exit, or a status nobody collected, names no cause and is a setup
/// failure with `EIO`.
pub(in crate::elevation::shim) fn died_before_exec(status: Option<i32>) -> NotExecuted {
    match status {
        Some(status) if status & 0x7f != 0 => NotExecuted::TerminatedBeforeExec(Signal(status & 0x7f)),
        _ => NotExecuted::SetupFailed(Errno(libc::EIO)),
    }
}

/// The kinds of step failure the child reports, as the protocol numbers the `F` frames.
const KIND_SETUP: u8 = 3;
const KIND_TERMINATED: u8 = 4;

/// What the child wrote to the status channel, as a [`NotExecuted`]. A step failure of a kind the shim
/// never gives its child is not the child's: an error.
pub(in crate::elevation::shim) fn not_executed(failure: Failure) -> std::io::Result<NotExecuted> {
    Ok(match failure {
        // The wire says a number for a stop of the parent's search too (`start_and_supervise`).
        Failure::Exec(errno) | Failure::Unexamined { errno, .. } => NotExecuted::ExecFailed(Errno(errno)),
        Failure::Step(StepFailure {
            kind: KIND_SETUP,
            value,
        }) => NotExecuted::SetupFailed(Errno(i32::from(value))),
        Failure::Step(StepFailure {
            kind: KIND_TERMINATED,
            value,
        }) => NotExecuted::TerminatedBeforeExec(Signal(i32::from(value))),
        Failure::Step(other) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the child failed a step no kind names: {other:?}"),
            ));
        }
    })
}

/// The child could not set itself up: the program never runs.
fn setup_failed(errno: libc::c_int) -> StepFailure {
    StepFailure {
        kind: KIND_SETUP,
        value: errno as u16,
    }
}

/// Everything between the clone and the core's `execve`. Raw system calls only.
///
/// # Safety
///
/// Called only in the child of a raw clone, with the `Prepared` the parent made for it.
unsafe fn steps(p: &Prepared) -> Result<(), StepFailure> {
    // SAFETY: the callees below are raw system calls and async-signal-safe libc wrappers on valid
    // arguments; nothing allocates.
    unsafe {
        libc::close(p.release_write);
        let mut record: libc::sigaction = std::mem::zeroed();
        record.sa_sigaction = record_termination as *const () as usize;
        record.sa_flags = libc::SA_RESTART;
        libc::sigfillset(&mut record.sa_mask);
        let mut noop: libc::sigaction = std::mem::zeroed();
        noop.sa_sigaction = nothing as *const () as usize;
        noop.sa_flags = libc::SA_RESTART;
        let mut default: libc::sigaction = std::mem::zeroed();
        default.sa_sigaction = libc::SIG_DFL;
        for signal in 1..=p.max_signal {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP || !*p.handleable.add(signal as usize) {
                continue;
            }
            if is_in(&FAULTS, signal) {
                // A fault before exec kills the child; a no-op would refault for ever.
                if libc::sigaction(signal, &default, std::ptr::null_mut()) != 0 {
                    return Err(setup_failed(*libc::__errno_location()));
                }
                continue;
            }
            // An inherited ignore reaches the program, except SIGPIPE's.
            if *p.ignored.add(signal as usize) && signal != libc::SIGPIPE {
                continue;
            }
            let action = if is_in(&TERMINATIONS, signal) { &record } else { &noop };
            if libc::sigaction(signal, action, std::ptr::null_mut()) != 0 {
                return Err(setup_failed(*libc::__errno_location()));
            }
        }
        let unblocked = libc::pthread_sigmask(libc::SIG_SETMASK, &p.saved_mask, std::ptr::null_mut());
        if unblocked != 0 {
            return Err(setup_failed(unblocked));
        }
        // Held here until the shim has checked that cosca is alive and closes its end of the pipe.
        let mut byte = 0u8;
        loop {
            let n = libc::read(p.release_read, (&mut byte as *mut u8).cast(), 1);
            if n >= 0 {
                break;
            }
            let errno = *libc::__errno_location();
            if errno != libc::EINTR {
                return Err(setup_failed(errno));
            }
        }
        libc::close(p.release_read);
        if let Some(gate) = &p.gate {
            write_log(p.log_fd, LOG_AT_GATE);
            let fd = libc::open(gate.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd >= 0 {
                let mut byte = 0u8;
                libc::read(fd, (&mut byte as *mut u8).cast(), 1);
                libc::close(fd);
            }
        }
        if p.fault {
            // A real fault before exec.
            std::ptr::write_volatile(8 as *mut i32, 0);
        }
        if libc::prctl(libc::PR_SET_PDEATHSIG, p.parent_death_signal) != 0 {
            return Err(setup_failed(*libc::__errno_location()));
        }
        if libc::getppid() != p.shim_pid {
            write_log(p.log_fd, LOG_NO_PARENT);
            libc::_exit(crate::elevation::shim::codes::NO_PARENT);
        }
        let blocked = libc::pthread_sigmask(libc::SIG_BLOCK, &p.all_signals, std::ptr::null_mut());
        if blocked != 0 {
            return Err(setup_failed(blocked));
        }
        let terminated = TERMINATED.load(Ordering::Relaxed);
        if terminated != 0 {
            return Err(StepFailure {
                kind: KIND_TERMINATED,
                value: terminated as u16,
            });
        }
        // A termination that arrives from here on ends the child by default. It is never swallowed.
        for signal in TERMINATIONS {
            if !*p.ignored.add(signal as usize) && libc::sigaction(signal, &default, std::ptr::null_mut()) != 0 {
                return Err(setup_failed(*libc::__errno_location()));
            }
        }
        let unblocked = libc::pthread_sigmask(libc::SIG_SETMASK, &p.saved_mask, std::ptr::null_mut());
        if unblocked != 0 {
            return Err(setup_failed(unblocked));
        }
        Ok(())
    }
}

fn is_in(list: &[libc::c_int], signal: libc::c_int) -> bool {
    list.contains(&signal)
}

/// One `write` of preformatted bytes to the seam log, if there is one.
unsafe fn write_log(fd: RawFd, bytes: &[u8]) {
    if fd >= 0 {
        // SAFETY: `bytes` is valid for its length.
        unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    }
}

/// A signal for the handle.
pub(in crate::elevation::shim) fn rustix_signal(to: ToChild) -> rustix::process::Signal {
    match to {
        ToChild::Kill => rustix::process::Signal::KILL,
        ToChild::Term => rustix::process::Signal::TERM,
    }
}

/// `pidfd_send_signal`: the only way the shim signals the child.
pub(in crate::elevation::shim) fn signal(child: &NewChild, to: ToChild) -> Result<(), rustix::io::Errno> {
    rustix::process::pidfd_send_signal(&child.pidfd, rustix_signal(to))
}
