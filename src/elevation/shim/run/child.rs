//! Creating the program's process (plan F, D3, D11, D12), Linux.
//!
//! The child is made by `clone3(CLONE_PIDFD)`, or `clone(CLONE_PIDFD)` where `clone3` is refused
//! (Docker's default seccomp profile answers `ENOSYS`). The handle exists from the child's first
//! instant, so no host thread can reap the child and let a stranger take its pid before the shim
//! has a handle on it, and every signal and reap afterwards goes through the handle.
//!
//! **The child makes raw system calls only, from the clone to `execve`.** Any host thread may hold a
//! lock at that instant, and a raw clone runs no atfork handlers, so the child allocates nothing,
//! formats nothing, calls no `getenv`, no std I/O and nothing that reads libc's cached thread id
//! (`raise`, `abort`, `pthread_*`), and it neither panics nor debug-asserts. Everything it uses is
//! prepared before the clone: [`Prepared`].

use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicI32, Ordering};

use super::signals::{Inherited, FAULTS, TERMINATIONS};
use crate::elevation::shim::protocol::{Errno, Frame, NotExecuted, Signal};
use crate::elevation::shim::step::ToChild;

/// A termination that reached the child before its `exec` (the first one).
static TERMINATED: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_termination(signal: libc::c_int) {
    // A failed exchange means an earlier one is already recorded.
    _ = TERMINATED.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

extern "C" fn nothing(_: libc::c_int) {}

const LOG_AT_GATE: &[u8] = b"child: waiting at gate (handlers ready)\n";
const LOG_NO_PARENT: &[u8] = b"child: the shim is gone before exec; exit 119\n";

/// What the child needs, built before the clone.
pub(in crate::elevation::shim) struct Prepared {
    exe: CString,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    /// `/bin/sh <exe> <args…>`, for a program `execve` refuses with `ENOEXEC`.
    sh_argv: Vec<*const libc::c_char>,
    /// Keep the strings the pointers above point into alive.
    _strings: Vec<CString>,
    max_signal: libc::c_int,
    ignored: *const bool,
    inherited: Inherited,
    saved_mask: libc::sigset_t,
    all_signals: libc::sigset_t,
    shim_pid: libc::pid_t,
    status_read: RawFd,
    status_write: RawFd,
    log_fd: RawFd,
    gate: Option<CString>,
    fault: bool,
}

const SH: &[u8] = b"/bin/sh\0";

impl Prepared {
    #[allow(
        clippy::too_many_arguments,
        reason = "the child's whole world, gathered once before the clone"
    )]
    pub(in crate::elevation::shim) fn new(
        exe: &OsStr,
        argv: &[&OsStr],
        env: impl Iterator<Item = (OsString, OsString)>,
        inherited: Inherited,
        saved_mask: libc::sigset_t,
        status: (RawFd, RawFd),
        log_fd: Option<RawFd>,
        gate: Option<&OsStr>,
        fault: bool,
    ) -> Prepared {
        let cstring = |s: &OsStr| CString::new(s.as_bytes()).expect("argv carries no NUL: ShimArgs::parse checked");
        let mut strings = vec![cstring(exe)];
        strings.extend(argv.iter().map(|a| cstring(a)));
        let env: Vec<CString> = env
            .map(|(mut k, v)| {
                k.push("=");
                k.push(v);
                cstring(&k)
            })
            .collect();
        let exe_c = strings[0].clone();
        let args_c = &strings[1..];
        let ptrs = |list: &[&CString]| -> Vec<*const libc::c_char> {
            list.iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect()
        };
        let argv_ptrs = ptrs(&args_c.iter().collect::<Vec<_>>());
        let sh = CString::from_vec_with_nul(SH.to_vec()).expect("a literal with its NUL");
        let mut sh_list: Vec<&CString> = vec![&sh, &strings[0]];
        sh_list.extend(args_c.iter().skip(1));
        let sh_argv = ptrs(&sh_list);
        let envp = ptrs(&env.iter().collect::<Vec<_>>());
        strings.extend(env);
        strings.push(sh);
        // SAFETY: an all-zero set is a valid out-parameter; `sigfillset` initialises it.
        let all_signals = unsafe {
            let mut all: libc::sigset_t = std::mem::zeroed();
            libc::sigfillset(&mut all);
            all
        };
        Prepared {
            exe: exe_c,
            argv: argv_ptrs,
            envp,
            sh_argv,
            _strings: strings,
            max_signal: inherited.max,
            ignored: inherited.ignored_ptr(),
            inherited,
            saved_mask,
            all_signals,
            // SAFETY: `getpid` has no preconditions.
            shim_pid: unsafe { libc::getpid() },
            status_read: status.0,
            status_write: status.1,
            log_fd: log_fd.unwrap_or(-1),
            gate: gate.map(cstring),
            fault,
        }
    }
}

/// A child with the handle the shim keeps on it.
pub(in crate::elevation::shim) struct Spawned {
    pub(in crate::elevation::shim) pid: libc::pid_t,
    pub(in crate::elevation::shim) pidfd: OwnedFd,
}

/// The arguments of `clone3`, version 0 (kernel 5.3).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}

const CLONE_PIDFD: u64 = 0x1000;

/// How the child was made.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::elevation::shim) enum Path {
    Clone3,
    Clone,
}

/// Test seams on the clone.
#[derive(Clone, Copy, Default)]
pub(in crate::elevation::shim) struct Faults {
    /// `clone3` answers `ENOSYS`, as Docker's default seccomp profile does.
    pub(in crate::elevation::shim) refuse_clone3: bool,
    /// Every clone fails with `EAGAIN`.
    pub(in crate::elevation::shim) fail: bool,
}

/// Creates the child. The caller holds `spawn_lock`. `Err` is the errno, and the program never ran.
pub(in crate::elevation::shim) fn spawn(prepared: &Prepared, faults: Faults) -> Result<(Spawned, Path), i32> {
    let mut pidfd: libc::c_int = -1;
    let mut path = Path::Clone3;
    let mut pid: libc::c_long = -1;
    if faults.fail {
        // SAFETY: `__errno_location` is always valid.
        unsafe { *libc::__errno_location() = libc::EAGAIN };
    } else if faults.refuse_clone3 {
        // SAFETY: `__errno_location` is always valid.
        unsafe { *libc::__errno_location() = libc::ENOSYS };
    } else {
        let args = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: (&mut pidfd as *mut libc::c_int) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        // SAFETY: `args` is a valid `clone_args` of the size passed; no stack is given, so the child
        // continues on a copy of this one, as after `fork`.
        pid = unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<CloneArgs>()) };
    }
    if pid < 0 && unsafe { *libc::__errno_location() } == libc::ENOSYS {
        path = Path::Clone;
        let flags = CLONE_PIDFD | libc::SIGCHLD as u64;
        // SAFETY: the legacy `clone` with no stack, as `fork`; the pidfd is stored through the
        // `parent_tid` argument. The argument order is the architecture's.
        pid = unsafe { raw_clone(flags, &mut pidfd) };
    }
    if pid == 0 {
        // SAFETY: this is the child, and `prepared` was built for it.
        unsafe { child_body(prepared) }
    }
    if pid < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    debug_assert!(pidfd >= 0, "CLONE_PIDFD stores the descriptor");
    // SAFETY: the kernel made `pidfd` for this call and nothing else owns it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok((
        Spawned {
            pid: pid as libc::pid_t,
            pidfd,
        },
        path,
    ))
}

#[cfg(not(target_arch = "s390x"))]
unsafe fn raw_clone(flags: u64, pidfd: &mut libc::c_int) -> libc::c_long {
    // SAFETY: the caller's contract.
    unsafe {
        libc::syscall(
            libc::SYS_clone,
            flags,
            0usize,
            pidfd as *mut libc::c_int,
            0usize,
            0usize,
        )
    }
}

/// s390x puts the stack pointer first (`CONFIG_CLONE_BACKWARDS2`).
#[cfg(target_arch = "s390x")]
unsafe fn raw_clone(flags: u64, pidfd: &mut libc::c_int) -> libc::c_long {
    // SAFETY: the caller's contract.
    unsafe {
        libc::syscall(
            libc::SYS_clone,
            0usize,
            flags,
            pidfd as *mut libc::c_int,
            0usize,
            0usize,
        )
    }
}

/// The `F` payload as the status pipe carries it: the frame's little-endian value.
fn status_value(kind: u16, value: i32) -> i32 {
    i32::from(kind) << 16 | value & 0xffff
}

/// What the child wrote to the status pipe, as a [`NotExecuted`].
pub(in crate::elevation::shim) fn decode_report(value: i32) -> NotExecuted {
    let mut bytes = vec![b'F'];
    bytes.extend_from_slice(&value.to_le_bytes());
    match crate::elevation::shim::protocol::decode_frame(&bytes) {
        Ok(Frame::NotExecuted(report)) => report,
        other => {
            debug_assert!(false, "the child wrote a value no F frame has: {other:?}");
            NotExecuted::ExecFailed(Errno(libc::EIO))
        }
    }
}

/// Everything between the clone and `execve`. Raw system calls only.
///
/// # Safety
///
/// Called only in the child of a raw clone, with the `Prepared` the parent made for it.
unsafe fn child_body(p: &Prepared) -> ! {
    // SAFETY: the callees below are raw system calls and async-signal-safe libc wrappers on valid
    // arguments; nothing allocates.
    unsafe {
        libc::close(p.status_read);
        let mut record: libc::sigaction = std::mem::zeroed();
        record.sa_sigaction = record_termination as usize;
        record.sa_flags = libc::SA_RESTART;
        libc::sigfillset(&mut record.sa_mask);
        let mut noop: libc::sigaction = std::mem::zeroed();
        noop.sa_sigaction = nothing as usize;
        noop.sa_flags = libc::SA_RESTART;
        let mut default: libc::sigaction = std::mem::zeroed();
        default.sa_sigaction = libc::SIG_DFL;
        for signal in 1..=p.max_signal {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP {
                continue;
            }
            if is_in(&FAULTS, signal) {
                // A fault before exec kills the child; a no-op would refault for ever.
                libc::sigaction(signal, &default, std::ptr::null_mut());
                continue;
            }
            // An inherited ignore reaches the program, except SIGPIPE's (D1b).
            if *p.ignored.add(signal as usize) && signal != libc::SIGPIPE {
                continue;
            }
            let action = if is_in(&TERMINATIONS, signal) { &record } else { &noop };
            libc::sigaction(signal, action, std::ptr::null_mut());
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &p.saved_mask, std::ptr::null_mut());
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
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        if libc::getppid() != p.shim_pid {
            write_log(p.log_fd, LOG_NO_PARENT);
            libc::_exit(crate::elevation::shim::codes::NO_PARENT);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &p.all_signals, std::ptr::null_mut());
        let terminated = TERMINATED.load(Ordering::Relaxed);
        if terminated != 0 {
            let value = status_value(4, terminated);
            libc::write(p.status_write, (&value as *const i32).cast(), 4);
            libc::_exit(crate::elevation::shim::codes::NOT_EXECUTED);
        }
        // A termination that arrives from here on ends the child by default. It is never swallowed.
        for signal in TERMINATIONS {
            if !*p.ignored.add(signal as usize) {
                libc::sigaction(signal, &default, std::ptr::null_mut());
            }
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &p.saved_mask, std::ptr::null_mut());
        libc::execve(p.exe.as_ptr(), p.argv.as_ptr(), p.envp.as_ptr());
        let mut errno = *libc::__errno_location();
        if errno == libc::ENOEXEC {
            libc::execve(SH.as_ptr().cast(), p.sh_argv.as_ptr(), p.envp.as_ptr());
            errno = *libc::__errno_location();
        }
        let value = status_value(2, errno);
        libc::write(p.status_write, (&value as *const i32).cast(), 4);
        libc::_exit(127)
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

impl Spawned {
    /// `pidfd_send_signal`: the only way the shim signals the child.
    pub(in crate::elevation::shim) fn signal(&self, to: ToChild) -> Result<(), rustix::io::Errno> {
        rustix::process::pidfd_send_signal(&self.pidfd, rustix_signal(to))
    }
}

/// Unused by the child: keeps [`Signal`] in the protocol's vocabulary for the report.
#[allow(dead_code, reason = "documents the report's signal type")]
type _ReportSignal = Signal;
