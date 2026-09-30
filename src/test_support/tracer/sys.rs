//! The helper's raw syscalls. Each returns the errno it failed with.

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .expect("a failed syscall sets errno")
}

/// The attach request. `PT_ATTACH`, not `PT_ATTACHEXC`: measured on CI, a tracee attached with
/// `PT_ATTACHEXC` by a tracer that registers no exception port usually never reaches `SSTOP`
/// (its `SIGSTOP` is turned into a Mach exception that nothing answers), so the stop every
/// later request needs never comes.
const ATTACH: libc::c_int = libc::PT_ATTACH;

/// `data` is the signal `PT_CONTINUE` or `PT_DETACH` delivers, 0 for none, and is ignored by the
/// attach requests.
fn ptrace(request: libc::c_int, pid: u32, data: i32) -> Result<(), i32> {
    // `addr` is `(caddr_t)1`, "resume where it stopped", for PT_CONTINUE and PT_DETACH, and is
    // ignored by the attach requests.
    // SAFETY: no pointer is dereferenced by these requests.
    let rc = unsafe {
        libc::ptrace(
            request,
            pid as libc::pid_t,
            std::ptr::dangling_mut::<libc::c_char>(),
            data,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

pub(super) fn attach(pid: u32) -> Result<(), i32> {
    ptrace(ATTACH, pid, 0)
}

/// `PT_CONTINUE`, delivering `signal` (0 for none).
pub(super) fn cont(pid: u32, signal: i32) -> Result<(), i32> {
    ptrace(libc::PT_CONTINUE, pid, signal)
}

/// `PT_CONTINUE` delivering no signal.
pub(super) fn resume(pid: u32) -> Result<(), i32> {
    cont(pid, 0)
}

/// `PT_DETACH`, handing `signal` (0 for none) to the thread that took the stop.
pub(super) fn detach(pid: u32, signal: i32) -> Result<(), i32> {
    ptrace(libc::PT_DETACH, pid, signal)
}

pub(super) fn kill(pid: u32, signal: i32) -> Result<(), i32> {
    // SAFETY: kill(2) has no memory preconditions.
    if unsafe { libc::kill(pid as libc::pid_t, signal) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// `wait4(pid)`, blocking. `Err(EINVAL)` if it returned a stop, which a tracer's `wait4` also
/// reports, rather than reaping an exit.
pub(super) fn reap(pid: u32) -> Result<(), i32> {
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer; rusage is not requested.
    let rc = unsafe { libc::wait4(pid as libc::pid_t, &mut status, 0, std::ptr::null_mut()) };
    if rc != pid as libc::pid_t {
        Err(errno())
    } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
        Ok(())
    } else {
        Err(libc::EINVAL)
    }
}

/// Blocking `waitid(P_PID, pid, WEXITED | WNOWAIT)`: returns once the tracee is a zombie,
/// without reaping it. `Err` carries the errno, or `EINVAL` for a record that is not an exit.
pub(super) fn await_zombie(pid: u32) -> Result<(), i32> {
    let info = peek(pid, libc::WEXITED)?;
    // CLD_EXITED, CLD_KILLED, CLD_DUMPED (<sys/signal.h>). Measured on CI: a WEXITED-only waitid
    // by the tracer also returns a traced child's stop, so the code is checked.
    if matches!(info.si_code, 1..=3) {
        Ok(())
    } else {
        Err(libc::EINVAL)
    }
}

/// `proc_pidinfo(PROC_PIDTBSDINFO)`: `Ok(pbi_status)` (`SSTOP` is 4), or the errno.
pub(super) fn pbi_status(pid: u32) -> Result<u32, i32> {
    // SAFETY: `proc_bsdinfo` is plain data; all-zero is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is a valid, writable buffer of `size` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    if n == size {
        Ok(info.pbi_status)
    } else {
        Err(errno())
    }
}

/// The stop peek's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stop {
    /// Not stopped: running, or exiting.
    Running,
    /// Stopped by the signal, but a thread still runs: the stop has not settled.
    Settling,
    /// Stopped by the signal, every thread blocked.
    Stopped(i32),
}

/// Whether the tracee is stopped, and by which signal, without consuming the stop.
///
/// A traced stop sets `SSTOP` and posts `SIGCHLD` to the tracer before its thread waits for the
/// tracer's release, and a `PT_CONTINUE` or `PT_DETACH` in between wakes nothing: the tracee then
/// never runs again (xnu `kern_sig.c`, `issignal`, `assert_wait` on `sigwait`; seen on CI as a
/// tracee that neither exits nor stops again). So a stop counts only once no thread of the
/// tracee is in the running state.
pub(super) fn stop(pid: u32) -> Result<Stop, i32> {
    let info = peek(pid, libc::WSTOPPED | libc::WNOHANG)?;
    if info.si_pid == 0 {
        return Ok(Stop::Running);
    }
    match threads_blocked(pid) {
        Ok(true) => Ok(Stop::Stopped(info.si_status)),
        Ok(false) => Ok(Stop::Settling),
        // Exiting, and so no longer stopped: its NOTE_EXIT follows.
        Err(libc::ESRCH) => Ok(Stop::Running),
        Err(e) => Err(e),
    }
}

/// What a process does with a signal it is sent, as `sysctl(KERN_PROC_PID)` reports it in
/// `kinfo_proc`'s `p_sigignore` and `p_sigcatch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Disposition {
    /// `SIG_DFL`.
    Default,
    /// A handler runs.
    Caught,
    /// `SIG_IGN`.
    Ignored,
}

/// `signal`'s disposition in `pid`. `Err(ESRCH)` once `pid` is reaped, `Err(EPERM)` if the kernel
/// refused the query.
///
/// An exiting process, a zombie included, is still found, and reports every signal ignored
/// while it keeps its handlers (xnu `kern_exit.c`, `proc_prepareexit` sets `p_sigignore`): a
/// handler wins, which is the answer it gave while it lived.
pub(super) fn disposition(pid: u32, signal: i32) -> Result<Disposition, i32> {
    use crate::identity::{kinfo::kinfo, Resolved};
    match kinfo(pid as _) {
        Resolved::Found(info) => {
            let (ignored, caught) = (info.kp_proc.sig_ignored(signal), info.kp_proc.sig_caught(signal));
            Ok(if caught {
                Disposition::Caught
            } else if ignored {
                Disposition::Ignored
            } else {
                Disposition::Default
            })
        }
        Resolved::Gone => Err(libc::ESRCH),
        Resolved::Unknown => Err(libc::EPERM),
    }
}

/// `<sys/proc_info.h>`: lists a process's thread handles. Not in `libc`.
const PROC_PIDLISTTHREADS: libc::c_int = 6;

/// `proc_pidinfo` into `buf`, `Ok` with the bytes written.
fn pidinfo<T>(pid: u32, flavor: libc::c_int, arg: u64, buf: &mut [T]) -> Result<usize, i32> {
    let size = std::mem::size_of_val(buf) as libc::c_int;
    // SAFETY: `buf` is a valid, writable buffer of `size` bytes of plain data.
    let n = unsafe { libc::proc_pidinfo(pid as libc::c_int, flavor, arg, buf.as_mut_ptr().cast(), size) };
    if n > 0 {
        Ok(n as usize)
    } else {
        Err(errno())
    }
}

/// `Ok(true)` if no thread of `pid` is in the running state.
fn threads_blocked(pid: u32) -> Result<bool, i32> {
    // SAFETY: `proc_taskinfo` is plain data; all-zero is a valid value.
    let mut task: [libc::proc_taskinfo; 1] = unsafe { std::mem::zeroed() };
    pidinfo(pid, libc::PROC_PIDTASKINFO, 0, &mut task)?;
    let mut handles = vec![0u64; task[0].pti_threadnum.max(1) as usize];
    let listed = loop {
        let n = pidinfo(pid, PROC_PIDLISTTHREADS, 0, &mut handles)? / std::mem::size_of::<u64>();
        // A full buffer may have cut the list short.
        if n < handles.len() {
            break n;
        }
        handles.resize(handles.len() * 2, 0);
    };
    for &handle in &handles[..listed] {
        // SAFETY: `proc_threadinfo` is plain data; all-zero is a valid value.
        let mut thread: [libc::proc_threadinfo; 1] = unsafe { std::mem::zeroed() };
        pidinfo(pid, libc::PROC_PIDTHREADINFO, handle, &mut thread)?;
        if thread[0].pth_run_state == libc::TH_STATE_RUNNING {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `Ok` while `pid` is this process's unreaped child: a `waitid` peek that neither blocks nor
/// reaps. `Err(ECHILD)` once it is reaped, or while another process traces it.
pub(super) fn peek_child(pid: u32) -> Result<(), i32> {
    peek(pid, libc::WEXITED | libc::WSTOPPED | libc::WNOHANG).map(drop)
}

/// `waitid(P_PID, pid, flags | WNOWAIT)`, retried on `EINTR`.
pub(super) fn peek(pid: u32, flags: libc::c_int) -> Result<libc::siginfo_t, i32> {
    loop {
        // SAFETY: `siginfo_t` is plain data; all-zero is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid out-pointer.
        if unsafe { libc::waitid(libc::P_PID, pid, &mut info, flags | libc::WNOWAIT) } == 0 {
            return Ok(info);
        }
        match errno() {
            libc::EINTR => continue,
            e => return Err(e),
        }
    }
}

/// `None` at EOF.
pub(super) fn read_byte(fd: i32) -> Option<u8> {
    let mut byte = 0u8;
    loop {
        // SAFETY: `byte` is a valid one-byte buffer.
        match unsafe { libc::read(fd, (&raw mut byte).cast(), 1) } {
            1 => return Some(byte),
            0 => return None,
            _ => match errno() {
                libc::EINTR => continue,
                e => panic!("read from fd {fd} failed: errno {e}"),
            },
        }
    }
}

fn receipt(kq: &Kqueue, change: KEvent) -> Result<(), i32> {
    match crate::wait::backend::add_with_receipt(kq, change) {
        Ok(0) => Ok(()),
        Ok(errno) => Err(errno as i32),
        Err(e) => panic!("kevent registration failed outright: {e}"),
    }
}

/// Registers `NOTE_EXIT` for `pid` (`EV_RECEIPT`, so its error is known at once).
pub(super) fn watch_exit(kq: &Kqueue, pid: u32) -> Result<(), i32> {
    receipt(
        kq,
        KEvent::new(
            pid as usize,
            EventFilter::EVFILT_PROC,
            EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
            FilterFlag::NOTE_EXIT,
            0,
            0,
        ),
    )
}

/// Registers `EVFILT_READ` on fd 0, the signal pipe.
pub(super) fn watch_signal_pipe(kq: &Kqueue) -> Result<(), i32> {
    receipt(kq, read_knote(EvFlags::EV_ADD | EvFlags::EV_RECEIPT))
}

/// Registers `EVFILT_SIGNAL` for `SIGCHLD`, which XNU sends this tracer when its tracee stops.
pub(super) fn watch_sigchld(kq: &Kqueue) -> Result<(), i32> {
    receipt(
        kq,
        KEvent::new(
            libc::SIGCHLD as usize,
            EventFilter::EVFILT_SIGNAL,
            EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
            FilterFlag::empty(),
            0,
            0,
        ),
    )
}

/// Removes the signal pipe's knote after its EOF, which would otherwise stay readable forever.
pub(super) fn unwatch_signal_pipe(kq: &Kqueue) {
    receipt(kq, read_knote(EvFlags::EV_DELETE | EvFlags::EV_RECEIPT))
        .unwrap_or_else(|e| panic!("EV_DELETE of the signal pipe's knote failed: errno {e}"));
}

fn read_knote(flags: EvFlags) -> KEvent {
    KEvent::new(0, EventFilter::EVFILT_READ, flags, FilterFlag::empty(), 0, 0)
}
