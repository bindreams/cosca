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

/// `data` is the signal `PT_CONTINUE` delivers, 0 for none, and is ignored by the other requests.
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

pub(super) fn detach(pid: u32) -> Result<(), i32> {
    ptrace(libc::PT_DETACH, pid, 0)
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
    /// Stopped by the signal, but not every thread is parked yet: the stop has not settled.
    Settling,
    /// Stopped by the signal, every thread parked (see [`stop`]).
    Stopped(i32),
}

/// Whether the tracee is stopped, and by which signal, without consuming the stop.
///
/// A traced stop sets `SSTOP` and `sigwait`, posts `SIGCHLD`, and only then waits on `sigwait`
/// (xnu `kern_sig.c`, `issignal_locked`). A `PT_CONTINUE`/`PT_DETACH` in that window finds no
/// waiter and is lost: the thread then sleeps for good and `ptrace` answers `EBUSY`. In the
/// window a thread runs or waits `THREAD_UNINT`; the `sigwait` wait is interruptible. So a stop
/// counts only once every thread is [`parked`].
pub(super) fn stop(pid: u32) -> Result<Stop, i32> {
    verdict(&peek(pid, libc::WSTOPPED | libc::WNOHANG)?, || threads(pid))
}

/// [`stop`]'s answer from its `waitid` peek and, if that found a stop, the tracee's `threads`.
fn verdict(peeked: &libc::siginfo_t, threads: impl FnOnce() -> Result<Vec<Thread>, i32>) -> Result<Stop, i32> {
    if peeked.si_pid == 0 {
        return Ok(Stop::Running);
    }
    match threads() {
        Ok(threads) if all_parked(&threads) => Ok(Stop::Stopped(peeked.si_status)),
        Ok(_) => Ok(Stop::Settling),
        // Exiting, and so no longer stopped: its NOTE_EXIT follows.
        Err(libc::ESRCH) => Ok(Stop::Running),
        Err(e) => Err(e),
    }
}

/// `<sys/proc_info_private.h>`: lists a process's unique thread ids. Not in `libc`.
const PROC_PIDLISTTHREADIDS: libc::c_int = 28;

/// `<sys/proc_info.h>`: one thread's info by unique thread id. Not in `libc`.
const PROC_PIDTHREADID64INFO: libc::c_int = 15;

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

/// Whether every one of `threads` is [`parked`]. A thread that exited between the listing and its
/// read (`None`) leaves the verdict unsettled, so the caller peeks again under its backoff.
fn all_parked(threads: &[Thread]) -> bool {
    threads
        .iter()
        .all(|(_, info)| info.is_some_and(|info| parked(info.pth_run_state, info.pth_flags)))
}

/// A thread's unique id and info, `None` if it exited between the listing and its read.
pub(super) type Thread = (u64, Option<libc::proc_threadinfo>);

/// Every thread of `pid`, or the errno. Listed by unique thread id: a listing by TSD base names
/// every raw Mach thread 0.
pub(super) fn threads(pid: u32) -> Result<Vec<Thread>, i32> {
    threads_with(
        || thread_ids(pid),
        |id| {
            // SAFETY: `proc_threadinfo` is plain data; all-zero is a valid value.
            let mut thread: [libc::proc_threadinfo; 1] = unsafe { std::mem::zeroed() };
            pidinfo(pid, PROC_PIDTHREADID64INFO, id, &mut thread).map(|_| thread[0])
        },
    )
}

/// `list`'s threads, each read with `read`. A read's `ESRCH` means that thread exited after the
/// listing, not the process: `None`.
fn threads_with<T>(
    list: impl FnOnce() -> Result<Vec<u64>, i32>,
    read: impl Fn(u64) -> Result<T, i32>,
) -> Result<Vec<(u64, Option<T>)>, i32> {
    list()?
        .into_iter()
        .map(|id| match read(id) {
            Ok(thread) => Ok((id, Some(thread))),
            Err(libc::ESRCH) => Ok((id, None)),
            Err(e) => Err(e),
        })
        .collect()
}

/// The unique ids of `pid`'s threads.
fn thread_ids(pid: u32) -> Result<Vec<u64>, i32> {
    // SAFETY: `proc_taskinfo` is plain data; all-zero is a valid value.
    let mut task: [libc::proc_taskinfo; 1] = unsafe { std::mem::zeroed() };
    pidinfo(pid, libc::PROC_PIDTASKINFO, 0, &mut task)?;
    let mut ids = vec![0u64; task[0].pti_threadnum.max(1) as usize];
    loop {
        let n = pidinfo(pid, PROC_PIDLISTTHREADIDS, 0, &mut ids)? / std::mem::size_of::<u64>();
        // A full buffer may have cut the list short.
        if n < ids.len() {
            ids.truncate(n);
            return Ok(ids);
        }
        ids.resize(ids.len() * 2, 0);
    }
}

/// Whether a thread is waiting interruptibly, suspended, or never started. XNU reports a running
/// or runnable thread as `TH_STATE_RUNNING`, and one in a `THREAD_UNINT` wait as
/// `TH_STATE_UNINTERRUPTIBLE`.
///
/// A never-started thread also reads `TH_STATE_UNINTERRUPTIBLE` and stays so while the stop
/// holds the task, but has no kernel stack (`TH_FLAGS_SWAPPED`); every wait in the stop's window
/// keeps its stack. So a stackless uninterruptible thread counts as parked, else such a stop
/// never settles.
///
/// Panics on a run state that is no `TH_STATE_*`: `retrieve_thread_basic_info` sets one under
/// `thread_lock` for every thread.
fn parked(run_state: i32, flags: i32) -> bool {
    match run_state {
        libc::TH_STATE_RUNNING => false,
        libc::TH_STATE_UNINTERRUPTIBLE => flags & libc::TH_FLAGS_SWAPPED != 0,
        libc::TH_STATE_WAITING | libc::TH_STATE_STOPPED | libc::TH_STATE_HALTED => true,
        other => panic!("pth_run_state {other} is no TH_STATE_*"),
    }
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

#[cfg(test)]
#[path = "sys_tests.rs"]
mod sys_tests;
