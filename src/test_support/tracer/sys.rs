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
/// later request needs never comes. `PT_ATTACH` reparents the tracee to the tracer exactly as
/// `PT_ATTACHEXC` does and stops it the BSD way.
const ATTACH: libc::c_int = libc::PT_ATTACH;

fn ptrace(request: libc::c_int, pid: u32) -> Result<(), i32> {
    // `addr` is `(caddr_t)1`, "resume where it stopped", for PT_CONTINUE and PT_DETACH, and is
    // ignored by the attach requests; `data` 0 delivers no signal. `dangling_mut::<c_char>()` is
    // address 1 without an integer-to-pointer cast.
    // SAFETY: no pointer is dereferenced by these requests.
    let rc = unsafe { libc::ptrace(request, pid as libc::pid_t, std::ptr::dangling_mut::<libc::c_char>(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

pub(super) fn attach(pid: u32) -> Result<(), i32> {
    ptrace(ATTACH, pid)
}

pub(super) fn cont(pid: u32) -> Result<(), i32> {
    ptrace(libc::PT_CONTINUE, pid)
}

/// `PT_CONTINUE` delivering `signal`: passes on the signal a traced stop intercepted.
pub(super) fn cont_with(pid: u32, signal: i32) -> Result<(), i32> {
    // SAFETY: as `ptrace` above; `data` is a signal number.
    let rc = unsafe {
        libc::ptrace(
            libc::PT_CONTINUE,
            pid as libc::pid_t,
            std::ptr::dangling_mut::<libc::c_char>(),
            signal,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

pub(super) fn detach(pid: u32) -> Result<(), i32> {
    ptrace(libc::PT_DETACH, pid)
}

pub(super) fn sigstop(pid: u32) -> Result<(), i32> {
    // SAFETY: plain kill(2).
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) } == 0 {
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
    loop {
        // SAFETY: `siginfo_t` is plain data; all-zero is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid out-pointer.
        if unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) } == 0 {
            // CLD_EXITED, CLD_KILLED, CLD_DUMPED (<sys/signal.h>). Measured on CI: a WEXITED-only
            // waitid by the tracer also returns a traced child's stop, so the code is checked.
            return if matches!(info.si_code, 1..=3) {
                Ok(())
            } else {
                Err(libc::EINVAL)
            };
        }
        match errno() {
            libc::EINTR => continue,
            e => return Err(e),
        }
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

/// `waitid(P_PID, pid, WSTOPPED | WNOHANG | WNOWAIT)`: `Ok(Some(signal))` while the tracee is
/// stopped by `signal`, `Ok(None)` while it runs or has exited. Does not consume the stop.
pub(super) fn stop_signal(pid: u32) -> Result<Option<i32>, i32> {
    loop {
        // SAFETY: `siginfo_t` is plain data; all-zero is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid out-pointer.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            return Ok((info.si_pid != 0).then_some(info.si_status));
        }
        match errno() {
            libc::EINTR => continue,
            e => return Err(e),
        }
    }
}

/// One blocking `read(2)` of a byte, retried on `EINTR`. `None` at EOF.
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
