//! What cosca asks Darwin about a process, and nothing else: the counterpart of
//! `identity::linux::kernel`. [`HostKernel`] makes the calls (`waitid`, `proc_pidinfo`,
//! `sysctl(KERN_PROC_PID)` and the kqueue registration); the test `FakeKernel` answers from a table of
//! stated answers and models no kernel.
//!
//! Every decision stays in a function above the trait, over a `&dyn Kernel` or a kernel the
//! caller owns.

use std::io;

use super::kinfo::{self, kinfo_proc};
use super::{pidinfo, warn_partial, ProcUniqIdentifierInfo, ReadErr, UniqInfo, UniqRead, PROC_PIDUNIQIDENTIFIERINFO};
use crate::identity::{RawPid, Record, Resolved};
use crate::os_process::macos::kqueue::{Kqueue, Subscription};

pub(crate) trait Kernel: Sync {
    /// `waitid(P_PID, pid, WEXITED | WNOHANG | WNOWAIT)`: the record a peek sees, without consuming it.
    fn peek(&self, pid: u32) -> io::Result<Option<Record>>;

    /// `waitid(P_PID, pid, WEXITED | WNOHANG)`: the record this call consumes.
    fn consume(&self, pid: u32) -> io::Result<Option<Record>>;

    /// `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO, 1)`: a process's unique id, unprivileged for any
    /// user's process, and it sees zombies.
    fn unique_info(&self, pid: RawPid) -> UniqRead;

    /// `proc_pidinfo(PROC_PIDT_SHORTBSDINFO, 1)`.
    fn short_bsd(&self, pid: RawPid) -> Result<libc::proc_bsdshortinfo, ReadErr>;

    /// `proc_pidinfo(PROC_PIDTBSDINFO, 1)`.
    fn bsd_info(&self, pid: RawPid) -> Result<libc::proc_bsdinfo, ReadErr>;

    /// `sysctl(KERN_PROC_PID)`. `Unknown` folds `EPERM`/`EACCES`, `ENOMEM`/`EINVAL` and a wrong-sized
    /// record; the second element is the failure that left it so (the errno, or the size written), and
    /// `None` for every other answer.
    fn kinfo(&self, pid: RawPid) -> (Resolved<kinfo_proc>, Option<io::Error>);

    /// The registration [`Kqueue::subscribe`] makes, through the kernel: every registration (exit
    /// watch, reap waiter, tracer arm) goes here.
    fn subscribe(&self, kq: &Kqueue, what: Subscription) -> io::Result<()>;
}

/// The real kernel.
pub(crate) struct HostKernel;

impl Kernel for HostKernel {
    fn peek(&self, pid: u32) -> io::Result<Option<Record>> {
        waitid_record(pid, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
    }

    fn consume(&self, pid: u32) -> io::Result<Option<Record>> {
        waitid_record(pid, libc::WEXITED | libc::WNOHANG)
    }

    fn unique_info(&self, pid: RawPid) -> UniqRead {
        // SAFETY: all-zero is a valid `ProcUniqIdentifierInfo`.
        let mut info: ProcUniqIdentifierInfo = unsafe { std::mem::zeroed() };
        match pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, &mut info) {
            Ok(()) => UniqRead::Found(UniqInfo {
                unique_id: info.p_uniqueid,
                id_version: info.p_idversion,
            }),
            Err(ReadErr::Gone) => UniqRead::Gone,
            Err(ReadErr::Refused(errno)) => UniqRead::Refused(errno),
            Err(partial @ ReadErr::Partial { .. }) => {
                warn_partial(pid, PROC_PIDUNIQIDENTIFIERINFO, &partial);
                UniqRead::Refused(libc::EIO)
            }
        }
    }

    fn short_bsd(&self, pid: RawPid) -> Result<libc::proc_bsdshortinfo, ReadErr> {
        // SAFETY: all-zero is a valid `proc_bsdshortinfo`.
        let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
        pidinfo(pid, libc::PROC_PIDT_SHORTBSDINFO, &mut info)
            .inspect_err(|e| warn_partial(pid, libc::PROC_PIDT_SHORTBSDINFO, e))
            .map(|()| info)
    }

    fn bsd_info(&self, pid: RawPid) -> Result<libc::proc_bsdinfo, ReadErr> {
        // SAFETY: all-zero is a valid `proc_bsdinfo`.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        pidinfo(pid, libc::PROC_PIDTBSDINFO, &mut info).map(|()| info)
    }

    fn kinfo(&self, pid: RawPid) -> (Resolved<kinfo_proc>, Option<io::Error>) {
        kinfo::host_kinfo(pid)
    }

    fn subscribe(&self, kq: &Kqueue, what: Subscription) -> io::Result<()> {
        kq.subscribe(what).map_err(crate::error::Error::into_io)
    }
}

/// One `waitid(P_PID, pid, options)`. `Ok(None)` when nothing matched: XNU leaves a `siginfo_t`
/// untouched then (`kern_exit.c:3364-3380`), so it is zeroed first and `si_pid == 0` means none.
///
/// `options` must carry `WNOHANG`. A blocking `waitid` sleeps until a child of this process changes
/// state: under `SIGCHLD` set to `SIG_IGN`, where the kernel reaps the child itself, until the child
/// list empties, which a live sibling can postpone for ever.
fn waitid_record(pid: u32, options: libc::c_int) -> io::Result<Option<Record>> {
    debug_assert!(
        options & libc::WNOHANG != 0,
        "a blocking waitid sleeps until the child list empties under SIG_IGN"
    );
    // SAFETY: `siginfo_t` is plain old data; all-zero is a valid value.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: `info` is a valid, writable `siginfo_t` for the whole call.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, options) };
        if r == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
    if info.si_pid == 0 {
        return Ok(None);
    }
    Ok(Some(Record {
        si_code: info.si_code,
        si_status: info.si_status,
    }))
}

forward_kernel! {
    fn peek(&self, pid: u32) -> io::Result<Option<Record>>;
    fn consume(&self, pid: u32) -> io::Result<Option<Record>>;
    fn unique_info(&self, pid: RawPid) -> UniqRead;
    fn short_bsd(&self, pid: RawPid) -> Result<libc::proc_bsdshortinfo, ReadErr>;
    fn bsd_info(&self, pid: RawPid) -> Result<libc::proc_bsdinfo, ReadErr>;
    fn kinfo(&self, pid: RawPid) -> (Resolved<kinfo_proc>, Option<io::Error>);
    fn subscribe(&self, kq: &Kqueue, what: Subscription) -> io::Result<()>;
}

#[cfg(test)]
#[path = "kernel/fake.rs"]
pub(crate) mod fake;

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod kernel_tests;
