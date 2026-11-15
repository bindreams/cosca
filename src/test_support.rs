//! Test-only support shared across the crate's unit tests.

// A `Root` with stated answers.
pub(crate) mod stated_root;

// The debugger stand-in is `ptrace` on macOS.
#[cfg(target_os = "macos")]
pub(crate) mod tracer;

// The foreign tracer: see the module doc.
#[cfg(target_os = "linux")]
pub(crate) mod foreign_tracer;

// The test thread as the tracer of its own child.
#[cfg(target_os = "linux")]
pub(crate) mod own_tracer;

/// Blocks until the spawn core's status has said all it will: a failure record, or the end.
#[cfg(target_os = "linux")]
pub(crate) fn settled(status: &mut crate::child::spawn::fork_exec::Status) -> crate::child::spawn::fork_exec::Progress {
    use crate::child::spawn::fork_exec::Progress;

    loop {
        match status.progress().expect("the status pipe reads") {
            Progress::Pending | Progress::Ready => {
                let fd = status.as_fd();
                let mut fds = [rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN)];
                crate::wait::poll_ready(&mut fds).expect("poll the status pipe");
            }
            settled => return settled,
        }
    }
}

/// The exit status of `child`, a clone the spawn core made, reaped through its pidfd.
#[cfg(target_os = "linux")]
pub(crate) fn exit_status(child: &crate::os_process::linux::fork::NewChild) -> i32 {
    use std::os::fd::AsFd;

    let done = rustix::process::waitid(
        rustix::process::WaitId::PidFd(child.pidfd.as_fd()),
        rustix::process::WaitIdOptions::EXITED,
    )
    .expect("waitid on the pidfd")
    .expect("a blocking wait returns a status");
    done.exit_status().unwrap_or_else(|| {
        panic!(
            "the child did not exit: it died of signal {:?}",
            done.terminating_signal()
        )
    }) as i32
}

/// Closes every descriptor above stdio, the spawn core's status channel among them, which the core's
/// contract forbids a real step: the child's writes to the channel are then `EBADF`. For a step run in
/// the child of a spawn; it makes raw system calls only.
#[cfg(target_os = "linux")]
pub(crate) fn close_every_descriptor_above_stdio() {
    // SAFETY: a raw `close_range` of every descriptor above stdio; where the kernel has none (it is
    // Linux 5.9, above the floor), a `close` of every number below the descriptor limit.
    unsafe {
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == -1 {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
            for fd in 3..limit.rlim_cur.min(libc::c_int::MAX as u64) as libc::c_int {
                libc::close(fd);
            }
        }
    }
}

/// The read of `pid` a policy test states as "could not be read": the identity read's own answer
/// when its `pidfd_open` is refused with `EMFILE`, cause included.
#[cfg(target_os = "linux")]
pub(crate) fn emfile_number_read(pid: u32) -> crate::identity::NumberRead {
    use crate::identity::{FakeKernel, HostKernel, ProcessId};
    let refused = FakeKernel::over(&HostKernel).on_pidfd_open(pid, Err(rustix::io::Errno::MFILE));
    ProcessId::of_with(&refused, pid)
}
