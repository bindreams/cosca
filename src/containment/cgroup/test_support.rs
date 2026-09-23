//! Helpers the cgroup module's tests share.

/// Fork a child that runs `body` and exits with `_exit(0)`. `body` must be async-signal-safe:
/// this process has other threads.
#[cfg(target_os = "linux")]
pub(crate) fn fork_running(body: impl FnOnce()) -> u32 {
    // SAFETY: the child runs only `body`, async-signal-safe by the caller's contract, then
    // `_exit`s without unwinding or running destructors.
    match unsafe { libc::fork() } {
        -1 => panic!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            body();
            // SAFETY: async-signal-safe.
            unsafe { libc::_exit(0) }
        }
        pid => pid as u32,
    }
}

/// Reap `pid`, a child of this process.
#[cfg(target_os = "linux")]
pub(crate) fn reap(pid: u32) {
    let mut status = 0;
    // SAFETY: `pid` is this process's own child; `status` is a valid, writable int.
    let reaped = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(reaped, pid as i32, "waitpid: {}", std::io::Error::last_os_error());
}

/// Block on `gate` until a byte arrives. Async-signal-safe.
#[cfg(target_os = "linux")]
pub(crate) fn block_on(gate: std::os::fd::RawFd) {
    let mut byte = 0u8;
    // SAFETY: `gate` is an open read end; `byte` is a valid one-byte buffer.
    unsafe { libc::read(gate, (&raw mut byte).cast(), 1) };
}

/// A copy of `channel`'s child end, standing in for the one a forked child inherits: the parent's
/// own copy closes when the exchange ends, as it does in a real spawn.
#[cfg(target_os = "linux")]
pub(crate) fn childs_copy(
    channel: &crate::containment::cgroup::ReportChannel,
) -> (std::os::fd::OwnedFd, crate::containment::cgroup::ReportSlot) {
    use std::os::fd::{AsRawFd, BorrowedFd};

    // SAFETY: the slot's descriptor is open for as long as `channel` lives, which spans this call.
    let end = unsafe { BorrowedFd::borrow_raw(channel.slot().fd) }
        .try_clone_to_owned()
        .expect("dup the child's end");
    let slot = crate::containment::cgroup::ReportSlot {
        fd: end.as_raw_fd(),
        parent_fd: -1,
    };
    (end, slot)
}
