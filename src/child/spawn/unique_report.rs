//! macOS: the child reports its own unique id before `exec`.
//!
//! macOS has no pidfd, so nothing pins a pid. A parent that read a fresh child's unique id by pid
//! after `spawn()` would race a foreign reap and a reuse of the number: it would take a stranger's
//! id for the child's. So the child reads `proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO)`
//! itself, in a `pre_exec` hook, and writes the answer to a pipe the parent reads after `spawn()`.
//!
//! The hook is async-signal-safe: it reads atomics, makes one `proc_pidinfo` call (a direct
//! `__proc_info` syscall) and one `write` of at most `PIPE_BUF` bytes, which is atomic. The pipe is
//! made on the shared [`fd_channel`](super::fd_channel) skeleton, and the hook is registered
//! before every other so `fd_map`'s `dup2` onto its number cannot come first.
//!
//! A refused read is reported, then the hook fails: `exec` never runs, the spawn is an `Err`, and
//! std collects the child. A signal that kills the child between the report and std's own errno
//! write makes the spawn `Ok` with the same report, and the same refusal.
//!
//! `spawn()` returning `Ok` does not mean the child execed: std reads EOF on its own close-on-exec
//! pipe both after a successful `exec` and after a child killed by a signal before it. So the
//! report may be missing on `Ok`, and [`Report::Missing`] says so.
//!
//! Nor does it mean the child has reported yet. With two of this process's fds 0 to 2 closed, std's
//! close-on-exec pipe takes one of the child's stdio numbers, so std returns before the child's
//! hooks run (see `crate::containment::cgroup::channel::ReportChannel`). The pipe is then empty but
//! open, [`Report::Unwritten`], and the child may report and `exec` afterwards.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use super::fd_channel::{self, publish_ends, Shared};
use super::SpawnLockGuard;
use crate::error::Error;

/// A report's tag: the value is the child's unique id.
const REPORT_ID: u32 = 1;
/// A report's tag: the child's own read failed; the value is its errno.
const REPORT_ERRNO: u32 = 2;
/// A report is a native-endian `u32` tag, then a native-endian `u64` value. At most `PIPE_BUF`,
/// so its `write` is atomic.
const REPORT_LEN: usize = 12;

/// What the parent found in the pipe.
#[derive(Debug)]
pub(crate) enum Report {
    /// The child's own unique id.
    Id(u64),
    /// The child's own read was refused with this errno; its hook then failed before `exec`.
    ChildRefused(i32),
    /// No report, or a short one, and every copy of the write end closed: the child died before it
    /// could write it (before `exec`).
    Missing,
    /// No report, and the pipe still open: the child has not written it yet, or a copy of the write
    /// end outlives it in another forked process. Nothing shows the child did not go on to `exec`.
    Unwritten,
    /// This process's own read of the pipe failed.
    ReadFailed(io::Error),
    /// A tag no hook writes.
    BadTag(u32),
}

/// The hook is registered; the pipe is not yet made. See [`register`].
pub(crate) struct Pending {
    shared: Arc<Shared>,
}

/// The pipe to one child. Consumed by [`run`](Self::run).
pub(crate) struct Channel {
    read_end: OwnedFd,
    write_end: OwnedFd,
    shared: Arc<Shared>,
}

/// Registers the reporting hook on `cmd`, before any other hook.
pub(crate) fn register(cmd: &mut std::process::Command) -> Pending {
    // Thread-locals are not visible in the forked child, so capture the seam before the fork.
    #[cfg(test)]
    let seam = seams::armed();
    // SAFETY: the hook is async-signal-safe: it reads atomics and makes only direct syscalls
    // (`proc_pidinfo`, `write`, and in tests `kill`) on stack buffers. It allocates nothing, takes
    // no lock and never panics.
    let shared = unsafe {
        fd_channel::register(cmd, move |shared| {
            report(
                shared,
                #[cfg(test)]
                seam,
            )
        })
    };
    Pending { shared }
}

impl Pending {
    /// Makes the pipe and publishes its write end to the hook. `_lock` is the witness that no other
    /// cosca fork can inherit the ends before they are close-on-exec.
    pub(crate) fn open(self, _lock: &SpawnLockGuard) -> Result<Channel, Error> {
        let (read_end, write_end) = std::io::pipe().map_err(|e| Error::Io(crate::error::io_context("pipe", e)))?;
        let (write_end, read_end) = publish_ends(&self.shared, OwnedFd::from(write_end), OwnedFd::from(read_end))?;
        set_nonblocking(&read_end)?;
        Ok(Channel {
            read_end,
            write_end,
            shared: self.shared,
        })
    }
}

/// Non-blocking, so a stray copy of the write end (a foreign fork) cannot hang the read.
fn set_nonblocking(fd: &OwnedFd) -> Result<(), Error> {
    // SAFETY: `fcntl` on an fd this function borrows.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::Io(crate::error::io_context("fcntl", io::Error::last_os_error())));
    }
    Ok(())
}

impl Channel {
    /// Runs `spawn` with the pipe published, then reads what the child reported. The report comes
    /// with the spawn's result either way.
    pub(crate) fn run<T, E>(self, spawn: impl FnOnce() -> Result<T, E>) -> (Result<T, E>, Report) {
        let Channel {
            read_end,
            write_end,
            shared,
        } = self;
        let spawned = spawn();
        shared.withdraw();
        // Closed before the read, so a child that never wrote leaves the pipe at EOF.
        drop(write_end);
        (spawned, read_report(&read_end))
    }
}

/// Reads one report from the non-blocking `read_end`.
fn read_report(read_end: &OwnedFd) -> Report {
    #[cfg(test)]
    if let Some(errno) = seams::parent_read_fails() {
        return Report::ReadFailed(io::Error::from_raw_os_error(errno));
    }
    #[cfg(test)]
    if seams::parent_read_finds_nothing() {
        return Report::Unwritten;
    }
    let mut buf = [0u8; REPORT_LEN];
    let mut got = 0;
    while got < REPORT_LEN {
        // SAFETY: the pointer and length name the unfilled tail of `buf`.
        let n = unsafe { libc::read(read_end.as_raw_fd(), buf[got..].as_mut_ptr().cast(), REPORT_LEN - got) };
        if n > 0 {
            got += n as usize;
        } else if n == 0 {
            return Report::Missing;
        } else {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EAGAIN) => return Report::Unwritten,
                _ => return Report::ReadFailed(e),
            }
        }
    }
    let tag = u32::from_ne_bytes(buf[..4].try_into().expect("four bytes"));
    let value = u64::from_ne_bytes(buf[4..].try_into().expect("eight bytes"));
    match tag {
        REPORT_ID => Report::Id(value),
        REPORT_ERRNO => Report::ChildRefused(value as i32),
        other => Report::BadTag(other),
    }
}

/// A child `spawn` returned `Ok` for that cannot be adopted.
#[derive(Debug)]
pub(crate) struct NotAdopted {
    pub(crate) error: Error,
    pub(crate) why: Unadoptable,
}

/// Why a child cannot be adopted, which decides what the spawn does with it and what it answers.
/// The caller signals and waits on none of them by pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unadoptable {
    /// It died before `exec`, so only a corpse is left, and the program did not start.
    DiedBeforeExec,
    /// It had not reported when its spawn returned ([`Report::Unwritten`]): it may yet report, `exec`
    /// and run the program, so it is left running, and the program may have started.
    Unreported,
    /// Its report could not be read or is malformed: nothing shows what it is doing, and the program
    /// may have started.
    Unverified,
}

/// The spawn's unique id, or why the child cannot be adopted, for a spawn that returned `Ok`.
/// Either way the caller does not signal or wait on the child by pid.
pub(crate) fn adopted_id(report: Report, pid: u32) -> Result<u64, NotAdopted> {
    let not = |why, error| Err(NotAdopted { error, why });
    match report {
        Report::Id(id) => Ok(id),
        // The hook fails its spawn after reporting a refusal, so `Ok` is a child killed between its
        // report and std's own errno write: the same refusal, with the program not started.
        Report::ChildRefused(errno) => not(Unadoptable::DiedBeforeExec, refused_error(errno)),
        Report::Missing => not(
            Unadoptable::DiedBeforeExec,
            Error::Io(io::Error::other(format!(
                "the spawned child {pid} died before exec; the program did not start"
            ))),
        ),
        Report::Unwritten => not(
            Unadoptable::Unreported,
            Error::Io(io::Error::other(format!(
                "the spawned child {pid} had not reported its unique id when its spawn returned; the child was \
                 not adopted"
            ))),
        ),
        Report::ReadFailed(e) => not(
            Unadoptable::Unverified,
            Error::Unassessable {
                detail: format!("pid {pid}: its unique-id report could not be read ({e}); the child was not adopted"),
                source: Some(e),
            },
        ),
        Report::BadTag(tag) => {
            debug_assert!(false, "a unique-id report with tag {tag}");
            not(
                Unadoptable::Unverified,
                Error::Unassessable {
                    detail: format!(
                        "pid {pid}: its unique-id report is malformed (tag {tag}); the child was not adopted"
                    ),
                    source: None,
                },
            )
        }
    }
}

/// Whether `report` proves that the child of a spawn did not run the program: it refused its own
/// id (its hook then fails before `exec`), or it died before it could report. Any other report
/// leaves the program possibly started. Only the tokio spawn asks: std's own failed spawn proves it.
#[cfg(any(test, feature = "tokio"))]
pub(crate) fn proves_no_exec(report: &Report) -> bool {
    match report {
        Report::ChildRefused(_) | Report::Missing => true,
        Report::Id(_) | Report::Unwritten | Report::ReadFailed(_) | Report::BadTag(_) => false,
    }
}

/// The error for a failed spawn: only the child's own refusal changes it, because only then did the
/// hook fail the spawn. Any other report state keeps std's error, and is logged.
pub(crate) fn failed_spawn_error(error: Error, report: &Report) -> Error {
    match report {
        Report::ChildRefused(errno) => refused_error(*errno),
        other => {
            debug_assert!(
                !matches!(other, Report::BadTag(_)),
                "a unique-id report is malformed: {other:?}"
            );
            log::debug!("the spawn failed ({error}); the child's unique-id report was {other:?}");
            error
        }
    }
}

/// The error for a child that could not read its own unique id (`errno`). It is a refusal, not a
/// vanish.
pub(crate) fn refused_error(errno: i32) -> Error {
    Error::Unassessable {
        detail: format!(
            "the spawned child could not read its own unique id (errno {errno}); it was stopped before exec, so the program did not start"
        ),
        source: Some(io::Error::from_raw_os_error(errno)),
    }
}

/// The hook: the child reads its own unique id and writes the report. Async-signal-safe.
fn report(shared: &Shared, #[cfg(test)] seam: seams::Armed) -> io::Result<()> {
    #[cfg(test)]
    if let Some(errno) = seam.fail_before_report() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    #[cfg(test)]
    let read = seam.read(shared.child_end());
    #[cfg(not(test))]
    let read = crate::identity::own_unique_id();
    let (tag, value) = match read {
        Ok(id) => (REPORT_ID, id),
        Err(errno) => (REPORT_ERRNO, errno as u64),
    };
    let mut buf = [0u8; REPORT_LEN];
    buf[..4].copy_from_slice(&tag.to_ne_bytes());
    buf[4..].copy_from_slice(&value.to_ne_bytes());
    loop {
        // SAFETY: `buf` is valid for `REPORT_LEN` bytes.
        let n = unsafe { libc::write(shared.child_end(), buf.as_ptr().cast(), REPORT_LEN) };
        if n == REPORT_LEN as isize {
            return match tag {
                REPORT_ERRNO => Err(io::Error::from_raw_os_error(value as i32)),
                _ => Ok(()),
            };
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        // A short or empty write of a message under `PIPE_BUF` breaks the pipe's contract.
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
}

/// Test seams. Thread-local, armed on the thread that spawns, captured at [`register`].
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::Cell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Force {
        None,
        /// The child's own read fails with this errno.
        Errno(i32),
        /// The child is killed by `SIGKILL` before it reports.
        KillSelf,
        /// The hook fails with this errno before it reports.
        FailBeforeReport(i32),
    }

    thread_local! {
        static FORCE: Cell<Force> = const { Cell::new(Force::None) };
        static PARENT_READ_ERRNO: Cell<Option<i32>> = const { Cell::new(None) };
        static PARENT_READ_UNWRITTEN: Cell<bool> = const { Cell::new(false) };
    }

    /// What a hook registered on this thread was armed with.
    #[derive(Debug, Clone, Copy)]
    pub(super) struct Armed(Force);

    impl Armed {
        /// The child's read, as the seam shapes it. Async-signal-safe.
        pub(super) fn fail_before_report(self) -> Option<i32> {
            match self.0 {
                Force::FailBeforeReport(errno) => Some(errno),
                _ => None,
            }
        }

        /// `child_end` is the report pipe's write end.
        pub(super) fn read(self, child_end: std::os::fd::RawFd) -> Result<u64, i32> {
            match self.0 {
                Force::None | Force::FailBeforeReport(_) => crate::identity::own_unique_id(),
                Force::Errno(errno) => Err(errno),
                Force::KillSelf => {
                    // The write end is closed first: the kernel closes a dying process's descriptors
                    // one by one, so std's own pipe could read EOF, and the spawn read the report,
                    // while this one is still open. The parent then sees `Unwritten`, a child that
                    // may yet run, where a test of this seam asks for one that died.
                    // SAFETY: `close`, `kill` and `getpid` are async-signal-safe; the child dies here.
                    unsafe {
                        libc::close(child_end);
                        libc::kill(libc::getpid(), libc::SIGKILL);
                    }
                    Err(libc::EINTR)
                }
            }
        }
    }

    pub(super) fn armed() -> Armed {
        Armed(FORCE.with(Cell::get))
    }

    /// Disarms the force when dropped.
    #[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
    pub(crate) struct Forced(());

    impl Drop for Forced {
        fn drop(&mut self) {
            FORCE.with(|f| f.set(Force::None));
        }
    }

    /// The next spawns on this thread have their child's own read fail with `errno`.
    pub(crate) fn force_child_read_errno(errno: i32) -> Forced {
        FORCE.with(|f| f.set(Force::Errno(errno)));
        Forced(())
    }

    /// The next spawns on this thread have their hook fail with `errno` before it reports, as any
    /// failure ahead of it (or std's own `chdir`) fails a spawn with no report written.
    pub(crate) fn force_hook_failure_before_report(errno: i32) -> Forced {
        FORCE.with(|f| f.set(Force::FailBeforeReport(errno)));
        Forced(())
    }

    /// While the guard lives, this thread's own read of a spawn's report fails with `errno`, after
    /// the child ran as it would: the parent cannot tell what the child is doing.
    pub(crate) fn fail_parent_read(errno: i32) -> FailedParentRead {
        PARENT_READ_ERRNO.with(|f| f.set(Some(errno)));
        FailedParentRead(())
    }

    #[must_use = "the read succeeds again as soon as the guard is dropped"]
    pub(crate) struct FailedParentRead(());

    impl Drop for FailedParentRead {
        fn drop(&mut self) {
            PARENT_READ_ERRNO.with(|f| f.set(None));
        }
    }

    pub(super) fn parent_read_fails() -> Option<i32> {
        PARENT_READ_ERRNO.with(Cell::get)
    }

    /// While the guard lives, this thread's own read of a spawn's report finds it not yet written,
    /// as when std's spawn returned before the child's hooks ran: the child runs on as it would.
    pub(crate) fn find_the_report_unwritten() -> UnwrittenRead {
        PARENT_READ_UNWRITTEN.with(|f| f.set(true));
        UnwrittenRead(())
    }

    #[must_use = "the read finds the report again as soon as the guard is dropped"]
    pub(crate) struct UnwrittenRead(());

    impl Drop for UnwrittenRead {
        fn drop(&mut self) {
            PARENT_READ_UNWRITTEN.with(|f| f.set(false));
        }
    }

    pub(super) fn parent_read_finds_nothing() -> bool {
        PARENT_READ_UNWRITTEN.with(Cell::get)
    }

    /// The next spawns on this thread have their child killed by `SIGKILL` before it reports, as
    /// any child may be killed by a signal.
    pub(crate) fn force_child_killed_before_report() -> Forced {
        FORCE.with(|f| f.set(Force::KillSelf));
        Forced(())
    }
}

#[cfg(test)]
#[path = "unique_report_tests.rs"]
mod unique_report_tests;
