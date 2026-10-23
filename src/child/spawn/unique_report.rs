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
//! open. The report hook is registered first, so the child either writes its report or dies without
//! one: after an `Ok` spawn, [`Channel::run`] watches the pipe and the child until one of the two
//! happens (see [`await_report`] for why the pipe's EOF is not enough), and
//! answers [`Report::Late`] for a report that came after the spawn returned. The program may then
//! have started and std's own spawn is not trusted (its error pipe was clobbered, so a failed `exec`
//! is invisible to it): the spawn tears the child down through its unique id. A failed spawn leaves
//! no child to wait on, so its pipe is read once.

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
    /// No report, or a short one, and either every copy of the write end closed or the child is gone:
    /// the child died before it could write it (before `exec`).
    Missing,
    /// The child's own unique id, which arrived only after the spawn returned (see the module doc).
    Late(u64),
    /// No report yet, and the pipe still open. [`Channel::run`] waits it out for a spawn that
    /// returned `Ok`, so only a failed spawn's caller sees it.
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
    /// with the spawn's result either way. `pid_of` names the child of a spawn that returned `Ok`; a
    /// child it cannot name is not waited for.
    pub(crate) fn run<T, E>(
        self,
        spawn: impl FnOnce() -> Result<T, E>,
        pid_of: impl FnOnce(&T) -> Option<u32>,
    ) -> (Result<T, E>, Report) {
        let Channel {
            read_end,
            write_end,
            shared,
        } = self;
        let spawned = spawn();
        shared.withdraw();
        // Closed before the read, so a child that never wrote leaves the pipe at EOF.
        drop(write_end);
        let first = read_report(&read_end);
        let pid = spawned.as_ref().ok().map(pid_of);
        #[cfg(test)]
        seams::first_read_done(pid.flatten());
        let report = match (first, pid) {
            (Report::Unwritten, Some(Some(pid))) => await_report(&read_end, pid),
            (Report::Unwritten, Some(None)) => {
                debug_assert!(false, "a freshly spawned child has a pid");
                Report::Unwritten
            }
            // A failed spawn leaves no child to wait on: std collected it, or tokio dropped it and
            // its pid with it. Its report came already or never comes, so the read stands.
            (report, _) => report,
        };
        (spawned, report)
    }
}

/// How long the wait runs before it says what it is waiting on.
const SAY_WAITING_AFTER: std::time::Duration = std::time::Duration::from_secs(1);

/// Blocks until the report of child `pid` is in `read_end`, or the child is gone, then answers what
/// the pipe holds: [`Report::Late`] for an id (it arrived after the spawn returned), and
/// [`Report::Missing`] for nothing from a child that is gone, which never reached its report.
///
/// The pipe's EOF alone cannot end the wait. `std::io::pipe` on macOS is `pipe()`, then a separate
/// `FD_CLOEXEC`, so any process another thread starts in between (not only a fork that never execs)
/// inherits the write end and holds the EOF off for as long as it lives. So one kqueue watches the
/// pipe (`EVFILT_READ`) and the child (`EVFILT_PROC`, `NOTE_EXIT`), and [`check`] asks after the
/// child once the watch is registered and again on every wake. The child is gone when that
/// registration answers `ESRCH`, when `NOTE_EXIT` comes, or when the check finds it gone; the pipe
/// is then read once more.
///
/// A traced child's `NOTE_EXIT` reaches this process only at its tracer's hand-back. So a live
/// tracer that holds the child's zombie keeps the wait going until it hands the zombie back: the
/// tracer owns its tracee's stops and hand-back. The wait also watches the tracer's exit
/// ([`TracerWatch`](crate::wait::backend::TracerWatch)), which ends it when the tracer exits while
/// the child is exiting and XNU gives the child to launchd.
///
/// The residuals. Something else reaps the child (`SIGCHLD` ignored, or a `waitpid(-1)` reaper) and
/// another child of this process, traced or not, takes its pid before the registration: the watch
/// and the check then name that process, and the wait lasts as long as it does, unless the pipe hits
/// EOF first. A tracer that attaches after the wait's last check is not watched, and a tracer that
/// is itself traced has its own `NOTE_EXIT` held back until its tracer reaps it. If either exits
/// while the child is exiting, nothing wakes the wait until launchd waits on the child (or, for a
/// traced tracer, until its own tracer reaps it).
///
/// It waits on events, never on a timer. Past one second it warns, once, naming what it waits for:
/// a message only, never a decision.
fn await_report(read_end: &OwnedFd, pid: u32) -> Report {
    #[cfg(test)]
    if seams::wait_is_refused() {
        return Report::ReadFailed(io::Error::other("test seam: the wait for a report was entered"));
    }
    match watch(read_end, pid) {
        Ok(Watch::Pipe(report)) => {
            #[cfg(test)]
            seams::woke(seams::Wake::Pipe);
            report
        }
        Ok(Watch::ChildGone) => {
            #[cfg(test)]
            seams::woke(seams::Wake::ChildGone);
            // Whatever the child wrote is in the pipe by now.
            match read_report(read_end) {
                Report::Id(id) => Report::Late(id),
                Report::Unwritten => Report::Missing,
                report => report,
            }
        }
        Err(e) => Report::ReadFailed(e),
    }
}

/// What ended a [`watch`].
enum Watch {
    /// The pipe had something to read, or hit EOF: the report as read, an id as [`Report::Late`].
    Pipe(Report),
    /// The child is gone.
    ChildGone,
}

/// The kqueue wait of [`await_report`].
fn watch(read_end: &OwnedFd, pid: u32) -> io::Result<Watch> {
    use crate::wait::backend::{OnTracer, TracerWatch};
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

    let kq = Kqueue::new()?;
    #[cfg(test)]
    seams::wait_begins();
    let pipe = KEvent::new(
        read_end.as_raw_fd() as usize,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
        FilterFlag::empty(),
        0,
        0,
    );
    match crate::wait::backend::add_with_receipt(&kq, pipe).map_err(into_io)? {
        0 => {}
        errno => return Err(io::Error::from_raw_os_error(errno as i32)),
    }
    // Registered before the first check, so a child that exits after it fires `NOTE_EXIT`.
    if crate::wait::backend::arm_note_exit_on(&kq, pid)
        .map_err(into_io)?
        .is_none()
    {
        return Ok(Watch::ChildGone);
    }
    let mut tracer = TracerWatch::default();
    let blank = KEvent::new(0, EventFilter::EVFILT_READ, EvFlags::empty(), FilterFlag::empty(), 0, 0);
    // Room for every knote at once: the pipe, the child, and the tracers watched.
    let mut events = [blank; 8];
    let started = std::time::Instant::now();
    let mut warned = false;
    loop {
        // Read before asking about the child: the report may have come since the last read.
        match read_report(read_end) {
            Report::Unwritten => {}
            Report::Id(id) => return Ok(Watch::Pipe(Report::Late(id))),
            report => return Ok(Watch::Pipe(report)),
        }
        let recheck = match check(pid)? {
            Check::Gone => return Ok(Watch::ChildGone),
            Check::Running => None,
            Check::Traced(by) => match tracer.held_by(&kq, by)? {
                OnTracer::Block => None,
                OnTracer::Recheck(after) if after.is_zero() => continue,
                OnTracer::Recheck(after) => Some(after),
            },
        };
        #[cfg(test)]
        seams::blocking(&kq);
        let warn_in = (!warned).then(|| SAY_WAITING_AFTER.saturating_sub(started.elapsed()));
        let timeout = match (recheck, warn_in) {
            (Some(recheck), Some(warn_in)) => Some(recheck.min(warn_in)),
            (recheck, warn_in) => recheck.or(warn_in),
        };
        let n = match kq.kevent(&[], &mut events, timeout.map(crate::wait::backend::kevent_timeout)) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        };
        if !warned && started.elapsed() >= SAY_WAITING_AFTER {
            warned = true;
            log::warn!(
                "the spawned child {pid} has not reported its unique id after 1 s; waiting for its report, or \
                 for it to exit"
            );
        }
        let woke = &events[..n];
        if woke
            .iter()
            .any(|e| e.filter() == Ok(EventFilter::EVFILT_PROC) && e.ident() == pid as usize)
        {
            return Ok(Watch::ChildGone);
        }
        // Any other wake (a tracer's exit, the pipe, a timer) reads the pipe and checks the child
        // again.
        for event in woke {
            tracer.fired(event, pid);
        }
    }
}

/// What [`check`] found.
enum Check {
    /// A child of this process that has not exited.
    Running,
    /// This process's child, held by this tracer.
    Traced(u32),
    /// Exited, reaped, or not this process's child: no report is coming.
    Gone,
}

/// Where `pid` is, by a `waitid` that consumes nothing. An exit record is [`Check::Gone`].
///
/// `ECHILD` alone is not: while a tracer holds our child, its parent's `waitid` answers `ECHILD`
/// too. So the pid is asked who forked it and who holds it ([`origin`](crate::identity::origin)). A
/// process this one forked is [`Check::Traced`] by the process that holds it, unless that is
/// launchd: XNU gives launchd a child whose tracer exited while the child was exiting, so it is
/// gone. Any other answer means the child is gone. A read that is refused is an error.
fn check(pid: u32) -> io::Result<Check> {
    use crate::identity::{origin, Origin, LAUNCHD};
    use crate::wait::exit_only::{peek, Peek, Target};
    Ok(match peek(&Target::pid(pid, None))? {
        Peek::Running => Check::Running,
        Peek::Exit(_) => Check::Gone,
        Peek::Foreign(_) => match origin(pid) {
            Origin::Ours { parent } if parent == LAUNCHD => Check::Gone,
            // A tracer detached between the two reads: the child is ours again, and its own
            // `NOTE_EXIT` reaches this process.
            Origin::Ours { parent } if parent == std::process::id() => Check::Running,
            Origin::Ours { parent } => Check::Traced(parent),
            Origin::NotOurs | Origin::Gone => Check::Gone,
            Origin::Refused(errno) => {
                return Err(io::Error::new(
                    io::Error::from_raw_os_error(errno).kind(),
                    format!("pid {pid}: whether it is this process's child could not be read (errno {errno})"),
                ))
            }
            Origin::Unreadable => {
                return Err(io::Error::other(format!(
                    "pid {pid}: whether it is this process's child could not be read (kinfo_proc refused)"
                )))
            }
        },
    })
}

fn into_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::other(other),
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
/// Only a [`Late`](Self::Late) child is signalled and waited on by pid, each act checked against its
/// id. Without a unique id nothing in cosca acts on a macOS pid, because nothing pins the number
/// against a foreign reap (`SIGCHLD` ignored, or a `waitpid(-1)` reaper) and its reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unadoptable {
    /// It died before `exec`, so only a corpse is left, and the program did not start.
    DiedBeforeExec,
    /// Its unique id arrived only after its spawn returned ([`Report::Late`]). The program may have
    /// started, and std's own spawn is not trusted, so the child is torn down through this id.
    Late(u64),
    /// Its report could not be read or is malformed: it has no verified identity, so it cannot be
    /// signalled and is left with a warning (leak and warn), and the program may have started.
    Unverified,
}

/// The spawn's unique id, or why the child cannot be adopted, for a spawn that returned `Ok`.
/// Every act on the child by pid is checked against the id; without one, nothing acts on it.
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
        Report::Late(id) => not(
            Unadoptable::Late(id),
            Error::Io(io::Error::other(format!(
                "the spawned child {pid} had not reported its unique id when its spawn returned (two of this \
                 process's descriptors 0 to 2 were closed), so its exec cannot be confirmed; the child was not adopted"
            ))),
        ),
        Report::Unwritten => {
            debug_assert!(false, "`Channel::run` waits out an unwritten report");
            not(
                Unadoptable::Unverified,
                Error::Unassessable {
                    detail: format!("pid {pid}: its unique-id report is still unwritten; the child was not adopted"),
                    source: None,
                },
            )
        }
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
        Report::Id(_) | Report::Late(_) | Report::Unwritten | Report::ReadFailed(_) | Report::BadTag(_) => false,
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
    seam.await_gate();
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
            #[cfg(test)]
            seam.await_after_gate();
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
        /// The hook reads one byte from this fd before it reports.
        Gate(std::os::fd::RawFd),
    }

    /// A gate the hook blocks on: the test holds both ends, and a byte written releases the child.
    struct Gate {
        read: std::io::PipeReader,
        write: std::io::PipeWriter,
        /// Released by the parent's first read of the report, rather than by the test.
        at_first_read: bool,
    }

    impl Gate {
        fn new(at_first_read: bool) -> Gate {
            let (read, write) = std::io::pipe().expect("the gate pipe");
            Gate {
                read,
                write,
                at_first_read,
            }
        }

        fn release(mut self) {
            use std::io::Write;
            self.write.write_all(b"r").expect("release the held child");
        }
    }

    /// What [`on_each_block`] runs: the block's number in its wait (1 for the first) and the
    /// wait's kqueue.
    type BlockHook = Box<dyn FnMut(u32, &nix::sys::event::Kqueue)>;

    /// What [`on_first_read`] runs: the child's pid.
    type FirstReadHook = Box<dyn FnOnce(u32)>;

    thread_local! {
        static FORCE: Cell<Force> = const { Cell::new(Force::None) };
        static PARENT_READ_ERRNO: Cell<Option<i32>> = const { Cell::new(None) };
        static PARENT_READ_UNWRITTEN: Cell<bool> = const { Cell::new(false) };
        static WAIT_REFUSED: Cell<bool> = const { Cell::new(false) };
        static GATE: std::cell::RefCell<Option<Gate>> = const { std::cell::RefCell::new(None) };
        static AFTER_GATE: std::cell::RefCell<Option<Gate>> = const { std::cell::RefCell::new(None) };
        static ON_FIRST_READ: std::cell::RefCell<Option<FirstReadHook>> = const { std::cell::RefCell::new(None) };
        static ON_FIRST_BLOCK: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static ON_EACH_BLOCK: std::cell::RefCell<Option<BlockHook>> = const { std::cell::RefCell::new(None) };
        static BLOCKS_IN_WAIT: Cell<u32> = const { Cell::new(0) };
        static BLOCKS: Cell<u32> = const { Cell::new(0) };
        static WAKE: Cell<Option<Wake>> = const { Cell::new(None) };
    }

    /// What a hook registered on this thread was armed with: the force, and the read end of the
    /// gate it blocks on after its report.
    #[derive(Debug, Clone, Copy)]
    pub(super) struct Armed(Force, Option<std::os::fd::RawFd>);

    /// Blocks until a byte can be read from `fd`, or it is at end of file. Async-signal-safe: `read`
    /// into a stack byte.
    fn await_byte(fd: std::os::fd::RawFd) {
        let mut byte = 0u8;
        loop {
            // SAFETY: one byte into a stack variable.
            let n = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
            // SAFETY: `__error` is this thread's errno location.
            if n < 0 && unsafe { *libc::__error() } == libc::EINTR {
                continue;
            }
            return;
        }
    }

    impl Armed {
        /// The child's read, as the seam shapes it. Async-signal-safe.
        pub(super) fn fail_before_report(self) -> Option<i32> {
            match self.0 {
                Force::FailBeforeReport(errno) => Some(errno),
                _ => None,
            }
        }

        /// Blocks before the report until its gate is released, if the seam says so.
        /// Async-signal-safe.
        pub(super) fn await_gate(self) {
            if let Force::Gate(fd) = self.0 {
                await_byte(fd);
            }
        }

        /// Blocks after the report until its gate is released, if the seam says so.
        /// Async-signal-safe.
        pub(super) fn await_after_gate(self) {
            if let Some(fd) = self.1 {
                await_byte(fd);
            }
        }

        /// `child_end` is the report pipe's write end.
        pub(super) fn read(self, child_end: std::os::fd::RawFd) -> Result<u64, i32> {
            match self.0 {
                Force::None | Force::FailBeforeReport(_) | Force::Gate(_) => crate::identity::own_unique_id(),
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
        use std::os::fd::AsRawFd;
        let after = AFTER_GATE.with(|g| g.borrow().as_ref().map(|gate| gate.read.as_raw_fd()));
        Armed(FORCE.with(Cell::get), after)
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

    /// This thread's next read of a spawn's report finds it not yet written, as when std's spawn
    /// returned before the child's hooks ran: the child runs on as it would, and the wait that
    /// follows reads the real pipe.
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

    /// Whether the next read finds nothing; take-once, so the wait that follows reads the real pipe.
    pub(super) fn parent_read_finds_nothing() -> bool {
        PARENT_READ_UNWRITTEN.with(|f| f.replace(false))
    }

    /// While the guard lives, the wait for a report on this thread answers `ReadFailed` at once, so a
    /// test sees by assertion that the wait was entered.
    pub(crate) fn refuse_the_wait() -> RefusedWait {
        WAIT_REFUSED.with(|f| f.set(true));
        RefusedWait(())
    }

    #[must_use = "the wait runs again as soon as the guard is dropped"]
    pub(crate) struct RefusedWait(());

    impl Drop for RefusedWait {
        fn drop(&mut self) {
            WAIT_REFUSED.with(|f| f.set(false));
        }
    }

    pub(super) fn wait_is_refused() -> bool {
        WAIT_REFUSED.with(Cell::get)
    }

    /// While the guard lives, the next spawn's child on this thread writes its report only after the
    /// parent's first read of it has returned, so the report is late whenever std returned before
    /// the child's hooks ran.
    pub(crate) fn hold_the_report_until_the_first_read() -> HeldReport {
        hold(Gate::new(true))
    }

    /// While the guard lives, the next spawn's child on this thread writes its report only once
    /// [`release_the_report`] is called.
    pub(crate) fn hold_the_report() -> HeldReport {
        hold(Gate::new(false))
    }

    fn hold(gate: Gate) -> HeldReport {
        use std::os::fd::AsRawFd;
        FORCE.with(|f| f.set(Force::Gate(gate.read.as_raw_fd())));
        GATE.with(|g| *g.borrow_mut() = Some(gate));
        HeldReport(())
    }

    /// Lets the child [`hold_the_report`] holds write its report.
    pub(crate) fn release_the_report() {
        GATE.with(|g| g.borrow_mut().take())
            .expect("a held report to release")
            .release();
    }

    /// While the guard lives, the next spawn's child on this thread stops right after its report,
    /// before any later hook, until [`release_the_child_after_its_report`] is called.
    pub(crate) fn hold_the_child_after_its_report() -> HeldAfterReport {
        AFTER_GATE.with(|g| *g.borrow_mut() = Some(Gate::new(false)));
        HeldAfterReport(())
    }

    #[must_use = "the child is held only while the guard lives"]
    pub(crate) struct HeldAfterReport(());

    impl Drop for HeldAfterReport {
        fn drop(&mut self) {
            AFTER_GATE.with(|g| g.borrow_mut().take());
        }
    }

    /// Lets the child [`hold_the_child_after_its_report`] holds run on.
    pub(crate) fn release_the_child_after_its_report() {
        AFTER_GATE
            .with(|g| g.borrow_mut().take())
            .expect("a child held after its report")
            .release();
    }

    #[must_use = "the report is held only while the guard lives"]
    pub(crate) struct HeldReport(());

    impl Drop for HeldReport {
        fn drop(&mut self) {
            FORCE.with(|f| f.set(Force::None));
            GATE.with(|g| g.borrow_mut().take());
        }
    }

    /// The parent's first read of a report has returned: lets a child held until then write it,
    /// and runs the hook [`on_first_read`] armed.
    pub(super) fn first_read_done(pid: Option<u32>) {
        let gate = GATE.with(|g| {
            let mut g = g.borrow_mut();
            if g.as_ref().is_some_and(|gate| gate.at_first_read) {
                g.take()
            } else {
                None
            }
        });
        if let Some(gate) = gate {
            gate.release();
        }
        let hook = ON_FIRST_READ.with(|h| h.borrow_mut().take());
        if let (Some(hook), Some(pid)) = (hook, pid) {
            hook(pid);
        }
    }

    /// Runs `hook` once with the child's pid, when the parent's first read of the report of a spawn
    /// that returned `Ok` on this thread has returned, before any wait for it.
    pub(crate) fn on_first_read(hook: impl FnOnce(u32) + 'static) -> FirstRead {
        ON_FIRST_READ.with(|h| {
            let previous = h.borrow_mut().replace(Box::new(hook));
            debug_assert!(previous.is_none(), "a first-read hook is already armed");
        });
        FirstRead(())
    }

    #[must_use = "the hook is cleared as soon as the guard is dropped"]
    pub(crate) struct FirstRead(());

    impl Drop for FirstRead {
        fn drop(&mut self) {
            ON_FIRST_READ.with(|h| h.borrow_mut().take());
        }
    }

    /// Runs `hook` once, the first time a wait for a report on this thread is about to block.
    pub(crate) fn on_first_block(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
        crate::oneshot_hook::arm(&ON_FIRST_BLOCK, hook)
    }

    /// How many times a wait for a report on this thread has been about to block.
    pub(crate) fn block_count() -> u32 {
        BLOCKS.with(Cell::get)
    }

    /// Runs `hook` each time a wait for a report on this thread is about to block, with the
    /// block's number in that wait (1 for the first) and the wait's kqueue, until the guard drops.
    pub(crate) fn on_each_block(hook: impl FnMut(u32, &nix::sys::event::Kqueue) + 'static) -> EachBlock {
        ON_EACH_BLOCK.with(|h| {
            let previous = h.borrow_mut().replace(Box::new(hook));
            debug_assert!(previous.is_none(), "a block hook is already armed");
        });
        EachBlock(())
    }

    #[must_use = "the hook is cleared as soon as the guard is dropped"]
    pub(crate) struct EachBlock(());

    impl Drop for EachBlock {
        fn drop(&mut self) {
            ON_EACH_BLOCK.with(|h| h.borrow_mut().take());
        }
    }

    /// A wait for a report has begun on this thread.
    pub(super) fn wait_begins() {
        BLOCKS_IN_WAIT.with(|b| b.set(0));
    }

    pub(super) fn blocking(kq: &nix::sys::event::Kqueue) {
        BLOCKS.with(|b| b.set(b.get() + 1));
        let n = BLOCKS_IN_WAIT.with(|b| {
            b.set(b.get() + 1);
            b.get()
        });
        crate::oneshot_hook::fire(&ON_FIRST_BLOCK);
        // Taken out for the call, so the hook may use the other seams.
        let hook = ON_EACH_BLOCK.with(|h| h.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook(n, kq);
            ON_EACH_BLOCK.with(|h| {
                h.borrow_mut().get_or_insert(hook);
            });
        }
    }

    /// What ended the last wait for a report on this thread.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Wake {
        /// The pipe had something to read, or hit EOF.
        Pipe,
        /// The child was gone.
        ChildGone,
    }

    pub(super) fn woke(wake: Wake) {
        WAKE.with(|w| w.set(Some(wake)));
    }

    /// What ended the last wait for a report on this thread, taken.
    pub(crate) fn take_wake() -> Option<Wake> {
        WAKE.with(Cell::take)
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
