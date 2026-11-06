//! macOS: an [`OsProcess`] over an exit watch and the kernel's audit-token signal, and the kqueue
//! behind [`WaitFor::Readable`](super::WaitFor::Readable).
//!
//! macOS has no pidfd. A signal goes through `proc_signal_with_audittoken` instead, with a token
//! that names the pid and the process's `p_idversion`: the kernel checks the version and signals
//! while it holds a reference, so a process that took a reused pid is never signalled.

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use mach2::message::audit_token_t;

use super::{Exit, OsProcess, WaitFor, OPEN_CONSEQUENCE};
use crate::error::{io_context, Error};
use crate::identity::{uniq_info, Existence, ProcessId, ReadPurpose, UniqInfo, UniqRead};
use crate::signal::{Sent, Sig};
use kqueue::{Kqueue, Subscription};

pub(crate) mod child;
pub(crate) mod kqueue;

extern "C" {
    /// `libproc.h`, macOS 14.4 and later. Not in `libc`. Returns `0` once the signal is sent, and
    /// otherwise the `errno` value itself (`libproc.c` returns `errno` when `__proc_info` fails),
    /// not `-1`. `EINVAL`: `sig` is not in `1..NSIG` (signal `0` is refused) or the pid is not
    /// positive. `ESRCH`: no process has the pid, or its `p_idversion` is not the token's.
    /// `EPERM`: this process may not signal it.
    fn proc_signal_with_audittoken(audittoken: *mut audit_token_t, sig: libc::c_int) -> libc::c_int;
}

/// A process, its exit watch, and what its audit token needs. `unique` is the process's
/// `p_uniqueid`: never reused, and kept across `exec`. `idversion` is its `p_idversion`: it changes
/// at `exec`, and `signal` follows it, so it is atomic. Every open arms the watch, one kqueue
/// descriptor, because the one open serves a signal and a wait alike.
#[derive(Debug)]
pub(crate) struct MacProcess {
    id: ProcessId,
    unique: u64,
    idversion: AtomicI32,
    watch: ExitWatch,
}

impl MacProcess {
    /// Open the process `id` names. `Ok(None)`: it is gone, or its pid now names another process.
    pub(crate) fn open(id: ProcessId) -> Result<Option<Self>, Error> {
        let pid = id.pid();
        let read = || read_for_open(pid);
        let Some(first) = read()? else {
            return Ok(None);
        };
        match id.exists() {
            Existence::Present => {}
            Existence::Gone => return Ok(None),
            Existence::Unknown => {
                log::warn!("wait: pid {pid} identity could not be confirmed; {OPEN_CONSEQUENCE}");
                return Err(Error::Unassessable {
                    detail: format!("pid {pid} identity could not be confirmed; {OPEN_CONSEQUENCE}"),
                    source: None,
                });
            }
        }
        let watch = ExitWatch::proc_exit(pid)?;
        // The watch was armed on whatever held the pid by now. The same unique id before and
        // after proves it was this process: a unique id is never reused.
        let Some(second) = read()?.filter(|second| second.unique_id == first.unique_id) else {
            return Ok(None);
        };
        Ok(Some(Self {
            id,
            unique: second.unique_id,
            idversion: AtomicI32::new(second.id_version),
            watch,
        }))
    }
}

/// `pid`'s unique id for an open. `Ok(None)`: it is gone. A refused read is `Unassessable`, with the
/// errno as its source.
pub(crate) fn read_for_open(pid: u32) -> Result<Option<UniqInfo>, Error> {
    match uniq_info(pid, ReadPurpose::Open) {
        UniqRead::Found(info) => Ok(Some(info)),
        UniqRead::Gone => Ok(None),
        UniqRead::Refused(errno) => {
            log::warn!("wait: pid {pid} identity could not be read (errno {errno}); {OPEN_CONSEQUENCE}");
            Err(Error::Unassessable {
                detail: format!("pid {pid} identity could not be read (errno {errno}); {OPEN_CONSEQUENCE}"),
                source: Some(std::io::Error::from_raw_os_error(errno)),
            })
        }
    }
}

/// An audit token that names `pid` at `id_version`: `val[5]` and `val[7]`, the two words the kernel
/// reads.
fn audit_token(pid: u32, id_version: i32) -> audit_token_t {
    let mut token = audit_token_t::default();
    token.val[5] = pid;
    token.val[7] = id_version as u32;
    token
}

/// Signal `sig` to `pid` if its `p_idversion` is still `id_version`. `Err` is the errno.
fn send_with_token(pid: u32, id_version: i32, sig: Sig) -> Result<(), i32> {
    #[cfg(test)]
    let seam = crate::signal::seams::kills_refused();
    #[cfg(not(test))]
    let seam: Option<i32> = None;
    let sent = match seam {
        Some(errno) => Err(errno),
        None => {
            let mut token = audit_token(pid, id_version);
            // SAFETY: `token` is a fully initialised audit token that outlives the call.
            match unsafe { proc_signal_with_audittoken(&mut token, sig.as_libc()) } {
                0 => Ok(()),
                errno => Err(errno),
            }
        }
    };
    #[cfg(test)]
    crate::send_log::record_by_identity(pid, sig.as_libc());
    sent
}

/// How [`signal_by_token`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalByTokenOutcome {
    /// The kernel took the signal.
    Delivered,
    /// The process has exited and is not reaped: `ESRCH`, and the pid still has the same unique id
    /// at the same `p_idversion`. Nothing was delivered. A caller that owns the child reads this as
    /// delivered, as a zombie it owns is on Linux; a caller that holds no child reads it as gone.
    ExitedUnreaped,
    /// The process is gone, or its pid names another process.
    Gone,
}

/// The `p_idversion` of the process `unique` names, if `pid` still names it. `Ok(None)`: the pid is
/// gone or names another process. A refusal is an error that keeps its errno.
pub(crate) fn read_version(pid: u32, unique: u64, sig: Sig) -> io::Result<Option<i32>> {
    match uniq_info(pid, ReadPurpose::Kill) {
        UniqRead::Found(now) if now.unique_id == unique => Ok(Some(now.id_version)),
        UniqRead::Found(_) | UniqRead::Gone => Ok(None),
        UniqRead::Refused(errno) => Err(io_context(
            format!("pid {pid}: its identity could not be read; {sig:?} not sent"),
            io::Error::from_raw_os_error(errno),
        )),
    }
}

/// Send `sig` to the process `unique` names at `pid`, through an audit token at `idversion`, which
/// follows the process across an `exec` and is left at the version it was last sent at. The kernel
/// checks the pid with its `p_idversion` and signals while it holds a reference, so only the
/// documented 2^32 version wrap can redirect it. A refused send is the bare errno, so an `EPERM`
/// stays raw for the callers that promise it.
///
/// `pid` must be a single-process signal target. No cap on the loop: each pass past the first needs
/// a fresh `exec` of the process.
pub(crate) fn signal_by_token(
    pid: u32,
    unique: u64,
    idversion: &mut i32,
    sig: Sig,
) -> io::Result<SignalByTokenOutcome> {
    loop {
        match send_with_token(pid, *idversion, sig) {
            Ok(()) => return Ok(SignalByTokenOutcome::Delivered),
            Err(libc::ESRCH) => {}
            // `EPERM` and the rest are surfaced, not swallowed.
            Err(errno) => return Err(io::Error::from_raw_os_error(errno)),
        }
        // `ESRCH` is a zombie, an `exec`, or a process that is gone: read what the pid names.
        match read_version(pid, unique, sig)? {
            Some(now) if now == *idversion => {
                log::debug!("{sig:?} to pid {pid}: it has exited and is not reaped yet");
                return Ok(SignalByTokenOutcome::ExitedUnreaped);
            }
            // It `exec`ed: the same process under a new version.
            Some(now) => *idversion = now,
            None => {
                log::debug!("{sig:?} to pid {pid}: it is gone, or its pid names another process");
                return Ok(SignalByTokenOutcome::Gone);
            }
        }
    }
}

impl OsProcess for MacProcess {
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        let pid = self.id.pid();
        // `kernel_task` is pid 0 and macOS resolves it, so an identity can name it. It is no
        // target, and the signal paths share one total guard against it.
        if crate::identity::probe::signal_target(pid).is_none() {
            // A discard site: the Result can carry this, so it must not read as a silent success.
            log::warn!("wait: pid {pid} is not a single-process signal target - not signaled");
            return Err(Error::Unassessable {
                detail: format!("pid {pid} is not a signalable single-process target"),
                source: None,
            });
        }
        let mut idversion = self.idversion.load(Ordering::Relaxed);
        let outcome = signal_by_token(pid, self.unique, &mut idversion, sig);
        self.idversion.store(idversion, Ordering::Relaxed);
        match outcome.map_err(Error::Io)? {
            SignalByTokenOutcome::Delivered => Ok(Sent::Delivered),
            // This process holds no child: an exited process is gone to it.
            SignalByTokenOutcome::ExitedUnreaped | SignalByTokenOutcome::Gone => Ok(Sent::Gone),
        }
    }

    fn exited(&self) -> Result<Exit<'_>, Error> {
        let watch = &self.watch;
        if watch.exited()? {
            Ok(Exit::Exited)
        } else {
            Ok(Exit::Running(WaitFor::Readable(watch.as_fd())))
        }
    }
}

/// A kqueue armed for the exit of one process, and nothing else. Nothing ever reads it: at exit XNU
/// leaves the `NOTE_EXIT` knote queued (`EV_EOF | EV_ONESHOT`), and a kqueue descriptor polls
/// readable while its queue is non-empty, so a zero-timeout `poll` is the look and any number of
/// threads may look, or wait on the descriptor, at once. A `kevent` read would take the event
/// away from every other waiter.
#[derive(Debug)]
pub(crate) struct ExitWatch {
    kq: Kqueue,
    /// The pid was already past registration (`ESRCH`) when the watch was armed: the process has
    /// exited, and no event will ever be queued.
    exited: bool,
}

impl ExitWatch {
    pub(super) fn new(kq: Kqueue) -> Self {
        Self { kq, exited: false }
    }

    /// Arm `NOTE_EXIT` for `pid`. A pid that is already gone is a watch that reads as exited.
    pub(crate) fn proc_exit(pid: u32) -> Result<Self, Error> {
        let kq = Kqueue::new()?;
        let exit = Subscription::Process {
            pid,
            signals: false,
            reap: false,
        };
        match kq.subscribe(exit) {
            Ok(()) => Ok(Self::new(kq)),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(Self { kq, exited: true }),
            Err(e) => Err(e),
        }
    }

    /// Whether the exit has happened. Reads nothing from the queue.
    pub(crate) fn exited(&self) -> Result<bool, Error> {
        if self.exited {
            return Ok(true);
        }
        crate::os_process::poll::is_readable(self.kq.as_fd()).map_err(Error::Io)
    }

    /// The kqueue's descriptor: readable once the exit has happened.
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.kq.as_fd()
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
