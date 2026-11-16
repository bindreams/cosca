//! macOS: an [`OsProcess`] over an exit watch and the kernel's audit-token signal, and the kqueue
//! behind [`WaitFor::Readable`](super::WaitFor::Readable).
//!
//! macOS has no pidfd. A signal goes through `proc_signal_with_audittoken` instead, with a token
//! that names the pid and the process's `p_idversion`: the kernel checks the version and signals
//! while it holds a reference, so a process that took a reused pid is never signalled.
//!
//! A [`MacosProcess`] owns the [`Kernel`] it asks, and [`open_with`](super::open_with) moves the
//! kernel it checked through into it.

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::OnceLock;

use mach2::message::audit_token_t;

use super::{Exit, OsProcess, WaitFor, EXIT_CONSEQUENCE, OPEN_CONSEQUENCE};
use crate::error::{io_context, Error};
use crate::identity::kinfo::ExitState;
use crate::identity::{exit_state_of, has_exited, Existence, Kernel, ProcessId, Resolved, UniqInfo, UniqRead};
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
/// at `exec`, and `signal` follows it, so it is atomic. The watch, one kqueue descriptor, is armed
/// by the first look ([`exited`](OsProcess::exited)): an open costs no descriptor, and a send never
/// fails for want of one.
pub(crate) struct MacosProcess<K> {
    /// What every read of the process asks.
    kernel: K,
    id: ProcessId,
    unique: u64,
    idversion: AtomicI32,
    watch: OnceLock<ExitWatch>,
}

impl<K> std::fmt::Debug for MacosProcess<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacosProcess")
            .field("id", &self.id)
            .field("unique", &self.unique)
            .field("idversion", &self.idversion)
            .field("watch", &self.watch)
            .finish_non_exhaustive()
    }
}

impl<K: Kernel + Send> MacosProcess<K> {
    /// Open the process `id` names, checking it through `kernel`, which the process then owns.
    /// `Ok(None)`: it is gone, or its pid now names another process.
    pub(crate) fn open(kernel: K, id: ProcessId) -> Result<Option<Self>, Error> {
        let pid = id.pid();
        let Some(read) = read_for_open(&kernel, pid, OPEN_CONSEQUENCE)? else {
            return Ok(None);
        };
        match id.exists_with(&kernel).0 {
            Existence::Present => {}
            Existence::Gone => return Ok(None),
            Existence::Unknown => {
                return Err(Error::Unassessable {
                    detail: format!("pid {pid} identity could not be confirmed; {OPEN_CONSEQUENCE}"),
                    source: None,
                });
            }
        }
        Ok(Some(Self {
            kernel,
            id,
            unique: read.unique_id,
            idversion: AtomicI32::new(read.id_version),
            watch: OnceLock::new(),
        }))
    }

    /// The watch on this process, armed on whatever holds the pid now; the same unique id read after
    /// arming proves it was this process, any other answer reads as exited.
    fn arm(&self) -> Result<ExitWatch, Error> {
        let pid = self.id.pid();
        let watch = ExitWatch::proc_exit(&self.kernel, pid)?;
        Ok(match read_for_open(&self.kernel, pid, EXIT_CONSEQUENCE)? {
            Some(now) if now.unique_id == self.unique => watch,
            Some(_) | None => watch.exited_now(),
        })
    }
}

/// `pid`'s unique id for an open. `Ok(None)`: it is gone. A refused read is `Unassessable`, with the
/// errno as its source; the caller names what its refusal leaves undone (`consequence`), since what
/// was already sent differs by caller. It logs nothing.
pub(crate) fn read_for_open(kernel: &dyn Kernel, pid: u32, consequence: &str) -> Result<Option<UniqInfo>, Error> {
    match kernel.unique_info(pid) {
        UniqRead::Found(info) => Ok(Some(info)),
        UniqRead::Gone => Ok(None),
        UniqRead::Refused(errno) => Err(Error::Unassessable {
            detail: format!("pid {pid} identity could not be read; {consequence}"),
            source: Some(Error::io_cause(std::io::Error::from_raw_os_error(errno))),
        }),
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
    /// at the same `p_idversion`; or a `SIGKILL` was refused with `EPERM` and the process is a
    /// zombie. Nothing was delivered. A caller that owns the child reads this as delivered, as a
    /// zombie it owns is on Linux; a caller that holds no child reads it as gone.
    ExitedUnreaped,
    /// A `SIGKILL` was refused with `EPERM` and the process's exit has begun (`P_WEXIT`, with
    /// `p_stat` not yet `SZOMB`). Nothing was delivered. The kernel answers `EPERM` to a send in that
    /// window, so it is no refusal. Every caller reads it as delivered, a holder of no child too,
    /// since the exit is still to come.
    Exiting,
    /// The process is gone, or its pid names another process.
    Gone,
}

/// The `p_idversion` of the process `unique` names, if `pid` still names it. `Ok(None)`: the pid is
/// gone or names another process. A refusal is an error that keeps its errno.
pub(crate) fn read_version(kernel: &dyn Kernel, pid: u32, unique: u64, sig: Sig) -> io::Result<Option<i32>> {
    match kernel.unique_info(pid) {
        UniqRead::Found(now) if now.unique_id == unique => Ok(Some(now.id_version)),
        UniqRead::Found(_) | UniqRead::Gone => Ok(None),
        UniqRead::Refused(errno) => Err(io_context(
            format!("pid {pid}: its identity could not be read; {sig} not sent"),
            io::Error::from_raw_os_error(errno),
        )),
    }
}

/// Send `sig` to the process `unique` names at `pid`, through an audit token at `idversion`, which
/// follows the process across an `exec` and is left at the version it was last sent at. The kernel
/// checks the pid with its `p_idversion` and signals while it holds a reference, so only the
/// documented 2^32 version wrap can redirect it. A refused send is the bare errno, so an `EPERM`
/// stays raw for the callers that promise it. The one exception is a `SIGKILL` (any other signal
/// keeps the raw `EPERM`): a read of the process `unique` names, taken after the `EPERM`, finds how
/// it ended:
///
/// - exit begun, not yet a zombie: [`SignalByTokenOutcome::Exiting`];
/// - a zombie: [`SignalByTokenOutcome::ExitedUnreaped`], as `ESRCH` from a zombie is;
/// - gone, or the pid names another process: [`SignalByTokenOutcome::Gone`];
/// - still running, or the read refused: the raw `EPERM`.
///
/// `pid` must be a single-process signal target. No cap on the loop: each pass past the first needs
/// a fresh `exec` of the process.
pub(crate) fn signal_by_token(
    kernel: &dyn Kernel,
    pid: u32,
    unique: u64,
    idversion: &mut i32,
    sig: Sig,
) -> io::Result<SignalByTokenOutcome> {
    loop {
        match send_with_token(pid, *idversion, sig) {
            Ok(()) => return Ok(SignalByTokenOutcome::Delivered),
            Err(libc::ESRCH) => {}
            // `P_WEXIT` is never cleared, so an `EPERM` that came from the exit shows it at this read.
            Err(libc::EPERM) if sig == Sig::Kill => {
                return match exit_state_of(kernel, pid, unique) {
                    Resolved::Found(ExitState::Exiting) => {
                        log::debug!("{sig} to pid {pid}: refused with EPERM, its exit has begun");
                        Ok(SignalByTokenOutcome::Exiting)
                    }
                    Resolved::Found(ExitState::Zombie) => {
                        log::debug!("{sig} to pid {pid}: refused with EPERM, it has exited and is not reaped yet");
                        Ok(SignalByTokenOutcome::ExitedUnreaped)
                    }
                    Resolved::Gone => {
                        log::debug!(
                            "{sig} to pid {pid}: refused with EPERM, and it is gone, or its pid names another process"
                        );
                        Ok(SignalByTokenOutcome::Gone)
                    }
                    Resolved::Unknown => {
                        log::debug!("{sig} to pid {pid}: refused with EPERM, and its exit state could not be read");
                        Err(io::Error::from_raw_os_error(libc::EPERM))
                    }
                    Resolved::Found(ExitState::Running) => Err(io::Error::from_raw_os_error(libc::EPERM)),
                };
            }
            Err(errno) => return Err(io::Error::from_raw_os_error(errno)),
        }
        // `ESRCH` is a zombie, an `exec`, or a process that is gone: read what the pid names.
        match read_version(kernel, pid, unique, sig)? {
            Some(now) if now == *idversion => {
                log::debug!("{sig} to pid {pid}: it has exited and is not reaped yet");
                return Ok(SignalByTokenOutcome::ExitedUnreaped);
            }
            // It `exec`ed: the same process under a new version.
            Some(now) => *idversion = now,
            None => {
                log::debug!("{sig} to pid {pid}: it is gone, or its pid names another process");
                return Ok(SignalByTokenOutcome::Gone);
            }
        }
    }
}

impl<K: Kernel + Send> OsProcess for MacosProcess<K> {
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        let pid = self.id.pid();
        // `kernel_task` is pid 0 and macOS resolves it, so an identity can name it. It is no
        // target, and the signal paths share one total guard against it.
        if crate::identity::probe::signal_target(pid).is_none() {
            return Err(Error::Unassessable {
                detail: format!("pid {pid} is not a signalable single-process target"),
                source: None,
            });
        }
        let mut idversion = self.idversion.load(Ordering::Relaxed);
        let outcome = signal_by_token(&self.kernel, pid, self.unique, &mut idversion, sig);
        self.idversion.store(idversion, Ordering::Relaxed);
        match outcome.map_err(Error::Io)? {
            SignalByTokenOutcome::Delivered | SignalByTokenOutcome::Exiting => Ok(Sent::Delivered),
            // This process holds no child: an exited process is gone to it.
            SignalByTokenOutcome::ExitedUnreaped | SignalByTokenOutcome::Gone => Ok(Sent::Gone),
        }
    }

    /// `Exited` once the process is a zombie or gone: see [`ExitWatch::look`].
    fn exited(&self) -> Result<Exit<'_>, Error> {
        // Two threads that look first may each arm a watch; one is kept and the other closed.
        let watch = match self.watch.get() {
            Some(watch) => watch,
            None => {
                let armed = self.arm()?;
                self.watch.get_or_init(|| armed)
            }
        };
        watch.look(&self.kernel, self.id.pid(), self.unique)
    }
}

/// The error of a [`has_exited`] read that was refused with `errno`, for every caller that reads
/// whether a process has exited: [`Error::Unassessable`] (a liveness read that could not be made),
/// saying `situation`, the errno its `source`.
pub(crate) fn exit_read_refused(pid: u32, errno: i32, situation: &str) -> Error {
    Error::Unassessable {
        detail: format!("pid {pid}: {situation}"),
        source: Some(Error::io_cause(io::Error::from_raw_os_error(errno))),
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
    /// A look has confirmed the exit. A zombie or gone process never runs again, so later looks
    /// make no read. Set once, never cleared.
    confirmed: AtomicBool,
}

impl ExitWatch {
    pub(super) fn new(kq: Kqueue) -> Self {
        Self {
            kq,
            exited: false,
            confirmed: AtomicBool::new(false),
        }
    }

    /// This watch, for a process that is gone: it reads as exited whatever its queue holds.
    fn exited_now(mut self) -> Self {
        self.exited = true;
        self
    }

    /// What [`ExitWatch::proc_exit`] registers: the exit of `pid` and nothing else.
    pub(crate) fn registration(pid: u32) -> Subscription {
        Subscription::Process {
            pid,
            signals: false,
            reap: false,
        }
    }

    /// Arm `NOTE_EXIT` for `pid`. A pid that is already gone is a watch that reads as exited.
    pub(crate) fn proc_exit(kernel: &dyn Kernel, pid: u32) -> Result<Self, Error> {
        let kq = Kqueue::new()?;
        match kernel.subscribe(&kq, Self::registration(pid)) {
            Ok(()) => Ok(Self::new(kq)),
            Err(e) if crate::error::first_os_code(&e) == Some(libc::ESRCH) => Ok(Self::new(kq).exited_now()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Whether the exit has happened. Reads nothing from the queue.
    pub(crate) fn exited(&self) -> Result<bool, Error> {
        if self.exited {
            return Ok(true);
        }
        crate::os_process::poll::is_readable(self.kq.as_fd()).map_err(Error::Io)
    }

    /// One look at the process `unique` names at `pid`, which this watch is armed for: the answer
    /// both [`MacosProcess`] and [`MacosChild`](child::MacosChild) give for [`OsProcess::exited`].
    ///
    /// The watch fires early: `NOTE_EXIT` precedes `p_stat = SZOMB`, and a pid past `P_REF_DEAD`
    /// refuses registration before either. A fired watch is `Exited` only once the process is a
    /// zombie or gone (`has_exited`, which keys on the unique id: a pid another process holds is
    /// gone), the state from which [`ProcessId::is_alive`] never reads `Alive`; until then it is
    /// `Recheck`, which the driver's uncapped backoff re-reads. A refused read is `Unassessable`
    /// with the errno as its source, never `Exited`; an unfired watch reads nothing, and neither
    /// does a look after the exit was confirmed.
    pub(crate) fn look(&self, kernel: &dyn Kernel, pid: u32, unique: u64) -> Result<Exit<'_>, Error> {
        if self.confirmed.load(Ordering::Relaxed) {
            return Ok(Exit::Exited);
        }
        if !self.exited()? {
            return Ok(Exit::Running(WaitFor::Readable(self.as_fd())));
        }
        match has_exited(kernel, pid, unique) {
            Ok(true) => {
                self.confirm();
                Ok(Exit::Exited)
            }
            Ok(false) => Ok(Exit::Recheck),
            Err(errno) => Err(exit_read_refused(
                pid,
                errno,
                "its exit watch fired, but whether it has exited could not be read",
            )),
        }
    }

    /// Records that a read found the process a zombie or gone, as [`look`](Self::look) does: later
    /// looks make no read.
    pub(crate) fn confirm(&self) {
        self.confirmed.store(true, Ordering::Relaxed);
    }

    /// The kqueue's descriptor: readable once the exit has happened.
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.kq.as_fd()
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
