//! macOS: an [`OsProcess`] over an exit watch and the kernel's audit-token signal, and the kqueue
//! behind [`WaitFor::Kqueue`](super::WaitFor::Kqueue).
//!
//! macOS has no pidfd. A signal goes through `proc_signal_with_audittoken` instead, with a token
//! that names the pid and the process's `p_idversion`: the kernel checks the version and signals
//! while it holds a reference, so a process that took a reused pid is never signalled.

use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use mach2::message::audit_token_t;
use nix::sys::event::{EvFlags, Kqueue};

use super::{Exit, Op, OsProcess, WaitFor};
use crate::error::{io_context, Error};
use crate::identity::{uniq_info, Existence, ProcessId, ReadPurpose, UniqRead};
use crate::signal::{Sent, Sig};
use crate::wait::backend::{arm_note_exit_on, block_on_kqueue, drain_proc_exit};

extern "C" {
    /// `libproc.h`, macOS 14.4 and later. Not in `libc`. Returns `0` once the signal is sent, and
    /// otherwise the `errno` value itself (`libproc.c` returns `errno` when `__proc_info` fails),
    /// not `-1`. `EINVAL`: `sig` is not in `1..NSIG` (signal `0` is refused) or the pid is not
    /// positive. `ESRCH`: no process has the pid, or its `p_idversion` is not the token's.
    /// `EPERM`: this process may not signal it.
    fn proc_signal_with_audittoken(audittoken: *mut audit_token_t, sig: libc::c_int) -> libc::c_int;
}

/// A process, its exit watch if it was opened for [`Op::Wait`], and what its audit token needs.
/// `unique` is the process's `p_uniqueid`: never reused, and kept across `exec`. `idversion` is its
/// `p_idversion`: it changes at `exec`. A signal needs no kqueue, so a kill or terminate holds no
/// watch and costs no descriptor.
#[derive(Debug)]
pub(crate) struct MacProcess {
    id: ProcessId,
    unique: u64,
    idversion: i32,
    watch: Option<ExitWatch>,
}

impl MacProcess {
    /// Open the process `id` names. `Ok(None)`: it is gone, or its pid now names another process.
    /// `op` words the `Unassessable` errors, and only [`Op::Wait`] arms the exit watch.
    pub(crate) fn open(id: ProcessId, op: Op) -> Result<Option<Self>, Error> {
        let pid = id.pid();
        let (warn_tail, detail_tail) = match op {
            Op::Wait => ("; its exit cannot be observed", "; its exit cannot be observed"),
            Op::Kill | Op::Terminate => (" - no signal was sent", "; no signal was sent"),
        };
        let read = || match uniq_info(pid, ReadPurpose::Open) {
            UniqRead::Found(info) => Ok(Some(info)),
            UniqRead::Gone => Ok(None),
            UniqRead::Refused(errno) => {
                log::warn!("wait: pid {pid} identity could not be read (errno {errno}){warn_tail}");
                Err(Error::Unassessable {
                    detail: format!("pid {pid} identity could not be read (errno {errno}){detail_tail}"),
                    source: Some(std::io::Error::from_raw_os_error(errno)),
                })
            }
        };
        let Some(first) = read()? else {
            return Ok(None);
        };
        match id.exists() {
            Existence::Present => {}
            Existence::Gone => return Ok(None),
            Existence::Unknown => {
                log::warn!("wait: pid {pid} identity could not be confirmed{warn_tail}");
                return Err(Error::Unassessable {
                    detail: format!("pid {pid} identity could not be confirmed{detail_tail}"),
                    source: None,
                });
            }
        }
        if !matches!(op, Op::Wait) {
            return Ok(Some(Self {
                id,
                unique: first.unique_id,
                idversion: first.id_version,
                watch: None,
            }));
        }
        let Some(watch) = ExitWatch::proc_exit(pid)? else {
            return Ok(None);
        };
        // The watch was armed on whatever held the pid by now. The same unique id before and
        // after proves it was this process: a unique id is never reused.
        let Some(second) = read()?.filter(|second| second.unique_id == first.unique_id) else {
            return Ok(None);
        };
        Ok(Some(Self {
            id,
            unique: second.unique_id,
            idversion: second.id_version,
            watch: Some(watch),
        }))
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

/// Signal `signo` to `pid` if its `p_idversion` is still `id_version`. `Err` is the errno.
fn send_with_token(pid: u32, id_version: i32, signo: libc::c_int) -> Result<(), i32> {
    let mut token = audit_token(pid, id_version);
    // SAFETY: `token` is a fully initialised audit token that outlives the call.
    match unsafe { proc_signal_with_audittoken(&mut token, signo) } {
        0 => Ok(()),
        errno => Err(errno),
    }
}

impl OsProcess for MacProcess {
    fn signal(&mut self, sig: Sig) -> Result<Sent, Error> {
        let pid = self.id.pid();
        let signo = sig.as_libc();
        // `kernel_task` is pid 0 and macOS resolves it, so an identity can name it. It is no
        // target; the same total guard as the by-pid signals use.
        if crate::identity::probe::signal_target(pid).is_none() {
            // A discard site: the Result can carry this, so it must not read as a silent success.
            log::warn!("wait: pid {pid} is not a single-process signal target - not signaled");
            return Err(Error::Unassessable {
                detail: format!("pid {pid} is not a signalable single-process target"),
                source: None,
            });
        }
        // No cap: each pass past the first needs a fresh `exec` of the process.
        loop {
            let sent = send_with_token(pid, self.idversion, signo);
            #[cfg(test)]
            crate::send_log::record_by_identity(pid, signo);
            match sent {
                Ok(()) => return Ok(Sent::Delivered),
                Err(libc::ESRCH) => {}
                // `EPERM` and the rest are surfaced, not swallowed.
                Err(errno) => return Err(Error::Io(std::io::Error::from_raw_os_error(errno))),
            }
            // `ESRCH` is a zombie, an `exec`, or a process that is gone: read what the pid names.
            match uniq_info(pid, ReadPurpose::Kill) {
                UniqRead::Found(now) if now.unique_id == self.unique => {
                    if now.id_version == self.idversion {
                        log::debug!("{sig:?} to pid {pid}: it has exited and is not reaped yet");
                        return Ok(Sent::Gone);
                    }
                    // It `exec`ed: the same process under a new version.
                    self.idversion = now.id_version;
                }
                UniqRead::Found(_) | UniqRead::Gone => {
                    log::debug!("{sig:?} to pid {pid}: it is gone, or its pid names another process");
                    return Ok(Sent::Gone);
                }
                UniqRead::Refused(errno) => {
                    return Err(Error::Io(io_context(
                        format!("pid {pid}: its identity could not be read; {sig:?} not sent"),
                        std::io::Error::from_raw_os_error(errno),
                    )));
                }
            }
        }
    }

    fn exited(&mut self) -> Result<Exit<'_>, Error> {
        let Some(watch) = &self.watch else {
            // As on Windows, where a handle opened for a signal lacks `SYNCHRONIZE`.
            debug_assert!(false, "exited() on a process opened for a signal, not a wait");
            return Err(Error::Io(std::io::Error::other(
                "this process was opened for a signal, not a wait; open it with Op::Wait to observe its exit",
            )));
        };
        // A consumed exit event stays in `seen`, so a look after a wait that read it is `Exited`.
        if watch.drain()? {
            Ok(Exit::Exited)
        } else {
            Ok(Exit::Running(WaitFor::Kqueue(watch)))
        }
    }
}

/// A kqueue armed for one event, and whether that event was ever read. A kqueue reports an exit
/// once, so a wait that consumed it must not hide it from the next look: `seen` stays set.
///
/// An `AtomicBool`, not a `Cell`, so a future that holds `&ExitWatch` stays `Send`.
#[derive(Debug)]
pub(crate) struct ExitWatch {
    kq: Kqueue,
    seen: AtomicBool,
}

impl ExitWatch {
    pub(super) fn new(kq: Kqueue) -> Self {
        Self {
            kq,
            seen: AtomicBool::new(false),
        }
    }

    /// Arm `NOTE_EXIT` for `pid`. `Ok(None)`: the pid is already gone.
    pub(crate) fn proc_exit(pid: u32) -> Result<Option<Self>, Error> {
        let kq = Kqueue::new().map_err(|e| Error::Io(e.into()))?;
        Ok(arm_note_exit_on(&kq, pid)?.map(|()| Self::new(kq)))
    }

    /// Block until the event has been read, by this call or an earlier one, or until `deadline`.
    /// `Ok(true)` = the event was read. An `EV_ERROR` event is `Err`.
    pub(crate) fn block(&self, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
        if self.seen.load(Ordering::Relaxed) {
            return Ok(true);
        }
        // Only a wait that is really armed counts as a block.
        #[cfg(test)]
        crate::wait::block_probe::record(crate::wait::remaining(deadline));
        block_on_kqueue(&self.kq, deadline, false, |event, _already_elapsed| {
            if event.flags().contains(EvFlags::EV_ERROR) {
                return Err(Error::Io(std::io::Error::from_raw_os_error(event.data() as i32)));
            }
            self.seen.store(true, Ordering::Relaxed);
            Ok(Some(true))
        })
    }

    /// Read a pending event without blocking. `Ok(true)` = the event has been read, now or
    /// earlier. An `EV_ERROR` event is `Err`.
    pub(crate) fn drain(&self) -> Result<bool, Error> {
        if drain_proc_exit(&self.kq)?.is_some() {
            self.seen.store(true, Ordering::Relaxed);
        }
        Ok(self.seen.load(Ordering::Relaxed))
    }

    /// The kqueue's descriptor, for a reactor that registers it.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only the async driver registers the kqueue")
    )]
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.kq.as_fd()
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
