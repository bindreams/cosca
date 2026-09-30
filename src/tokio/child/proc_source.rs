//! The process backend behind an async [`Child`](super::Child): tokio's own `process::Child`, or
//! (Windows) a raw `CreateProcessW` child that tokio's `Command` cannot express. `Child` forwards
//! its wait/kill/stream operations here so it stays backend-blind, mirroring the sync
//! [`ProcHandle`](crate::child::proc_handle::ProcHandle).

use std::process::ExitStatus;

use crate::error::Error;
#[cfg(all(test, unix))]
use crate::send_log::Via;
use crate::signal::Sig;

/// How [`ProcSource::wait_and_reap`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waited {
    /// The child exited and is still ours to reap.
    Exited,
    /// Something else reaped it, or nothing proves it is still ours: it must not be reaped by
    /// pid. The caller forgets it with [`ProcSource::forget_foreign`].
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    Foreign,
}

/// The process backend behind an async [`Child`](super::Child).
// The `Tokio` arm carries `::tokio::process::Child` inline — the common (and, on Unix, only)
// variant, and previously a plain `Child` field, so keeping it inline is no regression. Boxing it
// to shrink the rare Windows-only `Raw` variant would add a heap allocation + indirection to every
// async spawn, so the size difference is accepted deliberately.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing Raw to shrink it would add an allocation to every async spawn on the common Tokio path"
)]
#[derive(Debug)]
pub(crate) enum ProcSource {
    /// A `::tokio::process::Child` (the default path).
    Tokio {
        child: ::tokio::process::Child,
        /// Linux: the pidfd the spawn handshake opened while the child was held before `exec`.
        /// It names this process for good, so a signal through it cannot reach a process that
        /// later reuses the pid. `None` only when the child was already gone at the handshake
        /// (and in tests that build the backend by hand).
        #[cfg(target_os = "linux")]
        pidfd: Option<std::os::fd::OwnedFd>,
        /// macOS: a foreign reap was seen once. Sticky: from then on nothing is sent or reaped by
        /// pid, because the pid may name another process. A `&self` peek sets it.
        #[cfg(target_os = "macos")]
        foreign: std::sync::atomic::AtomicBool,
        /// macOS: the child's start token, read at spawn. A by-pid send re-reads the pid's start
        /// and sends only if it still matches: the peek alone cannot tell the child from another
        /// of ours that took its pid.
        #[cfg(target_os = "macos")]
        start: Option<crate::identity::StartToken>,
    },
    /// A child something else reaped: tokio's `Child` is forgotten, and only the streams it had
    /// not yet handed out remain, so a caller who waits and then reads keeps its output.
    #[cfg(unix)]
    Foreign {
        stdin: Option<::tokio::process::ChildStdin>,
        stdout: Option<::tokio::process::ChildStdout>,
        stderr: Option<::tokio::process::ChildStderr>,
    },
    /// A raw `CreateProcessW` child owning its process handle directly — the executable/argv[0]
    /// independence (and, later, arbitrary descriptors) that tokio's `Command` cannot express.
    #[cfg(windows)]
    Raw(crate::tokio::spawn::windows_raw::RawAsyncChild),
}

/// What [`ProcSource::signal`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sent {
    /// The signal was handed to the OS for the child.
    Delivered,
    /// Nothing was delivered: the child is gone, or there was no handle to send through.
    Gone,
}

/// What waiting on a forgotten child answers: nothing of ours is left to wait for.
#[cfg(unix)]
fn gone() -> Error {
    Error::Io(std::io::Error::from_raw_os_error(libc::ECHILD))
}

impl ProcSource {
    /// A tokio child with no handle beyond tokio's own.
    pub(crate) fn tokio(child: ::tokio::process::Child) -> ProcSource {
        ProcSource::Tokio {
            child,
            #[cfg(target_os = "linux")]
            pidfd: None,
            #[cfg(target_os = "macos")]
            foreign: std::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "macos")]
            start: None,
        }
    }

    /// macOS: record the child's start token, for the check before a by-pid send.
    #[cfg(target_os = "macos")]
    pub(crate) fn set_start(&mut self, token: crate::identity::StartToken) {
        if let ProcSource::Tokio { start, .. } = self {
            *start = Some(token);
        }
    }

    /// This backend, holding `held` as the pidfd that names the child.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_pidfd(mut self, held: std::os::fd::OwnedFd) -> ProcSource {
        match &mut self {
            ProcSource::Tokio { pidfd, .. } => *pidfd = Some(held),
            ProcSource::Foreign { .. } => unreachable!("a forgotten child has no pidfd to hold"),
        }
        self
    }

    /// The pidfd naming this child, if it has one.
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "the root waits borrow it from a later unit on")
    )]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        match self {
            ProcSource::Tokio { pidfd, .. } => pidfd.as_ref().map(AsFd::as_fd),
            ProcSource::Foreign { .. } => None,
        }
    }

    /// Take tokio's own stdin stream (the Raw backend serves its piped std ends via `owned_std`,
    /// so it has none here).
    pub(crate) fn take_stdin(&mut self) -> Option<::tokio::process::ChildStdin> {
        match self {
            ProcSource::Tokio { child: c, .. } => c.stdin.take(),
            #[cfg(unix)]
            ProcSource::Foreign { stdin, .. } => stdin.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }
    pub(crate) fn take_stdout(&mut self) -> Option<::tokio::process::ChildStdout> {
        match self {
            ProcSource::Tokio { child: c, .. } => c.stdout.take(),
            #[cfg(unix)]
            ProcSource::Foreign { stdout, .. } => stdout.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }
    pub(crate) fn take_stderr(&mut self) -> Option<::tokio::process::ChildStderr> {
        match self {
            ProcSource::Tokio { child: c, .. } => c.stderr.take(),
            #[cfg(unix)]
            ProcSource::Foreign { stderr, .. } => stderr.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }

    /// Block until the child exits, returning its status.
    pub(crate) async fn wait(&mut self) -> Result<ExitStatus, Error> {
        #[cfg(target_os = "macos")]
        if self.latched() {
            self.forget_foreign();
            return Err(gone());
        }
        match self {
            ProcSource::Tokio { child: c, .. } => c.wait().await.map_err(Error::Io),
            #[cfg(unix)]
            ProcSource::Foreign { .. } => Err(gone()),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.wait().await,
        }
    }

    /// macOS: a foreign reap was seen, so tokio's wait by pid may reap another child's pid.
    #[cfg(target_os = "macos")]
    fn latched(&self) -> bool {
        matches!(self, ProcSource::Tokio { child, foreign, .. }
            if child.id().is_some() && foreign.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Exit status if the child has already exited (non-blocking).
    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        #[cfg(target_os = "macos")]
        if self.latched() {
            self.forget_foreign();
            return Err(gone());
        }
        match self {
            ProcSource::Tokio { child: c, .. } => c.try_wait().map_err(Error::Io),
            #[cfg(unix)]
            ProcSource::Foreign { .. } => Err(gone()),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.try_wait(),
        }
    }

    /// Whether the backend still holds something that pins the child's pid against reuse.
    /// tokio's `Child` replaces its inner state the moment `wait`/`try_wait` observes the exit,
    /// dropping the guard that holds the process handle (`id()` goes `None` with it); the raw
    /// backend owns its handle for the child's whole life and never unpins.
    #[cfg(windows)]
    pub(crate) fn pins_pid(&self) -> bool {
        match self {
            ProcSource::Tokio { child: c, .. } => c.id().is_some(),
            ProcSource::Raw(_) => true,
        }
    }

    /// Send `sig` to the child. Does not reap. [`Sent::Gone`] means nothing was delivered because
    /// the child is already gone (reaped by tokio or by someone else) or, on Linux, this backend
    /// holds no pidfd to send through; it is not an error.
    ///
    /// - **Linux:** `pidfd_send_signal` on the handshake pidfd, never by pid, so a foreign reap
    ///   followed by a pid reuse cannot redirect it. `ESRCH` is `Gone`.
    /// - **macOS:** by pid, after a `waitid(WNOWAIT)` peek that finds no foreign reap. That closes
    ///   the window except for a reap by someone else between the peek and the send, which is
    ///   principle 5's accepted gap: macOS has no handle to send through.
    /// - **Windows:** `Kill` only, through the process handle.
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        match self {
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { child, pidfd } => {
                let Some(pid) = child.id() else {
                    log::debug!("the child is already reaped; nothing to signal");
                    return Ok(Sent::Gone);
                };
                let Some(pidfd) = pidfd else {
                    log::debug!("child {pid} has no pidfd to signal it through; sending nothing");
                    return Ok(Sent::Gone);
                };
                #[cfg(test)]
                crate::send_log::record(pid, sig, Via::Pidfd);
                match rustix::process::pidfd_send_signal(pidfd, sig.as_rustix()) {
                    Ok(()) => Ok(Sent::Delivered),
                    Err(rustix::io::Errno::SRCH) => {
                        log::debug!("pidfd_send_signal({sig:?}) to child {pid}: it is already gone");
                        Ok(Sent::Gone)
                    }
                    Err(e) => Err(Error::Io(crate::error::io_context("pidfd_send_signal", e.into()))),
                }
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child, foreign, start } => {
                use crate::identity::{pbi_start_quiet, ReadPurpose, Resolved};
                use crate::wait::exit_only::{self, Peek, Target};
                use std::sync::atomic::Ordering::Relaxed;
                let Some(pid) = child.id() else {
                    log::debug!("the child is already reaped; nothing to signal");
                    return Ok(Sent::Gone);
                };
                if foreign.load(Relaxed) {
                    log::debug!("child {pid} was reaped by someone else; nothing to signal");
                    return Ok(Sent::Gone);
                }
                match exit_only::peek(&Target::pid(pid, None)).map_err(Error::Io)? {
                    Peek::Foreign(_) => {
                        foreign.store(true, Relaxed);
                        log::debug!("child {pid} was reaped by someone else; nothing to signal");
                        return Ok(Sent::Gone);
                    }
                    Peek::Running | Peek::Exit(_) => {}
                }
                // The peek cannot tell our child from another of ours that took its pid, so the
                // pid's start is checked too. A start that cannot be read is never a mismatch.
                if let Some(start) = start {
                    match pbi_start_quiet(pid, ReadPurpose::Send) {
                        Resolved::Found(now) if now == *start => {}
                        Resolved::Found(_) | Resolved::Gone => {
                            foreign.store(true, Relaxed);
                            log::debug!("pid {pid} no longer names the child spawned as {pid}; nothing to signal");
                            return Ok(Sent::Gone);
                        }
                        Resolved::Unknown => {}
                    }
                }
                #[cfg(test)]
                crate::send_log::record(pid, sig, Via::Pid);
                // SAFETY: the peek found `pid` to be our own unreaped child.
                if unsafe { libc::kill(pid as libc::pid_t, sig.as_libc()) } == 0 {
                    return Ok(Sent::Delivered);
                }
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ESRCH) {
                    // XNU answers 0 for an unreaped zombie, so `ESRCH` after a peek that found
                    // our child means someone reaped it in between.
                    foreign.store(true, Relaxed);
                    log::debug!("kill({pid}, {sig:?}): the child is already gone");
                    return Ok(Sent::Gone);
                }
                Err(Error::Io(crate::error::io_context("kill", e)))
            }
            #[cfg(unix)]
            ProcSource::Foreign { .. } => {
                log::debug!("the child was reaped by someone else; nothing to signal");
                Ok(Sent::Gone)
            }
            #[cfg(windows)]
            ProcSource::Tokio { .. } | ProcSource::Raw(_) if sig != Sig::Kill => {
                debug_assert!(false, "Windows can send only Kill, not {sig:?}");
                Err(Error::Unsupported {
                    op: format!("sending {sig:?} to a process"),
                    platform: "windows",
                    detail: "only Kill is sent through a process handle".to_owned(),
                })
            }
            #[cfg(windows)]
            ProcSource::Tokio { child } => {
                use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE, WAIT_FAILED};
                use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
                // tokio drops its handle once it has reaped the child.
                let Some(h) = child.raw_handle() else {
                    return Ok(Sent::Gone);
                };
                // SAFETY: tokio owns the live process handle while `raw_handle` is `Some`; exit
                // code 1 is the forced-kill code std's `Child::kill` uses.
                match unsafe { TerminateProcess(HANDLE(h), 1) } {
                    Ok(()) => Ok(Sent::Delivered),
                    // As std's `Child::kill`: a process that is already exiting answers
                    // `ACCESS_DENIED`, which is success, unless the handle cannot even be waited on.
                    Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {
                        // SAFETY: as above; a zero-timeout wait only reads the handle's state.
                        if unsafe { WaitForSingleObject(HANDLE(h), 0) } == WAIT_FAILED {
                            Err(Error::Io(e.into()))
                        } else {
                            Ok(Sent::Delivered)
                        }
                    }
                    Err(e) => Err(Error::Io(e.into())),
                }
            }
            #[cfg(windows)]
            ProcSource::Raw(r) => r.start_kill().map(|()| Sent::Delivered),
        }
    }

    /// `true` once the backend has collected the child's status, so no reap remains.
    pub(crate) fn is_reaped(&self) -> bool {
        match self {
            ProcSource::Tokio { child: c, .. } => c.id().is_none(),
            #[cfg(unix)]
            ProcSource::Foreign { .. } => true,
            #[cfg(windows)]
            ProcSource::Raw(r) => r.is_reaped(),
        }
    }

    /// Block until the child has exited, then let the backend reap it. **Never kills** — the
    /// caller's own successful kill is what bounds the wait.
    /// **Invariant:** no `wait()` future for this child is in flight when this runs.
    ///
    /// Both callers reach here only past an [`is_reaped`](ProcSource::is_reaped) check or on a
    /// child that was never awaited, so an already-reaped one is a broken precondition, not a case
    /// to return quietly from.
    ///
    /// - **Linux:** `waitid(P_PIDFD, WEXITED | WNOWAIT)` on the kept pidfd, so tokio's own
    ///   field-drop reaps the zombie. `ECHILD` is [`Waited::Foreign`]. So is a missing pidfd, and
    ///   any other errno (a contract breach, asserted in debug): without proof the child is ours,
    ///   tokio's by-pid reap must not run.
    /// - **macOS:** the same wait by pid, after the latch. `ECHILD` sets the latch.
    /// - **Windows:** waits on the process handle.
    ///
    /// On [`Waited::Foreign`] the caller calls [`forget_foreign`](ProcSource::forget_foreign).
    pub(crate) fn wait_and_reap(&mut self, pid: u32) -> Waited {
        match self {
            #[cfg(unix)]
            ProcSource::Foreign { .. } => Waited::Foreign,
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { child, pidfd } => {
                if !still_ours(child) {
                    return Waited::Exited;
                }
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                let Some(pidfd) = pidfd else {
                    log::debug!("child {pid} has no pidfd to wait on; treating it as reaped by someone else");
                    return Waited::Foreign;
                };
                wait_on_pidfd(pid, pidfd)
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child, foreign, .. } => {
                if foreign.load(std::sync::atomic::Ordering::Relaxed) {
                    return Waited::Foreign;
                }
                if !still_ours(child) {
                    return Waited::Exited;
                }
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                let waited = wait_on_pid(pid);
                if waited == Waited::Foreign {
                    foreign.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                waited
            }
            #[cfg(windows)]
            ProcSource::Tokio { child } => {
                if !still_ours(child) {
                    return Waited::Exited;
                }
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                wait_on_handle(child, pid);
                Waited::Exited
            }
            #[cfg(windows)]
            ProcSource::Raw(r) => {
                r.wait_and_reap();
                Waited::Exited
            }
        }
    }

    /// Give up a child something else reaped: tokio's `Child` is forgotten, never dropped, because
    /// its drop would reap by pid, and the pid may name another process by now. The untaken
    /// streams are kept, and the backend is [`reaped`](ProcSource::is_reaped) from here on.
    ///
    /// Forgetting leaks what tokio's `Child` holds — on Linux its pidfd and its reactor
    /// registration, on macOS its `SIGCHLD` watch — so it is logged at `warn`, naming the pid.
    #[cfg(unix)]
    pub(crate) fn forget_foreign(&mut self) {
        if matches!(self, ProcSource::Foreign { .. }) {
            return;
        }
        let old = std::mem::replace(
            self,
            ProcSource::Foreign {
                stdin: None,
                stdout: None,
                stderr: None,
            },
        );
        let ProcSource::Tokio { child, .. } = old else {
            unreachable!("only a Tokio backend is not already forgotten on Unix");
        };
        // Forgotten before anything can unwind: a consumer's `Log` impl is untrusted, and a panic
        // out of it while tokio's `Child` is a live local would drop it and reap by pid.
        let mut child = std::mem::ManuallyDrop::new(child);
        let pid = child.id().map_or_else(|| "?".to_owned(), |pid| pid.to_string());
        let (stdin, stdout, stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
        *self = ProcSource::Foreign { stdin, stdout, stderr };
        log::debug!("child {pid} was reaped by someone else; it will not be reaped by pid");
        let leak = if cfg!(target_os = "linux") {
            "tokio's pidfd and its reactor registration"
        } else {
            "tokio's SIGCHLD watch"
        };
        log::warn!("child {pid} was reaped by someone else; forgetting tokio's handle for it leaks {leak}");
    }

    /// A process handle pins its process, so nothing on Windows is reaped behind the owner's back.
    #[cfg(windows)]
    pub(crate) fn forget_foreign(&mut self) {
        debug_assert!(false, "a process handle pins its process: no foreign reap");
    }

    /// [`forget_foreign`](ProcSource::forget_foreign), but only on evidence, for `Drop`'s branches
    /// that release the backend without waiting.
    ///
    /// - **macOS:** the latch is set.
    /// - **Linux:** a `peek` through the pidfd answers `Foreign`. The pidfd gives certainty. No
    ///   pidfd at all means the child was already gone when the spawn handshake looked for it,
    ///   which is the same evidence, as it is for [`wait_and_reap`](ProcSource::wait_and_reap).
    #[cfg(unix)]
    pub(crate) fn forget_if_foreign(&mut self) {
        let evident = match self {
            ProcSource::Foreign { .. } => false,
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { child, pidfd } => {
                use crate::wait::exit_only::{self, Peek, Target};
                child.id().is_some()
                    && pidfd.as_ref().is_none_or(|fd| {
                        matches!(
                            exit_only::peek(&Target::PidFd(std::os::fd::AsFd::as_fd(fd))),
                            Ok(Peek::Foreign(_))
                        )
                    })
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child, foreign, .. } => {
                child.id().is_some() && foreign.load(std::sync::atomic::Ordering::Relaxed)
            }
        };
        if evident {
            self.forget_foreign();
        }
    }

    /// Guaranteed synchronous teardown for a spawn that failed after the fork: kill the child
    /// through its handle, then block until it has exited. The kill is what bounds the wait, so a
    /// caller that has ALREADY killed uses [`wait_and_reap`](ProcSource::wait_and_reap) instead.
    ///
    /// A kill that is refused is not waited on — `EPERM` is a setuid child refusing it and is
    /// reachable without a bug, so it alone is not asserted — and tokio's own `Child` then drops
    /// into the runtime's orphan reaper. **Invariant:** no `wait()` future for this child is in
    /// flight when this runs.
    pub(crate) fn reap_now(&mut self, pid: u32) {
        #[cfg(test)]
        let forced = crate::child::spawn::fault::take_force_kill_failure();
        #[cfg(not(test))]
        let forced: Option<(&str, std::io::ErrorKind, bool)> = None;
        let killed = match forced {
            // The sync seam's "leave it alive" form is the only one this path honours: it replaces
            // the kill, so the child really is left unsignalled.
            Some((marker, kind, _)) => Err(Error::Io(std::io::Error::new(kind, marker))),
            None => self.signal(Sig::Kill),
        };
        if let Err(e) = &killed {
            log::warn!("teardown kill of child {pid} failed ({e}); it is not waited on");
            debug_assert!(
                matches!(e, Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied),
                "the teardown kill of an owned child failed: {e}"
            );
            return;
        }
        if self.wait_and_reap(pid) == Waited::Foreign {
            self.forget_foreign();
        }
    }

    /// Install the per-instance test wait observer (raw backend only). Panics on a Tokio child —
    /// the observer seam exists solely for the raw async wait path.
    #[cfg(all(test, windows))]
    pub(crate) fn install_wait_observer(
        &mut self,
        started: ::tokio::sync::oneshot::Sender<()>,
        outcome: ::tokio::sync::oneshot::Sender<crate::child::spawn::windows_raw::WaitOutcome>,
    ) {
        match self {
            ProcSource::Raw(r) => r.set_observer(started, outcome),
            ProcSource::Tokio { .. } => panic!("wait observer requires the raw CreateProcessW backend"),
        }
    }
}

/// Whether tokio still holds the child, so its pid is pinned. Once tokio is `Done` (a prior
/// `wait()` reaped it) the pid may be recycled and nothing may wait on it.
fn still_ours(child: &::tokio::process::Child) -> bool {
    let ours = child.id().is_some();
    debug_assert!(
        ours,
        "wait_and_reap found an already-reaped child where one was impossible"
    );
    ours
}

/// Linux: `waitid(P_PIDFD, WEXITED | WNOWAIT)` until the exit is visible to this process.
#[cfg(target_os = "linux")]
fn wait_on_pidfd(pid: u32, pidfd: &std::os::fd::OwnedFd) -> Waited {
    use std::os::fd::AsFd;

    use crate::wait::exit_only::{self, Peek, Target};

    match exit_only::wait_visible_exit(&Target::PidFd(pidfd.as_fd())) {
        Ok(Peek::Exit(_reaped)) => {
            #[cfg(test)]
            if let exit_only::Reaped::Status(status) = _reaped {
                crate::child::spawn::fault::record_teardown_reap(pid, status);
            }
            Waited::Exited
        }
        Ok(Peek::Foreign(_)) => Waited::Foreign,
        // A blocking wait that returns without an exit is a contract breach, like an errno that
        // is not `ECHILD`. Without proof the child is ours, tokio's by-pid reap must not run.
        Ok(Peek::Running) => {
            log::warn!("wait_and_reap: waitid on child {pid}'s pidfd returned without an exit");
            debug_assert!(false, "a blocking waitid on a pidfd returned without an exit");
            Waited::Foreign
        }
        Err(e) => {
            log::warn!("wait_and_reap: waitid on child {pid}'s pidfd failed: {e}");
            debug_assert!(false, "waitid on a child's own pidfd failed: {e}");
            Waited::Foreign
        }
    }
}

/// macOS: `waitid(P_PID, WEXITED | WNOWAIT)`, which leaves the zombie for tokio's field-drop.
#[cfg(target_os = "macos")]
fn wait_on_pid(pid: u32) -> Waited {
    debug_assert!(pid <= i32::MAX as u32, "pid {pid} exceeds i32::MAX");
    // SAFETY: an all-zero `siginfo_t` is a valid value; the kernel fills it in.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: a well-formed `waitid` call; `info` is a valid, owned `siginfo_t`. `WNOWAIT`
        // leaves the child reapable for tokio's in-drop reap.
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            #[cfg(test)]
            crate::child::spawn::fault::record_teardown_reap(pid, super::exit_status_of(&info));
            return Waited::Exited;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ECHILD) => return Waited::Foreign,
            _ => {
                // Without proof the child is ours, tokio's by-pid reap must not run.
                log::warn!("wait_and_reap: waitid on pid {pid} failed: {err}");
                return Waited::Foreign;
            }
        }
    }
}

/// Windows: waits on tokio's process handle, which pins the child.
#[cfg(windows)]
fn wait_on_handle(child: &::tokio::process::Child, pid: u32) {
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
    let _ = pid;
    let h = child.raw_handle().expect("tokio owns the handle while id() is Some");
    // SAFETY: tokio owns and (on its field-drop) closes the handle; we only wait on it.
    // INFINITE is bounded by the kill the caller already issued.
    let waited = unsafe { WaitForSingleObject(HANDLE(h), INFINITE) };
    debug_assert!(
        waited == WAIT_OBJECT_0,
        "wait_and_reap did not observe the child's exit: {waited:?}"
    );
    #[cfg(test)]
    {
        use std::os::windows::process::ExitStatusExt as _;
        let mut code = 0u32;
        // SAFETY: `h` is tokio's live process handle and `code` a valid out-parameter.
        unsafe { windows::Win32::System::Threading::GetExitCodeProcess(HANDLE(h), &mut code) }
            .expect("GetExitCodeProcess on an exited child");
        crate::child::spawn::fault::record_teardown_reap(pid, std::process::ExitStatus::from_raw(code));
    }
}
