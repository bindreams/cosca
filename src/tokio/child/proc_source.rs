//! The process backend behind an async [`Child`](super::Child): tokio's own `process::Child`, or
//! (Windows) a raw `CreateProcessW` child that tokio's `Command` cannot express. `Child` forwards
//! its wait/kill/stream operations here so it stays backend-blind, mirroring the sync
//! [`ProcHandle`](crate::child::proc_handle::ProcHandle).

use std::process::ExitStatus;

use crate::error::Error;
#[cfg(unix)]
use crate::signal::RootState;
use crate::signal::{Sent, Sig};

/// How [`ProcSource::wait_and_reap`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waited {
    /// The child exited and is still ours to reap.
    Exited,
    /// Something else reaped it, or it cannot be shown to be ours (macOS: no unique id, or a peek
    /// that failed): it must not be reaped by pid. The caller forgets it with
    /// [`ProcSource::forget_foreign`].
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
    /// A `::tokio::process::Child` (the default path), with what names the process for good.
    Tokio {
        /// tokio's `Child`, held so that nothing but [`ProcSource::release`] hands it to its own
        /// drop, which reaps by pid (see [`Held`]). The paths that have verified the child is ours
        /// release it, every other path forgets it, and dropping the backend with neither done
        /// (an unwind) does whichever is safe.
        child: Held,
        /// The streams tokio had not handed out when the backend was built. They live here, not
        /// in `child`, so that dropping the backend closes this process's ends whatever becomes
        /// of tokio's `Child`.
        stdin: Option<::tokio::process::ChildStdin>,
        stdout: Option<::tokio::process::ChildStdout>,
        stderr: Option<::tokio::process::ChildStderr>,
        /// The pidfd the spawn handshake opened while the child was held before `exec`. It names
        /// this process for good, so a signal through it cannot reach a process that later reuses
        /// the pid.
        #[cfg(target_os = "linux")]
        pidfd: PinnedPidfd,
        /// The child's unique id (see `child::spawn::unique_report`): the only identity a by-pid
        /// signal on macOS is checked against. `None`: no id is held, so the pid is acted on never.
        #[cfg(target_os = "macos")]
        identity: Option<u64>,
    },
    /// A child something else reaped, or one that cannot be shown to be ours (macOS: no unique id,
    /// or a peek that failed): tokio's `Child` is forgotten, and only the streams it had not yet
    /// handed out remain, so a caller who waits and then reads keeps its output.
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

/// The backend's pidfd. A [`ProcSource`] has a `Drop`, so a field cannot be moved out of it; this
/// lets the teardown take the original (never a duplicate, which can fail at the fd limit) and hand
/// it on. Taken only by the hand-off, which forgets the backend at once.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct PinnedPidfd(Option<std::os::fd::OwnedFd>);

#[cfg(target_os = "linux")]
impl PinnedPidfd {
    fn take(&mut self) -> std::os::fd::OwnedFd {
        self.0
            .take()
            .expect("the pidfd was taken by a hand-off that forgot the backend")
    }
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for PinnedPidfd {
    type Target = std::os::fd::OwnedFd;
    fn deref(&self) -> &std::os::fd::OwnedFd {
        self.0
            .as_ref()
            .expect("the pidfd was taken by a hand-off that forgot the backend")
    }
}

#[cfg(target_os = "linux")]
impl std::os::fd::AsRawFd for PinnedPidfd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&**self)
    }
}

#[cfg(target_os = "linux")]
impl std::os::fd::AsFd for PinnedPidfd {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&**self)
    }
}

/// What the warning for a refused teardown kill says became of the child: `handed` only when the
/// pidfd teardown really took it.
fn refused_kill_fate(handed: bool) -> &'static str {
    if handed {
        "it is handed to the pidfd teardown"
    } else {
        "it is not waited on"
    }
}

/// tokio's `Child`, which on Unix reaps by pid on drop, when the pid may name another process by
/// now. It is dropped only through [`ProcSource::release`], leaked only through
/// [`ProcSource::forget`], and dropping the backend with neither done is [`ProcSource`]'s own
/// `Drop`. On Windows the process handle pins the process, so none of this changes what it does.
#[derive(Debug)]
pub(crate) struct Held(Option<::tokio::process::Child>);

impl Held {
    fn take(&mut self) -> Option<::tokio::process::Child> {
        self.0.take()
    }
}

impl std::ops::Deref for Held {
    type Target = ::tokio::process::Child;
    fn deref(&self) -> &::tokio::process::Child {
        self.0
            .as_ref()
            .expect("the backend's tokio child was released or forgotten")
    }
}

impl std::ops::DerefMut for Held {
    fn deref_mut(&mut self) -> &mut ::tokio::process::Child {
        self.0
            .as_mut()
            .expect("the backend's tokio child was released or forgotten")
    }
}

/// Split tokio's untaken streams off `child`, so they outlive whatever becomes of it.
fn hold(
    mut child: ::tokio::process::Child,
) -> (
    Held,
    Option<::tokio::process::ChildStdin>,
    Option<::tokio::process::ChildStdout>,
    Option<::tokio::process::ChildStderr>,
) {
    let streams = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    (Held(Some(child)), streams.0, streams.1, streams.2)
}

/// `child`, counted when it is actually dropped (tests: `fault::count_backend_drops`), so a release
/// that does not drop it is not counted either.
#[cfg(test)]
fn counted(child: ::tokio::process::Child) -> super::fault::CountedDrop {
    super::fault::CountedDrop { _child: child }
}
#[cfg(not(test))]
fn counted(child: ::tokio::process::Child) -> ::tokio::process::Child {
    child
}

/// Dropping a backend that nothing released or forgot (an unwind out of a caller does this) does
/// the one safe thing: the untaken streams close with the fields, and tokio's `Child` goes to its
/// own drop only if [`ProcSource::state`] shows it ours, else it is forgotten. It is quiet where
/// it matters: no `log` call while unwinding, since a logger that panics there aborts.
///
/// Nothing is killed: the backend does not know whether the handle was armed.
#[cfg(unix)]
impl Drop for ProcSource {
    fn drop(&mut self) {
        let ProcSource::Tokio { child, .. } = self else {
            return;
        };
        let Some(child) = child.take() else {
            return;
        };
        // A child tokio already reaped has nothing left to drop wrongly.
        if child.id().is_none() || matches!(self.state_of(&child), RootState::Unreaped) {
            drop(counted(child));
        } else {
            std::mem::forget(child);
            #[cfg(test)]
            super::drop_fault::note_forget();
            if !std::thread::panicking() {
                log::debug!("a backend dropped without a release was forgotten: its child is not shown to be ours");
            }
        }
    }
}

/// What waiting on a forgotten child answers: nothing of ours is left to wait for.
#[cfg(unix)]
fn gone() -> Error {
    Error::Io(std::io::Error::from_raw_os_error(libc::ECHILD))
}

impl ProcSource {
    /// A tokio child that `pidfd`, opened by the spawn handshake, names.
    #[cfg(target_os = "linux")]
    pub(crate) fn new(child: ::tokio::process::Child, pidfd: std::os::fd::OwnedFd) -> ProcSource {
        let (child, stdin, stdout, stderr) = hold(child);
        ProcSource::Tokio {
            child,
            stdin,
            stdout,
            stderr,
            pidfd: PinnedPidfd(Some(pidfd)),
        }
    }

    /// A tokio child whose unique id was read as `identity`.
    #[cfg(target_os = "macos")]
    pub(crate) fn new(child: ::tokio::process::Child, identity: Option<u64>) -> ProcSource {
        let (child, stdin, stdout, stderr) = hold(child);
        ProcSource::Tokio {
            child,
            stdin,
            stdout,
            stderr,
            identity,
        }
    }

    /// A tokio child on Windows, where tokio's own process handle is the one that names it.
    #[cfg(windows)]
    pub(crate) fn new(child: ::tokio::process::Child) -> ProcSource {
        let (child, stdin, stdout, stderr) = hold(child);
        ProcSource::Tokio {
            child,
            stdin,
            stdout,
            stderr,
        }
    }

    /// The handle that names the child, for a check that must not go by pid alone. Linux: the pidfd.
    /// macOS: the pid with its unique id, while both are known. Windows: tokio's process handle.
    /// `None` when there is nothing to check a pid against: a forgotten child, a raw Windows child,
    /// or (macOS) one whose unique id or pid is unknown. On Linux a live backend always has its pidfd.
    pub(crate) fn target(&self) -> Option<crate::wait::exit_only::Target<'_>> {
        use crate::wait::exit_only::Target;
        match self {
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { pidfd, .. } => Some(Target::PidFd(std::os::fd::AsFd::as_fd(pidfd))),
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child, identity, .. } => Some(Target::pid(child.id()?, Some((*identity)?))),
            #[cfg(windows)]
            ProcSource::Tokio { child, .. } => {
                let handle = child.raw_handle()?;
                // SAFETY: tokio owns the live process handle while `raw_handle` is `Some`, and the
                // borrow lasts no longer than `self`.
                Some(Target::Handle(unsafe {
                    std::os::windows::io::BorrowedHandle::borrow_raw(handle)
                }))
            }
            #[cfg(unix)]
            ProcSource::Foreign { .. } => None,
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }

    /// The child as its spawn holds it, with the handshake pidfd. `None` for a forgotten backend.
    #[cfg(target_os = "linux")]
    pub(crate) fn child_handle(&self, pid: u32) -> Option<crate::containment::ChildHandle<'_>> {
        let crate::wait::exit_only::Target::PidFd(pidfd) = self.target()?;
        Some(crate::containment::ChildHandle { pid, pidfd })
    }

    /// Take tokio's own stdin stream (the Raw backend serves its piped std ends via `owned_std`,
    /// so it has none here).
    pub(crate) fn take_stdin(&mut self) -> Option<::tokio::process::ChildStdin> {
        match self {
            ProcSource::Tokio { stdin, .. } => stdin.take(),
            #[cfg(unix)]
            ProcSource::Foreign { stdin, .. } => stdin.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }
    pub(crate) fn take_stdout(&mut self) -> Option<::tokio::process::ChildStdout> {
        match self {
            ProcSource::Tokio { stdout, .. } => stdout.take(),
            #[cfg(unix)]
            ProcSource::Foreign { stdout, .. } => stdout.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }
    pub(crate) fn take_stderr(&mut self) -> Option<::tokio::process::ChildStderr> {
        match self {
            ProcSource::Tokio { stderr, .. } => stderr.take(),
            #[cfg(unix)]
            ProcSource::Foreign { stderr, .. } => stderr.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }

    /// Block until the child exits, returning its status.
    ///
    /// tokio's own `wait` is a `waitpid` by pid, so on Unix it runs only for a child the handle
    /// shows ours, before and after the exit is awaited (Linux: through the pidfd; macOS: a watch
    /// armed on the unique id read at spawn and checked again after arming). A child reaped
    /// elsewhere is forgotten and answers `ECHILD`. A child the handle cannot answer for
    /// (a failed peek, or macOS without a readable unique id) answers
    /// [`Error::Unassessable`], since it may well be running; it is not forgotten.
    pub(crate) async fn wait(&mut self) -> Result<ExitStatus, Error> {
        match self {
            ProcSource::Tokio { stdin, .. } => {
                // As tokio's own `wait`: stdin closes first, so a child reading it to EOF can exit.
                drop(stdin.take());
                #[cfg(unix)]
                {
                    // Checked before the watch too: a pid that names a stranger now would be
                    // watched until the stranger exits.
                    self.gate()?;
                    self.await_exit().await?;
                    self.gate()?;
                }
                let ProcSource::Tokio { child: c, .. } = self else {
                    unreachable!("a gate that forgot the child returned an error")
                };
                c.wait().await.map_err(Error::Io)
            }
            #[cfg(unix)]
            ProcSource::Foreign { .. } => Err(gone()),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.wait().await,
        }
    }

    /// Exit status if the child has already exited (non-blocking).
    ///
    /// On Unix tokio's `try_wait` is a `waitpid` by pid, so it runs only for a child the handle
    /// shows ours: one reaped elsewhere is forgotten and answers `ECHILD`, and one it cannot answer
    /// for answers [`Error::Unassessable`] (see [`wait`](ProcSource::wait)).
    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        #[cfg(unix)]
        self.gate()?;
        match self {
            ProcSource::Tokio { child: c, .. } => c.try_wait().map_err(Error::Io),
            #[cfg(unix)]
            ProcSource::Foreign { .. } => Err(gone()),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.try_wait(),
        }
    }

    /// `Ok` for a child the handle shows ours, or that tokio already reaped. Reaped elsewhere: the
    /// child is forgotten and the answer is `ECHILD`. Not shown either way: `Unassessable`, with the
    /// child left in place, so a later call can still answer and a `Drop` forgets it.
    #[cfg(unix)]
    fn gate(&mut self) -> Result<(), Error> {
        let ProcSource::Tokio { child, .. } = &*self else {
            return Ok(());
        };
        let Some(pid) = child.id() else {
            return Ok(());
        };
        match self.state_of(child) {
            RootState::Unreaped => Ok(()),
            RootState::Reaped => {
                self.forget_foreign();
                Err(gone())
            }
            RootState::Unknown(failed) => Err(Error::Unassessable {
                detail: format!("pid {pid}: the child cannot be shown to be ours; it was not waited on"),
                source: Some(failed),
            }),
        }
    }

    /// Waits, without reaping, until the child's exit is visible through its handle (Linux: the
    /// pidfd turns readable; macOS: the verified-id kqueue watch fires).
    #[cfg(unix)]
    async fn await_exit(&self) -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        {
            let ProcSource::Tokio { pidfd, .. } = self else {
                return Ok(());
            };
            let pidfd = pidfd.try_clone().map_err(Error::Io)?;
            crate::tokio::wait::watch_pidfd(pidfd).await
        }
        #[cfg(target_os = "macos")]
        {
            let ProcSource::Tokio { child, identity, .. } = self else {
                return Ok(());
            };
            // No unique id, or the child already reaped: nothing to watch, and the gate after this
            // decides what that means.
            let (Some(pid), Some(identity)) = (child.id(), *identity) else {
                return Ok(());
            };
            crate::tokio::wait::wait_exit_for(pid, identity).await
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
    /// the child is already gone (reaped by tokio or by someone else), or (macOS) there is nothing
    /// to verify the pid against: a backend with no unique id, or a forgotten one, answers `Gone`
    /// for a child that may still be running. It is not an error.
    ///
    /// - **Linux:** `pidfd_send_signal` on the handshake pidfd, never by pid, so a foreign reap
    ///   followed by a pid reuse cannot redirect it.
    /// - **macOS:** by pid, only while the pid still has the unique id read at spawn; macOS has no
    ///   handle to send through, so a reap between check and send is an accepted gap.
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        match self {
            #[cfg(unix)]
            ProcSource::Foreign { .. } => {
                log::debug!("the child was reaped by someone else, or cannot be shown to be ours; {sig:?} not sent");
                Ok(Sent::Gone)
            }
            #[cfg(unix)]
            ProcSource::Tokio { child, .. } if child.id().is_none() => {
                log::debug!("the child is already reaped; {sig:?} not sent");
                Ok(Sent::Gone)
            }
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { child, pidfd, .. } => {
                let pid = child.id().expect("checked above");
                crate::signal::via_pidfd(Some(std::os::fd::AsFd::as_fd(pidfd)), pid, sig).map_err(Error::Io)
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child, identity, .. } => {
                let pid = child.id().expect("checked above");
                crate::signal::via_verified_pid(pid, *identity, sig).map_err(Error::Io)
            }
            #[cfg(windows)]
            ProcSource::Tokio { child, .. } => {
                let Sig::Kill = sig;
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
            ProcSource::Raw(r) => {
                let Sig::Kill = sig;
                r.start_kill().map(|()| Sent::Delivered)
            }
        }
    }

    /// Whether the root is still this backend's child to act on, from its own handle; see
    /// [`RootState`]. Nothing is logged: it may run during an unwind.
    ///
    /// - **Linux:** a peek through the pidfd. Exact, with no start token to collide.
    /// - **macOS:** a peek that checks the pid's unique id, including that a running child's id can
    ///   be read ([`exit_only::peek_verified`](crate::wait::exit_only)). A child with no unique id
    ///   (a spawn whose unique id was not adopted, see `adopted_id`) is `Unknown`: its unique-id
    ///   read was refused, and nothing shows the pid still names it.
    ///
    /// A child tokio reaped (`id()` is `None`) and a forgotten backend are `Reaped`.
    #[cfg(unix)]
    pub(crate) fn state(&self) -> RootState {
        match self {
            ProcSource::Foreign { .. } => RootState::Reaped,
            ProcSource::Tokio { child, .. } if child.id().is_none() => RootState::Reaped,
            ProcSource::Tokio { child, .. } => self.state_of(child),
        }
    }

    /// [`state`](ProcSource::state) of a `Tokio` backend whose `child` may already be taken out of
    /// it (the drop does that), for a child tokio has not reaped.
    #[cfg(unix)]
    fn state_of(
        &self,
        #[cfg_attr(
            target_os = "linux",
            allow(unused_variables, reason = "Linux peeks the pidfd, not the pid")
        )]
        child: &::tokio::process::Child,
    ) -> RootState {
        let ProcSource::Tokio { .. } = self else {
            return RootState::Reaped;
        };
        #[cfg(target_os = "linux")]
        let peeked = {
            let ProcSource::Tokio { pidfd, .. } = self else {
                unreachable!("checked above")
            };
            crate::wait::exit_only::peek(&crate::wait::exit_only::Target::PidFd(std::os::fd::AsFd::as_fd(pidfd)))
        };
        #[cfg(target_os = "macos")]
        let peeked = {
            let ProcSource::Tokio { identity, .. } = self else {
                unreachable!("checked above")
            };
            let (Some(pid), Some(identity)) = (child.id(), *identity) else {
                return RootState::Unknown(std::io::Error::other(
                    "the child's unique id is unknown, so nothing shows its pid still names it",
                ));
            };
            crate::wait::exit_only::peek_verified(&crate::wait::exit_only::Target::pid(pid, Some(identity)))
        };
        RootState::of_peek(peeked)
    }

    /// Whether the child's own handle shows it was reaped by someone else, or cannot show it is
    /// ours, so tokio's `Child` must not be dropped (its drop reaps by pid, and the pid may name
    /// another process by now): its [`state`](ProcSource::state) is not `Unreaped`. A child that
    /// cannot be shown to be ours is logged, naming `RootState::Unknown` and the failed peek.
    ///
    /// `false` for a child tokio itself already reaped (`id()` is `None`), and for one already
    /// forgotten.
    #[cfg(unix)]
    pub(crate) fn reaped_elsewhere(&self) -> bool {
        let ProcSource::Tokio { child, .. } = self else {
            return false;
        };
        let Some(pid) = child.id() else {
            return false;
        };
        match self.state_of(child) {
            RootState::Unreaped => false,
            RootState::Reaped => true,
            RootState::Unknown(e) => {
                log::warn!("child {pid} cannot be shown to be ours: RootState::Unknown, its peek failed: {e}");
                true
            }
        }
    }

    /// Forget the child: tokio's `Child` is leaked, never dropped, because its drop would reap by
    /// pid, and the pid may name another process by now. The untaken streams close, and so does
    /// cosca's own pidfd. What leaks is tokio's own: on Linux its pidfd and its reactor
    /// registration, on macOS its `SIGCHLD` watch.
    #[cfg(unix)]
    pub(crate) fn forget(mut self) {
        if let ProcSource::Tokio { child, .. } = &mut self {
            if let Some(child) = child.take() {
                std::mem::forget(child);
            }
        }
    }

    /// Hand tokio's `Child` to its own drop, which `try_wait`s once and queues a still-running
    /// child on the runtime's orphan queue. Only for a child verified to be ours: that drop reaps
    /// by pid.
    pub(crate) fn release(mut self) {
        if let ProcSource::Tokio { child, .. } = &mut self {
            drop(child.take().map(counted));
        }
    }

    /// Whether the child is still running, read without reaping it: `false` once it is reaped, by
    /// tokio or by someone else, or has exited. On macOS a child with no unique id cannot be read.
    #[cfg(unix)]
    pub(crate) fn is_running(&self) -> std::io::Result<bool> {
        if self.is_reaped() {
            return Ok(false);
        }
        let Some(target) = self.target() else {
            return Err(std::io::Error::other(
                "the child's unique id is unknown, so nothing shows its pid still names it",
            ));
        };
        Ok(matches!(
            crate::wait::exit_only::peek(&target)?,
            crate::wait::exit_only::Peek::Running
        ))
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
    /// The caller's child was never awaited, so an already-reaped one is a broken precondition,
    /// asserted in debug.
    ///
    /// - **Linux:** `waitid(P_PIDFD, WEXITED | WNOWAIT)` on the kept pidfd, so tokio's own
    ///   field-drop reaps the zombie. `ECHILD` is [`Waited::Foreign`]. So is any other failure (a
    ///   contract breach, asserted in debug): without proof the child is ours, tokio's by-pid reap
    ///   must not run.
    /// - **macOS:** the sync child's verified-id wait (a kqueue plus peeks that check the pid's
    ///   unique id), which never reaps. A child a tracer holds is waited for until the tracer
    ///   hands it back. Anything that cannot be shown to be ours is [`Waited::Foreign`]: a
    ///   foreign reap, a pid with another unique id, a launchd-held zombie, a refused read, a
    ///   failed peek or kqueue (warned), and a child with no unique id (a spawn whose unique id was
    ///   not adopted, see `adopted_id`), which is not waited on at all. A reap and reuse
    ///   between the verified exit and tokio's reap is an accepted gap.
    /// - **Windows:** waits on tokio's process handle, which pins the child.
    ///
    /// On [`Waited::Foreign`] the caller calls [`forget_foreign`](ProcSource::forget_foreign).
    pub(crate) fn wait_and_reap(&mut self, pid: u32) -> Waited {
        crate::bounded::assert_may_block("wait_and_reap");
        match self {
            #[cfg(unix)]
            ProcSource::Foreign { .. } => Waited::Foreign,
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { child, pidfd, .. } => {
                if !still_ours(child) {
                    return Waited::Exited;
                }
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                wait_on_pidfd(pid, pidfd)
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child, identity, .. } => {
                if !still_ours(child) {
                    return Waited::Exited;
                }
                // No unique id is held, so nothing shows the pid names this child: it is never waited
                // on.
                let Some(identity) = identity else {
                    return Waited::Foreign;
                };
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                wait_reapable(pid, *identity)
            }
            #[cfg(windows)]
            ProcSource::Tokio { child, .. } => {
                if !still_ours(child) {
                    return Waited::Exited;
                }
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                wait_on_handle(child, pid);
                Waited::Exited
            }
            #[cfg(windows)]
            ProcSource::Raw(_) => unreachable!("the raw backend tears its own spawn failures down"),
        }
    }

    /// Give up a child something else reaped, or that cannot be shown to be ours
    /// ([`Waited::Foreign`]): tokio's `Child` is forgotten, never dropped, because its drop
    /// would reap by pid, and the pid may name another process by now. The untaken
    /// streams are kept, and the backend is [`reaped`](ProcSource::is_reaped) from here on.
    ///
    /// Forgetting leaks what tokio's `Child` holds — on Linux its pidfd and its reactor
    /// registration, on macOS its `SIGCHLD` watch — so it is logged at `warn`, naming the pid.
    #[cfg(unix)]
    pub(crate) fn forget_foreign(&mut self) {
        self.forget_because("was reaped by someone else, or cannot be shown to be ours");
    }

    /// [`forget_foreign`](ProcSource::forget_foreign) for any reason: `why` completes "child N ...",
    /// so the warning says what actually happened.
    #[cfg(unix)]
    pub(crate) fn forget_because(&mut self, why: &str) {
        let ProcSource::Tokio {
            child,
            stdin,
            stdout,
            stderr,
            ..
        } = self
        else {
            return;
        };
        let pid = child.id().map_or_else(|| "?".to_owned(), |pid| pid.to_string());
        let foreign = ProcSource::Foreign {
            stdin: stdin.take(),
            stdout: stdout.take(),
            stderr: stderr.take(),
        };
        std::mem::replace(self, foreign).forget();
        #[cfg(test)]
        super::drop_fault::note_forget();
        let leak = if cfg!(target_os = "linux") {
            "tokio's pidfd and its reactor registration"
        } else {
            "tokio's SIGCHLD watch"
        };
        log::warn!("child {pid} {why}; forgetting tokio's handle for it leaks {leak}");
    }

    /// [`forget_foreign`](ProcSource::forget_foreign), but only on evidence, for the places that
    /// release the backend without waiting: [`reaped_elsewhere`](ProcSource::reaped_elsewhere).
    #[cfg(unix)]
    pub(crate) fn forget_if_foreign(&mut self) {
        if self.reaped_elsewhere() {
            self.forget_foreign();
        }
    }

    /// Guaranteed synchronous teardown for a spawn that failed after the fork: kill the child
    /// through its handle (Linux: the pidfd; macOS: the pid, only while it has the child's unique
    /// id; a child with none is neither signalled nor waited on), then block until it has exited. A
    /// child something else reaped, or one that cannot be shown to be ours, is forgotten
    /// ([`forget_foreign`](ProcSource::forget_foreign)) instead, with a warning naming it. The kill
    /// is what bounds the wait, so a caller that has ALREADY killed uses
    /// [`wait_and_reap`](ProcSource::wait_and_reap) instead.
    ///
    /// A refused kill is not waited on here. Linux: the child goes to the pidfd teardown (another
    /// kill, then a reap through the pidfd, or a background reap once it exits) and tokio's `Child` is
    /// forgotten. Elsewhere: a child its handle does not show reaped elsewhere is released to the
    /// runtime's orphan reaper. A child shown reaped elsewhere is forgotten either way. Consumes the
    /// backend, so every path ends in [`release`](ProcSource::release) or
    /// [`forget`](ProcSource::forget). **Invariant:** no `wait()` future for this child is in flight
    /// when this runs.
    pub(crate) fn reap_now(mut self, pid: u32) {
        crate::bounded::assert_may_block("reap_now");
        let killed = self.teardown_kill();
        if let Err(e) = &killed {
            // Tokio's drop reaps by pid: a child the handle shows reaped elsewhere is forgotten.
            #[cfg(unix)]
            self.forget_if_foreign();
            // Handed off before the log and the assertion: a panic from either must not strand a
            // child that is ours. Linux: through its pidfd, never to tokio's orphan queue, whose
            // `waitpid(pid)` could one day reap a reused pid.
            #[cfg(target_os = "linux")]
            let handed = self.hand_to_pidfd_reaper(pid);
            #[cfg(not(target_os = "linux"))]
            let handed = {
                self.release();
                false
            };
            log::warn!(
                "teardown kill of child {pid} failed ({e}); {}",
                refused_kill_fate(handed)
            );
            // `EPERM` is a setuid child refusing the kill, reachable without a bug: it alone is not
            // asserted.
            debug_assert!(
                matches!(e, Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied),
                "the teardown kill of an owned child failed: {e}"
            );
            return;
        }
        #[cfg(unix)]
        if self.wait_and_reap(pid) == Waited::Foreign {
            self.forget_foreign();
        }
        #[cfg(windows)]
        self.wait_and_reap(pid);
        self.release();
    }

    /// [`reap_now`](ProcSource::reap_now) for an elevation front (see [`crate::elevation::front`]):
    /// it is sent nothing, and tokio's `Child` is forgotten, never handed to a reaper. The sync
    /// spawn's front teardown reaps it through its pidfd if it has already exited. **Invariant:** no
    /// `wait()` future for this child is in flight.
    #[cfg(target_os = "linux")]
    pub(crate) fn leave_front(
        mut self,
        pid: u32,
        front: crate::elevation::front::Front,
    ) -> crate::child::spawn::FrontFate {
        self.forget_if_foreign();
        let ProcSource::Tokio { pidfd, .. } = &mut self else {
            // Only something that broke the reaping precondition (see `Command::contain`) leaves a
            // spawn's backend foreign this early.
            log::warn!(
                "elevation front pid {pid}: its backend is foreign (reaped elsewhere), so it cannot be waited on"
            );
            debug_assert!(
                false,
                "elevation front pid {pid}: a spawn's backend is foreign before its teardown"
            );
            return crate::child::spawn::FrontFate::Unaccounted;
        };
        let pidfd = pidfd.take();
        self.forget_because("is an elevation front, sent nothing, and handed to the pidfd teardown");
        crate::child::spawn::leave_front_through_pidfd(Some(pid), pidfd, front)
    }

    /// The teardown's kill: [`Sig::Kill`] through the handle, or (tests) the forced refusal of the
    /// sync seam's "leave it alive" form, which replaces the kill so the child is really left alone.
    fn teardown_kill(&self) -> Result<Sent, Error> {
        #[cfg(test)]
        if let Some((marker, kind, _)) = crate::child::spawn::fault::take_force_kill_failure() {
            return Err(Error::Io(std::io::Error::new(kind, marker)));
        }
        self.signal(Sig::Kill)
    }

    /// A child whose teardown kill was refused (a setuid child answers `EPERM`) and that is not
    /// shown reaped elsewhere: tokio's `Child` is forgotten, never dropped or released, because
    /// tokio would reap it later with `waitpid(pid)` from its orphan queue, when the number may
    /// name another process. The child goes to the same teardown the sync spawn uses, through its own
    /// pidfd, moved out of the backend: another kill, then a reap through the pidfd, or one non-blocking
    /// look and a background reap through the pidfd once it exits. Answers whether it was handed on:
    /// `false` when the backend was already forgotten, so nothing is left to hand.
    #[cfg(target_os = "linux")]
    fn hand_to_pidfd_reaper(mut self, pid: u32) -> bool {
        let ProcSource::Tokio { pidfd, .. } = &mut self else {
            return false;
        };
        // The original, moved out: a duplicate could fail at the fd limit and strand the child.
        let pidfd = pidfd.take();
        self.forget_because("had its teardown kill refused and is handed to the pidfd teardown");
        crate::child::spawn::teardown_through_pidfd(Some(pid), pidfd);
        true
    }

    /// Linux teardown of a spawn whose identity check could not answer: kill the child through its
    /// pidfd, which pins it whatever any peek said, then reap it through the same pidfd, and forget
    /// tokio's `Child` (its drop would reap a pid that is already collected). Consumes the backend.
    /// A refused kill is handled as in [`reap_now`](ProcSource::reap_now): the child goes to the
    /// pidfd reaper. **Invariant:** no `wait()` future for this child is in flight.
    #[cfg(target_os = "linux")]
    pub(crate) fn teardown_through_pidfd(mut self, pid: u32) {
        use crate::wait::exit_only::{self, Target};

        crate::bounded::assert_may_block("teardown_through_pidfd");
        if let Err(e) = self.teardown_kill() {
            self.forget_if_foreign();
            let handed = self.hand_to_pidfd_reaper(pid);
            log::warn!(
                "teardown kill of child {pid} failed ({e}); {}",
                refused_kill_fate(handed)
            );
            debug_assert!(
                matches!(&e, Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied),
                "the teardown kill of an owned child failed: {e}"
            );
            return;
        }
        let ProcSource::Tokio { pidfd, .. } = &self else {
            unreachable!("a freshly spawned backend is a tokio child");
        };
        match exit_only::reap_blocking(&Target::PidFd(std::os::fd::AsFd::as_fd(pidfd))) {
            Ok(Ok(_reaped)) =>
            {
                #[cfg(test)]
                if let exit_only::Reaped::Status(status) = _reaped {
                    crate::child::spawn::fault::record_teardown_reap(pid, status);
                }
            }
            Ok(Err(_foreign)) => log::debug!("child {pid} was reaped by someone else during its teardown"),
            Err(e) => {
                log::warn!("teardown of child {pid}: reaping through its pidfd failed: {e}");
                debug_assert!(false, "waitid on a child's own pidfd failed: {e}");
            }
        }
        self.forget_foreign();
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

/// Linux: waits until the exit is visible to this process, through the child's own pidfd.
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

/// macOS: waits, through the same verified-id wait the sync child uses, until the child is a zombie
/// this process can reap. It never reaps: tokio's field-drop does. A child a tracer holds answers
/// `ECHILD` to `waitid` and is still running, so the wait goes on until the tracer hands it back.
/// Anything that cannot be shown to be ours is [`Waited::Foreign`] (see
/// [`ProcSource::wait_and_reap`]).
#[cfg(target_os = "macos")]
fn wait_reapable(pid: u32, identity: u64) -> Waited {
    use crate::wait::backend::{await_reapable, Waited as Awaited};
    match await_reapable(pid, Some(identity), None) {
        Ok(Awaited::Reapable) => {
            #[cfg(test)]
            if let Ok(crate::wait::exit_only::Peek::Exit(crate::wait::exit_only::Reaped::Status(status))) =
                crate::wait::exit_only::peek(&crate::wait::exit_only::Target::pid(pid, Some(identity)))
            {
                crate::child::spawn::fault::record_teardown_reap(pid, status);
            }
            Waited::Exited
        }
        Ok(Awaited::Gone) => Waited::Foreign,
        Ok(Awaited::Orphaned) => {
            log::warn!(
                "wait_and_reap: child {pid} cannot be shown to be ours or reaped (launchd holds it, because its \
                 tracer died)"
            );
            Waited::Foreign
        }
        // Unbounded, so the deadline cannot pass: a contract breach.
        Ok(Awaited::DeadlinePassed) => {
            log::warn!("wait_and_reap: the unbounded wait on child {pid} reported a passed deadline");
            debug_assert!(false, "an unbounded wait reported a passed deadline");
            Waited::Foreign
        }
        // Without proof the child is ours, tokio's by-pid reap must not run.
        Err(e) => {
            log::warn!("wait_and_reap: waiting on child {pid} failed: {e}");
            Waited::Foreign
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
