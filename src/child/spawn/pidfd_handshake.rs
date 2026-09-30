//! Linux: hold a forked child before `exec` until the parent has its pidfd.
//!
//! std forks before cosca can call `pidfd_open`, and `spawn()` does not return until `exec`. A
//! `pidfd_open` that failed afterwards would leave a running child with no pidfd, which cosca
//! neither leaves nor reaps by pid. So the child blocks in a `pre_exec` hook until told to go.
//!
//! ```text
//! child (pre_exec hook)                   helper thread (parent)
//! ---------------------                   ----------------------
//! close(parent end)
//! send(getpid())               ------->   recv pid
//!                                         pidfd_open(pid); waitid peek; fd >= 3
//! recv verdict                 <-------   send GO       (pidfd held)
//!                                         send ABORT    (pidfd_open failed)
//! GO: return Ok, std execs                return the pidfd, or the error
//! else: return Err, std reports it and collects the child, which never ran the program
//! ```
//!
//! The channel is one `AF_UNIX` stream socketpair, `SOCK_CLOEXEC`, made under `spawn_lock` (the
//! witness parameter of [`Pending::open`]). A socket rather than two pipes so the child can `send` with
//! `MSG_NOSIGNAL`: a hook that wrote to a dead parent would otherwise die of `SIGPIPE`, which std
//! resets to the default in the child, and std reads a child that died before `exec` as a success.
//!
//! # Every path ends, without a timeout
//!
//! The helper blocks in exactly one place: `recv` of the child's pid. It ends when the pid
//! arrives, or at EOF, which needs every copy of the child's end closed. The child's copy closes
//! when it dies or execs. The parent's copy is closed by [`Handshake::run`] once `spawn()` has
//! returned, and `spawn()` returns when the child has execed or died, or if it failed before the
//! fork. `spawn_lock` is held throughout, so no other cosca fork inherits a copy. A forker outside
//! cosca can hold a copy until its own `exec`, which delays EOF but cannot deadlock: nothing it
//! does waits on this handshake.
//!
//! The child blocks in exactly one place: `recv` of the verdict, after it has sent its pid. The
//! helper answers, or ends and drops the parent's end, and the child reads EOF as abort. The
//! child closes its inherited copy of the parent's end first, or that EOF could never come.
//!
//! The helper is a scoped thread, joined before [`Handshake::run`] returns: nothing detached,
//! nothing global.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use rustix::process::Pid;

use super::SpawnLockGuard;
use crate::error::Error;

const GO: u8 = 1;
const ABORT: u8 = 0;

/// What the hook reads in the child: fd numbers only, published by [`Pending::open`] before the
/// fork, and withdrawn by [`Handshake::run`] after it.
struct Shared {
    child_end: AtomicI32,
    parent_end: AtomicI32,
    /// Whether the fd numbers name this spawn's channel. Cleared when the spawn is over: a command
    /// spawned again after that would otherwise read whatever now owns the numbers; the hook
    /// fails it instead.
    live: AtomicBool,
}

/// The hook is registered; the channel is not yet made. See [`register`].
pub(crate) struct Pending {
    shared: Arc<Shared>,
}

/// The channel to one child. Consumed by [`run`](Self::run).
pub(crate) struct Handshake {
    parent_end: OwnedFd,
    child_end: OwnedFd,
    shared: Arc<Shared>,
}

/// A spawned child, and the pidfd the parent opened while it was held before `exec`.
pub(crate) struct Held<T> {
    pub(crate) child: T,
    /// `None` only when the child was already gone at the handshake.
    pub(crate) pidfd: Option<OwnedFd>,
}

/// What the helper thread learned.
enum Outcome {
    /// The pidfd is held and the child was told to go.
    Opened(OwnedFd),
    /// The child was gone when the pidfd was opened, and was told to go anyway.
    Gone,
    /// The pidfd could not be opened; the child was told to abort.
    Failed(Error),
    /// EOF before any pid: the child died before it could report. Not an error of the helper's.
    NoPid,
}

/// Registers the hook on `cmd`, as its FIRST `pre_exec` hook where the caller can arrange it: the
/// child then reports itself before anything else in it can fail, so a child that dies later has
/// a pidfd held on it and is collected through that.
///
/// The channel is made later, under `spawn_lock`, by [`Pending::open`]; a hook whose channel was
/// never opened fails the spawn it belongs to rather than read fd numbers that mean nothing.
pub(crate) fn register(cmd: &mut std::process::Command) -> Pending {
    let shared = Arc::new(Shared {
        child_end: AtomicI32::new(-1),
        parent_end: AtomicI32::new(-1),
        live: AtomicBool::new(false),
    });
    #[cfg(test)]
    let fault = fault::child_fault();
    let hook = Arc::clone(&shared);
    // SAFETY: the hook runs between fork and exec and is async-signal-safe: it reads atomics, and
    // makes raw `close`, `syscall`, `send` and `recv` calls on fd numbers. It allocates nothing
    // and takes no lock, and `io::Error::from_raw_os_error` does not allocate.
    unsafe {
        cmd.pre_exec(move || {
            hold_child(
                &hook,
                #[cfg(test)]
                fault,
            )
        });
    }
    Pending { shared }
}

impl Pending {
    /// Makes the channel and publishes its fd numbers to the hook. The child's end sits at fd 3 or
    /// above: std's stdio setup `dup2`s onto 0, 1 and 2 before any hook runs. Both ends are
    /// `SOCK_CLOEXEC`, and `_lock` is the witness that no other cosca fork can inherit them.
    pub(crate) fn open(self, _lock: &SpawnLockGuard) -> Result<Handshake, Error> {
        let (parent_end, child_end) =
            rustix::net::socketpair(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None)
                .map_err(|e| Error::Io(crate::error::io_context("socketpair", e.into())))?;
        let parent_end = above_stdio(parent_end)?;
        let child_end = above_stdio(child_end)?;
        self.shared.child_end.store(child_end.as_raw_fd(), Ordering::Relaxed);
        self.shared.parent_end.store(parent_end.as_raw_fd(), Ordering::Relaxed);
        self.shared.live.store(true, Ordering::Release);
        Ok(Handshake {
            parent_end,
            child_end,
            shared: self.shared,
        })
    }
}

fn above_stdio(fd: OwnedFd) -> Result<OwnedFd, Error> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    rustix::io::fcntl_dupfd_cloexec(&fd, 3).map_err(|e| Error::Io(crate::error::io_context("fcntl", e.into())))
}

impl Handshake {
    /// Runs `spawn` (the fork) with the helper thread alive beside it, then answers the pidfd.
    /// `pid_of` reads the pid of a spawned child.
    ///
    /// - A `pidfd_open` failure is the helper's error, whatever `spawn` answered: the child was
    ///   told to abort, and std collected it.
    /// - If the helper thread cannot be started, `spawn` is never called: no child exists.
    /// - A child killed before it reported its pid leaves `spawn` answering `Ok` (std reads the
    ///   closed status pipe as success) and the helper at EOF. It is dead but unreaped, and its
    ///   number cannot be trusted without a pidfd, so it is left unreaped and warned about, as a
    ///   macOS `Drop` leaves a child it cannot verify. The spawn fails.
    pub(crate) fn run<T>(
        self,
        spawn: impl FnOnce() -> io::Result<T>,
        pid_of: impl Fn(&T) -> Option<u32>,
    ) -> Result<Held<T>, Error> {
        let Handshake {
            parent_end,
            child_end,
            shared,
        } = self;
        // The seam is thread-local, and the helper is another thread: take the outcome here.
        #[cfg(test)]
        let scripted = crate::wait::backend::take_scripted_pidfd_open();
        #[cfg(not(test))]
        let scripted = None;
        #[cfg(test)]
        let probe = fault::take_helper_probe();
        #[cfg(test)]
        let helper_probe = probe.clone();

        std::thread::scope(|scope| {
            let helper = std::thread::Builder::new()
                .name("cosca-pidfd-handshake".into())
                .spawn_scoped(scope, move || {
                    let outcome = help(&parent_end, scripted);
                    // Ends the child's wait if no verdict was sent.
                    drop(parent_end);
                    #[cfg(test)]
                    if let Some(probe) = &helper_probe {
                        probe.wait_gate_then_finish();
                    }
                    outcome
                });
            let helper = match helper {
                Ok(helper) => helper,
                Err(e) => {
                    shared.live.store(false, Ordering::Release);
                    return Err(Error::Io(crate::error::io_context(
                        "starting the pidfd handshake thread",
                        e,
                    )));
                }
            };

            #[cfg(test)]
            fault::count_spawn();
            let spawned = spawn();
            shared.live.store(false, Ordering::Release);
            // The last copy of the child's end that can keep the helper waiting.
            #[cfg(test)]
            let ident = fault::identify(child_end.as_raw_fd());
            #[cfg(test)]
            let raw_child_end = child_end.as_raw_fd();
            drop(child_end);
            // Answers before the join can block on a copy that was never closed.
            #[cfg(test)]
            fault::check_child_end_closed(raw_child_end, ident);
            let outcome = join_helper(
                helper,
                #[cfg(test)]
                probe.as_ref(),
            );
            conclude(spawned, outcome, pid_of)
        })
    }
}

/// The helper thread's whole job.
fn help(parent_end: &OwnedFd, scripted: Option<rustix::io::Errno>) -> Outcome {
    let mut pid = [0u8; 4];
    match recv_exact(parent_end, &mut pid) {
        Ok(true) => {}
        Ok(false) => return Outcome::NoPid,
        // A socket that fails is gone with its child; the child reads EOF and aborts.
        Err(e) => return Outcome::Failed(Error::Io(crate::error::io_context("pidfd handshake recv", e))),
    }
    let pid = i32::from_ne_bytes(pid);
    debug_assert!(pid > 0, "a child reported pid {pid}");
    let opened = crate::wait::backend::open_own_child_via(pid as u32, None, |raw: Pid| {
        crate::wait::backend::pidfd_open_or(raw, scripted)
    });
    match opened {
        Ok(pidfd) => {
            send_verdict(parent_end, GO);
            match pidfd {
                Some(pidfd) => Outcome::Opened(pidfd),
                None => Outcome::Gone,
            }
        }
        Err(e) => {
            send_verdict(parent_end, ABORT);
            Outcome::Failed(e)
        }
    }
}

/// Tells the child. An error means the child is gone, which is what the verdict was for.
fn send_verdict(parent_end: &OwnedFd, verdict: u8) {
    _ = rustix::net::send(parent_end, &[verdict], SendFlags::NOSIGNAL);
}

fn recv_exact(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match rustix::net::recv(fd.as_fd(), &mut buf[filled..], RecvFlags::empty()) {
            Ok((0, _)) => return Ok(false),
            Ok((n, _)) => filled += n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

/// Joins the helper. A helper that panicked drops the parent's end as it unwinds, so the child
/// was told to abort; the panic goes on.
fn join_helper(
    helper: std::thread::ScopedJoinHandle<'_, Outcome>,
    #[cfg(test)] probe: Option<&fault::HelperProbe>,
) -> Outcome {
    #[cfg(test)]
    if let Some(probe) = probe {
        probe.release();
    }
    match helper.join() {
        Ok(outcome) => outcome,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Combines the fork's answer with the helper's.
fn conclude<T>(spawned: io::Result<T>, outcome: Outcome, pid_of: impl Fn(&T) -> Option<u32>) -> Result<Held<T>, Error> {
    match (spawned, outcome) {
        // The helper's error explains the abort std reports.
        (Err(_), Outcome::Failed(e)) => Err(e),
        // Told to abort, so the child cannot have execed: it was killed on its way out, which
        // std reads as success. Dead, uncollected, and with no pidfd to collect it with.
        (Ok(child), Outcome::Failed(e)) => {
            leave_unreaped(pid_of(&child));
            Err(e)
        }
        (Ok(child), Outcome::Opened(pidfd)) => Ok(Held {
            child,
            pidfd: Some(pidfd),
        }),
        (Ok(child), Outcome::Gone) => Ok(Held { child, pidfd: None }),
        (Ok(child), Outcome::NoPid) => {
            let pid = pid_of(&child);
            leave_unreaped(pid);
            Err(Error::Io(io::Error::other(format!(
                "the spawned child (pid {pid:?}) died before it could be held for its pidfd"
            ))))
        }
        // std reported the failure and collected the child, which never ran the program.
        (Err(e), _) => Err(Error::Io(e)),
    }
}

/// Warns that a dead child stays unreaped: without its pidfd its number cannot be trusted.
fn leave_unreaped(pid: Option<u32>) {
    log::warn!(
        "pid {pid:?} died before its pidfd was opened; it is left unreaped, as cosca never reaps a Linux child by pid"
    );
    #[cfg(test)]
    fault::leaked_pid(pid);
}

/// The child's side. Async-signal-safe: raw calls only, no allocation, no lock.
fn hold_child(shared: &Shared, #[cfg(test)] fault: fault::ChildFault) -> io::Result<()> {
    if !shared.live.load(Ordering::Acquire) {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    let child_end: RawFd = shared.child_end.load(Ordering::Relaxed);
    let parent_end: RawFd = shared.parent_end.load(Ordering::Relaxed);
    // The parent's end, inherited: closed so the parent's drop of it is the child's EOF.
    // SAFETY: a plain `close` of a number this hook was given.
    unsafe { libc::close(parent_end) };
    #[cfg(test)]
    fault.apply()?;
    // SAFETY: `getpid` through `syscall`, so no libc pid cache can be stale after a fork.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) } as i32;
    send_all(child_end, &pid.to_ne_bytes())?;
    let mut verdict = [ABORT];
    if recv_one(child_end, &mut verdict)? == 1 && verdict[0] == GO {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::ECANCELED))
    }
}

fn send_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `buf` is a live slice; `MSG_NOSIGNAL` turns a closed peer into `EPIPE`.
        let n = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

fn recv_one(fd: RawFd, buf: &mut [u8; 1]) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is a live one-byte buffer.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), 1, 0) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(test)]
pub(crate) mod fault {
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};

    /// What the next child does before it reports its pid.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ChildFault {
        None,
        /// Its hook fails: the child exits before `exec`, std reports it.
        Fail,
        /// It kills itself: std reads that as a success.
        Sigkill,
    }

    impl ChildFault {
        /// Async-signal-safe.
        pub(super) fn apply(self) -> std::io::Result<()> {
            match self {
                ChildFault::None => Ok(()),
                ChildFault::Fail => Err(std::io::Error::from_raw_os_error(libc::EIO)),
                ChildFault::Sigkill => {
                    // SAFETY: `kill(getpid(), SIGKILL)` through raw `syscall`s.
                    unsafe {
                        let pid = libc::syscall(libc::SYS_getpid);
                        libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
                    }
                    Err(std::io::Error::from_raw_os_error(libc::EIO))
                }
            }
        }
    }

    thread_local! {
        static CHILD_END_LEAKED: Cell<bool> = const { Cell::new(false) };
        static CHILD_FAULT: Cell<ChildFault> = const { Cell::new(ChildFault::None) };
        static SPAWNS: Cell<usize> = const { Cell::new(0) };
        static LEAKED: Cell<Option<Option<u32>>> = const { Cell::new(None) };
        static PROBE: RefCell<Option<HelperProbe>> = const { RefCell::new(None) };
    }

    /// Disarms the child fault on drop.
    #[must_use = "dropping this disarms the fault at once"]
    pub(crate) struct ArmedChildFault(());

    /// Make the NEXT spawn's child do `fault` before it reports its pid.
    pub(crate) fn arm_child_fault(fault: ChildFault) -> ArmedChildFault {
        CHILD_FAULT.with(|f| f.set(fault));
        ArmedChildFault(())
    }

    impl Drop for ArmedChildFault {
        fn drop(&mut self) {
            CHILD_FAULT.with(|f| f.set(ChildFault::None));
        }
    }

    /// `(st_dev, st_ino)` of `fd`.
    pub(super) fn identify(fd: i32) -> Option<(u64, u64)> {
        // SAFETY: `fstat` into a zeroed buffer.
        unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            (libc::fstat(fd, &mut st) == 0).then_some((st.st_dev as u64, st.st_ino as u64))
        }
    }

    /// Records whether the parent's copy of the child's end (`fd`, whose identity was `ident`) is
    /// still open. A leaked copy is closed here, so the helper still gets its EOF and the test
    /// fails at its assert instead of hanging.
    pub(super) fn check_child_end_closed(fd: i32, ident: Option<(u64, u64)>) {
        let leaked = ident.is_some() && identify(fd) == ident;
        if leaked {
            // SAFETY: the leaked copy is this spawn's own.
            unsafe { libc::close(fd) };
        }
        CHILD_END_LEAKED.with(|c| c.set(leaked));
    }

    /// Whether the last `run` on this thread left the parent's copy of the child's end open.
    pub(crate) fn child_end_leaked() -> bool {
        CHILD_END_LEAKED.with(Cell::get)
    }

    /// Taken once by `install`.
    pub(super) fn child_fault() -> ChildFault {
        CHILD_FAULT.with(|f| f.replace(ChildFault::None))
    }

    /// How many times `run` reached its fork on this thread.
    pub(crate) fn spawns() -> usize {
        SPAWNS.with(Cell::get)
    }

    pub(crate) fn reset_spawns() {
        SPAWNS.with(|c| c.set(0));
    }

    pub(crate) fn reset_leaked_pid() {
        LEAKED.with(|c| c.set(None));
    }

    pub(super) fn count_spawn() {
        SPAWNS.with(|c| c.set(c.get() + 1));
    }

    /// The pid of the last child a spawn left unreaped; `Some(None)` if it had no pid.
    pub(crate) fn take_leaked_pid() -> Option<Option<u32>> {
        LEAKED.with(Cell::take)
    }

    pub(super) fn leaked_pid(pid: Option<u32>) {
        LEAKED.with(|c| c.set(Some(pid)));
    }

    /// Holds the helper at its very end until the spawning thread reaches its join, then records
    /// that it finished. A helper nobody joins is still held, and never finishes.
    #[derive(Clone)]
    pub(crate) struct HelperProbe {
        gate: Arc<(Mutex<bool>, Condvar)>,
        finished: Arc<AtomicBool>,
    }

    impl HelperProbe {
        pub(super) fn wait_gate_then_finish(&self) {
            let (lock, condvar) = &*self.gate;
            let mut open = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*open {
                open = condvar.wait(open).unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            self.finished.store(true, Ordering::Release);
        }

        /// Opens the gate: called where the spawning thread joins.
        pub(super) fn release(&self) {
            let (lock, condvar) = &*self.gate;
            *lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            condvar.notify_all();
        }

        /// Whether the helper thread has run to its end.
        pub(crate) fn finished(&self) -> bool {
            self.finished.load(Ordering::Acquire)
        }
    }

    /// Arms a probe for the NEXT spawn's helper.
    pub(crate) fn arm_helper_probe() -> HelperProbe {
        let probe = HelperProbe {
            gate: Arc::new((Mutex::new(false), Condvar::new())),
            finished: Arc::new(AtomicBool::new(false)),
        };
        PROBE.with(|p| *p.borrow_mut() = Some(probe.clone()));
        probe
    }

    pub(super) fn take_helper_probe() -> Option<HelperProbe> {
        PROBE.with(|p| p.borrow_mut().take())
    }
}

#[cfg(test)]
#[path = "pidfd_handshake_tests.rs"]
mod pidfd_handshake_tests;
