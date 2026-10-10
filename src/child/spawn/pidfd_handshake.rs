//! Linux: hold a forked child before `exec` until the parent holds its pidfd.
//!
//! std forks before cosca can open a pidfd, and `spawn()` does not return until `exec`. A child
//! that ran with no pidfd held on it would be one cosca neither leaves nor reaps by pid. So the
//! child opens a pidfd on itself in a `pre_exec` hook, sends it to the parent, and waits to be told
//! to go.
//!
//! ```text
//! child (pre_exec hook)                     helper thread (parent)
//! ---------------------                     ----------------------
//! close(parent end)
//! pidfd_open(getpid())
//! send PIDFD + the pidfd (SCM_RIGHTS) ---->  recvmsg(MSG_CMSG_CLOEXEC): exactly one fd; fd >= 3
//!   or ERRNO + errno, and abort
//! recv verdict                        <----  send GO     (the pidfd is held)
//!                                            shutdown(parent end)
//! GO: return Ok, std execs
//! EOF: return Err, std reports it and collects the child, which never ran the program
//! ```
//!
//! No pid number crosses from the child to the parent. The pidfd names the child in whatever pid
//! namespace either of them is, and it is opened by the child itself, so no reap and reuse of the
//! number can come before it.
//!
//! The child's own `pidfd_open` failing is classified as the pre-fork probe's is: a refusal is
//! [`Error::Unsupported`] naming `spawn`, anything else [`Error::Io`] naming `pidfd_open`.
//!
//! The channel is one `AF_UNIX` `SOCK_SEQPACKET` socketpair, `SOCK_CLOEXEC`, made under `spawn_lock`
//! (the witness parameter of [`Pending::open`]). A socket rather than pipes, to carry the pidfd, and
//! so the child can `send` with `MSG_NOSIGNAL`: a hook that wrote to a dead parent would otherwise
//! die of `SIGPIPE`, which std resets to the default in the child, and std reads a child that died
//! before `exec` as a success. Seqpacket, so each message arrives whole.
//!
//! # Every path ends, without a timeout
//!
//! The helper blocks in one place: `recvmsg` of the child's report. The child blocks in one place:
//! `recv` of the verdict. Each ends at the other side's message, or at EOF, and EOF comes from
//! `shutdown`, not from a close. A process forked without `exec`, by any thread in or outside
//! cosca, holds copies of both ends, and a close waits for every copy; a `shutdown` does not.
//!
//! - The parent closes its own copy of the child's end as soon as `spawn()` returns. With no other
//!   copy, the child's death or a failed hook then closes the last one, and the helper reads EOF
//!   by itself.
//! - A copy made by a fork without `exec` (any thread, in or outside cosca) outlives the child, so
//!   the parent can also force EOF: `shutdown` of the read side of its own end. It does so once
//!   nothing is left to report. A failed `spawn()` means that at once: std collected the child (by its own
//!   by-pid wait, see residuals b and c in [`child_exited_before_the_helper_finished`]), or never
//!   forked. A successful one means the child has execed or died, except that std returns
//!   before the child's hooks even run when this process has two of fds 0 to 2 closed (see
//!   [`ReportChannel`]). So the parent then waits for the helper to finish or the child to exit,
//!   watched through a pidfd opened on its number, and forces EOF only if the child exited first.
//!   The watch is never signalled through. See [`child_exited_before_the_helper_finished`] for the
//!   window that watch leaves open until #383.
//! - The helper shuts the parent's end when it is done, and when it unwinds. A child still waiting
//!   for its verdict reads EOF, which is abort: the helper never has to send one.
//!
//! Descriptors this module creates are moved above stdio by
//! [`above_stdio`](crate::above_stdio::above_stdio), which states what that does and does not
//! guarantee.
//!
//! [`ReportChannel`]: crate::containment::cgroup::channel::ReportChannel
//!
//! The helper is a scoped thread, joined before [`Handshake::run`] returns: nothing detached,
//! nothing global. Linux refuses a new thread to a thread whose pid namespace for children is not
//! its own (after `unshare` or `setns` of `CLONE_NEWPID`), so a spawn from such a thread fails,
//! naming that cause, before it forks.

use std::io;
use std::os::fd::{IntoRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use rustix::io::Errno;
use rustix::net::{AddressFamily, RecvFlags, ReturnFlags, SendFlags, Shutdown, SocketFlags, SocketType};

use super::fd_channel::{above_stdio, above_stdio_keeping, publish_ends, register as register_hook, Shared};
use super::{SpawnFailure, SpawnLockGuard};
use crate::error::{ChildFate, Error};

const GO: u8 = 1;
/// A report's tag: the child's pidfd is attached as `SCM_RIGHTS`; the value is 0.
const REPORT_PIDFD: i32 = 1;
/// A report's tag: `pidfd_open` on itself failed in the child; the value is its errno.
const REPORT_ERRNO: i32 = 2;
/// A report is two native-endian `i32`s: its tag, then its value.
const REPORT_LEN: usize = 8;

/// The hook is registered; the channel is not yet made. See [`register`].
pub(crate) struct Pending {
    shared: Arc<Shared>,
}

/// The channel to one child. Consumed by [`run`](Self::run).
pub(crate) struct Handshake {
    parent_end: OwnedFd,
    child_end: OwnedFd,
    done: OwnedFd,
    shared: Arc<Shared>,
    /// The elevation front the spawn launches, if it does: a spawn that fails after its fork sends
    /// it nothing (see [`Handshake::leaving_front`]).
    front: LeftFront,
}

/// A spawned child, and the pidfd it sent while it was held before `exec`.
pub(crate) struct Held<T> {
    pub(crate) child: T,
    pub(crate) pidfd: OwnedFd,
}

/// A child `spawn` returned, as the handshake disposes of it when the spawn fails anyway.
pub(crate) trait Spawned {
    /// Whether an `Err` from `spawn` proves that a child told to go never ran the program. std's
    /// does: it fails only on a report from the child before `exec`, and collects that child. tokio's
    /// does not: it can fail after std's spawn succeeded, so after `exec`.
    const ERR_PROVES_NO_EXEC: bool;
    /// Its pid, for logs.
    fn pid(&self) -> Option<u32>;
    /// Reap this child through `pidfd`: it never ran the program, and is dead or on its way out.
    fn reap_unexecuted(self, pidfd: OwnedFd);
    /// Give up on this child: no pidfd reached this process, so there is none to reap it through.
    /// `why` says what happened to the report.
    fn abandon_unreported(self, why: &str);
}

impl Spawned for std::process::Child {
    const ERR_PROVES_NO_EXEC: bool = true;

    fn pid(&self) -> Option<u32> {
        Some(self.id())
    }

    // std's `Child` reaps nothing on drop: the pidfd is the only reaper.
    fn reap_unexecuted(self, pidfd: OwnedFd) {
        _ = super::teardown_through_pidfd(Some(self.id()), pidfd, None);
    }

    fn abandon_unreported(self, why: &str) {
        leave_unreaped(Some(self.id()), why);
    }
}

/// What the helper thread learned.
enum Outcome {
    /// The child sent its pidfd and was told to go.
    Opened(OwnedFd),
    /// The child sent its pidfd, and every copy of its end was closed or shut before GO was sent:
    /// it never ran the program. A GO sent while any copy was still open is buffered, even if the
    /// child had already died: this thread holds a copy until `spawn()` returns. The spawn then
    /// succeeds with a child that dies without running the program, as any child may die.
    Gone(OwnedFd),
    /// The spawn cannot go on. The child was not told to go, so it aborts at EOF. Carries the
    /// child's pidfd if it sent one.
    Failed(Error, Option<OwnedFd>),
    /// EOF before any report: the child died before it could report, or never reached its hook.
    NoReport,
    /// [`Outcome::NoReport`], the EOF forced because the child's exit could not be watched. Carries
    /// why.
    Unwatched(String),
}

/// Registers the hook on `cmd`, as its FIRST `pre_exec` hook where the caller can arrange it: the
/// child then reports itself before anything else in it can fail, so a child that dies later has
/// a pidfd held on it and is collected through that.
///
/// The channel is made later, under `spawn_lock`, by [`Pending::open`]; a hook whose channel was
/// never opened fails the spawn it belongs to rather than read fd numbers that mean nothing.
pub(crate) fn register(cmd: &mut std::process::Command) -> Pending {
    #[cfg(test)]
    let fault = fault::child_fault();
    // The child opens its own pidfd, where a thread-local seam cannot reach: take it here.
    #[cfg(test)]
    let scripted = crate::wait::backend::take_scripted_pidfd_open();
    // SAFETY: the hook reads atomics and makes only direct syscalls (libc or rustix, see
    // `open_self`) on integers and fd numbers; `io::Error::from_raw_os_error` does not allocate.
    let shared = unsafe {
        register_hook(cmd, move |shared| {
            hold_child(
                shared,
                #[cfg(test)]
                fault,
                #[cfg(test)]
                scripted,
            )
        })
    };
    Pending { shared }
}

impl Pending {
    /// Makes the channel and publishes its fd numbers to the hook. The child's end sits at fd 3 or
    /// above: std's stdio setup `dup2`s onto 0, 1 and 2 before any hook runs. Both ends are
    /// `SOCK_CLOEXEC`, and `_lock` is the witness that no other cosca fork can inherit them.
    pub(crate) fn open(self, _lock: &SpawnLockGuard) -> Result<Handshake, Error> {
        let (parent_end, child_end) =
            rustix::net::socketpair(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None)
                .map_err(|e| Error::Io(crate::error::io_context("socketpair", e.into())))?;
        // Written, not closed, when the helper is done: a forked copy cannot hold it off. Made
        // before the ends are published, so no failure here can leave stale numbers live.
        let done = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)
            .map_err(|e| Error::Io(crate::error::io_context("eventfd", e.into())))?;
        #[cfg(test)]
        if let Some(errno) = fault::take_done_fd_failure() {
            return Err(Error::Io(crate::error::io_context("eventfd", errno.into())));
        }
        let done = above_stdio(done)?;
        let (child_end, parent_end) = publish_ends(&self.shared, child_end, parent_end)?;
        Ok(Handshake {
            parent_end,
            child_end,
            done,
            shared: self.shared,
            front: LeftFront::NotAFront,
        })
    }
}

/// Shuts `fd`'s socket both ways, so every copy of either end reads EOF.
fn shut(fd: &OwnedFd) {
    // An `AF_UNIX` socketpair end is always connected: `shutdown` has nothing to refuse.
    if let Err(e) = rustix::net::shutdown(fd, Shutdown::Both) {
        log::warn!("pidfd handshake: shutdown of the channel failed: {e}");
        debug_assert!(false, "shutdown of a socketpair end failed: {e}");
    }
}

/// Makes the helper's `recvmsg` on the parent's end read EOF, whatever copies of the child's end
/// exist: a shutdown of the read side, which a close of the other end's copies cannot do.
fn force_eof(parent_end: &OwnedFd) {
    // An `AF_UNIX` socketpair end is always connected: `shutdown` has nothing to refuse.
    if let Err(e) = rustix::net::shutdown(parent_end, Shutdown::Read) {
        log::warn!("pidfd handshake: shutdown of the parent's end failed: {e}");
        debug_assert!(false, "shutdown of a socketpair end failed: {e}");
    }
}

/// Forces EOF on the parent's end when dropped while this thread unwinds.
struct ForceEofOnUnwind<'a>(&'a OwnedFd);

impl Drop for ForceEofOnUnwind<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            force_eof(self.0);
        }
    }
}

/// Shuts the parent's end, then says the helper is done, when dropped, unwinding included.
struct ShutOnDrop<'a> {
    parent_end: &'a OwnedFd,
    done: &'a OwnedFd,
    #[cfg(test)]
    seams: &'a fault::HelperSeams,
}

impl Drop for ShutOnDrop<'_> {
    fn drop(&mut self) {
        shut(self.parent_end);
        #[cfg(test)]
        self.seams.record_parent_end_shut(self.parent_end);
        // An eventfd counter never fills at one write per spawn.
        if let Err(e) = rustix::io::write(self.done, &1u64.to_ne_bytes()) {
            log::warn!("pidfd handshake: the helper could not say it is done: {e}");
            debug_assert!(false, "write to the handshake's eventfd failed: {e}");
        }
    }
}

/// Where a front spawned for a cgroup leaf leaves the handshake's pidfd when its spawn fails after
/// its fork: for the leaf's abandonment, which uses it for a child the leaf cannot name (see
/// [`Handshake::leaving_front`]).
pub(crate) type LeftPidfd = std::rc::Rc<std::cell::Cell<Option<OwnedFd>>>;

/// Who answers for a child whose spawn failed after its fork, when that child is an elevation
/// front (see [`Handshake::leaving_front`]).
enum LeftFront {
    /// Not a front: torn down as any child.
    NotAFront,
    /// A front, left here: sent nothing, reaped only if it has exited, its fate noted.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only tokio's spawn names a front")
    )]
    Here(crate::elevation::front::Front),
    /// A front spawned for a cgroup leaf, left to the leaf's abandonment: the handshake signals
    /// and waits on nothing, and leaves its pidfd here.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only tokio's spawn names a front")
    )]
    ToLeaf(LeftPidfd),
}

impl Handshake {
    /// Names the elevation front this spawn launches. A spawn that fails after its fork then sends
    /// the child nothing, a kill of which would orphan its elevated program (see
    /// [`crate::elevation::front`]), and its error says what became of it. Only a spawn whose failed
    /// `spawn()` leaves the child unreaped (tokio's) names one: std reaps the child of a spawn it
    /// fails.
    ///
    /// A front spawned for a cgroup leaf (`leaf` names where its pidfd goes) is left to the leaf,
    /// whose abandonment kills through it and then answers for the front: the handshake neither
    /// signals nor waits on it, nor notes its fate. Its pidfd goes to `leaf`, for a child the leaf
    /// cannot name: one whose intent carried no handle, or that never sent one.
    #[cfg(feature = "tokio")]
    pub(crate) fn leaving_front(
        mut self,
        front: Option<crate::elevation::front::Front>,
        leaf: Option<LeftPidfd>,
    ) -> Handshake {
        self.front = match (front, leaf) {
            (Some(_), Some(leaf)) => LeftFront::ToLeaf(leaf),
            (Some(front), None) => LeftFront::Here(front),
            (None, _) => LeftFront::NotAFront,
        };
        self
    }

    /// Runs `spawn` (the fork) with the helper thread alive beside it, then answers the pidfd.
    ///
    /// - A failed `pidfd_open` in the child is the error, whatever `spawn` answered: the child
    ///   aborted, and std collected it by pid (see residuals b and c in
    ///   [`child_exited_before_the_helper_finished`]).
    /// - If the helper thread cannot be started, `spawn` is never called: no child exists.
    /// - A child killed before it reported leaves `spawn` answering `Ok` (std reads the closed
    ///   status pipe as success) and the helper at EOF. It is dead but unreaped, and its number
    ///   cannot be trusted without a pidfd, so it is left unreaped and warned about, as a macOS
    ///   `Drop` leaves a child it cannot verify. The spawn fails.
    /// - A child that sent its pidfd and died before its verdict never ran the program. Which
    ///   answer it gets is a race between the helper's GO and the close of the last copy of its
    ///   end (this thread's goes when `spawn()` returns). If the send meets a closed end, the child
    ///   is reaped through the pidfd and the spawn fails. Otherwise GO is buffered, and the spawn
    ///   succeeds with a child that died. Either way the pidfd names it.
    /// - A spawn that fails after its fork: std collected the child (see residuals b and c in
    ///   [`child_exited_before_the_helper_finished`]), or tokio dropped it neither
    ///   killed nor reaped. The pidfd tells which, and a child still there is killed and reaped
    ///   through it.
    ///
    /// The child runs the program only once told to go, so every failure but one proves the program
    /// did not start: a failed `spawn` after the child was told to go, from a spawn whose error does
    /// not prove it (see [`Spawned::ERR_PROVES_NO_EXEC`]).
    pub(crate) fn run<T: Spawned>(self, spawn: impl FnOnce() -> io::Result<T>) -> Result<Held<T>, SpawnFailure> {
        let Handshake {
            parent_end,
            child_end,
            done,
            shared,
            front,
        } = self;
        #[cfg(test)]
        let seams = fault::take_helper_seams();
        #[cfg(test)]
        let helper_seams = seams.clone();
        #[cfg(test)]
        let mut ends = fault::EndProbes::start(&child_end);
        let done = &done;
        // Borrowed by the helper, so this thread can still force EOF on it.
        let parent_end = &parent_end;

        std::thread::scope(|scope| {
            #[cfg(test)]
            let _unwind_checks = fault::UnwindChecks::new(parent_end, &seams);
            #[cfg(test)]
            let _open_held_verdict = seams.open_on_drop();
            let helper = std::thread::Builder::new()
                .name("cosca-pidfd-handshake".into())
                .spawn_scoped(scope, move || {
                    let outcome = {
                        let _shut = ShutOnDrop {
                            parent_end,
                            done,
                            #[cfg(test)]
                            seams: &helper_seams,
                        };
                        help(
                            parent_end,
                            #[cfg(test)]
                            &helper_seams,
                        )
                    };
                    #[cfg(test)]
                    helper_seams.finish();
                    outcome
                });
            let helper = match helper {
                Ok(helper) => helper,
                Err(e) => {
                    shared.withdraw();
                    return Err(SpawnFailure::NotStarted(helper_start_error(e)));
                }
            };

            // A panic on this thread from here on (a panicking logger, tokio's no-IO panic after
            // the fork) unwinds into a join of the helper, which waits for EOF on the child's end:
            // a forked copy of it would hold the join for as long as the copy lives.
            let _eof_on_unwind = ForceEofOnUnwind(parent_end);
            #[cfg(test)]
            let _wait_over = fault::WaitOverOnDrop;
            #[cfg(test)]
            fault::count_spawn();
            #[cfg(test)]
            fault::fork_holder_if_armed();
            let spawned = spawn();
            shared.withdraw();
            #[cfg(test)]
            fault::spawn_returned(spawned.as_ref().ok().and_then(Spawned::pid));
            // This thread's copy goes first: the child, or a hook that failed, closing its own copy
            // then gives the helper EOF, with nothing left to wait for.
            drop(child_end);
            #[cfg(test)]
            ends.check_copies_closed();
            let mut unwatched = None;
            let finished = match &spawned {
                // std collected the child (its by-pid wait, residuals b and c), or never forked.
                Err(_) => true,
                Ok(child) => match child_exited_before_the_helper_finished(child.pid(), done) {
                    Watch::Running => false,
                    Watch::Exited => true,
                    // Not knowing is no reason to wait on a copy this process cannot see: with
                    // open stdio the child has execed or died, so nothing is lost by the EOF.
                    Watch::Unwatchable(cause) => {
                        unwatched = Some(cause);
                        true
                    }
                },
            };
            // Nothing is left to report, but a copy of the child's end made by a fork without
            // `exec` (any thread, in or outside cosca) outlives the child and keeps the helper
            // from EOF: force it.
            if finished {
                force_eof(parent_end);
                #[cfg(test)]
                ends.forced_eof();
            }
            #[cfg(test)]
            fault::wait_over();
            #[cfg(test)]
            ends.finish(parent_end);
            #[cfg(test)]
            seams.release_verdict(spawned.as_ref().ok().and_then(Spawned::pid));
            let outcome = join_helper(
                helper,
                #[cfg(test)]
                &seams,
            );
            let outcome = match (outcome, unwatched) {
                (Outcome::NoReport, Some(cause)) => Outcome::Unwatched(cause),
                (outcome, _) => outcome,
            };
            conclude(spawned, outcome, front)
        })
    }
}

/// What the wait after a successful `spawn()` found.
enum Watch {
    /// The helper finished first, or there is nothing to watch.
    Running,
    /// The child exited while the helper still waited, or its number names no child of this one.
    Exited,
    /// The child could not be watched, for this cause.
    Unwatchable(String),
}

/// After a successful `spawn()`: blocks until the helper is done or the child has exited, and says
/// whether the child exited while the helper still waited. The wait is the child's own progress
/// to its report, as `spawn()`'s is to `exec`. A child that cannot be watched is
/// [`Watch::Unwatchable`]: the caller forces EOF, as for an exit.
fn child_exited_before_the_helper_finished(pid: Option<u32>, done: &OwnedFd) -> Watch {
    use std::os::fd::AsFd;

    use rustix::event::{poll, PollFd, PollFlags, Timespec};

    use crate::wait::exit_only::{peek, Peek, Target};

    let helper_done = |fds: &mut [PollFd<'_>], timeout: Option<&Timespec>| loop {
        match poll(fds, timeout) {
            Ok(_) => return Ok(()),
            // `ENOMEM` is the kernel's transient shortage, not an answer.
            Err(Errno::INTR | Errno::NOMEM) => continue,
            Err(e) => return Err(e),
        }
    };
    // Normally the child reported and execed: the helper is done, and nothing needs watching.
    let mut fds = [PollFd::new(done, PollFlags::IN)];
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    if helper_done(&mut fds, Some(&zero)).is_ok() && fds[0].revents().contains(PollFlags::IN) {
        return Watch::Running;
    }
    let Some(raw) = pid
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(rustix::process::Pid::from_raw)
    else {
        debug_assert!(false, "a spawned child without a pid: {pid:?}");
        return Watch::Running;
    };
    let unwatchable = |what: &str, e: &dyn std::fmt::Display| {
        let cause = format!("{what}: {e}");
        log::warn!(
            "{}: the spawned child's exit cannot be watched ({cause}); the wait for its report is ended",
            super::named(pid)
        );
        Watch::Unwatchable(cause)
    };
    // A watch only, opened by number. The number is the child's own while the child is an unreaped
    // child of this process. After a foreign reap, it shows only while the number is free
    // (`ESRCH`, or the peek's `ECHILD`), or names no thread-group leader (`ENOENT` or `EINVAL`,
    // by kernel: a thread of this process took it).
    //
    // The window that remains, until #383 (an atomic pidfd) removes the watch: the number can be
    // reaped by a foreign reaper (a `SIG_IGN` host, another thread's `waitpid(-1)`) and taken by a
    // RUNNING child or tracee of this process, and then the watch opens that process and the peek
    // answers `Running`. Nothing is signalled through the watch, but the poll below then waits
    // until the helper is done or that process exits. It needs ALL of:
    //  1. the child dies before it reports, so the helper is not done when this code looks;
    //  2. a fork without `exec` (any thread) copied the child's end, at any point from
    //     `Pending::open` until the spawning thread closes its own copy after `spawn()`, so the
    //     helper cannot read EOF by itself: without a copy, the helper finishes at the child's
    //     death and ends the poll at once;
    //  3. a foreign reap of the child;
    //  4. the number taken, before the watch opens, by a process that is a RUNNING child or tracee
    //     of this process (`waitid` on its pidfd answers "nothing to report" for both).
    // Closed stdio is NOT needed. A number taken by a thread, a zombie child or a non-child is
    // not in the window, and neither is a watch that cannot be set up (open, move, peek or poll) or a
    // panic on the spawning thread: those force EOF.
    //
    // Separate residuals, owned by std's fork path (std 1.90 to 1.98), until #383 removes the
    // handshake. Without a `pre_exec` hook std takes `posix_spawn` and has none of them; the hook
    // puts every Linux spawn on this path, as an fd mapping already did. No test pins them.
    //  a. std makes its own CLOEXEC status `socketpair` before it forks, drops its write end just
    //     after the fork returns in the parent, and blocks reading the other until every copy of
    //     the write end is closed. A fork without `exec` between that `socketpair` and std's close
    //     of the write end holds a copy, and `spawn()` waits in std for as long as the holder
    //     lives, with a healthy child and no death, reap or reuse needed. The handshake cannot end
    //     that wait. Nothing hooks the parent inside that interval.
    //  b. After a pre-exec failure report (an exec failure, or a handshake abort), std waits for
    //     the child by pid. With `SIGCHLD` set to `SIG_IGN` that wait fails and std panics, where
    //     `posix_spawn` returns the exec error (`PermissionDenied` for a mode-644 file, say).
    //  c. In the same wait, a foreign reap of the child plus reuse of its number lets std wait on,
    //     and reap, an unrelated child, losing its exit status.
    #[cfg(test)]
    let injected = fault::watch_open_errno();
    #[cfg(not(test))]
    let injected = None;
    let opened = match injected {
        Some(errno) => Err(errno),
        None => rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty()),
    };
    let watch = match opened {
        Ok(watch) => {
            #[cfg(test)]
            let moved = match fault::watch_move_errno() {
                Some(errno) => Err(Error::Io(io::Error::from(errno))),
                None => above_stdio(watch),
            };
            #[cfg(not(test))]
            let moved = above_stdio(watch);
            match moved {
                Ok(watch) => watch,
                Err(e) => return unwatchable("moving its pidfd above stdio", &e),
            }
        }
        // The child was reaped, and the number is free or names no thread-group leader.
        Err(Errno::SRCH | Errno::INVAL | Errno::NOENT) => return Watch::Exited,
        Err(e) => return unwatchable("pidfd_open", &e),
    };
    #[cfg(test)]
    let injected = fault::watch_peek_errno();
    #[cfg(test)]
    let peeked = match injected {
        Some(errno) => Err(io::Error::from(errno)),
        None if fault::watch_poll_armed() => Ok(Peek::Running),
        None => peek(&Target::PidFd(watch.as_fd())),
    };
    #[cfg(test)]
    let injected = injected.is_some();
    #[cfg(not(test))]
    let (peeked, injected) = (peek(&Target::PidFd(watch.as_fd())), false);
    match peeked {
        Ok(Peek::Foreign(_) | Peek::Exit(_)) => return Watch::Exited,
        Ok(Peek::Running) => {}
        Err(e) => {
            debug_assert!(injected, "waitid on a spawned child's pidfd failed: {e}");
            return unwatchable("waitid on its pidfd", &e);
        }
    }
    #[cfg(test)]
    fault::before_awaiting_the_child();
    let mut fds = [PollFd::new(done, PollFlags::IN), PollFd::new(&watch, PollFlags::IN)];
    #[cfg(test)]
    let polled = match fault::watch_poll_errno() {
        Some(errno) => Err(errno),
        None => helper_done(&mut fds, None),
    };
    #[cfg(not(test))]
    let polled = helper_done(&mut fds, None);
    // No contract: a process of the same user can lower `RLIMIT_NOFILE` below the two descriptors
    // polled, and `poll` then fails with `EINVAL`.
    if let Err(e) = polled {
        return unwatchable("poll on its pidfd", &e);
    }
    if !fds[0].revents().contains(PollFlags::IN) && !fds[1].revents().is_empty() {
        Watch::Exited
    } else {
        Watch::Running
    }
}

/// The helper thread could not be started, so nothing was forked.
fn helper_start_error(e: io::Error) -> Error {
    let context = if e.raw_os_error() == Some(libc::EINVAL) {
        // `clone` refuses `CLONE_THREAD` to a task whose namespace for children is not its own.
        "starting the pidfd handshake thread (Linux refuses new threads to a thread that has \
         unshared or entered a pid or time namespace for its children, and a spawn on Linux needs one)"
    } else {
        "starting the pidfd handshake thread"
    };
    Error::Io(crate::error::io_context(context, e))
}

/// The helper thread's whole job. It sends no verdict but GO: a child not told to go reads EOF
/// once the helper shuts its end, and aborts.
fn help(parent_end: &OwnedFd, #[cfg(test)] seams: &fault::HelperSeams) -> Outcome {
    let report = recv_report(parent_end);
    #[cfg(test)]
    seams.wait_verdict();
    let pidfd = match report {
        Ok(Report::Pidfd(pidfd)) => pidfd,
        Ok(Report::Errno(errno)) => return Outcome::Failed(crate::wait::backend::spawn_open_error(errno), None),
        Ok(Report::Eof) => return Outcome::NoReport,
        Err(e) => return Outcome::Failed(e, None),
    };
    // A pidfd in a stdio slot could be replaced under it, so it is moved above them. If that fails
    // it is still the child's pidfd, and the spawn fails with it in hand: the child is not told to
    // go, and is reaped through it.
    #[cfg(test)]
    let moved = match seams.take_move_errno() {
        Some(errno) => Err((Error::Io(io::Error::from(errno)), pidfd)),
        None => above_stdio_keeping(pidfd),
    };
    #[cfg(not(test))]
    let moved = above_stdio_keeping(pidfd);
    let pidfd = match moved {
        Ok(pidfd) => pidfd,
        Err((e, pidfd)) => return Outcome::Failed(e, Some(pidfd)),
    };
    match send_go(
        parent_end,
        #[cfg(test)]
        seams,
    ) {
        Delivery::Delivered => Outcome::Opened(pidfd),
        Delivery::Gone => Outcome::Gone(pidfd),
        Delivery::Failed(e) => Outcome::Failed(
            Error::Io(crate::error::io_context(
                "pidfd handshake: sending the child its go-ahead",
                e,
            )),
            Some(pidfd),
        ),
    }
}

/// What the child sent first.
#[derive(Debug)]
enum Report {
    Pidfd(OwnedFd),
    /// Its `pidfd_open` on itself failed with this.
    Errno(Errno),
    /// Nothing: every copy of its end closed, or the parent shut it.
    Eof,
}

fn recv_report(parent_end: &OwnedFd) -> Result<Report, Error> {
    use std::mem::MaybeUninit;

    use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage};

    let mut message = [0u8; REPORT_LEN];
    // Room for two: a second descriptor is then counted, not lost to a truncation.
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = loop {
        match recvmsg(
            parent_end,
            &mut [io::IoSliceMut::new(&mut message)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        ) {
            Err(Errno::INTR) => continue,
            other => break other,
        }
    };
    let received = received.map_err(|e| {
        Error::Io(crate::error::io_context(
            "pidfd handshake: receiving the child's report",
            e.into(),
        ))
    })?;
    let mut fds = Vec::new();
    let mut foreign = 0;
    for ancillary in control.drain() {
        match ancillary {
            RecvAncillaryMessage::ScmRights(received) => fds.extend(received),
            _ => foreign += 1,
        }
    }
    parse_report(received.bytes, received.flags, &message, fds, foreign)
}

/// Checks a received report: its size, its tag, and that a pidfd report carries exactly one
/// descriptor. `foreign` counts control messages other than `SCM_RIGHTS`.
fn parse_report(
    bytes: usize,
    flags: ReturnFlags,
    message: &[u8; REPORT_LEN],
    fds: Vec<OwnedFd>,
    foreign: usize,
) -> Result<Report, Error> {
    // The kernel drops a descriptor it cannot install, as when this process's table is full.
    if flags.contains(ReturnFlags::CTRUNC) {
        return Err(Error::Io(io::Error::other(
            "pidfd handshake: the child's pidfd could not be received (its control message was \
             truncated, as when this process has no descriptor free)",
        )));
    }
    if bytes == 0 && fds.is_empty() && foreign == 0 {
        return Ok(Report::Eof);
    }
    let violation = |what: String| {
        debug_assert!(false, "pidfd handshake: {what}");
        Err(Error::Io(io::Error::other(format!("pidfd handshake: {what}"))))
    };
    if bytes != REPORT_LEN || flags.contains(ReturnFlags::TRUNC) || foreign != 0 {
        return violation(format!(
            "malformed report: {bytes} bytes, flags {flags:?}, {foreign} foreign control messages"
        ));
    }
    let tag = i32::from_ne_bytes(message[..4].try_into().expect("four bytes"));
    let value = i32::from_ne_bytes(message[4..].try_into().expect("four bytes"));
    match tag {
        REPORT_PIDFD => match <[OwnedFd; 1]>::try_from(fds) {
            Ok([pidfd]) => Ok(Report::Pidfd(pidfd)),
            Err(fds) => violation(format!("a pidfd report carried {} descriptors, not one", fds.len())),
        },
        REPORT_ERRNO if fds.is_empty() && value > 0 => Ok(Report::Errno(Errno::from_raw_os_error(value))),
        _ => violation(format!(
            "unexpected report: tag {tag}, value {value}, {} descriptors",
            fds.len()
        )),
    }
}

/// What sending GO came to.
#[derive(Debug)]
enum Delivery {
    Delivered,
    /// The child's end is closed or shut: the child is dead, or `spawn()` returned without it
    /// execing.
    Gone,
    Failed(io::Error),
}

fn send_go(parent_end: &OwnedFd, #[cfg(test)] seams: &fault::HelperSeams) -> Delivery {
    loop {
        #[cfg(test)]
        let sent = match seams.take_send_errno() {
            Some(errno) => Err(errno),
            None => rustix::net::send(parent_end, &[GO], SendFlags::NOSIGNAL),
        };
        #[cfg(not(test))]
        let sent = rustix::net::send(parent_end, &[GO], SendFlags::NOSIGNAL);
        if let Some(sent) = classify_send(sent) {
            return sent;
        }
    }
}

/// What a `send` of GO answered; `None` to send again.
fn classify_send(sent: Result<usize, Errno>) -> Option<Delivery> {
    match sent {
        Ok(1) => Some(Delivery::Delivered),
        Ok(n) => {
            debug_assert!(
                false,
                "SOCK_SEQPACKET sends a message whole or not at all; sent {n} of 1"
            );
            Some(Delivery::Failed(io::Error::from_raw_os_error(libc::EMSGSIZE)))
        }
        Err(Errno::INTR) => None,
        // `ECONNRESET` is the same close, with a message still unread in the child's end.
        Err(Errno::PIPE | Errno::CONNRESET) => Some(Delivery::Gone),
        Err(e) => Some(Delivery::Failed(e.into())),
    }
}

/// Joins the helper. A helper that panicked shut the parent's end as it unwound, so the child
/// read EOF and aborted; the panic goes on.
fn join_helper(helper: std::thread::ScopedJoinHandle<'_, Outcome>, #[cfg(test)] seams: &fault::HelperSeams) -> Outcome {
    #[cfg(test)]
    seams.release_probe();
    let outcome = match helper.join() {
        Ok(outcome) => outcome,
        Err(payload) => std::panic::resume_unwind(payload),
    };
    #[cfg(test)]
    seams.publish();
    outcome
}

/// Combines the fork's answer with the helper's. A child that sent its pidfd and then failed its
/// `spawn()` is torn down through that pidfd. The exception is the elevation `front` still there:
/// tokio dropped it after it ran the program, so it is sent nothing. A child std already
/// collected never ran the program (its exec failed): it is not a front. A front spawned for a
/// cgroup leaf is the leaf's to answer for: its pidfd is left for the leaf, unused here, and the
/// failure's fate is a placeholder (`Unknown`) that the leaf's abandonment replaces.
///
/// Only a child the helper told to go can run the program, so only the one arm with
/// [`Outcome::Opened`] and a failed `spawn` may answer that it started.
fn conclude<T: Spawned>(spawned: io::Result<T>, outcome: Outcome, front: LeftFront) -> Result<Held<T>, SpawnFailure> {
    let opened_teardown = |pidfd: OwnedFd, error: Error| {
        use crate::wait::exit_only::{peek, Peek, Target};
        use std::os::fd::AsFd as _;
        // A child std collected never ran the program. A peek that fails tells nothing, so the
        // child is taken for a front still there, which is sent nothing.
        let collected = match peek(&Target::PidFd(pidfd.as_fd())) {
            Ok(Peek::Foreign(_)) => true,
            Ok(_) => false,
            Err(e) => {
                log::debug!("a failed spawn's child cannot be peeked ({e}); taken to be uncollected");
                false
            }
        };
        match front {
            LeftFront::ToLeaf(leaf) => {
                leaf.set(Some(pidfd));
                (error, ChildFate::Unknown)
            }
            LeftFront::Here(front) if !collected => {
                let (fate, child_fate) = super::leave_front_through_pidfd(None, pidfd, front, None, None);
                (fate.note(error, Some(front), None), child_fate)
            }
            LeftFront::Here(_) | LeftFront::NotAFront => {
                let child_fate = super::teardown_through_pidfd(None, pidfd, None);
                (error, child_fate)
            }
        }
    };
    let not_started = |error| Err(SpawnFailure::NotStarted(error));
    match (spawned, outcome) {
        (Ok(child), Outcome::Opened(pidfd)) => Ok(Held { child, pidfd }),
        // Not told to go, so it cannot have execed: it was killed on its way, which std reads as
        // success.
        (Ok(child), Outcome::Gone(pidfd)) => {
            let named = super::named(child.pid());
            child.reap_unexecuted(pidfd);
            not_started(Error::Io(io::Error::other(format!(
                "the spawned child ({named}) died before exec: the program never ran"
            ))))
        }
        // Not told to go, as in every arm below but the first with `Opened`.
        (Ok(child), Outcome::Failed(e, Some(pidfd))) => {
            child.reap_unexecuted(pidfd);
            not_started(e)
        }
        (Ok(child), Outcome::Failed(e, None)) => {
            child.abandon_unreported(&format!("its pidfd could not be used ({e})"));
            not_started(e)
        }
        (Ok(child), Outcome::NoReport) => {
            let named = super::named(child.pid());
            child.abandon_unreported("it died before it sent its pidfd");
            not_started(Error::Io(io::Error::other(format!(
                "the spawned child ({named}) died before it could send its pidfd"
            ))))
        }
        // The spawn failed after the fork. std collects the child of a spawn it fails; tokio can
        // fail one after std's succeeded, and drops that child neither killed nor reaped.
        (Err(e), Outcome::Opened(pidfd)) => {
            let (error, fate) = opened_teardown(pidfd, Error::Io(e));
            Err(if T::ERR_PROVES_NO_EXEC {
                SpawnFailure::NotStarted(error)
            } else {
                SpawnFailure::started(error, fate)
            })
        }
        // Not told to go, so it never ran the program.
        (Err(e), Outcome::Gone(pidfd)) => {
            _ = super::teardown_through_pidfd(None, pidfd, None);
            not_started(Error::Io(e))
        }
        // The helper's error explains the abort std reports.
        (Err(_), Outcome::Failed(e, pidfd)) => {
            if let Some(pidfd) = pidfd {
                _ = super::teardown_through_pidfd(None, pidfd, None);
            }
            not_started(e)
        }
        // The child reads EOF in place of its verdict, whenever it reaches its hook.
        (Ok(child), Outcome::Unwatched(cause)) => {
            let named = super::named(child.pid());
            child.abandon_unreported("it sent no pidfd, and its exit could not be watched");
            not_started(Error::Io(io::Error::other(format!(
                "the spawned child ({named}) sent no pidfd, and its exit could not be watched ({cause})"
            ))))
        }
        (Err(e), Outcome::NoReport | Outcome::Unwatched(_)) => not_started(Error::Io(e)),
    }
}

/// Blocks until the child `pidfd` names has exited, without reaping it: a child that never ran
/// the program, and is dead or on its way out. Killed first, in case it is not.
#[cfg(feature = "tokio")]
pub(crate) fn await_unexecuted_exit(pidfd: &OwnedFd, pid: Option<u32>) {
    use std::os::fd::AsFd;

    use crate::wait::exit_only::{wait_visible_exit, Target};

    // It never execed, so it has this process's credentials: nothing but its being gone, which the
    // helper answers `Ok`, can refuse.
    if let Err(e) = crate::signal::via_pidfd(Some(pidfd.as_fd()), pid.unwrap_or(0), crate::signal::Sig::Kill) {
        log::warn!(
            "{}: a spawned child that never ran could not be killed: {e}",
            super::named(pid)
        );
        debug_assert!(false, "SIGKILL through a pidfd to an unexecuted child failed: {e}");
    }
    if let Err(e) = wait_visible_exit(&Target::PidFd(pidfd.as_fd())) {
        log::warn!(
            "{}: a spawned child that never ran could not be waited on: {e}",
            super::named(pid)
        );
        debug_assert!(false, "waitid on an unexecuted child's pidfd failed: {e}");
    }
}

/// Warns that a child stays unreaped: without its pidfd its number cannot be trusted.
fn leave_unreaped(pid: Option<u32>, why: &str) {
    log::warn!(
        "{}: {why}; it is left unreaped, as cosca never reaps a Linux child by pid",
        super::named(pid)
    );
    #[cfg(test)]
    fault::leaked_pid(pid);
}

/// The child's side. Async-signal-safe: direct syscalls only, no allocation, no lock.
fn hold_child(
    shared: &Shared,
    #[cfg(test)] fault: fault::ChildFault,
    #[cfg(test)] scripted: Option<Errno>,
) -> io::Result<()> {
    let child_end: RawFd = shared.child_end();
    let parent_end: RawFd = shared.parent_end();
    // The parent's end, inherited: it has nothing to do here.
    // SAFETY: a plain `close` of a number this hook was given.
    unsafe { libc::close(parent_end) };
    #[cfg(test)]
    fault.apply()?;
    match open_self(
        #[cfg(test)]
        scripted,
    ) {
        Ok(pidfd) => {
            let sent = send_report(child_end, REPORT_PIDFD, 0, pidfd);
            // SAFETY: the pidfd this hook just opened; the parent has its own copy once sent.
            unsafe { libc::close(pidfd) };
            sent?;
        }
        Err(errno) => {
            // Whether or not the report arrives, this child must not run the program.
            _ = send_report(child_end, REPORT_ERRNO, errno, -1);
            return Err(io::Error::from_raw_os_error(errno));
        }
    }
    #[cfg(test)]
    fault.apply_after_report()?;
    let mut verdict = [0u8];
    if recv_one(child_end, &mut verdict)? == 1 && verdict[0] == GO {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::ECANCELED))
    }
}

/// `pidfd_open(getpid(), 0)` through rustix: the `linux_raw` backend issues raw syscalls (no
/// allocation, lock or thread-local), so no libc pid cache can be stale after a fork. The errno on
/// failure.
fn open_self(#[cfg(test)] scripted: Option<Errno>) -> Result<RawFd, i32> {
    #[cfg(test)]
    if let Some(errno) = scripted {
        return Err(errno.raw_os_error());
    }
    match rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty()) {
        Ok(fd) => Ok(fd.into_raw_fd()),
        Err(e) => Err(e.raw_os_error()),
    }
}

/// Sends one report, with `pidfd` attached as `SCM_RIGHTS` unless it is -1. One `sendmsg` from
/// buffers on this frame.
fn send_report(fd: RawFd, tag: i32, value: i32, pidfd: RawFd) -> io::Result<()> {
    #[repr(C, align(8))]
    struct Control([u8; 64]);

    let mut message = [0u8; REPORT_LEN];
    message[..4].copy_from_slice(&tag.to_ne_bytes());
    message[4..].copy_from_slice(&value.to_ne_bytes());
    let mut iov = libc::iovec {
        iov_base: message.as_mut_ptr().cast(),
        iov_len: message.len(),
    };
    let mut control = Control([0; 64]);
    // SAFETY: plain data; zeroed is a valid empty header.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    if pidfd >= 0 {
        let fd_len = std::mem::size_of::<RawFd>() as libc::c_uint;
        header.msg_control = control.0.as_mut_ptr().cast();
        // `as _`: `size_t` on glibc, `socklen_t` on musl.
        // SAFETY: arithmetic on a length.
        header.msg_controllen = unsafe { libc::CMSG_SPACE(fd_len) } as _;
        // SAFETY: `control` is aligned and large enough for one descriptor's header and data.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&header);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_len) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), pidfd);
        }
    }
    loop {
        // SAFETY: every pointer in `header` is to this frame; `MSG_NOSIGNAL` turns a closed peer
        // into `EPIPE`.
        let sent = unsafe { libc::sendmsg(fd, &header, libc::MSG_NOSIGNAL) };
        if sent == REPORT_LEN as isize {
            return Ok(());
        }
        if sent >= 0 {
            // SOCK_SEQPACKET sends a message whole or not at all.
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
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
#[path = "pidfd_handshake/fault.rs"]
pub(crate) mod fault;

#[cfg(test)]
#[path = "pidfd_handshake_tests.rs"]
pub(crate) mod pidfd_handshake_tests;
