//! The channel the forked child reports its placement outcome through (see [`ReportChannel`]).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use super::*;

/// A report of a successful placement. Negative so it can never collide with an errno, which
/// `write(2)` only ever reports as positive.
#[cfg(target_os = "linux")]
pub(super) const REPORT_PLACED: i32 = -1;

/// A message's length: its tag and its value.
#[cfg(target_os = "linux")]
const MESSAGE_LEN: usize = 8;

/// The tag of a child's intent message; its value is the child's pid.
#[cfg(target_os = "linux")]
pub(super) const TAG_INTENT: i32 = 1;
/// The tag of a child's report message; its value is [`REPORT_PLACED`] or the write's errno.
#[cfg(target_os = "linux")]
const TAG_REPORT: i32 = 2;
/// The parent's one message: it has decided without the rest of the exchange.
#[cfg(target_os = "linux")]
const PROCEED: u8 = b'P';

/// The channel of the placement exchange (see the module's contract): a `SOCK_SEQPACKET` socket
/// pair. The child sends two messages of two native-endian `i32`s — its *intent* (with its pid),
/// then its *report* (the write's errno or [`REPORT_PLACED`]). The parent may send one byte back:
/// *proceed*. The child names itself to the parent's teardown by pid alone: the spawn handshake's
/// pidfd, which the parent holds before the child sends anything, is the handle.
///
/// `pre_exec` runs after `fork`, where async-signal-safety forbids allocating, formatting or
/// locking, and nothing the child computes survives its `exec`. A `sendmsg(2)` from a buffer on
/// the stack is all a message needs. It is sent with `MSG_NOSIGNAL`: a parent that has stopped
/// listening makes it fail with `EPIPE` instead of killing the child with `SIGPIPE`.
///
/// # When the report is final
/// Not when `spawn` returns. `std`'s Unix spawn returns once its own close-on-exec error channel
/// reads EOF, normally at the child's `exec`. But that channel takes the lowest free fds: with two
/// of this process's 0, 1 and 2 closed, its child end is one of them. When `std` `dup2`s the
/// child's stdio for that slot into place, before any `pre_exec` runs, it closes that end, and
/// `spawn` returns before the child has placed itself.
///
/// [`ReportChannel::wait`] therefore waits for the child itself: for the report, or for the
/// child's exit, watched through the child's own pidfd, which it handed over at the spawn handshake
/// from before `exec`. That pidfd names the child whoever reaps it and whoever takes its number: a
/// reaped child's pidfd is readable, so the wait ends. The report is always sent before `exec`, so
/// a child that exits without one never exec'd, so nothing of its is in the leaf, and
/// `NotReported` says so. The channel's EOF is no substitute for the pidfd: every process this one
/// forks while the channel is open inherits the child's end, so EOF would also wait for other
/// threads' children to exec or exit — and forever on one that never execs.
///
/// Both ends sit at fd 3 or above. The child's stdio `dup2` cannot close its end there. The only
/// later `dup2` is fd_map's mapping of fds 3 and up, whose hook the spawn registers after the
/// placement hook: it can replace the child's end only once the report is sent.
///
/// The wait is no longer than the one `std` intends: the child reaches its report on `std`'s own
/// path from `fork` to `exec`, all of which `spawn` normally waits out.
///
/// **One child per channel.** A caller that routes several children through one channel reads
/// the last intent and the first report sent, whoever sent them.
///
/// # What this costs, and what it can cost a spawn
/// Two fds per contained spawn in flight, held from the leaf's creation until `attach` takes the
/// placement verdict; a live contained child costs the supervisor none. A channel that cannot be
/// opened (`EMFILE`, `ENFILE`) DEGRADES the spawn — it keeps its process group and loses the
/// fork-proof kill — rather than failing it. `LeafError::OpenReportChannel` is what makes that
/// audible.
#[cfg(target_os = "linux")]
pub(crate) struct ReportChannel {
    /// The parent's end.
    pub(super) read: OwnedFd,
    /// The parent's copy of the child's end. Closed before waiting.
    pub(super) write: Option<OwnedFd>,
    /// What the child has sent so far.
    received: Received,
}

/// What the child has sent over a [`ReportChannel`].
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub(crate) struct Received {
    /// Its report, once sent.
    pub(crate) report: Option<PlacementReport>,
    /// Its pid, once its intent is sent: it reached cosca's hook and may enter the leaf.
    pub(crate) pid: Option<u32>,
}

#[cfg(target_os = "linux")]
impl Received {
    /// The report, where nothing received reads as `NotReported`.
    pub(crate) fn placement(&self) -> PlacementReport {
        self.report.unwrap_or(PlacementReport::NotReported)
    }
}

#[cfg(target_os = "linux")]
impl ReportChannel {
    pub(crate) fn new() -> io::Result<ReportChannel> {
        use rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType};

        // Test-only fault seam: fail the channel (take semantics — see `fault`).
        #[cfg(test)]
        if fault::take_force_report_channel_failure() {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        // Both ends close-on-exec: the child needs its end only until `exec`, and no program this
        // process starts may inherit either. Both at fd 3 or above: the child's end so the child's
        // stdio cannot replace it, and the parent's so it takes no std slot this process left
        // closed — that gap is the host's, not cosca's to fill.
        let (read, write) = socketpair(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None)?;
        Ok(ReportChannel {
            read: crate::above_stdio::above_stdio(read)?,
            write: Some(crate::above_stdio::above_stdio(write)?),
            received: Received::default(),
        })
    }

    /// A duplicate of the child's end, so a test can keep the channel open past the child's exit.
    #[cfg(test)]
    pub(crate) fn dup_child_end_for_test(&self) -> std::os::fd::OwnedFd {
        self.write
            .as_ref()
            .expect("the child's end is open until the wait")
            .try_clone()
            .expect("dup the child's end")
    }

    /// A `Copy` handle to the child's end for capture by the `pre_exec` closure (which must not
    /// capture the owning `ReportChannel`: the leaf keeps it).
    pub(crate) fn slot(&self) -> ReportSlot {
        ReportSlot {
            fd: self
                .write
                .as_ref()
                .expect("the child's end is open until the wait")
                .as_raw_fd(),
            parent_fd: self.read.as_raw_fd(),
        }
    }

    /// Block until the report of the child `pidfd` names, spawned with this channel's slot, is
    /// final, and return it. See [`ReportChannel`] for why `spawn` returning is not enough, and for
    /// why the wait goes through `pidfd`.
    pub(crate) fn wait(&mut self, pidfd: std::os::fd::BorrowedFd<'_>) -> PlacementReport {
        use rustix::event::{PollFd, PollFlags};

        // The parent's own copy would otherwise keep the channel open forever.
        self.write = None;
        #[cfg(test)]
        fault::notify_wait_entry(std::os::fd::AsRawFd::as_raw_fd(&pidfd));
        loop {
            // An intent alone is not final: the report, or the child's exit, is.
            let closed = self.drain();
            if let Some(report) = self.received.report {
                return report;
            }
            if closed {
                return PlacementReport::NotReported;
            }
            let mut fds = [
                PollFd::new(&self.read, PollFlags::IN),
                PollFd::new(&pidfd, PollFlags::IN),
            ];
            #[cfg(test)]
            fault::notify_wait_polling();
            // No timeout: the child reports or exits on its way to `exec`, like `std`'s own wait.
            if let Err(e) = crate::wait::poll_ready(&mut fds) {
                panic!("poll on the placement report channel failed: {e}");
            }
            if !fds[1].revents().is_empty() {
                // The child has exited: whatever it sent is queued.
                self.drain();
                return self.received.placement();
            }
        }
    }

    /// Read every message queued, without blocking, into what was received. `true` once the
    /// channel can deliver no more: shut for reading, or every copy of the child's end closed.
    fn drain(&mut self) -> bool {
        use rustix::net::{recv, RecvFlags};

        loop {
            let mut message = [0u8; MESSAGE_LEN];
            let bytes = match recv(&self.read, &mut message, RecvFlags::DONTWAIT) {
                // Read, and the message's full length: whole or not at all on a `SEQPACKET` socket.
                Ok((bytes, _)) => bytes,
                // `ENOMEM` is the kernel's transient shortage, not an answer.
                Err(rustix::io::Errno::INTR | rustix::io::Errno::NOMEM) => continue,
                Err(rustix::io::Errno::AGAIN) => return false,
                Err(e) => panic!("recvmsg on the placement report channel failed: {e}"),
            };
            if bytes == 0 {
                return true;
            }
            debug_assert_eq!(bytes, message.len(), "a message is two i32s");
            let tag = i32::from_ne_bytes(message[..4].try_into().expect("four bytes"));
            let value = i32::from_ne_bytes(message[4..].try_into().expect("four bytes"));
            match tag {
                TAG_INTENT => self.received.pid = u32::try_from(value).ok(),
                TAG_REPORT => {
                    self.received.report.get_or_insert(match value {
                        REPORT_PLACED => PlacementReport::Placed,
                        errno => {
                            debug_assert!(errno > 0, "a failed write reports its positive errno, got {errno}");
                            PlacementReport::WriteFailed(errno)
                        }
                    });
                }
                tag => debug_assert!(false, "unknown placement message tag {tag}"),
            }
        }
    }

    /// End the exchange by deciding: send *proceed*, then close. A child whose send then fails
    /// finds *proceed* queued, and carries on to `exec`.
    pub(super) fn proceed(mut self) {
        // Drained first: closing with messages unread gives the child `ECONNRESET`, not `EPIPE`.
        self.drain();
        // Nothing to do if nobody holds the child's end any more.
        _ = rustix::net::send(
            &self.read,
            &[PROCEED],
            rustix::net::SendFlags::NOSIGNAL | rustix::net::SendFlags::DONTWAIT,
        );
    }

    /// End the exchange by abandoning it: shut the channel for reading, then read everything sent
    /// before. Every later send fails with no *proceed* queued, and the child exits without
    /// `exec` — so what this returns is all the child will ever have said.
    pub(super) fn shut(mut self) -> Received {
        self.write = None;
        rustix::net::shutdown(&self.read, rustix::net::Shutdown::Read)
            .expect("shut the placement report channel for reading");
        self.drain();
        // Test-only fault seam: a child's send landing after the read, before the close.
        #[cfg(test)]
        fault::run_after_shut_read();
        self.received
    }
}

#[cfg(all(target_os = "linux", test))]
impl ReportChannel {
    /// The report of a child that has already been reaped, or of reports sent from this process.
    pub(crate) fn report_for_test(mut self) -> PlacementReport {
        self.write = None;
        self.drain();
        self.received.placement()
    }
}

/// How a child's message fared.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// It was queued for the parent.
    Queued,
    /// The parent has decided without it: carry on.
    Decided,
    /// The parent has abandoned the spawn: exit without `exec`.
    Abandoned,
}

/// The child-side half of a [`ReportChannel`]: its end's number, with async-signal-safe sends.
/// Owns nothing — the parent's `ReportChannel` closes the channel.
///
/// The closure holding it can OUTLIVE the channel: `attach` closes the channel once the spawn has
/// returned, and on the spawn-FAILURE path `Prepared` (and with it the leaf) drops first — both
/// before the `Command` that still owns the closure. The number is stale from then on, which is
/// sound only because nothing ever invokes the closure again: each `Command` is spawned once.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) struct ReportSlot {
    pub(super) fd: RawFd,
    /// The parent's end, which a forked child inherits a copy of until `exec`: see
    /// [`ReportSlot::close_parents_end`].
    pub(super) parent_fd: RawFd,
}

#[cfg(target_os = "linux")]
impl ReportSlot {
    /// Send the intent: this process's pid.
    ///
    /// # Safety
    /// As [`ReportSlot::send`].
    pub(super) unsafe fn send_intent(self) -> io::Result<Delivery> {
        // A raw syscall, so async-signal-safe.
        let pid = rustix::process::getpid();
        // Safety: the caller's guarantee.
        unsafe { self.send(TAG_INTENT, pid.as_raw_nonzero().get()) }
    }

    /// Close this child's inherited copy of the parent's end, before anything else in the hook.
    ///
    /// Until `exec` the child holds that copy, so the parent's own close would not end the
    /// socket, and a decided parent's close would never reach the child as `EPIPE`.
    ///
    /// # Safety
    /// Only in a forked child, where `parent_fd` is its own inherited copy — never in the parent,
    /// whose end it would close.
    pub(crate) unsafe fn close_parents_end(self) {
        // Safety: the caller's guarantee; close is async-signal-safe.
        unsafe { libc::close(self.parent_fd) };
    }

    /// Send the report: [`REPORT_PLACED`] or the placement write's errno.
    ///
    /// # Safety
    /// As [`ReportSlot::send`].
    pub(super) unsafe fn send_report(self, value: i32) -> io::Result<Delivery> {
        // Safety: the caller's guarantee.
        unsafe { self.send(TAG_REPORT, value) }
    }

    /// Send one message. Async-signal-safe: one `send(2)` from a buffer on the stack, then at most
    /// one `recv(2)`.
    ///
    /// `EPIPE` (or `ECONNRESET`) means the parent has ended the exchange (see the module's
    /// contract): *proceed* queued means it decided, and this child carries on; none means it
    /// abandoned the spawn.
    ///
    /// # Safety
    /// The child's end must still be open at this number, which holds from the leaf's creation
    /// until the parent has taken the verdict.
    pub(super) unsafe fn send(self, tag: i32, value: i32) -> io::Result<Delivery> {
        let mut message = [0u8; MESSAGE_LEN];
        message[..4].copy_from_slice(&tag.to_ne_bytes());
        message[4..].copy_from_slice(&value.to_ne_bytes());
        loop {
            // Safety: `message` is a buffer on this frame; the caller guarantees the fd.
            let sent = unsafe { libc::send(self.fd, message.as_ptr().cast(), message.len(), libc::MSG_NOSIGNAL) };
            if sent == message.len() as isize {
                return Ok(Delivery::Queued);
            }
            // Safety: errno is this thread's own; `__errno_location` is async-signal-safe.
            let errno = unsafe { *libc::__errno_location() };
            return match (sent, errno) {
                (-1, libc::EINTR) => continue,
                // Safety: the caller's guarantee.
                // `ECONNRESET` is the same close, made with a message still unread.
                (-1, libc::EPIPE | libc::ECONNRESET) => Ok(if unsafe { self.proceed_queued() } {
                    Delivery::Decided
                } else {
                    Delivery::Abandoned
                }),
                (-1, errno) => Err(io::Error::from_raw_os_error(errno)),
                // SOCK_SEQPACKET sends a message whole or not at all.
                _ => Err(io::Error::from_raw_os_error(libc::EMSGSIZE)),
            };
        }
    }

    /// Whether the parent left *proceed* for this child before closing its end.
    ///
    /// # Safety
    /// As [`ReportSlot::send`].
    unsafe fn proceed_queued(self) -> bool {
        let mut byte = 0u8;
        loop {
            // Safety: a one-byte buffer on this frame; the caller guarantees the fd.
            let got = unsafe { libc::recv(self.fd, (&raw mut byte).cast(), 1, libc::MSG_DONTWAIT) };
            // Safety: as in `send`.
            if got == -1 && unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return got == 1 && byte == PROCEED;
        }
    }
}

#[cfg(all(target_os = "linux", test))]
impl ReportSlot {
    /// Report `Placed` without a `cgroup.procs` write, for tests of what cosca does with a report.
    ///
    /// # Safety
    /// As [`ReportSlot::send`].
    pub(crate) unsafe fn report_placed_for_test(self) {
        // Safety: the caller guarantees the channel is open.
        let sent = unsafe { self.send_report(REPORT_PLACED) }.expect("send the report");
        assert_eq!(sent, Delivery::Queued, "the parent must still be listening");
    }
}

#[cfg(test)]
#[path = "channel_tests.rs"]
mod channel_tests;
