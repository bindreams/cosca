//! The channel the forked child reports its placement outcome through (see [`ReportChannel`]).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use super::*;

/// A report of a successful placement. Negative so it can never collide with an errno, which
/// `write(2)` only ever reports as positive.
#[cfg(target_os = "linux")]
pub(super) const REPORT_PLACED: i32 = -1;

/// A message's length: its tag, its value, and — in an intent — the child's start time.
#[cfg(target_os = "linux")]
const MESSAGE_LEN: usize = 16;

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
/// pair. The child sends two messages of two native-endian `i32`s — its *intent* (with its pid,
/// and its pidfd as `SCM_RIGHTS` when it can open one), then its *report* (the write's errno or
/// [`REPORT_PLACED`]). The parent may send one byte back: *proceed*.
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
/// child's exit, watched through a pidfd. The report is always sent before `exec`, so a child that
/// exits without one never exec'd, so nothing of its is in the leaf, and `NotReported` says so. The channel's
/// EOF is no substitute for the pidfd: every process this one forks while the channel is open
/// inherits the child's end, so EOF would also wait for other threads' children to exec or exit —
/// and forever on one that never execs.
///
/// Both ends sit at fd 3 or above. The child's stdio `dup2` cannot close its end there. The only
/// later `dup2` is command-fds' mapping of fds 3 and up, whose hook the spawn registers after the
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
    /// The pidfd its intent carried, when it could open one.
    pub(crate) pidfd: Option<OwnedFd>,
    /// Its start time in clock ticks since boot (`/proc/<pid>/stat` field 22), when it could read
    /// it: with its pid, an identity no other process can share.
    pub(crate) start: Option<u64>,
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
            read: rustix::io::fcntl_dupfd_cloexec(&read, 3)?,
            write: Some(rustix::io::fcntl_dupfd_cloexec(&write, 3)?),
            received: Received::default(),
        })
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

    /// Block until the report of `pid`, the child spawned with this channel's slot, is final, and
    /// return it. See [`ReportChannel`] for why `spawn` returning is not enough.
    ///
    /// `pid` must be this process's own unreaped child, so no other process can hold its number
    /// (see [`Command::contain`](crate::Command::contain) for what breaks that). If something
    /// else reaped it, `pidfd_open` fails with `ESRCH` and the verdict decides without a pidfd.
    ///
    /// `Err` is `pidfd_open`'s: the child's exit cannot be watched, so only a report already
    /// sent is final. Nothing blocks in that case; [`CgroupLeaf::take_placement`] decides without
    /// the report.
    pub(crate) fn wait(&mut self, pid: u32) -> Result<PlacementReport, io::Error> {
        use rustix::event::{poll, PollFd, PollFlags};

        // The parent's own copy would otherwise keep the channel open forever.
        self.write = None;
        let pid = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .expect("a spawned child's pid is a positive i32");
        #[cfg(test)]
        let pidfd = if let Some(errno) = fault::take_force_pidfd_failure() {
            Err(errno)
        } else {
            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        };
        #[cfg(not(test))]
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty());
        let pidfd = match pidfd {
            Ok(pidfd) => pidfd,
            Err(e) => {
                debug_assert_ne!(
                    e,
                    rustix::io::Errno::SRCH,
                    "{pid:?} is not an unreaped child of this process: something else reaped it"
                );
                self.drain();
                return self.received.report.ok_or(e.into());
            }
        };
        loop {
            // An intent alone is not final: the report, or the child's exit, is.
            let closed = self.drain();
            if let Some(report) = self.received.report {
                return Ok(report);
            }
            if closed {
                return Ok(PlacementReport::NotReported);
            }
            let mut fds = [
                PollFd::new(&self.read, PollFlags::IN),
                PollFd::new(&pidfd, PollFlags::IN),
            ];
            #[cfg(test)]
            fault::notify_wait_polling();
            // No timeout: the child reports or exits on its way to `exec`, like `std`'s own wait.
            loop {
                match poll(&mut fds, None) {
                    Ok(_) => break,
                    // `ENOMEM` is the kernel's transient shortage, not an answer.
                    Err(rustix::io::Errno::INTR | rustix::io::Errno::NOMEM) => continue,
                    Err(e) => panic!("poll on the placement report channel failed: {e}"),
                }
            }
            if !fds[1].revents().is_empty() {
                // The child has exited: whatever it sent is queued.
                self.drain();
                return Ok(self.received.placement());
            }
        }
    }

    /// Read every message queued, without blocking, into what was received. `true` once the
    /// channel can deliver no more: shut for reading, or every copy of the child's end closed.
    fn drain(&mut self) -> bool {
        use std::mem::MaybeUninit;

        use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};

        loop {
            let mut message = [0u8; MESSAGE_LEN];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let received = recvmsg(
                &self.read,
                &mut [std::io::IoSliceMut::new(&mut message)],
                &mut control,
                RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
            );
            let bytes = match received {
                Ok(received) => received.bytes,
                // `ENOMEM` is the kernel's transient shortage, not an answer.
                Err(rustix::io::Errno::INTR | rustix::io::Errno::NOMEM) => continue,
                Err(rustix::io::Errno::AGAIN) => return false,
                Err(e) => panic!("recvmsg on the placement report channel failed: {e}"),
            };
            if bytes == 0 {
                return true;
            }
            debug_assert_eq!(bytes, message.len(), "a message is two i32s and a u64");
            let tag = i32::from_ne_bytes(message[..4].try_into().expect("four bytes"));
            let value = i32::from_ne_bytes(message[4..8].try_into().expect("four bytes"));
            let start = u64::from_ne_bytes(message[8..].try_into().expect("eight bytes"));
            let mut pidfd = None;
            for ancillary in control.drain() {
                if let RecvAncillaryMessage::ScmRights(fds) = ancillary {
                    for fd in fds {
                        pidfd.get_or_insert(fd);
                    }
                }
            }
            match tag {
                TAG_INTENT => {
                    self.received.pid = u32::try_from(value).ok();
                    self.received.start = (start != 0).then_some(start);
                    self.received.pidfd = pidfd;
                }
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

    /// The report sent so far, read without blocking: final once the child has reported or can
    /// no longer report.
    pub(super) fn read_final(&mut self) -> PlacementReport {
        self.drain();
        self.received.placement()
    }

    /// End the exchange by deciding: send *proceed*, then close. A child whose send then fails
    /// finds *proceed* queued, and carries on to `exec`.
    pub(super) fn proceed(mut self) {
        // Drained first: closing with messages unread gives the child `ECONNRESET`, not `EPIPE`.
        self.drain();
        // Nothing to do if nobody holds the child's end any more.
        let _ = rustix::net::send(
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
        self.read_final()
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
    /// Send the intent: this process's pid, and a pidfd for it when one can be opened.
    ///
    /// # Safety
    /// As [`ReportSlot::send`].
    pub(super) unsafe fn send_intent(self) -> io::Result<Delivery> {
        // Safety: async-signal-safe syscalls on this process's own pid.
        let pid = unsafe { libc::getpid() };
        let start = own_start_time();
        #[cfg(test)]
        let denied = fault::take_force_child_pidfd_failure();
        #[cfg(not(test))]
        let denied = false;
        let pidfd = if denied {
            -1
        } else {
            // Safety: as above; a pidfd is opened close-on-exec.
            unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd }
        };
        // Safety: the caller's guarantee; `pidfd` is this process's own or -1.
        let sent = unsafe { self.send(TAG_INTENT, pid, start, pidfd) };
        if pidfd >= 0 {
            // Safety: the descriptor opened above, closed once.
            unsafe { libc::close(pidfd) };
        }
        sent
    }

    /// Close this child's inherited copy of the parent's end, before anything else in the hook.
    ///
    /// Until `exec` the child holds that copy, so the parent's own close would not end the
    /// socket, and a decided parent's close would never reach the child as `EPIPE`. It also
    /// frees a descriptor for the `pidfd_open` that follows, in a table that may be full.
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
        unsafe { self.send(TAG_REPORT, value, 0, -1) }
    }

    /// Send one message, with `pidfd` attached as `SCM_RIGHTS` unless it is -1. Async-signal-safe:
    /// one `sendmsg(2)` from buffers on the stack, then at most one `recv(2)`.
    ///
    /// `EPIPE` (or `ECONNRESET`) means the parent has ended the exchange (see the module's
    /// contract): *proceed* queued means it decided, and this child carries on; none means it
    /// abandoned the spawn.
    ///
    /// # Safety
    /// The child's end must still be open at this number, which holds from the leaf's creation
    /// until the parent has taken the verdict.
    pub(super) unsafe fn send(self, tag: i32, value: i32, start: u64, pidfd: RawFd) -> io::Result<Delivery> {
        #[repr(C, align(8))]
        struct Control([u8; 64]);

        let mut message = [0u8; MESSAGE_LEN];
        message[..4].copy_from_slice(&tag.to_ne_bytes());
        message[4..8].copy_from_slice(&value.to_ne_bytes());
        message[8..].copy_from_slice(&start.to_ne_bytes());
        let mut iov = libc::iovec {
            iov_base: message.as_mut_ptr().cast(),
            iov_len: message.len(),
        };
        let mut control = Control([0; 64]);
        // Safety: plain data; zeroed is a valid empty header.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        if pidfd >= 0 {
            let fd_len = std::mem::size_of::<RawFd>() as libc::c_uint;
            header.msg_control = control.0.as_mut_ptr().cast();
            // Safety: arithmetic on a length.
            header.msg_controllen = unsafe { libc::CMSG_SPACE(fd_len) } as usize;
            // Safety: `control` is aligned and large enough for one descriptor's header and data.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&header);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(fd_len) as usize;
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), pidfd);
            }
        }
        loop {
            // Safety: every pointer in `header` is to this frame; the caller guarantees the fd.
            let sent = unsafe { libc::sendmsg(self.fd, &header, libc::MSG_NOSIGNAL) };
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

/// This process's start time in clock ticks since boot, or 0 when `/proc/self/stat` cannot be
/// read. Async-signal-safe: `open`, `read` and `close` into a buffer on the stack, and a parse
/// that allocates nothing.
#[cfg(target_os = "linux")]
fn own_start_time() -> u64 {
    let mut stat = [0u8; 1024];
    // Safety: a NUL-terminated path; the result is checked.
    let fd = unsafe { libc::open(c"/proc/self/stat".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return 0;
    }
    let mut len = 0;
    while len < stat.len() {
        // Safety: the rest of `stat` is a valid, writable buffer; `fd` is open.
        let got = unsafe { libc::read(fd, stat[len..].as_mut_ptr().cast(), stat.len() - len) };
        match got {
            // Safety: errno is this thread's own.
            -1 if unsafe { *libc::__errno_location() } == libc::EINTR => continue,
            n if n <= 0 => break,
            n => len += n as usize,
        }
    }
    // Safety: the descriptor opened above, closed once.
    unsafe { libc::close(fd) };
    crate::identity::stat_parse::parse_starttime_jiffies(&stat[..len]).unwrap_or(0)
}
