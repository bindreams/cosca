//! The channel the forked child reports its placement outcome through (see [`ReportChannel`]).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use super::*;

/// A report of a successful placement. Negative so it can never collide with an errno, which
/// `write(2)` only ever reports as positive.
#[cfg(target_os = "linux")]
pub(super) const REPORT_PLACED: i32 = -1;

/// The channel the forked child reports its self-placement outcome through: a `SOCK_SEQPACKET`
/// socket pair carrying one message, a native-endian `i32` — the write's errno or
/// [`REPORT_PLACED`].
///
/// `pre_exec` runs after `fork`, where async-signal-safety forbids allocating, formatting or
/// locking, and nothing the child computes survives its `exec`. One `send(2)` of four bytes is
/// all a report needs. It is sent with `MSG_NOSIGNAL`: a parent that has stopped listening makes
/// it fail with `EPIPE` instead of killing the child with `SIGPIPE`.
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
/// **One report per channel.** A caller that routes several children through one channel reads
/// the first report sent, whoever sent it.
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
                return match self.read_final() {
                    PlacementReport::NotReported => Err(e.into()),
                    sent => Ok(sent),
                };
            }
        };
        let mut fds = [
            PollFd::new(&self.read, PollFlags::IN),
            PollFd::new(&pidfd, PollFlags::IN),
        ];
        // No timeout: the child reports or exits on its way to `exec`, like `std`'s own wait.
        loop {
            match poll(&mut fds, None) {
                Ok(_) => break,
                // `ENOMEM` is the kernel's transient shortage, not an answer.
                Err(rustix::io::Errno::INTR | rustix::io::Errno::NOMEM) => continue,
                Err(e) => panic!("poll on the placement report channel failed: {e}"),
            }
        }
        Ok(self.read_final())
    }

    /// The report sent so far, read without blocking: final once the child has reported or can
    /// no longer report.
    pub(super) fn read_final(&mut self) -> PlacementReport {
        let queued = rustix::io::ioctl_fionread(&self.read).expect("FIONREAD on the report channel");
        if queued == 0 {
            return PlacementReport::NotReported;
        }
        let mut report = [0u8; 4];
        // A queued message makes this return at once. SOCK_SEQPACKET delivers it whole.
        let read = loop {
            match rustix::io::read(&self.read, &mut report) {
                Err(rustix::io::Errno::INTR) => continue,
                other => break other.expect("read a report that is already queued"),
            }
        };
        debug_assert_eq!(read, report.len(), "a report is one 4-byte message");
        match i32::from_ne_bytes(report) {
            REPORT_PLACED => PlacementReport::Placed,
            errno => {
                debug_assert!(errno > 0, "a failed write reports its positive errno, got {errno}");
                PlacementReport::WriteFailed(errno)
            }
        }
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

/// The child-side half of a [`ReportChannel`]: its end's number, with one async-signal-safe
/// operation. Owns nothing — the parent's `ReportChannel` closes the channel.
///
/// The closure holding it can OUTLIVE the channel: `attach` closes the channel once the spawn has
/// returned, and on the spawn-FAILURE path `Prepared` (and with it the leaf) drops first — both
/// before the `Command` that still owns the closure. The number is stale from then on, which is
/// sound only because nothing ever invokes the closure again: each `Command` is spawned once.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) struct ReportSlot {
    pub(super) fd: RawFd,
}

#[cfg(target_os = "linux")]
impl ReportSlot {
    /// Send the child's outcome. Async-signal-safe: one `send(2)`, no allocation.
    ///
    /// `EPIPE` is `Ok`: the parent closes its end before the report arrives only after deciding
    /// without it (see [`CgroupLeaf::decide_unwaitable`]), and that decision already holds for
    /// this child. Either the leaf was closed, so this child's placement failed with `ENODEV`;
    /// or this child was found in the leaf; or it is being killed. Every other failure is `Err`.
    ///
    /// # Safety
    /// The child's end must still be open at this number, which holds from the leaf's creation
    /// until the parent has taken the verdict.
    pub(super) unsafe fn report(self, value: i32) -> io::Result<()> {
        let bytes = value.to_ne_bytes();
        loop {
            // Safety: `bytes` is a valid buffer; the caller guarantees the fd.
            let sent = unsafe { libc::send(self.fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL) };
            if sent == bytes.len() as isize {
                return Ok(());
            }
            // Safety: errno is this thread's own; `__errno_location` is async-signal-safe.
            let errno = unsafe { *libc::__errno_location() };
            match (sent, errno) {
                (-1, libc::EINTR) => continue,
                (-1, libc::EPIPE) => return Ok(()),
                (-1, errno) => return Err(io::Error::from_raw_os_error(errno)),
                // SOCK_SEQPACKET sends a message whole or not at all.
                _ => return Err(io::Error::from_raw_os_error(libc::EMSGSIZE)),
            }
        }
    }
}

#[cfg(all(target_os = "linux", test))]
impl ReportSlot {
    /// Report `Placed` without a `cgroup.procs` write, for tests of what cosca does with a report.
    ///
    /// # Safety
    /// As [`ReportSlot::report`].
    pub(crate) unsafe fn report_placed_for_test(self) {
        // Safety: the caller guarantees the channel is open.
        unsafe { self.report(REPORT_PLACED) }.expect("send the report");
    }
}
