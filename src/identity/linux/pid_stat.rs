//! One pid's `stat` through the checked `/proc`, with the errno policy every whole-table scan
//! shares (`containment::unix::group::members`, `containment::enumerate`).
//!
//! A scan that skips a pid it could not read reports a table with a live process missing, and a
//! tree walk over it misses that process and its subtree. So only the errnos that mean "this pid is
//! not there for us" skip; every other one fails the scan. A refused `openat2` (a seccomp filter
//! installed mid-scan) is [`PidStat::Refused`], for the scan to fail as `Unsupported`, as a refused
//! view-open does.

use std::io;

use rustix::io::Errno;

use super::kernel::Kernel;
use super::proc_view::ProcDir;
use super::prove::FailedCall;

/// What reading one pid's `stat` yielded.
#[derive(Debug)]
pub(crate) enum PidStat {
    Read(Vec<u8>),
    /// The pid exited mid-scan (`ENOENT`/`ESRCH`), or `hidepid` hides it (`EACCES`, or `EPERM`
    /// while the checked directory still answers). The error is why.
    Skipped(io::Error),
    /// The `openat2` of the read was refused: the `stat` answered `ENOSYS`/`ENODEV`, or `EPERM` while
    /// the checked directory refuses `self/stat` too, with a refusal errno. The call carries the
    /// refusing errno.
    Refused(FailedCall),
}

/// Why one pid's `stat` could not be read and is not simply absent. Its words say what failed; the
/// OS error behind them is the [`source`](std::error::Error::source).
///
/// A layer of the error chain: a caller wraps it as the cause of its own error and never folds its
/// words into a message of its own.
#[derive(Debug)]
pub(crate) struct Unreadable {
    pid: u32,
    kind: Kind,
    cause: io::Error,
    /// The other read that failed with it, when there is one ([`Kind::RecheckFailed`]): the pid's
    /// `EPERM` beside the re-check's error. It is no layer of the chain; the caller takes it
    /// ([`into_cause`](Self::into_cause)).
    peer: Option<io::Error>,
}

impl Unreadable {
    /// The other failure that came with this one, once: for a caller that holds both.
    pub(crate) fn take_peer(&mut self) -> Option<io::Error> {
        self.peer.take()
    }

    /// This failure as the cause of its caller's error, with the peer beside it when there is one
    /// (a [`Error::Several`](crate::error::Error::Several), this failure first).
    pub(crate) fn into_cause(mut self) -> crate::error::Error {
        use crate::error::Error;
        let peer = self.take_peer();
        let own = Error::Io(io::Error::other(self));
        match peer {
            None => own,
            Some(peer) => Error::Several(crate::error::Failures::new(
                std::sync::Arc::new(own),
                [Error::io_cause(peer)],
            )),
        }
    }
}

#[derive(Debug)]
enum Kind {
    /// `EXDEV`/`ELOOP`: the checked directory refused to cross a mount, so the record is not the
    /// kernel's.
    BeyondMount,
    /// `EPERM`, and the `self/stat` re-check failed without refusing (`EMFILE`, `ENOMEM`, ...):
    /// whether the pid is hidden is unknown. The re-check's error is the source, and the pid's own
    /// `EPERM` is the peer.
    RecheckFailed,
    /// `EMFILE`, `ENOMEM`, `EIO`, ...: nothing is known about the pid.
    Other,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Unreadable { pid, kind, .. } = self;
        match kind {
            Kind::BeyondMount => write!(f, "{pid}/stat lies beyond a mount in /proc and was not read"),
            Kind::RecheckFailed => write!(f, "{pid}/stat was refused, and the re-check of self/stat failed"),
            Kind::Other => write!(f, "{pid}/stat could not be read"),
        }
    }
}

impl std::error::Error for Unreadable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// `pid`'s `stat` through `dir`: [`PidStat::Skipped`] for the errnos that mean the pid is not
/// there for us, [`PidStat::Refused`] for a refused `openat2`, [`Unreadable`] for every other.
/// Never asks `kill(pid, 0)`.
pub(crate) fn read_in_scan(kernel: &dyn Kernel, dir: &ProcDir, pid: u32) -> Result<PidStat, Unreadable> {
    let source = match read_stat_file(kernel, dir, pid) {
        Ok(stat) => return Ok(PidStat::Read(stat)),
        Err(e) => e,
    };
    let (kind, cause, peer) = match source.raw_os_error() {
        // Deliberately NOT disambiguated with `kill(pid, 0)`: a scan covers all of `/proc`, and a
        // `hidepid` `/proc` answers a foreign-uid probe `EPERM` too, so the first foreign-uid
        // process would abort every scan.
        Some(libc::ENOENT | libc::ESRCH | libc::EACCES) => return Ok(PidStat::Skipped(source)),
        // `hidepid`'s answer only if the checked directory still reads.
        Some(libc::EPERM) => match check_dir_answers(kernel, dir) {
            Ok(()) => return Ok(PidStat::Skipped(source)),
            Err(recheck) => match refusal(&recheck) {
                Some(call) => return Ok(PidStat::Refused(call)),
                None => (Kind::RecheckFailed, recheck, Some(source)),
            },
        },
        Some(libc::EXDEV | libc::ELOOP) => (Kind::BeyondMount, source, None),
        _ => match refusal(&source) {
            Some(call) => return Ok(PidStat::Refused(call)),
            None => (Kind::Other, source, None),
        },
    };
    Err(Unreadable { pid, kind, cause, peer })
}

/// The raw `stat` read; what a failure means is each caller's policy ([`read_in_scan`],
/// `identity::linux::stat_by_pid`, the cgroup leaf's state read).
pub(crate) fn read_stat_file(kernel: &dyn Kernel, dir: &ProcDir, pid: u32) -> io::Result<Vec<u8>> {
    kernel.read(dir, &format!("{pid}/stat"))
}

/// The refused `openat2` that `error` is, when its errno is one [`FailedCall::requirement`] counts
/// as a refusal.
fn refusal(error: &io::Error) -> Option<FailedCall> {
    let call = FailedCall::openat2(Errno::from_io_error(error)?);
    call.requirement().map(|_| call)
}

/// Whether the checked directory still reads (`self/stat`).
fn check_dir_answers(kernel: &dyn Kernel, dir: &ProcDir) -> io::Result<()> {
    kernel.read(dir, "self/stat").map(drop)
}

#[cfg(test)]
#[path = "pid_stat_tests.rs"]
mod pid_stat_tests;
