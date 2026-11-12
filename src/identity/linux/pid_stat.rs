//! One pid's `stat` through the checked `/proc`, with the errno policy every whole-table scan
//! shares (`containment::unix::group::members`, `containment::enumerate`).
//!
//! A scan that skips a pid it could not read reports a table with a live process missing, and a
//! tree walk over it misses that process and its subtree. So only the errnos that mean "this pid is
//! not there for us" skip; every other one fails the scan.

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
}

#[derive(Debug)]
enum Kind {
    /// `EXDEV`/`ELOOP`: the checked directory refused to cross a mount, so the record is not the
    /// kernel's.
    BeyondMount,
    /// `EPERM`, and the checked directory refused `self/stat` too, with an `openat2` refusal (a
    /// seccomp filter installed mid-scan answers every `openat2` so). The `self/stat` refusal is
    /// named in the words only; the pid's own `stat` error is the source.
    DirectoryRefuses,
    /// `EPERM`, and the `self/stat` re-check failed without refusing (`EMFILE`, `ENOMEM`, ...):
    /// whether the pid is hidden is unknown. The re-check's error is the source.
    RecheckFailed,
    /// `EMFILE`, `ENOMEM`, `EIO`, ...: nothing is known about the pid.
    Other,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Unreadable { pid, kind, .. } = self;
        match kind {
            Kind::BeyondMount => write!(f, "{pid}/stat lies beyond a mount in /proc and was not read"),
            Kind::DirectoryRefuses => write!(
                f,
                "{pid}/stat was refused (its error below), and the checked /proc refused self/stat too"
            ),
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
/// there for us, [`Unreadable`] for every other. Never asks `kill(pid, 0)`.
pub(crate) fn read_in_scan(kernel: &dyn Kernel, dir: &ProcDir, pid: u32) -> Result<PidStat, Unreadable> {
    let source = match read_stat_file(kernel, dir, pid) {
        Ok(stat) => return Ok(PidStat::Read(stat)),
        Err(e) => e,
    };
    let (kind, cause) = match source.raw_os_error() {
        // Deliberately NOT disambiguated with `kill(pid, 0)`: a scan covers all of `/proc`, and a
        // `hidepid` `/proc` answers a foreign-uid probe `EPERM` too, so the first foreign-uid
        // process would abort every scan.
        Some(libc::ENOENT | libc::ESRCH | libc::EACCES) => return Ok(PidStat::Skipped(source)),
        // `hidepid`'s answer only if the checked directory still reads.
        Some(libc::EPERM) => match check_dir_answers(kernel, dir) {
            Ok(()) => return Ok(PidStat::Skipped(source)),
            Err(recheck) if is_refusal(&recheck) => (Kind::DirectoryRefuses, source),
            Err(recheck) => (Kind::RecheckFailed, recheck),
        },
        Some(libc::EXDEV | libc::ELOOP) => (Kind::BeyondMount, source),
        _ => (Kind::Other, source),
    };
    Err(Unreadable { pid, kind, cause })
}

/// The raw `stat` read; what a failure means is each caller's policy ([`read_in_scan`],
/// `identity::linux::stat_by_pid`, the cgroup leaf's state read).
pub(crate) fn read_stat_file(kernel: &dyn Kernel, dir: &ProcDir, pid: u32) -> io::Result<Vec<u8>> {
    kernel.read(dir, &format!("{pid}/stat"))
}

/// Whether `error` is an `openat2` refusal, the errnos [`FailedCall::requirement`] counts as one.
fn is_refusal(error: &io::Error) -> bool {
    Errno::from_io_error(error).is_some_and(|errno| FailedCall::openat2(errno).requirement().is_some())
}

/// Whether the checked directory still reads (`self/stat`).
fn check_dir_answers(kernel: &dyn Kernel, dir: &ProcDir) -> io::Result<()> {
    kernel.read(dir, "self/stat").map(drop)
}

#[cfg(test)]
#[path = "pid_stat_tests.rs"]
mod pid_stat_tests;
