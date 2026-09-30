//! One pid's `stat` through the checked `/proc`, with the errno policy every whole-table scan
//! shares (`containment::unix::group::members`, `containment::enumerate`).
//!
//! A scan that skips a pid it could not read reports a table with a live process missing, and a
//! tree walk over it misses that process and its subtree. So only the errnos that mean "this pid is
//! not there for us" skip; every other one fails the scan.

use std::io;

use super::proc_view::ProcDir;

/// What reading one pid's `stat` yielded.
#[derive(Debug)]
pub(crate) enum PidStat {
    Read(Vec<u8>),
    /// The pid exited mid-scan (`ENOENT`/`ESRCH`), or `hidepid` hides it (`EACCES`, or `EPERM`
    /// while the checked directory still answers). The error is why.
    Skipped(io::Error),
}

/// Why one pid's `stat` could not be read and is not simply absent.
#[derive(Debug)]
pub(crate) struct Unreadable {
    pid: u32,
    kind: Kind,
    source: io::Error,
}

#[derive(Debug)]
enum Kind {
    /// `EXDEV`/`ELOOP`: the checked directory refused to cross a mount, so the record is not the
    /// kernel's.
    BeyondMount,
    /// `EPERM`, and the checked directory refused `self/stat` too (a seccomp filter installed
    /// mid-scan answers every `openat2` so).
    DirectoryRefuses(io::Error),
    /// `EMFILE`, `ENOMEM`, `EIO`, ...: nothing is known about the pid.
    Other,
}

impl Unreadable {
    /// The `stat` read's own error.
    pub(crate) fn into_source(self) -> io::Error {
        self.source
    }
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Unreadable { pid, kind, source } = self;
        match kind {
            Kind::BeyondMount => write!(
                f,
                "{pid}/stat lies beyond a mount in /proc and was not read: {source}"
            ),
            Kind::DirectoryRefuses(refusal) => write!(
                f,
                "{pid}/stat answered {source} and the checked /proc then refused self/stat: {refusal}"
            ),
            Kind::Other => write!(f, "{pid}/stat could not be read: {source}"),
        }
    }
}

/// `pid`'s `stat` through `dir`: [`PidStat::Skipped`] for the errnos that mean the pid is not
/// there for us, [`Unreadable`] for every other.
pub(crate) fn read(dir: &ProcDir, pid: u32) -> Result<PidStat, Unreadable> {
    let source = match read_raw(dir, pid) {
        Ok(stat) => return Ok(PidStat::Read(stat)),
        Err(e) => e,
    };
    let kind = match source.raw_os_error() {
        // Deliberately NOT disambiguated with `kill(pid, 0)`: a scan covers all of `/proc`, and a
        // `hidepid` `/proc` answers a foreign-uid probe `EPERM` too, so the first foreign-uid
        // process would abort every scan.
        Some(libc::ENOENT | libc::ESRCH | libc::EACCES) => return Ok(PidStat::Skipped(source)),
        // `hidepid`'s answer only if the checked directory still reads.
        Some(libc::EPERM) => match check_dir_answers(dir) {
            Ok(()) => return Ok(PidStat::Skipped(source)),
            Err(refusal) => Kind::DirectoryRefuses(refusal),
        },
        Some(libc::EXDEV | libc::ELOOP) => Kind::BeyondMount,
        _ => Kind::Other,
    };
    Err(Unreadable { pid, kind, source })
}

fn read_raw(dir: &ProcDir, pid: u32) -> io::Result<Vec<u8>> {
    #[cfg(test)]
    if let Some(errno) = fault::forced_stat_read_errno() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    dir.read(&format!("{pid}/stat"))
}

/// Whether the checked directory still reads (`self/stat`).
fn check_dir_answers(dir: &ProcDir) -> io::Result<()> {
    #[cfg(test)]
    if let Some(errno) = fault::forced_recheck_errno() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    dir.read("self/stat").map(drop)
}

/// Test-only seam: force the per-pid `stat` read.
#[cfg(test)]
pub(crate) mod fault {
    thread_local! {
        static STAT_READ: std::cell::Cell<Option<(i32, Option<i32>)>> = const { std::cell::Cell::new(None) };
    }

    /// Disarms [`force_stat_read`] on drop.
    #[must_use = "dropping this immediately disarms the forced read"]
    pub(crate) struct ForcedStatRead(());

    impl Drop for ForcedStatRead {
        fn drop(&mut self) {
            STAT_READ.with(|f| f.set(None));
        }
    }

    /// Make EVERY per-pid `stat` read on THIS thread fail with `errno` until the guard drops.
    /// `recheck` is what the "does the checked directory still answer" re-read answers: `None` for
    /// success, `Some(errno)` for that failure.
    pub(crate) fn force_stat_read(errno: i32, recheck: Option<i32>) -> ForcedStatRead {
        STAT_READ.with(|f| f.set(Some((errno, recheck))));
        ForcedStatRead(())
    }

    pub(super) fn forced_recheck_errno() -> Option<i32> {
        STAT_READ.with(|f| f.get()).and_then(|(_, recheck)| recheck)
    }

    pub(super) fn forced_stat_read_errno() -> Option<i32> {
        STAT_READ.with(|f| f.get()).map(|(errno, _)| errno)
    }
}
