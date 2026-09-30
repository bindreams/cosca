//! Linux process-identity backend: raw field-22 `starttime` (jiffies) from
//! `/proc/<pid>/stat` as the start token; `is_running` via process state; `created_at` via
//! `/proc/stat` `btime` and `_SC_CLK_TCK`.

#[path = "linux/pid_stat.rs"]
pub(crate) mod pid_stat;
#[path = "linux/proc_view.rs"]
pub(crate) mod proc_view;

#[cfg(test)]
#[path = "linux/read_tests.rs"]
mod read_tests;

#[cfg(test)]
#[path = "linux/read_namespace_tests.rs"]
mod read_namespace_tests;

use std::time::{Duration, SystemTime};

use self::proc_view::ProcDir;
use super::probe::{classify_unreadable, SignalProbe};
use super::stat_parse::parse_starttime_jiffies;
use super::{Liveness, RawPid, Resolved, StartToken};
use crate::error::Error;

/// `kill(pid, 0)` — existence/permission check only, no signal delivered. The target
/// validation lives in the pure `probe` module so it is executed on every host.
fn signal_probe(pid: RawPid) -> SignalProbe {
    let Some(p) = super::probe::signal_target(pid) else {
        return SignalProbe::NotAPid;
    };
    // SAFETY: kill with signal 0 performs the permission/existence check only.
    if unsafe { libc::kill(p, 0) } == 0 {
        return SignalProbe::Signalable;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => SignalProbe::NoSuchProcess,
        _ => SignalProbe::Denied,
    }
}

/// `pid`'s `stat` through a `/proc` that is shown to describe this process's own pid namespace,
/// else `Unknown` unless `kill(pid, 0)` says the pid is gone: an outer namespace's `/proc/<pid>`
/// names another process, so what it says is no answer about `pid`.
fn read_stat(pid: RawPid) -> Resolved<Vec<u8>> {
    read_stat_explained(pid).0
}

/// [`read_stat`], and the unusable view that made it `Unknown`, when one did.
fn read_stat_explained(pid: RawPid) -> (Resolved<Vec<u8>>, Option<proc_view::ViewUnreadable>) {
    match proc_view::proc_view().into_dir() {
        Ok(dir) => (read_stat_in(&dir, pid), None),
        Err(why) => (
            resolve_unreadable(pid, format_args!("the /proc view could not be established: {why}")),
            Some(why),
        ),
    }
}

/// [`read_stat`] via `openat` on `proc_dir`, not a `/proc` path lookup.
fn read_stat_in(proc_dir: &ProcDir, pid: RawPid) -> Resolved<Vec<u8>> {
    #[cfg(test)]
    if let Some(errno) = proc_view::fault::forced_identity_stat_errno(pid) {
        return resolve_unreadable(pid, std::io::Error::from_raw_os_error(errno));
    }
    read_stat_with(pid, || proc_dir.read(&format!("{pid}/stat")))
}

/// `stat` through `read`, else [`resolve_unreadable`].
fn read_stat_with(pid: RawPid, read: impl FnOnce() -> std::io::Result<Vec<u8>>) -> Resolved<Vec<u8>> {
    match read() {
        Ok(bytes) => Resolved::Found(bytes),
        Err(e) => resolve_unreadable(pid, e),
    }
}

/// What `pid`'s `stat` being unavailable (`why`) says about it: `Gone` only if `kill(pid, 0)`
/// says `ESRCH`, else `Unknown`. `ErrorKind` alone is not enough: under a `hidepid` mount
/// another user's `/proc/<pid>` is invisible, so a LIVE process yields `ENOENT`; and a task
/// that exits mid-read yields `ESRCH`, which has no `ErrorKind`.
fn resolve_unreadable(pid: RawPid, why: impl std::fmt::Display) -> Resolved<Vec<u8>> {
    match classify_unreadable(signal_probe(pid)) {
        Resolved::Gone => Resolved::Gone,
        _ => {
            // `debug`, not `warn`: this is a per-pid probe the tree-walk calls once per
            // process per sweep. The decision made from it warns.
            log::debug!("/proc/{pid}/stat not read ({why}) but the pid is not provably gone");
            Resolved::Unknown
        }
    }
}

/// Whether `kill(pid, 0)` answers `ESRCH`. It resolves `pid` in THIS process's pid namespace,
/// which is the one a caller's pid lives in, so unlike a `/proc` read this answer does not
/// depend on which namespace `/proc` describes.
pub(super) fn signal_says_no_such_process(pid: RawPid) -> bool {
    signal_probe(pid) == SignalProbe::NoSuchProcess
}

/// The start token of `pid`, and the unusable `/proc` view behind an `Unknown`, when that is why.
pub(super) fn start_token_explained(pid: RawPid) -> (Resolved<StartToken>, Option<proc_view::ViewUnreadable>) {
    let (stat, cause) = read_stat_explained(pid);
    (start_token_from(pid, stat), cause)
}

/// [`start_token`], read through the `/proc` at `proc_dir`.
pub(super) fn start_token_in(proc_dir: &ProcDir, pid: RawPid) -> Resolved<StartToken> {
    start_token_from(pid, read_stat_in(proc_dir, pid))
}

fn start_token_from(pid: RawPid, stat: Resolved<Vec<u8>>) -> Resolved<StartToken> {
    match stat {
        // RAW jiffies are the identity token — NOT converted to wall-clock.
        Resolved::Found(stat) => match parse_starttime_jiffies(&stat) {
            Some(j) => Resolved::Found(StartToken::from_raw(j)),
            // Reachable when a task exits mid-read and the kernel hands back a truncated
            // buffer, so this must not be an assertion.
            None => {
                log::debug!("/proc/{pid}/stat has no parseable starttime");
                Resolved::Unknown
            }
        },
        Resolved::Gone => Resolved::Gone,
        Resolved::Unknown => Resolved::Unknown,
    }
}

pub(super) fn is_running(pid: RawPid, start: StartToken) -> Liveness {
    match read_stat(pid) {
        Resolved::Found(stat) => super::stat_parse::running_from_stat(&stat, start),
        Resolved::Gone => Liveness::Dead, // gone (reaped) => not running
        Resolved::Unknown => Liveness::Unknown,
    }
}

/// [`is_running`], read through the `/proc` at `proc_dir`.
pub(super) fn is_running_in(proc_dir: &ProcDir, pid: RawPid, start: StartToken) -> Liveness {
    match read_stat_in(proc_dir, pid) {
        Resolved::Found(stat) => super::stat_parse::running_from_stat(&stat, start),
        Resolved::Gone => Liveness::Dead,
        Resolved::Unknown => Liveness::Unknown,
    }
}

/// Our own start token, read from `self`.
///
/// `ProcessId` is the pair `(std::process::id(), token)`. Under an outer namespace's `/proc`
/// (`unshare --pid --fork` without `--mount-proc`: `getpid()` is 1, `/proc/1` is another
/// process) `/proc/<getpid()>` names someone else, but the kernel resolves `self` for the reader.
/// A plain read, so it needs neither `openat2` nor a `/proc` view; the by-pid re-reads
/// (`exists()`/`is_alive()`) then answer `Unknown`, never `Gone`/`Dead` for the running caller.
///
/// `hidepid` never hides a task from itself, so a failure here is not a foreign-pid outcome: it
/// is logged at `error`, and [`ProcessId::current`](super::ProcessId::current) panics on it.
pub(super) fn current_token() -> Resolved<StartToken> {
    match read_self_stat() {
        Ok(stat) => start_token_from(std::process::id(), Resolved::Found(stat)),
        Err(e) => {
            log::error!("own start token unreadable: /proc/self/stat: {e}");
            Resolved::Unknown
        }
    }
}

fn read_self_stat() -> std::io::Result<Vec<u8>> {
    #[cfg(test)]
    if let Some(bytes) = proc_view::fault::take_forced_self_stat() {
        return Ok(bytes);
    }
    std::fs::read("/proc/self/stat")
}

/// The error for a by-pid identity read of `subject` that answered `Unknown` because the
/// `/proc` view is unavailable, or `None` when it is not (`hidepid`, a racing exit).
///
/// Without `openat2` it is [`Error::Unsupported`] naming that; otherwise
/// [`Error::Unassessable`] carrying the view's reason.
pub(crate) fn unknown_identity_error(subject: &str) -> Option<Error> {
    proc_view::proc_view()
        .into_dir()
        .err()
        .map(|why| view_error(subject, why))
}

/// The error for a by-pid identity read of `subject` that `why` (an unusable view) made `Unknown`.
pub(crate) fn view_error(subject: &str, why: proc_view::ViewUnreadable) -> Error {
    why.unsupported(format!("identifying {subject}"))
        .unwrap_or_else(|| unassessable_view(subject, &why.reason, why.source))
}

fn unassessable_view(subject: &str, reason: &str, source: Option<std::io::Error>) -> Error {
    let mut detail = format!("{subject} identity could not be read: {reason}");
    if let Some(source) = &source {
        detail.push_str(&format!(": {source}"));
    }
    Error::Unassessable { detail, source }
}

pub(super) fn created_at(start: StartToken) -> Option<SystemTime> {
    let jiffies = start.raw();
    let hz = clock_ticks_per_sec()?;
    let btime = boot_time_secs()?;
    let secs = btime + jiffies / hz;
    let nanos = ((jiffies % hz) * 1_000_000_000 / hz) as u32;
    Some(SystemTime::UNIX_EPOCH + Duration::new(secs, nanos))
}

fn clock_ticks_per_sec() -> Option<u64> {
    // SAFETY: sysconf with a constant name is always safe.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (hz > 0).then_some(hz as u64)
}

fn boot_time_secs() -> Option<u64> {
    std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<u64>().ok())
}

// Persisted-identity session scope ====================================================

use super::persist::{Scope, ScopeReadError};

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const PID_NS_PATH: &str = "/proc/self/ns/pid";

/// This host's boot session, as the two things a `/proc` jiffy token is relative to.
///
/// `boot_id` scopes the jiffy counter, which restarts at every boot; the `/proc/self/ns/pid`
/// inode scopes the PID, because a container shares the host's `boot_id` (it is not
/// namespaced) while numbering its processes independently. Either one alone would let a
/// saved token be compared against an unrelated process.
///
/// Both reads are of the caller's own `/proc` entries, which no `hidepid` mount hides from
/// the task itself; a failure here means `/proc` is not mounted at all.
pub(super) fn session_scope() -> Result<Scope, ScopeReadError> {
    session_scope_at(std::path::Path::new(BOOT_ID_PATH), std::path::Path::new(PID_NS_PATH))
}

/// [`session_scope`] with the two `/proc` paths as parameters, so a test can point them at
/// paths that really do not exist and exercise the failure without mocking a syscall.
pub(super) fn session_scope_at(
    boot_id_path: &std::path::Path,
    pid_ns_path: &std::path::Path,
) -> Result<Scope, ScopeReadError> {
    use std::os::unix::fs::MetadataExt;

    let boot_id = std::fs::read_to_string(boot_id_path).map_err(|source| ScopeReadError {
        path: boot_id_path.display().to_string(),
        source,
    })?;
    // Trimmed: the kernel appends a newline, and an untrimmed value would never match a
    // record written by anything else that reads this file.
    let boot_id = boot_id.trim();
    // A BLANK value is refused, not stored. A container runtime that masks this file by
    // bind-mounting /dev/null over it makes the read SUCCEED and return "", which would be
    // stored as `Some("")` and then compare equal to the next boot's `Some("")` — silently
    // turning the boot-session check into a no-op, which is the exact aliasing this record
    // exists to prevent. Failing here surfaces it as `ScopeUnreadable` instead.
    if boot_id.is_empty() {
        return Err(ScopeReadError {
            path: boot_id_path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "boot_id is empty"),
        });
    }
    let pid_ns = std::fs::metadata(pid_ns_path)
        .map_err(|source| ScopeReadError {
            path: pid_ns_path.display().to_string(),
            source,
        })?
        .ino();
    Ok(Scope {
        boot_id: Some(boot_id.to_owned()),
        pid_ns: Some(pid_ns),
    })
}
