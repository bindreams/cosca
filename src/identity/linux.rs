//! Linux process-identity backend: raw field-22 `starttime` (jiffies) from
//! `/proc/<pid>/stat` as the start token; `is_running` via process state; `created_at` via
//! `/proc/stat` `btime` and `_SC_CLK_TCK`.

#[path = "linux/kernel.rs"]
pub(crate) mod kernel;
#[path = "linux/pid_stat.rs"]
pub(crate) mod pid_stat;
#[path = "linux/proc_view.rs"]
pub(crate) mod proc_view;
#[path = "linux/prove.rs"]
pub(crate) mod prove;

#[cfg(test)]
#[path = "linux/fault.rs"]
pub(crate) mod fault;

#[cfg(test)]
#[path = "linux/read_tests.rs"]
mod read_tests;

#[cfg(test)]
#[path = "linux/read_namespace_tests.rs"]
mod read_namespace_tests;

use std::os::fd::AsFd as _;
use std::time::{Duration, SystemTime};

use rustix::io::Errno;
use rustix::process::Pid;

use self::kernel::Kernel;
use self::proc_view::ProcDir;
use self::prove::Proof;
use super::probe::{classify_unreadable, SignalProbe};
use super::stat_parse::parse_starttime_jiffies;
use super::{Existence, Liveness, OrderKey, RawPid, Resolved, UnknownCause};
use crate::error::Error;

/// `kill(pid, 0)` — existence/permission check only, no signal delivered. The target
/// validation lives in the pure `probe` module so it is executed on every host.
fn signal_probe(kernel: &dyn Kernel, pid: RawPid) -> SignalProbe {
    let Some(target) = super::probe::signal_target(pid).and_then(Pid::from_raw) else {
        return SignalProbe::NotAPid;
    };
    match kernel.signal_probe(target) {
        Ok(()) => SignalProbe::Signalable,
        Err(Errno::SRCH) => SignalProbe::NoSuchProcess,
        Err(_) => SignalProbe::Denied,
    }
}

/// `pid`'s `stat` through a `/proc` that is shown to describe this process's own pid namespace,
/// else `Unknown` unless `kill(pid, 0)` says the pid is gone: an outer namespace's `/proc/<pid>`
/// names another process, so what it says is no answer about `pid`.
fn read_stat(kernel: &dyn Kernel, pid: RawPid) -> Resolved<Vec<u8>> {
    read_stat_explained(kernel, pid).0
}

/// [`read_stat`], and the unusable view that made it `Unknown`, when one did.
fn read_stat_explained(kernel: &dyn Kernel, pid: RawPid) -> (Resolved<Vec<u8>>, Option<proc_view::ViewUnreadable>) {
    match proc_view::proc_view_with(kernel).into_dir() {
        Ok(dir) => (stat_by_pid(kernel, &dir, pid), None),
        Err(why) => (
            resolve_unreadable(
                kernel,
                pid,
                format_args!("the /proc view could not be established: {why}"),
            ),
            Some(why),
        ),
    }
}

/// [`read_stat`] via `openat` on `proc_dir`, not a `/proc` path lookup. A failed read is `Gone`
/// only when `kill(pid, 0)` says so ([`resolve_unreadable`]); a whole-table scan has the other
/// policy (`pid_stat::read_in_scan`).
fn stat_by_pid(kernel: &dyn Kernel, proc_dir: &ProcDir, pid: RawPid) -> Resolved<Vec<u8>> {
    match pid_stat::read_stat_file(kernel, proc_dir, pid) {
        Ok(bytes) => Resolved::Found(bytes),
        Err(e) => resolve_unreadable(kernel, pid, e),
    }
}

/// What `pid`'s `stat` being unavailable (`why`) says about it: `Gone` only if `kill(pid, 0)`
/// says `ESRCH`, else `Unknown`. `ErrorKind` alone is not enough: under a `hidepid` mount
/// another user's `/proc/<pid>` is invisible, so a LIVE process yields `ENOENT`; and a task
/// that exits mid-read yields `ESRCH`, which has no `ErrorKind`.
fn resolve_unreadable(kernel: &dyn Kernel, pid: RawPid, why: impl std::fmt::Display) -> Resolved<Vec<u8>> {
    match classify_unreadable(signal_probe(kernel, pid)) {
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
pub(super) fn signal_says_no_such_process(kernel: &dyn Kernel, pid: RawPid) -> bool {
    signal_probe(kernel, pid) == SignalProbe::NoSuchProcess
}

/// What makes a Linux process: `pidfs`, the inode of its pidfd, or, below Linux 6.9 where pidfds
/// have no inode of their own, the `starttime` ticks `/proc` shows. Two ids of different kinds never
/// compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    Pidfs(u64),
    Ticks(u64),
}

impl Key {
    /// The value, whichever the kind.
    pub(super) fn raw(self) -> u64 {
        match self {
            Key::Pidfs(v) | Key::Ticks(v) => v,
        }
    }

    /// A key restored from a record's `token`.
    pub(super) fn restored(token: u64, _kind: Option<&str>) -> Key {
        Key::Ticks(token)
    }

    /// The `Ticks` key of `v`: this backend's default kind, for tests that run on every platform.
    #[cfg(test)]
    pub(crate) fn for_test(v: u64) -> Key {
        Key::Ticks(v)
    }

    /// The ticks of a `Ticks` key, for a test that states them in a `stat` it fakes.
    #[cfg(test)]
    pub(crate) fn ticks(self) -> u64 {
        match self {
            Key::Ticks(v) => v,
            Key::Pidfs(_) => panic!("{self:?} has no ticks"),
        }
    }

    /// The same kind with another value.
    #[cfg(test)]
    pub(super) fn other_value(self) -> Key {
        match self {
            Key::Pidfs(v) => Key::Pidfs(v.wrapping_add(1)),
            Key::Ticks(v) => Key::Ticks(v.wrapping_add(1)),
        }
    }
}

/// The identity of `pid`, and the unusable `/proc` view behind an `Unknown`, when that is why.
pub(super) fn of(kernel: &dyn Kernel, pid: RawPid) -> (Resolved<Key>, UnknownCause) {
    let (stat, view) = read_stat_explained(kernel, pid);
    (ticks_from(pid, stat).map(Key::Ticks), UnknownCause::of_view(view))
}

/// [`of`], and a `stat` record that is that process's own.
pub(super) fn of_stat(kernel: &dyn Kernel, pid: RawPid) -> (Resolved<(Key, Vec<u8>)>, UnknownCause) {
    let (stat, view) = read_stat_explained(kernel, pid);
    let bytes = match &stat {
        Resolved::Found(bytes) => bytes.clone(),
        _ => Vec::new(),
    };
    (
        ticks_from(pid, stat).map(|ticks| (Key::Ticks(ticks), bytes)),
        UnknownCause::of_view(view),
    )
}

/// Whether the process `key` names still holds `pid`.
pub(super) fn exists(kernel: &dyn Kernel, pid: RawPid, key: Key) -> (Existence, UnknownCause) {
    match key {
        Key::Ticks(ticks) => {
            let (stat, view) = read_stat_explained(kernel, pid);
            (
                existence_of_ticks(ticks_from(pid, stat), ticks),
                UnknownCause::of_view(view),
            )
        }
        Key::Pidfs(ino) => match prove::prove(kernel, pid, ino) {
            Proof::Holds { .. } => (Existence::Present, UnknownCause::default()),
            Proof::Lost => (Existence::Gone, UnknownCause::default()),
            Proof::Unknown(cause) => (Existence::Unknown, cause),
        },
    }
}

/// [`exists`], reading through the `/proc` at `proc_dir`: a `Pidfs` id needs no `/proc`.
pub(super) fn exists_in(kernel: &dyn Kernel, proc_dir: &ProcDir, pid: RawPid, key: Key) -> Existence {
    match key {
        Key::Ticks(ticks) => existence_of_ticks(ticks_from(pid, stat_by_pid(kernel, proc_dir, pid)), ticks),
        Key::Pidfs(_) => exists(kernel, pid, key).0,
    }
}

/// What `read`, the ticks now at the pid, says about the process that had `ticks`.
fn existence_of_ticks(read: Resolved<u64>, ticks: u64) -> Existence {
    match read {
        Resolved::Found(now) if now == ticks => Existence::Present,
        Resolved::Found(_) | Resolved::Gone => Existence::Gone,
        Resolved::Unknown => Existence::Unknown,
    }
}

/// `pid`'s `starttime` ticks from `stat`: RAW jiffies, NOT converted to wall-clock.
fn ticks_from(pid: RawPid, stat: Resolved<Vec<u8>>) -> Resolved<u64> {
    #[cfg(test)]
    if let Some(aliased) = fault::on_read(pid, matches!(stat, Resolved::Found(_))) {
        return Resolved::Found(aliased.raw());
    }
    match stat {
        Resolved::Found(stat) => match parse_starttime_jiffies(&stat) {
            Some(j) => Resolved::Found(j),
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

/// When `pid` started, for ordering: the ticks.
pub(super) fn order_key(kernel: &dyn Kernel, pid: RawPid, key: Key) -> (Resolved<OrderKey>, UnknownCause) {
    let _ = (kernel, pid);
    (Resolved::Found(OrderKey(key.raw())), UnknownCause::default())
}

pub(super) fn is_running(kernel: &dyn Kernel, pid: RawPid, key: Key) -> Liveness {
    match key {
        Key::Ticks(ticks) => liveness_of(read_stat(kernel, pid), ticks),
        // The pidfd polls readable once the process has exited, a zombie included, and not before:
        // `/proc` shows `Z` for a live process whose leader thread exited, its pidfd does not.
        Key::Pidfs(ino) => match prove::prove(kernel, pid, ino) {
            Proof::Holds { fd, .. } => match crate::os_process::poll::is_readable(fd.as_fd()) {
                Ok(true) => Liveness::Dead,
                Ok(false) => Liveness::Alive,
                Err(e) => {
                    log::debug!("the pidfd of pid {pid} could not be polled: {e}");
                    Liveness::Unknown
                }
            },
            Proof::Lost => Liveness::Dead,
            Proof::Unknown(_) => Liveness::Unknown,
        },
    }
}

/// [`is_running`], read through the `/proc` at `proc_dir`: a `Pidfs` id needs no `/proc`.
pub(super) fn is_running_in(kernel: &dyn Kernel, proc_dir: &ProcDir, pid: RawPid, key: Key) -> Liveness {
    match key {
        Key::Ticks(ticks) => liveness_of(stat_by_pid(kernel, proc_dir, pid), ticks),
        Key::Pidfs(_) => is_running(kernel, pid, key),
    }
}

fn liveness_of(stat: Resolved<Vec<u8>>, ticks: u64) -> Liveness {
    match stat {
        Resolved::Found(stat) => super::stat_parse::running_from_stat(&stat, ticks),
        Resolved::Gone => Liveness::Dead,
        Resolved::Unknown => Liveness::Unknown,
    }
}

/// Our own key.
///
/// `ProcessId` is the pair `(std::process::id(), key)`. Under an outer namespace's `/proc`
/// (`unshare --pid --fork` without `--mount-proc`: `getpid()` is 1, `/proc/1` is another
/// process) `/proc/<getpid()>` names someone else, but the kernel resolves `self` for the reader.
/// A plain read, so it needs neither `openat2` nor a `/proc` view; the by-pid re-reads
/// (`exists()`/`is_alive()`) then answer `Unknown`, never `Gone`/`Dead` for the running caller.
///
/// `hidepid` never hides a task from itself, so a failure here is not a foreign-pid outcome: it
/// is logged at `error`, and [`ProcessId::current`](super::ProcessId::current) panics on it.
pub(super) fn current_key(_kernel: &dyn Kernel) -> Resolved<Key> {
    match std::fs::read("/proc/self/stat") {
        Ok(stat) => ticks_from(std::process::id(), Resolved::Found(stat)).map(Key::Ticks),
        Err(e) => {
            log::error!("own start token unreadable: /proc/self/stat: {e}");
            Resolved::Unknown
        }
    }
}

/// The error for a by-pid identity read of `subject` that `why` (an unusable view) made `Unknown`:
/// [`Error::Unsupported`] naming `openat2` when that is missing, else [`Error::Unassessable`]
/// carrying the view's reason.
pub(crate) fn view_error(subject: &str, why: proc_view::ViewUnreadable) -> Error {
    why.unsupported(format!("identifying {subject}"))
        .unwrap_or_else(|| unassessable_view(subject, &why.reason, why.source))
}

/// The error for a by-pid identity read of `subject` that a failed pidfd call (`errno`) made
/// `Unknown`: [`Error::Unsupported`] when the call was refused, else [`Error::Unassessable`]
/// carrying the errno.
pub(crate) fn errno_error(subject: &str, errno: Errno) -> Error {
    match crate::os_process::linux::open::refusal_name(errno) {
        Some(name) => crate::os_process::linux::open::pidfd_open_unsupported(&format!("identifying {subject}"), name),
        None => Error::Unassessable {
            detail: format!("{subject} identity could not be read: {errno}"),
            source: Some(std::io::Error::from(errno)),
        },
    }
}

fn unassessable_view(subject: &str, reason: &str, source: Option<std::io::Error>) -> Error {
    let mut detail = format!("{subject} identity could not be read: {reason}");
    if let Some(source) = &source {
        detail.push_str(&format!(": {source}"));
    }
    Error::Unassessable { detail, source }
}

pub(super) fn created_at(kernel: &dyn Kernel, pid: RawPid, key: Key) -> Option<SystemTime> {
    let _ = (kernel, pid);
    let jiffies = key.raw();
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
