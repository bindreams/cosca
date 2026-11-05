//! Linux process-identity backend. A process's [`Key`] is the inode of its pidfd on pidfs (6.9+),
//! proved by opening the pid again ([`prove`]), else the raw field-22 `starttime` (jiffies) from
//! `/proc/<pid>/stat`. `is_running` polls the pidfd, or reads the process state before 6.9;
//! `created_at` reads the `starttime` (bracketed for a pidfs id) and uses `/proc/stat` `btime` and
//! `_SC_CLK_TCK`.

#[path = "linux/kernel.rs"]
pub(crate) mod kernel;
#[path = "linux/pid_stat.rs"]
pub(crate) mod pid_stat;
#[path = "linux/proc_view.rs"]
pub(crate) mod proc_view;
#[path = "linux/prove.rs"]
pub(crate) mod prove;

#[cfg(test)]
#[path = "linux/bracket_tests.rs"]
mod bracket_tests;

#[cfg(test)]
#[path = "linux/look_tests.rs"]
mod look_tests;

#[cfg(test)]
#[path = "linux/read_tests.rs"]
mod read_tests;

#[cfg(test)]
#[path = "linux/read_namespace_tests.rs"]
mod read_namespace_tests;

use std::os::fd::AsFd as _;
use std::time::{Duration, SystemTime};

use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags};

use self::kernel::Kernel;
use self::proc_view::ProcDir;
use self::prove::Proof;
use super::probe::{classify_unreadable, SignalProbe};
use super::stat_parse::{parse_ppid, parse_starttime_jiffies};
use super::{Existence, Liveness, OrderKey, OrderedRead, ParentRead, RawPid, Resolved, TokenKind, UnknownCause};
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

    /// A key restored from a record's `token` of the kind the record names. The record was
    /// validated against this host's kind first, so the kind is one of the two.
    pub(super) fn restored(token: u64, kind: Option<&TokenKind>) -> Key {
        debug_assert!(
            matches!(kind, Some(TokenKind::Pidfs | TokenKind::Ticks)),
            "a validated record names a kind of token, not {kind:?}"
        );
        match kind {
            Some(TokenKind::Pidfs) => Key::Pidfs(token),
            _ => Key::Ticks(token),
        }
    }

    /// The kind a record names for this key.
    pub(super) fn wire_kind(self) -> Option<TokenKind> {
        Some(match self {
            Key::Pidfs(_) => TokenKind::Pidfs,
            Key::Ticks(_) => TokenKind::Ticks,
        })
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

/// What a pidfd opened for a pid says about which kind of [`Key`] it has.
enum Look {
    /// The process's pidfd has this inode on pidfs.
    Pidfs(u64),
    /// This host's pidfds have no inode of their own (before Linux 6.9): `/proc` says.
    Ticks,
    /// No process holds the pid.
    Gone,
    /// The open or the inode read failed in a way that says nothing about the pid.
    Unknown(UnknownCause),
}

/// Opens `pid` and asks its pidfd which kind of key the process has.
///
/// A pid that neither open takes with `EINVAL` is a reaped group leader whose number lives on as a
/// process-group id (6.12), or a kernel with no `PIDFD_THREAD` (before 6.9). Which one is a fact
/// about the host, so the host's own pidfd is asked: on pidfs the pid is no task (`Gone`, and
/// `/proc` is not read, so a process that takes the number meanwhile is not misread as ticks), and
/// elsewhere `/proc` says.
fn look(kernel: &dyn Kernel, pid: RawPid) -> Look {
    let Some(target) = prove::target(pid) else {
        return Look::Gone;
    };
    match prove::open(kernel, target) {
        Ok(opened) => match kernel.pidfs_ino(opened.fd.as_fd()) {
            Ok(Some(ino)) => Look::Pidfs(ino),
            Ok(None) => Look::Ticks,
            Err(e) => Look::Unknown(prove::cause(e)),
        },
        // `ENOENT` is the retry's: `open` retries only after `INVAL` or `ENOENT`, and `prove` takes
        // it as `Lost` too.
        Err(Errno::SRCH | Errno::NOENT) => Look::Gone,
        Err(Errno::INVAL) => match own_pidfs_ino(kernel) {
            Ok(Some(_)) => Look::Gone,
            Ok(None) => Look::Ticks,
            Err(e) => Look::Unknown(prove::cause(e)),
        },
        Err(e) => Look::Unknown(prove::cause(e)),
    }
}

/// The identity of `pid`: its pidfd's inode on pidfs, else its `starttime` ticks; and what made it
/// `Unknown`, when the read knows.
pub(super) fn of(kernel: &dyn Kernel, pid: RawPid) -> (Resolved<Key>, UnknownCause) {
    match look(kernel, pid) {
        Look::Pidfs(ino) => (Resolved::Found(Key::Pidfs(ino)), UnknownCause::default()),
        Look::Gone => (Resolved::Gone, UnknownCause::default()),
        Look::Unknown(cause) => (Resolved::Unknown, cause),
        Look::Ticks => {
            let (stat, view) = read_stat_explained(kernel, pid);
            (ticks_from(pid, stat).map(Key::Ticks), UnknownCause::of_view(view))
        }
    }
}

/// [`of`], and a `stat` record that is that process's own: for a `Pidfs` key the bracketed one, and
/// for ticks the very record the ticks were read from.
pub(super) fn of_stat(kernel: &dyn Kernel, pid: RawPid) -> (Resolved<(Key, Vec<u8>)>, UnknownCause) {
    match look(kernel, pid) {
        Look::Pidfs(ino) => {
            let (stat, cause) = bracketed_stat(kernel, pid, ino);
            (stat.map(|stat| (Key::Pidfs(ino), stat)), cause)
        }
        Look::Gone => (Resolved::Gone, UnknownCause::default()),
        Look::Unknown(cause) => (Resolved::Unknown, cause),
        Look::Ticks => {
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
    }
}

/// The key, the order key (the `starttime`) and the parent number of `pid`, all from the `stat` that
/// [`of_stat`] pairs with the key. A `stat` with no readable ppid or no `starttime` is unreadable,
/// not a parent number or a start of zero.
pub(super) fn ordered_read(kernel: &dyn Kernel, pid: RawPid) -> OrderedRead {
    let (read, cause) = of_stat(kernel, pid);
    let (key, stat) = match read {
        Resolved::Found(found) => found,
        // No `stat`, so no parent number.
        Resolved::Gone => {
            return OrderedRead {
                read: Resolved::Gone,
                parent: ParentRead::Unreadable,
                cause,
            }
        }
        Resolved::Unknown => {
            return OrderedRead {
                read: Resolved::Unknown,
                parent: ParentRead::Unreadable,
                cause,
            }
        }
    };
    let parent = match parse_ppid(&stat) {
        Some(ppid) => ParentRead::Is(ppid),
        None => {
            log::debug!("identity: the stat of pid {pid} has no readable ppid");
            ParentRead::Unreadable
        }
    };
    match parse_starttime_jiffies(&stat) {
        Some(ticks) => OrderedRead {
            read: Resolved::Found((key, OrderKey(ticks))),
            parent,
            cause,
        },
        None => OrderedRead {
            read: Resolved::Unknown,
            parent,
            cause: UnknownCause::default(),
        },
    }
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

/// `pid`'s `stat` while the process with `pidfs` inode `ino` holds the pid: read, then proved again.
/// A process that holds the pid when the proof is made held it from when the id was made, so the
/// `stat` read between is its own; the other order would let a reuser's `stat` through. `Gone` when
/// the proof finds another process.
fn bracketed_stat(kernel: &dyn Kernel, pid: RawPid, ino: u64) -> (Resolved<Vec<u8>>, UnknownCause) {
    let (stat, view) = read_stat_explained(kernel, pid);
    let stat = match stat {
        Resolved::Found(stat) => stat,
        Resolved::Gone => return (Resolved::Gone, UnknownCause::of_view(view)),
        Resolved::Unknown => return (Resolved::Unknown, UnknownCause::of_view(view)),
    };
    match prove::prove(kernel, pid, ino) {
        Proof::Holds { .. } => (Resolved::Found(stat), UnknownCause::default()),
        Proof::Lost => (Resolved::Gone, UnknownCause::default()),
        Proof::Unknown(cause) => (Resolved::Unknown, cause),
    }
}

/// When the process `key` names started, in ticks: a `Ticks` key is that, and a `Pidfs` key's
/// process shows it in its bracketed `stat`.
fn start_ticks(kernel: &dyn Kernel, pid: RawPid, key: Key) -> (Resolved<u64>, UnknownCause) {
    match key {
        Key::Ticks(ticks) => (Resolved::Found(ticks), UnknownCause::default()),
        Key::Pidfs(ino) => {
            let (stat, cause) = bracketed_stat(kernel, pid, ino);
            (ticks_from(pid, stat), cause)
        }
    }
}

/// When `pid` started, for ordering.
pub(super) fn order_key(kernel: &dyn Kernel, pid: RawPid, key: Key) -> (Resolved<OrderKey>, UnknownCause) {
    let (ticks, cause) = start_ticks(kernel, pid, key);
    (ticks.map(OrderKey), cause)
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
            Proof::Unknown(cause) => {
                log::debug!(
                    "the pidfd of pid {pid} could not be opened or proved: {:?}",
                    cause.errno()
                );
                Liveness::Unknown
            }
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
/// `ProcessId` is the pair `(std::process::id(), key)`. On pidfs it is the inode of the process's
/// own pidfd, which names the process whatever `/proc` the caller sees. Where pidfds have none, it
/// is read from `/proc/self/stat`: under an outer namespace's `/proc` (`unshare --pid --fork`
/// without `--mount-proc`: `getpid()` is 1, `/proc/1` is another process) `/proc/<getpid()>` names
/// someone else, but the kernel resolves `self` for the reader. A plain read, so it needs neither
/// `openat2` nor a `/proc` view; the by-pid re-reads (`exists()`/`is_alive()`) then answer
/// `Unknown`, never `Gone`/`Dead` for the running caller.
///
/// `hidepid` never hides a task from itself, so a failure here is not a foreign-pid outcome:
/// [`ProcessId::current`](super::ProcessId::current) panics on it. That includes a kernel or filter
/// that refuses `pidfd_open` to the process itself, which is the error [`Process::open`] gives (an
/// `Unsupported` for a refusal).
pub(super) fn current_key(kernel: &dyn Kernel) -> Result<Key, Error> {
    match own_pidfs_ino(kernel) {
        Ok(Some(ino)) => Ok(Key::Pidfs(ino)),
        Ok(None) => {
            let stat = std::fs::read("/proc/self/stat").map_err(Error::Io)?;
            match ticks_from(std::process::id(), Resolved::Found(stat)) {
                Resolved::Found(ticks) => Ok(Key::Ticks(ticks)),
                _ => Err(Error::Io(std::io::Error::other(
                    "/proc/self/stat has no parseable starttime",
                ))),
            }
        }
        Err(e) => Err(crate::os_process::linux::open::open_error(e)),
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
    let jiffies = start_ticks(kernel, pid, key).0.found()?;
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

/// This host's boot session, as the things a saved token is relative to.
///
/// `boot_id` scopes the token, which restarts at every boot (the jiffy counter, the pidfs inode
/// counter); the `/proc/self/ns/pid` inode scopes the PID, because a container shares the host's
/// `boot_id` (it is not namespaced) while numbering its processes independently; and the kind of
/// token says whether the host's tokens are `pidfs` inodes or `starttime` ticks, which are not
/// comparable. Any one alone would let a saved token be compared against an unrelated process.
///
/// The first two reads are of the caller's own `/proc` entries, which no `hidepid` mount hides
/// from the task itself; a failure there means `/proc` is not mounted at all. The kind is read from
/// the caller's own pidfd, so a host that refuses `pidfd_open` to it has no scope either.
pub(super) fn session_scope() -> Result<Scope, ScopeReadError> {
    session_scope_at(
        &kernel::HostKernel,
        std::path::Path::new(BOOT_ID_PATH),
        std::path::Path::new(PID_NS_PATH),
    )
}

/// [`session_scope`] through `kernel`, with the two `/proc` paths as parameters, so a test can
/// point them at paths that really do not exist and exercise the failure without mocking a syscall.
pub(super) fn session_scope_at(
    kernel: &dyn Kernel,
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
    let token_kind = own_token_kind(kernel).map_err(|errno| ScopeReadError {
        path: "pidfd_open of this process".to_owned(),
        source: std::io::Error::from(errno),
    })?;
    Ok(Scope {
        boot_id: Some(boot_id.to_owned()),
        pid_ns: Some(pid_ns),
        token_kind: Some(token_kind),
    })
}

/// The inode of this process's own pidfd: `Some` on pidfs, `None` where pidfds have none.
fn own_pidfs_ino(kernel: &dyn Kernel) -> Result<Option<u64>, Errno> {
    let pidfd = kernel.pidfd_open(rustix::process::getpid(), PidfdFlags::empty())?;
    kernel.pidfs_ino(pidfd.as_fd())
}

/// The kind of [`Key`] this host's processes have, as a record names it.
fn own_token_kind(kernel: &dyn Kernel) -> Result<TokenKind, Errno> {
    Ok(match own_pidfs_ino(kernel)? {
        Some(_) => TokenKind::Pidfs,
        None => TokenKind::Ticks,
    })
}
