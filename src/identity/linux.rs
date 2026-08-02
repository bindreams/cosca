//! Linux process-identity backend: raw field-22 `starttime` (jiffies) from
//! `/proc/<pid>/stat` as the start token; `is_running` via process state; `created_at` via
//! `/proc/stat` `btime` and `_SC_CLK_TCK`.

use std::time::{Duration, SystemTime};

use super::probe::{classify_unreadable, SignalProbe};
use super::stat_parse::parse_starttime_jiffies;
use super::{Liveness, RawPid, Resolved, StartToken};

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

/// Classify a failed `/proc/<pid>/stat` read. `ErrorKind` alone is not enough: under a
/// `hidepid` mount another user's `/proc/<pid>` is invisible, so a LIVE process yields
/// `ENOENT`; and a task that exits mid-read yields `ESRCH`, which has no `ErrorKind`.
fn read_stat(pid: RawPid) -> Resolved<Vec<u8>> {
    match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(bytes) => Resolved::Found(bytes),
        Err(e) => match classify_unreadable(signal_probe(pid)) {
            Resolved::Gone => Resolved::Gone,
            _ => {
                // `debug`, not `warn`: this is a per-pid probe the tree-walk calls once per
                // process per sweep. The decision made from it warns.
                log::debug!("/proc/{pid}/stat unreadable ({e}) but the pid is not provably gone");
                Resolved::Unknown
            }
        },
    }
}

pub(super) fn start_token(pid: RawPid) -> Resolved<StartToken> {
    match read_stat(pid) {
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

/// Our own start token, read by pid — deliberately NOT via `/proc/self`.
///
/// `ProcessId` is the pair `(std::process::id(), token)`, so the token must come from the
/// same namespace view as that pid. `/proc/self` and `/proc/<getpid()>` diverge exactly when
/// the reading task's pid namespace is not the one `/proc` was mounted from (`unshare --pid
/// --fork` without `--mount-proc`): there `getpid()` is 1 while `/proc` still shows the outer
/// namespace. Reading `/proc/self` there would pair the caller's real token with the inner
/// pid 1, and `exists()`/`is_alive()` — which re-read BY PID — would then report the running
/// caller as `Gone`/`Dead`. Keeping both halves by-pid keeps the pair self-consistent.
///
/// `hidepid` never hides a task from itself, so this read cannot be denied to us.
pub(super) fn current_token() -> Resolved<StartToken> {
    start_token(std::process::id())
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
