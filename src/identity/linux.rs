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
