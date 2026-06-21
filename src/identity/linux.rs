//! Linux process-identity backend: raw field-22 `starttime` (jiffies) from
//! `/proc/<pid>/stat` as the start token; `is_running` via process state;
//! `created_at` via `/proc/stat` `btime` and `_SC_CLK_TCK`.

use std::time::{Duration, SystemTime};

use super::stat_parse::parse_starttime_jiffies;
use super::{RawPid, StartToken};

pub(super) fn start_token(pid: RawPid) -> Option<StartToken> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    // RAW jiffies are the identity token — NOT converted to wall-clock.
    parse_starttime_jiffies(&stat).map(StartToken::from_raw)
}

pub(super) fn is_running(pid: RawPid, start: StartToken) -> bool {
    let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat")) else {
        return false; // gone (reaped) => not running
    };
    super::stat_parse::running_from_stat(&stat, start)
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
