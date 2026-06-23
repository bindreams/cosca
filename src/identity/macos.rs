//! macOS process-identity backend: `proc_pidinfo(PROC_PIDTBSDINFO)` start time
//! (µs since epoch) as the start token; `is_running` via `pbi_status`.

use std::time::{Duration, SystemTime};

use super::{RawPid, StartToken};

/// Read `proc_bsdinfo` for `pid`, or `None` if the process is not resolvable.
fn bsd_info(pid: RawPid) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; the pointer
    // and size match.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    // proc_pidinfo returns the number of bytes written; a full struct == success.
    (n == size).then_some(info)
}

fn token_of(info: &libc::proc_bsdinfo) -> StartToken {
    StartToken::from_raw(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

pub(super) fn start_token(pid: RawPid) -> Option<StartToken> {
    bsd_info(pid).as_ref().map(token_of)
}

pub(super) fn is_running(pid: RawPid, start: StartToken) -> bool {
    let Some(info) = bsd_info(pid) else {
        return false; // gone => not running
    };
    if token_of(&info) != start {
        return false; // reused PID
    }
    // SZOMB == zombie (exited, unreaped). Anything else is a live process.
    info.pbi_status != libc::SZOMB
}

pub(super) fn created_at(start: StartToken) -> Option<SystemTime> {
    Some(SystemTime::UNIX_EPOCH + Duration::from_micros(start.raw()))
}
