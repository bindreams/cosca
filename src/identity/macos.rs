//! macOS process-identity backend: `proc_pidinfo` (Apple's stable public libproc API) is
//! the PRIMARY source; `sysctl(KERN_PROC_PID)` (the `kinfo` module) is the FALLBACK for
//! what libproc cannot see — ZOMBIES and EPERM-hidden cross-user processes — keeping
//! identity resolution zombie-inclusive like Linux procfs while the common live path stays
//! on the stable ABI. Both sources report the process start time in µs (cross-source
//! equality pinned by the kinfo_tests oracle), so a layout drift in the undocumented
//! kinfo_proc ABI degrades only zombie/cross-user resolution (a token mismatch — the
//! pre-fix behavior), never live same-uid identity.
//!
//! [`ppid_of`] exposes the same sysctl source's `e_ppid` field for
//! `containment::enumerate::macos`, which keeps its own separate `proc_pidinfo`-primary ppid
//! resolver and needs only this module's sysctl knowledge for its miss — never a second copy
//! of `kinfo_proc`'s layout.

use std::time::{Duration, SystemTime};

use super::{Liveness, RawPid, Resolved, StartToken};

#[path = "macos/kinfo.rs"]
mod kinfo;

fn bsd_info(pid: RawPid) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; pointer and size match.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n == size {
        return Some(info);
    }
    if n <= 0 {
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            // Expected misses: gone/zombie (ESRCH) or an unprivileged cross-user query
            // (EPERM) — the sysctl fallback covers both.
            Some(libc::ESRCH) | Some(libc::EPERM) => {}
            _ => contract_violation(format_args!("proc_pidinfo({pid}) failed: {e}")),
        }
        return None;
    }
    // 0 < n < size: a partial record — never trust it.
    contract_violation(format_args!("proc_pidinfo({pid}) wrote {n} bytes, expected {size}"));
    None
}

/// The shared contract-violation disposition for BOTH identity sources: trace FIRST (so
/// the warn executes in every build mode), then the debug tripwire.
pub(super) fn contract_violation(what: std::fmt::Arguments<'_>) {
    log::warn!("{what}");
    debug_assert!(false, "{what}");
}

fn token_of_bsd(info: &libc::proc_bsdinfo) -> StartToken {
    StartToken::from_raw(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

fn token_of_kinfo(info: &kinfo::kinfo_proc) -> StartToken {
    // SAFETY: the kernel's KERN_PROC copy always fills `p_starttime` (XNU
    // fill_externproc); the union's other arm is kernel-internal queue pointers never
    // exported here. Both arms are plain old data, so the read is defined.
    let start = unsafe { info.kp_proc.p_un.p_starttime };
    StartToken::from_raw(start.tv_sec as u64 * 1_000_000 + start.tv_usec as u64)
}

pub(super) fn start_token(pid: RawPid) -> Resolved<StartToken> {
    if let Some(info) = bsd_info(pid) {
        return Resolved::Found(token_of_bsd(&info));
    }
    // libproc-invisible: gone, a ZOMBIE, or EPERM-hidden - only sysctl resolves the latter
    // two, and it distinguishes an empty reply (gone) from a failure (unknown).
    kinfo::kinfo(pid).map(|info| token_of_kinfo(&info))
}

/// `eproc.e_ppid` via the sysctl fallback ONLY — no libproc call. `containment::enumerate`
/// already has its own `proc_pidinfo`-primary ppid resolver and only needs this module's
/// sysctl knowledge for ITS miss (EPERM cross-user, or a ZOMBIE), the same fallback shape
/// [`start_token`] uses for its own libproc miss.
///
/// `e_ppid == 0` for any pid but 1 is never trusted as `Found`: pid 1 (launchd) is the only
/// real process whose parent is the kernel, so a `0` elsewhere means XNU served this pid's
/// `kinfo_proc` before `fork()` finished filling in `eproc` (measured live: a busy host
/// occasionally does, `e_ppid` momentarily 0 while `proc_pidinfo` already sees the real
/// value — see `sysctl_e_ppid_matches_libproc_across_the_live_process_table`). The record
/// itself is valid (correctly sized, no sysctl error) - this is not `contract_violation`'s
/// "layout drifted or the kernel misbehaved" case, only a narrow timing window - so it is a
/// DESIGNED `Unknown`, `debug`-logged like every other per-pid probe.
pub(crate) fn ppid_of(pid: RawPid) -> Resolved<RawPid> {
    match kinfo::kinfo(pid) {
        Resolved::Found(info) => {
            let ppid = info.e_ppid();
            if ppid == 0 && pid != 1 {
                log::debug!(
                    "sysctl(KERN_PROC_PID, {pid}) reported e_ppid == 0 for a non-pid-1 process \
                     - a fork()-in-progress record, not a resolvable ppid"
                );
                Resolved::Unknown
            } else {
                Resolved::Found(ppid as RawPid)
            }
        }
        Resolved::Gone => Resolved::Gone,
        Resolved::Unknown => Resolved::Unknown,
    }
}

/// `proc_pidinfo` on self is always permitted, so the by-pid path cannot be denied here.
pub(super) fn current_token() -> Resolved<StartToken> {
    start_token(std::process::id())
}

pub(super) fn is_running(pid: RawPid, start: StartToken) -> Liveness {
    if let Some(info) = bsd_info(pid) {
        if token_of_bsd(&info) != start {
            return Liveness::Dead; // reused PID
        }
        // SZOMB == zombie (exited, unreaped). Anything else is a live process.
        return if info.pbi_status == libc::SZOMB {
            Liveness::Dead
        } else {
            Liveness::Alive
        };
    }
    // libproc-invisible: gone, a ZOMBIE, or an EPERM-hidden LIVE process (an unprivileged
    // cross-user query — pid 1 on darwin CI proved a miss is NOT always gone-or-zombie).
    // The fallback keeps the same shape — token-guarded, zombie-EXCLUSIVE via `p_stat` —
    // and a kinfo layout drift fails safe to the pre-fix answer (token mismatch => false).
    match kinfo::kinfo(pid) {
        Resolved::Found(info) => {
            // A reused PID names a different process; SZOMB is exited-but-unreaped. Both
            // are "not running", and neither is an unassessable read.
            if token_of_kinfo(&info) != start || info.kp_proc.p_stat as u32 == libc::SZOMB {
                Liveness::Dead
            } else {
                Liveness::Alive
            }
        }
        Resolved::Gone => Liveness::Dead,
        Resolved::Unknown => Liveness::Unknown,
    }
}

pub(super) fn created_at(start: StartToken) -> Option<SystemTime> {
    Some(SystemTime::UNIX_EPOCH + Duration::from_micros(start.raw()))
}

/// The `kinfo_proc` / `proc_bsdinfo` start time is absolute µs since the Unix epoch,
/// recorded once at creation, so it survives a reboot unchanged and needs no scope.
pub(super) fn session_scope() -> Result<super::persist::Scope, super::persist::ScopeReadError> {
    Ok(super::persist::Scope::none())
}
