//! Process-group membership, and turning a signal-and-verify pass into a checkable list.
//!
//! `killpg` cannot answer "is the group down?" On both Unix platforms its return value
//! reports only whether *at least one* member took the signal, never who it skipped: Linux
//! returns 0 as soon as one `group_send_sig_info` succeeds (`kernel/signal.c`,
//! `__kill_pgrp_info`), and xnu returns `nfound > 0 ? 0 : (posix ? EPERM : ESRCH)`
//! (`bsd/kern/kern_sig.c`, `killpg1`). So a group holding one member we may signal and one we
//! may not reports plain success while the second keeps running — measured on both
//! (this file's Background in the plan). Darwin's undocumented third `kill` argument does not
//! help: it only chooses which errno labels `nfound == 0`, returning `ESRCH` for a live
//! unsignalable group exactly as it does for an all-zombie one (measured, macOS 26.5.2).
//!
//! So the group's actual membership decides (see `converge` below), and this module owns the
//! listing: sysctl `KERN_PROC_PGRP` on macOS, `/proc` on Linux.

use crate::identity::RawPid;

/// One process-group member as the listing found it, carrying the start token needed to
/// re-verify later that a check still lands on the SAME process (`converge`, below) rather
/// than a zombie or a pid recycled onto someone else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) pid: RawPid,
    pub(crate) token: u64,
}

/// Every process the kernel currently lists in process group `pgid`. An empty result means
/// the group holds nothing — not an error.
///
/// macOS: `sysctl(KERN_PROC_PGRP)`, which lists a group belonging to another user
/// unprivileged (verified, this file's Background) and reports each member's start time in
/// the same record as its pid. libproc's `proc_listpgrppids` is deliberately NOT used: it
/// returns a COUNT where its siblings return bytes, and it carries no start time.
#[cfg(target_os = "macos")]
pub(crate) fn members(pgid: i32) -> std::io::Result<Vec<Member>> {
    use crate::identity::kinfo::kinfo_proc;

    const RECORD: usize = std::mem::size_of::<kinfo_proc>();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PGRP, pgid];
    // Extra headroom beyond the (padded) sizing query's own answer, doubled on every genuine
    // ENOMEM retry below — NOT a retry cap (the loop itself stays uncapped; only the buffer
    // grows). Flagged by review: a single fixed record of slack, re-derived fresh from a new
    // sizing query on every retry, has no independent termination argument against a group
    // that keeps growing faster than that one-record margin between the sizing and fetch
    // calls — the same shape `converge`'s rejected repeat-until-stable loop was cut for. This
    // is a real but much narrower version of that risk (the sizing-to-fetch gap here is two
    // syscalls back to back, not a full signal-and-relist pass), so it was not promoted to a
    // must-fix by review, but the fix is free and removes the gap rather than merely narrowing
    // it: doubling `slack` on each ENOMEM guarantees it eventually exceeds any BOUNDED
    // per-iteration growth rate (forking still takes non-zero wall-clock time even in a tight
    // loop), giving a genuine, finite termination argument — not a probability one — matching
    // what this plan's own Self-review section already claims for this loop.
    let mut slack: usize = 1;
    loop {
        let mut len: libc::size_t = 0;
        // SAFETY: a size query — null buffer, `len` receives the byte count.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        // No `len == 0` early return here: measured directly (Background), the sizing query
        // is always padded by xnu's `KERN_PROCSLOP` and so is never literally 0, even for a
        // genuinely empty group — the real "empty" signal is `got == 0` from the FETCH call
        // below, already handled correctly (an empty `buf` after `set_len(0)`, `Ok(vec![])`).
        // A `len == 0` branch here would be dead code, not a safety net.
        let mut buf: Vec<kinfo_proc> = Vec::with_capacity(len / RECORD + slack);
        let mut got = buf.capacity() * RECORD;
        // SAFETY: `buf` has room for `got` bytes of records; sysctl writes at
        // most `got` and updates it to what it actually wrote.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast(),
                &mut got,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            // ENOMEM: the group grew between sizing and fetching. Size it again, with the
            // slack doubled (see this function's opening comment) so the margin outruns any
            // bounded growth rate rather than staying fixed. EINTR: no growth implied, retry
            // with the same slack. There is no retry CAP either way: the loop ends when
            // sysctl succeeds, which the growing margin guarantees in finite iterations.
            if e.raw_os_error() == Some(libc::ENOMEM) {
                slack = slack.saturating_mul(2);
                continue;
            }
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        // A partial trailing record means the kernel's `kinfo_proc` no longer matches this
        // crate's 648-byte definition — the same ENOMEM-is-the-only-runtime-detector situation
        // `identity/macos/kinfo.rs`'s single-pid reader already guards (`kinfo.rs:126-137`,
        // its own size-mismatch `contract_violation`). Reject rather than reinterpret at the
        // wrong stride, which would silently produce garbage `p_pid` values that `converge`
        // would then send a real signal to.
        if !got.is_multiple_of(RECORD) {
            return Err(std::io::Error::other(format!(
                "sysctl(KERN_PROC_PGRP, {pgid}) returned {got} bytes, not a whole multiple of \
                 the {RECORD}-byte kinfo_proc record — kernel ABI drift, refusing to reinterpret"
            )));
        }
        // SAFETY: sysctl initialised exactly `got / RECORD` whole records (checked above).
        unsafe { buf.set_len(got / RECORD) };
        return Ok(buf
            .iter()
            .map(|k| Member {
                pid: k.kp_proc.p_pid as RawPid,
                // SAFETY: the kernel's KERN_PROC copy always fills `p_starttime`
                // (see `identity::macos::token_of_kinfo`, the same formula).
                token: unsafe {
                    k.kp_proc.p_un.p_starttime.tv_sec as u64 * 1_000_000 + k.kp_proc.p_un.p_starttime.tv_usec as u64
                },
            })
            .collect());
    }
}

/// Linux: scan `/proc` and keep the entries whose `stat` field 5 is `pgid`, carrying field 22
/// (`starttime`) as the token. There is no narrower kernel interface for process-group
/// membership.
#[cfg(target_os = "linux")]
pub(crate) fn members(pgid: i32) -> std::io::Result<Vec<Member>> {
    use crate::identity::stat_parse::{parse_pgrp, parse_starttime_jiffies};

    let mut out = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        // A genuine read_dir iteration error means the listing itself is unreliable —
        // propagate it rather than silently treating it as one absent entry among many.
        let entry = entry?;
        // /proc/<pid> directories are named by their decimal pid; skip the rest (self, net, ...).
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<RawPid>().ok()) else {
            continue;
        };
        let stat = match std::fs::read(format!("/proc/{pid}/stat")) {
            Ok(bytes) => bytes,
            // Deliberately NOT propagated as a listing failure, and deliberately NOT trying to
            // disambiguate the cause (an earlier version of this plan tried: probe with
            // `kill(pid, 0)` and propagate unless it confirms ESRCH). That attempt made things
            // WORSE, not better: this loop scans ALL of `/proc`, not just `pgid`'s members, and
            // a `hidepid`-restricted `/proc` answers a foreign-uid signal probe with `EPERM`
            // (permission and /proc-visibility are separate kernel subsystems; hidepid governs
            // only the latter) — so on a `hidepid` host, the very FIRST foreign-uid process
            // encountered anywhere on the host, however unrelated to `pgid`, would abort the
            // entire listing and turn every `kill_group`/`term_group` call into `Unassessable`,
            // including a fully-torn-down group of the caller's own same-uid children. A read
            // failure on a pid we have not yet even determined belongs to `pgid` at all carries
            // no information about `pgid` specifically — it is simply excluded, the same as any
            // other non-matching entry. What THIS does leave open, honestly: on a `hidepid`
            // host, a genuine FOREIGN-uid member of `pgid` itself is invisible to this scan and
            // silently excluded, undercounting the group — see the report's open question.
            Err(e) => {
                log::debug!(
                    "containment::unix::group::members: /proc/{pid}/stat unreadable ({e}); \
                     excluding it (not evidence it belongs to pgid {pgid} either way)"
                );
                continue;
            }
        };
        let Some(g) = parse_pgrp(&stat) else {
            // The stat line read but its pgrp field did not parse — a malformed/unexpected
            // record, not evidence this pid belongs to a different group. Visible, not
            // silently folded into "not a member", mirroring the starttime-parse-failure
            // handling three lines below.
            log::debug!(
                "containment::unix::group::members: /proc/{pid}/stat had no parseable pgrp \
                 field; excluding it"
            );
            continue;
        };
        if g != pgid as u32 {
            continue;
        }
        let Some(token) = parse_starttime_jiffies(&stat) else {
            // No usable identity token — a later re-check could never confirm this pid is
            // still the SAME process, so it cannot be counted as a member either; visible,
            // not silent.
            log::debug!(
                "containment::unix::group::members: /proc/{pid}/stat matched pgid {pgid} but \
                 had no parseable starttime; excluding it"
            );
            continue;
        };
        out.push(Member { pid, token });
    }
    Ok(out)
}

/// Other Unix: the crate supports Linux, macOS and Windows (see
/// `containment::enumerate`), so there is no listing here. Reported as
/// unlistable rather than silently empty — an empty group would read as
/// "teardown succeeded".
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
pub(crate) fn members(_pgid: i32) -> std::io::Result<Vec<Member>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process-group membership is implemented only for Linux and macOS",
    ))
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod group_tests;
