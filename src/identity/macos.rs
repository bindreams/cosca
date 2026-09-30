//! macOS process-identity backend: `proc_pidinfo` (Apple's stable public libproc API) is
//! the PRIMARY source; `sysctl(KERN_PROC_PID)` (the `kinfo` module) is the FALLBACK for
//! what libproc cannot see — ZOMBIES and EPERM-hidden cross-user processes — keeping
//! identity resolution zombie-inclusive like Linux procfs while the common live path stays
//! on the stable ABI. Both sources report the process start time in µs (cross-source
//! equality pinned by the kinfo_tests oracle), so a layout drift in the undocumented
//! kinfo_proc ABI degrades only zombie/cross-user resolution (a token mismatch — the
//! pre-fix behavior), never live same-uid identity.
//!
//! [`ppid_of`] resolves a pid's parent the same primary/fallback way — `proc_pidinfo` first,
//! the sysctl fallback on a miss — and is reused whole by `containment::enumerate::macos`,
//! rather than that module keeping a second `proc_pidinfo` call and a second copy of the
//! zero-ppid guard ([`trusted_ppid`]) next to a duplicated `kinfo_proc` layout.

use std::time::{Duration, SystemTime};

use super::{Liveness, RawPid, Resolved, StartToken};

#[path = "macos/kinfo.rs"]
pub(crate) mod kinfo;

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

/// Which `exit_only` read a `pbi_start_quiet` call is, so a test can inject a result into one
/// read without touching the others, and a `warn` can name the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadPurpose {
    /// A start-checked peek's, just before its consume.
    Peek,
    /// The own-zombie start read before the first reap, for the second peek.
    PreReap,
    /// The second peek's.
    SecondPeek,
    /// The check after a by-pid `ECHILD`, that the pid still names our child.
    Echild,
    /// A `Running` peek's, that the pid still names our child.
    Running,
}

/// What a by-pid identity read saw: the start time, and whether launchd owns `pid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PbiRead {
    pub(crate) start: StartToken,
    /// The parent is launchd (pid 1). A child of ours that a tracer held is handed back to us, or
    /// its zombie stays on the tracer's list; when the tracer dies first, XNU reparents the
    /// zombie to launchd instead (measured on CI: `p_stat` `SZOMB`, `ppid` 1, `P_TRACED` clear,
    /// `p_oppid` still ours), and nothing hands it back.
    pub(crate) orphaned: bool,
}

/// The pid launchd runs as, the parent of every orphan.
const LAUNCHD: RawPid = 1;

/// `pid`'s start time through `proc_pidinfo(PROC_PIDTBSDINFO)` with `arg = 1`, which sees
/// zombies and never waits on `P_LINTRANSIT` (xnu-12377.121.6 and xnu-10063.101.15: `proc_pidinfo`
/// looks the process up with `proc_find`, then `proc_find_zombref`, and `proc_info.c` has no
/// `proc_transwait`; `proc_find` waits only for the brief `P_REF_WILL_EXEC | P_REF_IN_EXEC` switch
/// after exec's point of no return, as `kill(2)` does). A `sysctl(KERN_PROC_PID)` read sleeps
/// while the pid's `exec` is in transit (`proc_iterate` without `PROC_NOWAITTRANS`), which spans
/// image activation, so a hung NFS or FUSE mount can stretch it without bound. It fails with
/// `EPERM` for another user's process. Every
/// failure is a value, never [`contract_violation`]: `Gone` for `ESRCH`, `Unknown` for the rest,
/// with a `warn` naming `purpose` for those.
pub(crate) fn pbi_start_quiet(pid: RawPid, purpose: ReadPurpose) -> Resolved<StartToken> {
    pbi_read_quiet(pid, purpose).map(|read| read.start)
}

/// [`pbi_start_quiet`], with whether launchd owns the process.
pub(crate) fn pbi_read_quiet(pid: RawPid, purpose: ReadPurpose) -> Resolved<PbiRead> {
    #[cfg(test)]
    if let Some((forced, orphaned)) = quiet_fault::take(purpose) {
        return forced.map(|start| PbiRead { start, orphaned });
    }
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; pointer and size match.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            1,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n == size {
        return Resolved::Found(PbiRead {
            start: token_of_bsd(&info),
            orphaned: info.pbi_ppid == LAUNCHD,
        });
    }
    if n <= 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            return Resolved::Gone;
        }
        log::warn!("proc_pidinfo({pid}) for the {purpose:?} start read failed: {e}");
        return Resolved::Unknown;
    }
    log::warn!("proc_pidinfo({pid}) for the {purpose:?} start read wrote {n} bytes, expected {size}");
    Resolved::Unknown
}

/// `PROC_PIDUNIQIDENTIFIERINFO`, `proc_info_private.h`. Private, and read unprivileged: the kernel
/// answers it for any user's process (`NO_CHECK_SAME_USER`, `proc_info.c`).
const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

/// `struct proc_uniqidentifierinfo` (`proc_info_private.h`, 56 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcUniqIdentifierInfo {
    p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    p_idversion: i32,
    p_orig_ppidversion: i32,
    p_reserve2: u64,
    p_reserve3: u64,
}
const _: () = assert!(std::mem::size_of::<ProcUniqIdentifierInfo>() == 56);

/// What `proc_pidinfo(pid, 17, ...)` says of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UniqInfo {
    /// The process's 64-bit id, never reused and kept across `exec`.
    pub(crate) unique_id: u64,
}

/// The outcome of [`uniq_info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UniqRead {
    Found(UniqInfo),
    /// `ESRCH`: no such process, or one that is exiting and not yet a zombie.
    Gone,
    /// Any other errno (`EPERM`, `EACCES`, ...): the identity could not be read.
    Refused(i32),
}

/// `pid`'s unique id through `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)` with `arg = 1`, which
/// sees zombies, on the same `proc_find` path every `kill(2)` takes: it never waits on
/// `P_LINTRANSIT`, and it answers for another user's process where the `PROC_PIDTBSDINFO` start
/// read is refused. `n <= 0` is classified by errno: `ESRCH` is `Gone`, the rest `Refused`.
pub(crate) fn uniq_info(pid: RawPid) -> UniqRead {
    #[cfg(test)]
    if let Some(forced) = uniq_fault::take() {
        return forced;
    }
    // SAFETY: all-zero is a valid `ProcUniqIdentifierInfo`.
    let mut info: ProcUniqIdentifierInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcUniqIdentifierInfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; pointer and size match.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n == size {
        return UniqRead::Found(UniqInfo {
            unique_id: info.p_uniqueid,
        });
    }
    if n <= 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        let _gone = UniqRead::Gone;
        return UniqRead::Refused(errno);
    }
    log::warn!("proc_pidinfo({pid}) for the unique id wrote {n} bytes, expected {size}");
    UniqRead::Refused(libc::EIO)
}

/// Forces [`uniq_info`] below the syscall.
#[cfg(test)]
pub(crate) mod uniq_fault {
    use std::cell::RefCell;

    use super::UniqRead;

    thread_local! {
        static FORCED: RefCell<Vec<UniqRead>> = const { RefCell::new(Vec::new()) };
    }

    #[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
    pub(crate) struct Forced(());

    /// The next `uniq_info` on this thread answers `read`. Forces queue.
    pub(crate) fn force_uniq_read_once(read: UniqRead) -> Forced {
        FORCED.with(|f| f.borrow_mut().push(read));
        Forced(())
    }

    impl Drop for Forced {
        fn drop(&mut self) {
            FORCED.with(|f| f.borrow_mut().clear());
        }
    }

    pub(super) fn take() -> Option<UniqRead> {
        FORCED.with(|f| {
            let mut forced = f.borrow_mut();
            (!forced.is_empty()).then(|| forced.remove(0))
        })
    }
}

pub(super) fn start_token(pid: RawPid) -> Resolved<StartToken> {
    #[cfg(test)]
    if fault::is_unknown(pid) {
        return Resolved::Unknown;
    }
    if let Some(info) = bsd_info(pid) {
        return Resolved::Found(token_of_bsd(&info));
    }
    // libproc-invisible: gone, a ZOMBIE, or EPERM-hidden - only sysctl resolves the latter
    // two, and it distinguishes an empty reply (gone) from a failure (unknown).
    kinfo::kinfo(pid).map(|info| token_of_kinfo(&info))
}

/// Whether a raw ppid value read from the kernel for `pid` is trustworthy - shared by BOTH
/// [`ppid_of`]'s primary read (`proc_bsdinfo.pbi_ppid`, via `proc_pidinfo`) and its sysctl
/// fallback (`kinfo_proc.kp_eproc.e_ppid`), which read the same underlying kernel field,
/// `p->p_ppid` (confirmed live, across the whole process table, by
/// `sysctl_e_ppid_matches_libproc_across_the_live_process_table`, which also calls this
/// function rather than re-deriving the rule) - a single function so production's two call
/// sites and that oracle test cannot silently drift apart on what counts as trustworthy.
///
/// `0` is legitimate ONLY for pid 1 (launchd, the one real process whose parent is the
/// kernel). For any other pid, a `0` here means XNU served this pid's process-info record
/// before `fork()` finished filling in its parent field. This IS a real, live race, not a
/// theoretical one: measured directly on a busy host during this crate's own test runs (a
/// live, non-pid-1, freshly-forked process's sysctl record read `e_ppid == 0` while
/// `proc_pidinfo` already reported the true value moments earlier), diagnosed against
/// `ps -eo pid,ppid,comm` to confirm genuine process churn rather than an offset bug. A
/// separate synthetic stress harness (two threads, 30k `fork()`+`_exit` and 4k
/// `posix_spawn` iterations, ~2.3M records) did NOT reproduce it - which sharpens rather
/// than clears the finding, since a targeted fork-storm and ordinary host churn during a
/// parallel test run are different windows onto the same kernel-internal, userspace-
/// invisible race, the same class already documented for `proc_listallpids`'s walk cap.
/// Never trusted as a real ppid: [`ppid_of`] re-reads it until the fork finishes. The record
/// itself is otherwise valid (correctly sized, no sysctl/libproc error) - this is not
/// `contract_violation`'s "layout drifted or the kernel misbehaved" case, only a narrow timing
/// window - so an excluded `0` is a DESIGNED `None`, `debug`-logged like every other per-pid probe.
fn trusted_ppid(pid: RawPid, raw: RawPid) -> Option<RawPid> {
    if raw == 0 && pid != 1 {
        log::debug!(
            "pid {pid}'s process-info record reported ppid == 0 for a non-pid-1 process - a \
             fork()-in-progress record, not a resolvable ppid"
        );
        None
    } else {
        Some(raw)
    }
}

/// One attempt at `pid`'s parent pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PpidRead {
    Found(RawPid),
    /// Both reads reported an untrusted `e_ppid == 0` ([`trusted_ppid`]): `fork()` has not
    /// finished. Transient.
    Forking,
    /// The fallback positively confirmed the pid does not exist.
    Gone,
    /// The sysctl fallback was refused (`EPERM`/`EACCES`, a sandbox) or answered outside its
    /// contract. Persistent.
    Refused,
}

/// One attempt: `proc_pidinfo` first (the same primary read [`bsd_info`] makes), the sysctl
/// fallback on a miss - the shape [`start_token`] already uses for its own libproc miss. An
/// untrusted `0` from the primary falls through to the fallback exactly like any other miss.
fn read_ppid_once(pid: RawPid) -> PpidRead {
    #[cfg(test)]
    if let Some(read) = fault::next_ppid_read(pid) {
        return read;
    }
    if let Some(info) = bsd_info(pid) {
        if let Some(ppid) = trusted_ppid(pid, info.pbi_ppid) {
            return PpidRead::Found(ppid);
        }
    }
    match kinfo::kinfo(pid) {
        Resolved::Found(info) => match trusted_ppid(pid, info.e_ppid() as RawPid) {
            Some(ppid) => PpidRead::Found(ppid),
            None => PpidRead::Forking,
        },
        Resolved::Gone => PpidRead::Gone,
        Resolved::Unknown => PpidRead::Refused,
    }
}

/// Drive `read` to an answer. `Forking` is re-read after `pause(attempt)`; nothing else is.
fn resolve_ppid(mut read: impl FnMut() -> PpidRead, mut pause: impl FnMut(u32)) -> Resolved<RawPid> {
    let mut attempt = 0;
    loop {
        match read() {
            PpidRead::Found(ppid) => return Resolved::Found(ppid),
            PpidRead::Gone => return Resolved::Gone,
            PpidRead::Refused => return Resolved::Unknown,
            PpidRead::Forking => {
                pause(attempt);
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

/// `pid`'s parent pid.
///
/// `Unknown` is only a PERSISTENT refusal: the sysctl fallback answering `EPERM`/`EACCES` (a
/// sandbox), which a re-read would not change. The other cause is transient, so it is not
/// `Unknown`: both reads reporting the untrusted `e_ppid == 0` of a `fork()` in progress
/// ([`trusted_ppid`]) is re-read, with a growing pause, until it resolves. That re-checks a
/// deterministic condition - a fork always finishes - so it has neither a count cap nor a
/// deadline; the pid exiting meanwhile ends it as `Gone`. `Gone` is only returned when the
/// fallback itself positively confirms the pid no longer exists.
pub(crate) fn ppid_of(pid: RawPid) -> Resolved<RawPid> {
    resolve_ppid(|| read_ppid_once(pid), fork_pause)
}

/// The pause before re-reading a pid whose `fork()` is still filling in its parent: yield first,
/// then sleep for `2^attempt` microseconds, growing to 1 ms.
fn fork_pause(attempt: u32) {
    if attempt == 0 {
        std::thread::yield_now();
    } else {
        std::thread::sleep(Duration::from_micros(1 << attempt.min(10)));
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

/// Test-only seam: a by-pid identity read answers `Unknown`, as an OS refusal would.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::RefCell;

    thread_local! {
        static UNKNOWN: RefCell<Vec<super::RawPid>> = const { RefCell::new(Vec::new()) };
        static PPID_READS: RefCell<Vec<(super::RawPid, std::collections::VecDeque<super::PpidRead>)>> =
            const { RefCell::new(Vec::new()) };
        static PPID_READ_COUNT: RefCell<Vec<(super::RawPid, usize)>> = const { RefCell::new(Vec::new()) };
    }

    /// Disarms [`force_unknown`] on drop.
    #[must_use = "dropping this immediately disarms the forced read"]
    pub(crate) struct Forced(());

    impl Drop for Forced {
        fn drop(&mut self) {
            UNKNOWN.with(|u| u.borrow_mut().clear());
            PPID_READS.with(|p| p.borrow_mut().clear());
            PPID_READ_COUNT.with(|p| p.borrow_mut().clear());
        }
    }

    /// Script the first attempts of `pid`'s parent read on THIS thread: each attempt takes the
    /// next of `reads`; once they run out the real read answers. Every attempt is counted, real
    /// or scripted ([`ppid_read_attempts`]).
    pub(crate) fn force_ppid_reads(pid: super::RawPid, reads: &[super::PpidRead]) -> Forced {
        PPID_READ_COUNT.with(|c| c.borrow_mut().retain(|&(p, _)| p != pid));
        PPID_READS.with(|p| p.borrow_mut().push((pid, reads.iter().copied().collect())));
        Forced(())
    }

    /// How many attempts `pid`'s parent read has made on THIS thread since the guard was made.
    pub(crate) fn ppid_read_attempts(pid: super::RawPid) -> usize {
        PPID_READ_COUNT.with(|c| c.borrow().iter().find(|&&(p, _)| p == pid).map_or(0, |&(_, n)| n))
    }

    pub(super) fn next_ppid_read(pid: super::RawPid) -> Option<super::PpidRead> {
        PPID_READ_COUNT.with(|c| {
            let mut c = c.borrow_mut();
            match c.iter_mut().find(|(p, _)| *p == pid) {
                Some((_, n)) => *n += 1,
                None => c.push((pid, 1)),
            }
        });
        PPID_READS.with(|p| {
            p.borrow_mut()
                .iter_mut()
                .find(|(q, _)| *q == pid)
                .and_then(|(_, reads)| reads.pop_front())
        })
    }

    /// Make every by-pid identity read of `pid` on THIS thread answer `Resolved::Unknown`.
    pub(crate) fn force_unknown(pid: super::RawPid) -> Forced {
        UNKNOWN.with(|u| u.borrow_mut().push(pid));
        Forced(())
    }

    pub(super) fn is_unknown(pid: super::RawPid) -> bool {
        UNKNOWN.with(|u| u.borrow().contains(&pid))
    }
}

#[cfg(test)]
#[path = "macos/ppid_tests.rs"]
mod ppid_tests;

/// Forces [`pbi_start_quiet`] and [`kinfo_start`] reads of chosen purposes to chosen results,
/// below the syscall.
#[cfg(test)]
pub(crate) mod quiet_fault {
    use std::cell::{Cell, RefCell};

    use super::{ReadPurpose, Resolved, StartToken};

    /// One force: its id, the purpose, the answer, and the orphaned flag.
    type Force = (u64, ReadPurpose, Resolved<StartToken>, bool);

    thread_local! {
        static FORCED: RefCell<Vec<Force>> = const { RefCell::new(Vec::new()) };
        static NEXT_ID: Cell<u64> = const { Cell::new(0) };
    }

    #[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
    pub(crate) struct Forced(u64);

    /// The next read for `purpose` on this thread answers `result`. Other purposes are untouched.
    /// Forces for different purposes, or for the same one, queue.
    pub(crate) fn force_quiet_read_error_once(purpose: ReadPurpose, result: Resolved<StartToken>) -> Forced {
        force_quiet_read_once(purpose, result, false)
    }

    /// [`force_quiet_read_error_once`], with the read's orphaned flag.
    pub(crate) fn force_quiet_read_once(purpose: ReadPurpose, result: Resolved<StartToken>, orphaned: bool) -> Forced {
        let id = NEXT_ID.with(|n| n.replace(n.get() + 1));
        FORCED.with(|f| f.borrow_mut().push((id, purpose, result, orphaned)));
        Forced(id)
    }

    impl Drop for Forced {
        fn drop(&mut self) {
            FORCED.with(|f| f.borrow_mut().retain(|(id, ..)| *id != self.0));
        }
    }

    pub(super) fn take(purpose: ReadPurpose) -> Option<(Resolved<StartToken>, bool)> {
        FORCED.with(|f| {
            let mut forced = f.borrow_mut();
            let at = forced.iter().position(|(_, p, ..)| *p == purpose)?;
            let (_, _, result, orphaned) = forced.remove(at);
            Some((result, orphaned))
        })
    }
}
