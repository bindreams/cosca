//! macOS inherited-fd marker: containment membership the child carries.
//!
//! A contained root is handed the write end of a pipe with `FD_CLOEXEC` cleared *in the
//! forked child*, so every descendant inherits it across `fork` and `exec`. Membership
//! becomes "holds this kernel object", which no credential or grouping change can shed — it
//! survives `setsid`, `setpgid` and reparenting to launchd, and it nests arbitrarily.
//!
//! Holders are matched by `pipe_handle` (a `VM_KERNEL_ADDRHASH` of the kernel pipe object)
//! read via `proc_pidfdinfo(…, PROC_PIDFDPIPEINFO, …)`.
//!
//! # Why the supervisor must hold the read end for the mechanism's whole life
//!
//! `pipe_handle` is a true, collision-free identity only while some descriptor on that pipe —
//! either end, in any process — is still open. Once every descriptor on both ends closes, the
//! kernel re-issues the freed address (hence the same handle) almost immediately, to any
//! process on the host, not just this one. A sweep run after the read end was dropped could
//! therefore match an arbitrary unrelated process. `Marker::sweep` takes `&self` and `Marker`
//! owns the read end, so this is structural rather than a rule to remember.
//!
//! # Documented limits
//!
//! This is naive-child containment, not a sandbox: `close(fd)` escapes, and a spawn path that
//! scrubs inherited descriptors — notably Python's `subprocess` (`close_fds=True` by default)
//! and Node's `child_process` — drops the marker for everything below it.
//! `POSIX_SPAWN_CLOEXEC_DEFAULT` drops it unless the fd is passed to
//! `posix_spawn_file_actions_addinherit_np`. Elevation wrappers drop it too: `sudo` closes
//! every descriptor >= 3 by default (`closefrom`), which is why the marker is not installed on
//! an elevation-derived spawn. A concurrent, unrelated `fork()` in THIS process — outside
//! cosca's own spawn path, which serialises itself via `spawn_lock` and drops its
//! supervisor-side copy before releasing that lock, fully excluding every OTHER cosca spawn —
//! can still transiently inherit the marker write end into its own not-yet-`exec`'d child,
//! since `fork()` copies the whole fd table regardless of `FD_CLOEXEC` (that flag only takes
//! effect at THAT child's own `exec`). This residual cannot be closed to zero: no local code
//! change can control a third party's fork timing in the same process.
//!
//! **A tree member that `exec`s a setuid binary, or otherwise changes credentials, becomes
//! unqueryable via `PROC_PIDLISTFDS` (`EPERM`).** If the ppid-walk channel can still place it as
//! a descendant, `sweep` already folds the gap into `incomplete` there, so `holders()`'s own
//! denial for the same pid stays an aggregate `debug!`, not a second `warn!`. But for a pid
//! ppid-walk cannot place — a double-fork-reparented-to-launchd orphan, this module's primary
//! scenario — a denial leaves no channel able to catch it: `holders()` folds it into the same
//! aggregate, never-escalated denial count as ordinary host noise, so `sweep` can return
//! `Ok(())` while that pid is a real, un-swept member. Not escalated to `incomplete`, for the
//! same reason `enumerate::snapshot()`'s ppid-denial count is excluded: folding in bulk
//! per-scan denials (hundreds of unrelated pids on a real host) would make `Ok(())`
//! unreachable in practice.
//!
//! **The marker fd is inherited-only, not an IPC channel — do not write to it.** Every
//! descendant is handed the WRITE end of a pipe whose read end the supervisor holds but never
//! reads. A member that writes to its inherited marker descriptor blocks once the kernel pipe
//! buffer fills (nothing ever drains it), and after `Child::detach()` — which drops the
//! supervisor's read end while a surviving member's write-end copy is what then keeps the
//! marker's `pipe_handle` from being recycled — a subsequent write by that member raises
//! `SIGPIPE` (default action: terminate) instead. Ordinary programs never write to a
//! descriptor they did not open themselves for that purpose, so this is not expected to matter
//! in practice, but it is a real behavior of an fd a tree member's own code could, in
//! principle, stumble onto by number.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::Instant;

use crate::identity::RawPid;

// FFI: sys/proc_info.h =====
//
// `libc` exposes `proc_pidfdinfo`, `proc_fdinfo`, `vinfo_stat`, `PROC_PIDLISTFDS` and
// `PROX_FDTYPE_PIPE`, but not the five symbols below. They are public SDK API, not private
// layout: the values and offsets are pinned by the static asserts underneath.

/// `proc_pidfdinfo` flavor yielding `struct pipe_fdinfo`.
pub(crate) const PROC_PIDFDPIPEINFO: libc::c_int = 6;
/// `proc_fileinfo::fi_status` bit: this descriptor closes at the holder's next `exec`.
pub(crate) const PROC_FP_CLEXEC: u32 = 2;

/// `struct proc_fileinfo`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// `struct pipe_fdinfo` — the buffer `PROC_PIDFDPIPEINFO` fills. Using `struct pipe_info`
/// here instead (the shape the folklore recipe uses) makes every call return <= 0 and the
/// sweep find nobody.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PipeFdInfo {
    pfi: ProcFileInfo,
    pipe_stat: libc::vinfo_stat,
    pub(crate) pipe_handle: u64,
    pub(crate) pipe_peerhandle: u64,
    pipe_status: i32,
    rfu_1: i32,
}

const _: () = assert!(std::mem::size_of::<ProcFileInfo>() == 24);
const _: () = assert!(std::mem::size_of::<PipeFdInfo>() == 184);
const _: () = assert!(std::mem::offset_of!(PipeFdInfo, pipe_handle) == 160);

// Reading a pipe's identity =====

/// The `pipe_handle` of `fd` in THIS process, or `None` if `fd` is not a pipe. A self-query, so
/// `FdPipeInfoQuery::Denied` is not expected in practice (a process may always query its own
/// fds) — folded into `None` alongside `Absent` for this convenience wrapper regardless.
pub(crate) fn pipe_handle_of(fd: BorrowedFd<'_>) -> Option<u64> {
    match fd_pipe_info(std::process::id(), fd.as_raw_fd()) {
        FdPipeInfoQuery::Found(info) => Some(info.pipe_handle),
        FdPipeInfoQuery::Absent | FdPipeInfoQuery::Denied => None,
    }
}

/// Same tri-state shape as `PipeQuery`, for the per-fd `PROC_PIDFDPIPEINFO` query — added
/// because `holders()` and `holds_marker_query()` both call this on an fd `pipe_fds_of` JUST
/// reported as a pipe, so a denial here is not the routine "not a pipe" case; it means the
/// query was refused between the two calls (matching the module docs' credential-changing-exec
/// scenario), and each caller needs to react to that specifically — see each call site.
pub(crate) enum FdPipeInfoQuery {
    Found(PipeFdInfo),
    /// Not a pipe, the fd closed, or the pid is gone — indistinguishable at this layer, and
    /// (unlike `PipeQuery`) not worth separating: nothing calls this hoping to count denials
    /// against a NOT-yet-confirmed candidate the way `holders()`'s outer `pipe_fds_of` does.
    Absent,
    /// The OS refused the query (measured: the same `0`-with-`EPERM` shape as `PROC_PIDLISTFDS`).
    Denied,
}

pub(crate) fn fd_pipe_info(pid: RawPid, fd: libc::c_int) -> FdPipeInfoQuery {
    let mut info: PipeFdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<PipeFdInfo>() as libc::c_int;
    // SAFETY: proc_pidfdinfo writes up to `size` bytes into `info`; pointer and size match.
    let n = clear_errno_and_call(|| unsafe {
        libc::proc_pidfdinfo(
            pid as libc::c_int,
            fd,
            PROC_PIDFDPIPEINFO,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    });
    if n == size {
        return FdPipeInfoQuery::Found(info);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        // ESRCH: pid is gone. EBADF: measured directly — the kernel returns this both for "fd
        // was a pipe a moment ago but is now closed" and "fd was never a pipe," i.e. it is
        // `proc_pidfdinfo`'s generic "not found" code for this call, not an access-control
        // signal. Treating it as `Denied` would misreport an ordinary closed-descriptor race
        // (the fd this loop is iterating came from a separate, earlier `PROC_PIDLISTFDS` call)
        // as a permissions problem.
        None | Some(0) | Some(libc::ESRCH) | Some(libc::EBADF) => FdPipeInfoQuery::Absent,
        _ => FdPipeInfoQuery::Denied,
    }
}

// The sweep =====

/// One process found holding the marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Holder {
    pub pid: RawPid,
    /// The holder's marker descriptor is `FD_CLOEXEC`: it leaves the containment set at the
    /// holder's next `exec`. An imminent, observable membership loss.
    pub clexec: bool,
}

/// The outcome of trying to read `pid`'s pipe descriptors — a tri-state, not a `Vec` alone,
/// because `holders()` (scanning the WHOLE host) and `holds_marker_query()` (re-checking a
/// KNOWN candidate) need to react to a denial completely differently. See the module docs and
/// each caller for why.
pub(crate) enum PipeQuery {
    /// The fd table was read; these are its pipe descriptors (possibly none).
    Found(Vec<libc::c_int>),
    /// The pid is gone (`ESRCH`) — expected, never worth logging.
    Gone,
    /// The OS refused the query (measured: `EPERM`, returned as `0` — see below). Whether this
    /// is worth logging depends on WHO is asking; `pipe_fds_of` itself stays silent.
    Denied,
}

/// Every process in `pids` holding the pipe named by `handle`. Best-effort: a pid we may not
/// query, or one that vanishes mid-sweep, is simply absent — but a denial is COUNTED, not
/// discarded silently, and reported in aggregate (see below).
///
/// A process can hold MULTIPLE descriptors naming the same marker — the inherited one plus any
/// `dup`/`fcntl(F_DUPFD_CLOEXEC)` copy, trivially produced by a shell `exec N>&M` or by any
/// runtime that dups an inherited fd. `Holder.clexec` claims the descriptor "will lose the
/// marker at its next exec"; that is only true if EVERY copy the process holds is CLOEXEC, so
/// the fold below is an AND across every matching fd: a single non-CLOEXEC copy keeps the
/// marker alive past the next exec even if another copy is CLOEXEC.
///
/// **Denials are aggregated, not warned per-pid.** This scans EVERY pid on the host, and most
/// denials here are for processes that have nothing to do with the tree (any other user's
/// processes) — measured on this host: `ps -Ao user=` shows several hundred non-self-owned
/// pids out of roughly a thousand live, every one of which denies `PROC_PIDLISTFDS`. Warning
/// per pid here would bury the genuinely actionable case — a denial on a pid ALREADY confirmed
/// to hold the marker — under hundreds of lines about processes that were never candidates.
/// That actionable case is `kill_holder`'s live re-check via `holds_marker_query`, which DOES
/// `warn!`, because by then the pid is a known member, not an arbitrary host process.
pub(crate) fn holders(handle: u64, pids: &[RawPid]) -> Vec<Holder> {
    let mut out = Vec::new();
    let mut denied = 0usize;
    for &pid in pids {
        let fds = match pipe_fds_of(pid) {
            PipeQuery::Found(fds) => fds,
            PipeQuery::Gone => continue,
            PipeQuery::Denied => {
                denied += 1;
                continue;
            }
        };
        let mut found = false;
        let mut all_clexec = true;
        for fd in fds {
            match fd_pipe_info(pid, fd) {
                FdPipeInfoQuery::Found(info) => {
                    if info.pipe_handle != handle {
                        continue;
                    }
                    found = true;
                    all_clexec &= info.pfi.fi_status & PROC_FP_CLEXEC != 0;
                }
                FdPipeInfoQuery::Absent => {
                    // `pipe_fds_of` just reported this exact fd as a pipe (moments ago), so
                    // this IS the routine "vanished between the two calls" case — `debug!`,
                    // not counted (matches a genuinely gone pid, not a denial).
                    log::debug!(
                        "fd marker {handle:#x}: PROC_PIDFDPIPEINFO for pid {pid} fd {fd} \
                         (already listed as a pipe) came back empty; treating as vanished \
                         between the two calls"
                    );
                }
                FdPipeInfoQuery::Denied => {
                    // Same class of gap as a whole-pid `PROC_PIDLISTFDS` denial (this fd WAS
                    // just listed as a pipe, so this is a real, not routine, miss) — folded
                    // into the SAME aggregate count, not a separate `warn!` per pid, for the
                    // same "most of these are unrelated host noise" reasoning above.
                    denied += 1;
                    log::debug!(
                        "fd marker {handle:#x}: PROC_PIDFDPIPEINFO for pid {pid} fd {fd} \
                         (already listed as a pipe) was denied"
                    );
                }
            }
        }
        if !found {
            continue;
        }
        if all_clexec {
            // The HANDLE is in the message, not just the pid: `log_capture` is one
            // process-global buffer shared by every parallel test, and every unit test
            // shares this pid — only the handle distinguishes one marker from another.
            log::warn!(
                "fd marker {handle:#x}: holder pid {pid} will lose the marker at its next \
                 exec (every copy of its inherited descriptor is FD_CLOEXEC)"
            );
        }
        out.push(Holder {
            pid,
            clexec: all_clexec,
        });
    }
    if denied > 0 {
        log::debug!(
            "fd marker {handle:#x}: {denied} of {} host pids were unqueryable this pass \
             (access denied); none were confirmed holders, but a denied pid already holding \
             the marker would be invisible to this scan",
            pids.len()
        );
    }
    out
}

/// Whether `pid` holds the marker right now — the plain-`bool` convenience most callers
/// (including this file's own tests) want; folds `MarkerQuery::Denied` into `false` alongside
/// `NotHeld`, which is correct for a caller that does not need to distinguish them. `kill_holder`
/// uses `holds_marker_query` directly instead, because IT does need to.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn holds_marker(pid: RawPid, handle: u64) -> bool {
    matches!(holds_marker_query(pid, handle), MarkerQuery::Held)
}

/// The tri-state membership re-check `kill_holder` actually needs: a confirmed non-holder (the
/// documented `close(fd)` escape — safe to leave running, `debug!` only) is a different fact
/// from a KNOWN holder (`holders()` found this pid moments earlier, this pass) that became
/// unqueryable before the kill — almost always the credential-changing `exec` the module docs
/// name, a real teardown gap, not an escape, and worth a `warn!` plus counting toward
/// `incomplete`. Collapsing the two (as a bare `bool` must) would silently reclassify "still a
/// member, now unreachable" as "no longer a member".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkerQuery {
    Held,
    NotHeld,
    Denied,
}

pub(crate) fn holds_marker_query(pid: RawPid, handle: u64) -> MarkerQuery {
    let fds = match pipe_fds_of(pid) {
        PipeQuery::Found(fds) => fds,
        PipeQuery::Gone => return MarkerQuery::NotHeld,
        PipeQuery::Denied => return MarkerQuery::Denied,
    };
    for fd in fds {
        match fd_pipe_info(pid, fd) {
            FdPipeInfoQuery::Found(info) if info.pipe_handle == handle => return MarkerQuery::Held,
            FdPipeInfoQuery::Found(_) => continue,
            FdPipeInfoQuery::Absent => {
                // Same shape as `holders()`'s inner loop, same disposition — see there.
                log::debug!(
                    "fd marker {handle:#x}: PROC_PIDFDPIPEINFO for pid {pid} fd {fd} (already \
                     listed as a pipe) came back empty; treating as vanished between the two calls"
                );
                continue;
            }
            FdPipeInfoQuery::Denied => {
                // This pid is a CONFIRMED candidate (`kill_holder` only calls this on an
                // already-discovered holder) — a per-fd denial here is exactly the "known
                // member became unqueryable" gap `MarkerQuery::Denied` exists to report, NOT
                // the same fact as a genuinely absent descriptor. Returning here (rather than
                // continuing to check other fds) is deliberately conservative: one denied fd
                // on a confirmed holder is enough to say "this pid could not be fully
                // re-verified," matching `kill_holder`'s own doc comment.
                return MarkerQuery::Denied;
            }
        }
    }
    MarkerQuery::NotHeld
}

/// `pid`'s pipe descriptors, as a [`PipeQuery`] — see there for what each variant means and
/// why the caller, not this function, decides whether a denial is worth logging.
///
/// **Measured on this host: `PROC_PIDLISTFDS` reports a denial by returning `0` with
/// `errno == EPERM`, NOT a negative value.** `proc_pidinfo(1, PROC_PIDLISTFDS, …)` (pid 1,
/// root-owned, from an unprivileged caller) returns `0`/`EPERM` for both the sizing and fill
/// forms; across the live table, every EPERM-denied pid returned exactly `0`, none returned
/// negative. This matches `identity::macos::bsd_info`'s established handling of the sibling
/// `PROC_PIDTBSDINFO` call: gate on `n <= 0`, then classify by errno. So the failure gate here
/// is `<= 0`, not `< 0` — and because `0` is ALSO the legitimate "successful, empty answer"
/// return (e.g. a zombie with no open fds), `errno` must be cleared immediately before each
/// call (`clear_errno_and_call`) so a `0` return can be told apart from an `EPERM` one: success
/// never touches `errno`, so it reads back as whatever this call just zeroed it to.
///
/// The kernel fills the buffer and reports bytes written with no error on truncation, so a
/// short list is indistinguishable from a complete one unless the buffer was provably larger
/// than the answer. Re-read with a doubled capacity until it is — a truncated fd list means a
/// holder silently missed.
/// The `proc_pidinfo` buffer-size argument for `cap` `proc_fdinfo` entries. Mirrors
/// `size_argument_for` in `enumerate/macos.rs`, guarding the identical hazard: `cap` doubles
/// unbounded in `pipe_fds_of`'s retry loop below, and an unchecked `as libc::c_int` cast wraps
/// once `cap * entry` passes `i32::MAX`, producing an arbitrary size that no longer describes
/// the buffer `fds` actually is — the exact correspondence the caller's `// SAFETY:` comment
/// depends on.
fn fd_list_buf_bytes(cap: usize, entry: usize) -> std::io::Result<libc::c_int> {
    cap.checked_mul(entry)
        .and_then(|bytes| libc::c_int::try_from(bytes).ok())
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "a {cap}-entry proc_fdinfo buffer cannot be described in proc_pidinfo's int \
                 size argument"
            ))
        })
}

pub(crate) fn pipe_fds_of(pid: RawPid) -> PipeQuery {
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    let needed = clear_errno_and_call(|| unsafe {
        libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    });
    if needed <= 0 {
        return classify_pidlistfds_failure();
    }
    let mut cap = needed as usize / entry + 16;
    loop {
        let buf_bytes = match fd_list_buf_bytes(cap, entry) {
            Ok(b) => b,
            Err(e) => {
                // A loud, per-pid denial, not a wrapped cast: matches `collect_pids`'s sibling
                // over-report guard in spirit — a contract this call cannot honor must fail
                // rather than silently truncate. Folded into `Denied` (counted, aggregated by
                // `holders()`) rather than propagated as a hard error: one pid with an
                // unenumerable fd table must not abort a whole-host sweep.
                log::warn!(
                    "fd marker: pid {pid}'s open-fd count cannot be enumerated ({e}); treating \
                     as denied for this pass"
                );
                return PipeQuery::Denied;
            }
        };
        let mut fds: Vec<libc::proc_fdinfo> = vec![unsafe { std::mem::zeroed() }; cap];
        // SAFETY: `fds` owns `buf_bytes` writable bytes (`fd_list_buf_bytes` computed it from
        // the SAME `cap`/`entry` that sized `fds`, and failed loudly above rather than wrap);
        // proc_pidinfo writes proc_fdinfo records.
        let written = clear_errno_and_call(|| unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr() as *mut libc::c_void,
                buf_bytes,
            )
        });
        if written <= 0 {
            return classify_pidlistfds_failure();
        }
        let count = written as usize / entry;
        if count > cap {
            // The over-report guard `collect_pids` has too: the kernel cannot legitimately
            // write more entries than the buffer it was handed. Folding this into "ask again
            // with more room" would silently accept an out-of-contract overwrite past `fds`'s
            // own allocation instead of failing loudly on it.
            log::warn!(
                "fd marker: pid {pid}'s proc_pidinfo(PROC_PIDLISTFDS) reported {count} entries \
                 into a {cap}-entry buffer; treating as denied for this pass"
            );
            return PipeQuery::Denied;
        }
        if count == cap {
            cap *= 2;
            continue;
        }
        return PipeQuery::Found(
            fds[..count]
                .iter()
                .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_PIPE as u32)
                .map(|f| f.proc_fd)
                .collect(),
        );
    }
}

/// Clears this thread's `errno` immediately before calling `f`, so a `0` return can be told
/// apart from a same-shaped `0`-meaning-EPERM failure (see `pipe_fds_of`'s doc comment for the
/// measurement). `errno` is thread-local on every platform this crate targets, so this is
/// race-free against other threads.
fn clear_errno_and_call(f: impl FnOnce() -> libc::c_int) -> libc::c_int {
    // SAFETY: `__error()` returns this thread's own errno cell; writing to it is always defined.
    unsafe {
        *libc::__error() = 0;
    }
    f()
}

/// Classifies a `<= 0` `PROC_PIDLISTFDS` return, following a call made through
/// `clear_errno_and_call`. `errno == 0` (never touched) means the call genuinely succeeded with
/// an empty answer; `ESRCH` means gone; anything else (measured: `EPERM` for a cross-user
/// query) is a real denial.
fn classify_pidlistfds_failure() -> PipeQuery {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        None | Some(0) => PipeQuery::Found(Vec::new()), // genuine empty success, not a failure
        Some(libc::ESRCH) => PipeQuery::Gone,
        _ => PipeQuery::Denied,
    }
}

// Installing the marker on a spawn =====

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::containment::ContainMode;

/// Whether this spawn installs a marker. Pure, so the policy is directly unit-testable —
/// the same shape as `unix_setup_for` and `windows_contain_setup`.
///
/// Only the outermost root installs one: a nested member inherits the root's marker across
/// `fork`, so a second pipe would add an fd per nesting level and buy nothing. `suppressed`
/// is set for an elevation-derived spawn, whose `sudo`/`doas`/`pkexec` wrapper closes every
/// descriptor >= 3 before exec — installing there would report a guarantee that cannot hold.
pub(crate) fn marker_wanted(mode: Option<ContainMode>, is_root: bool, suppressed: bool) -> bool {
    mode.is_some() && is_root && !suppressed
}

/// A descriptor number clear of everything that could overwrite the marker inside the forked
/// child: `command-fds` `dup2`s each user mapping onto its `child_fd`, std `dup2`s the stdio
/// slots before any `pre_exec` hook runs, AND ordinary, non-adversarial shell scripts and
/// libraries conventionally claim LOW numbers for their own redirections (`exec 3>&1`,
/// `exec 4<file`, a library's own `dup2` bookkeeping) — `dup2` silently closes whatever
/// occupied that number first. A floor of merely "above stdio" (3) still lands the marker at
/// 4-6 in the common case (nothing reserved), squarely inside that conventional range: a
/// script doing `exec 4>log` would then silently drop the marker for itself and everything it
/// spawns afterward — a far likelier ACCIDENTAL escape than the documented deliberate
/// `close(fd)` one, and nothing in this design would log or detect it. `HIGH_FLOOR` puts the
/// marker well clear of that whole range at negligible cost (one descriptor number, unused by
/// convention).
const HIGH_FLOOR: RawFd = 64;

/// `reserved` is caller-supplied (ultimately from `Command::fd()`'s child fd numbers), so
/// `m + 1` must not silently wrap: `saturating_add` keeps a `RawFd::MAX` entry from wrapping to
/// `RawFd::MIN`, which `.max(HIGH_FLOOR)` would otherwise "recover" from into a floor BELOW
/// that reserved fd — silently defeating the entire purpose of this function.
pub(crate) fn safe_marker_fd(candidate: RawFd, reserved: &[RawFd]) -> RawFd {
    let floor = reserved
        .iter()
        .copied()
        .max()
        .map_or(HIGH_FLOOR, |m| m.saturating_add(1))
        .max(HIGH_FLOOR);
    candidate.max(floor)
}

/// A marker pipe created for a spawn: the write end is already owned by the `Command`.
pub(crate) struct PreparedMarker {
    /// The supervisor's read end. See the module docs: holding it is what keeps `handle`
    /// from being re-issued to an unrelated pipe.
    pub read: OwnedFd,
    pub handle: u64,
    /// `read`'s OWN `pipe_handle` (a distinct kernel object from `handle`, the write end's —
    /// see `a_live_pipe_has_a_nonzero_handle_distinct_per_end`), captured while both ends are
    /// provably still open. Unlike `read`'s PEER handle (which reports `0` once every write
    /// end anywhere closes — measured; see `Marker::sweep`'s entry contract for why that
    /// matters), `read`'s OWN handle stays valid for as long as `read` itself stays open,
    /// letting `Marker` re-assert "this really is still my pipe" at sweep time without
    /// depending on the write side's state.
    pub read_handle: u64,
    /// The descriptor number the marker occupies in the child (`preserved_fds` does not
    /// renumber, so it is the parent's number too).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fd: RawFd,
}

/// Create the marker pipe and hand its write end to `std_cmd`. `reserved` is every child fd
/// number the spawn will `dup2` into (the caller's `fd()` mappings).
///
/// `preserved_fds` registers a `pre_exec` hook that clears `FD_CLOEXEC` on the descriptor
/// **in the forked child only**, so the supervisor's copy stays CLOEXEC and is never inherited
/// by a concurrent, unrelated spawn's EXEC'D process image. `command-fds`' own doc comment
/// notes the `Command` retains ownership of (and does not close) the write end until the
/// `Command` itself is dropped — so the CALLER must drop `std_cmd` promptly after `.spawn()`
/// returns to bound the (documented, non-zero) window where a truly concurrent `fork()` in this
/// same process could transiently see this fd before its own `exec`; see the module docs.
///
/// `None` on any failure — the caller falls back to the pre-existing mechanism rather than
/// failing the spawn.
pub(crate) fn install(std_cmd: &mut std::process::Command, reserved: &[RawFd]) -> Option<PreparedMarker> {
    use command_fds::CommandFdExt;

    let (read, write) = match create_pipe() {
        Ok(p) => p,
        Err(e) => {
            log::warn!(
                "fd marker: pipe() failed ({e}); falling back to the pre-existing containment channel for this mode"
            );
            return None;
        }
    };

    // A supervisor whose soft RLIMIT_NOFILE sits below `want` (HIGH_FLOOR=64 in the common
    // case, or higher with a large reserved set) makes F_DUPFD_CLOEXEC fail EINVAL here on
    // EVERY contained spawn, not just an occasional one — diagnosable from this log line alone
    // since `nix::errno::Errno`'s `Display` names the symbolic errno (e.g. "EINVAL: Invalid
    // argument"), not just a bare OS error number.
    let want = safe_marker_fd(write.as_fd().as_raw_fd(), reserved);
    let write: OwnedFd = match place_write_end(write, want) {
        Ok(fd) => fd,
        Err(e) => {
            log::warn!("fd marker: could not place the marker descriptor ({e}); falling back to the pre-existing containment channel for this mode");
            return None;
        }
    };
    let fd = write.as_raw_fd();
    // CONTRACT: `place_write_end` used `F_DUPFD_CLOEXEC`, which must place the copy WITH
    // FD_CLOEXEC set — the supervisor's own copy staying CLOEXEC (so no concurrent, unrelated
    // fork can inherit it into an exec'd image) is a documented safety property this whole
    // design leans on, not an incidental detail. Asserted, not just documented: a future
    // refactor that swaps in a non-CLOEXEC placement call must fail loudly in a debug/test
    // build, not silently in release.
    // SAFETY: F_GETFD is a plain fcntl read, no allocation.
    debug_assert!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "the marker's supervisor-side write-end copy must be FD_CLOEXEC"
    );

    let Some(handle) = read_handle(write.as_fd()) else {
        log::warn!("fd marker: the marker pipe has no readable handle; falling back to the pre-existing containment channel for this mode");
        return None;
    };
    // CONTRACT: `handle == 0` must never reach a live `Marker` — 0 is the sentinel this whole
    // mechanism treats as "matches no live pipe" (see `a_dead_handle_finds_no_holders`'s doc
    // comment: 0 is never a valid `pipe_handle` and cannot become one through any amount of
    // churn). If `proc_pidfdinfo` ever DID hand back 0 for a real, live pipe here, installing
    // it anyway would make `Marker.handle == 0` — the one value documented to match NOTHING —
    // instead match the WIDEST possible set: every host pid whose own unrelated pipe fds
    // happen to read back the same sentinel. Rejected as a failed install, exactly like the
    // other two `install()` failure arms, rather than trusted silently.
    if handle == 0 {
        log::warn!("fd marker: the marker pipe's write end reported a zero handle; falling back to the pre-existing containment channel for this mode");
        debug_assert!(
            false,
            "fd marker: pipe_handle_of the write end returned 0, the reserved sentinel"
        );
        return None;
    }
    // CONTRACT, checked HERE specifically because both ends are provably still open (unlike
    // at `Marker::sweep` time, where the write side may already be fully drained — see there):
    // `read` must pin the SAME kernel pipe object `handle` names. The measured invariant
    // (facts C/E) this whole mechanism rests on is exactly "holding a live descriptor on this
    // pipe keeps `handle` from being reissued", and that is only true if `read` really is a
    // descriptor on THIS pipe, not assumed from having called `create_pipe()` moments earlier.
    debug_assert!(
        matches!(
            fd_pipe_info(std::process::id(), read.as_raw_fd()),
            FdPipeInfoQuery::Found(info) if info.pipe_peerhandle == handle
        ),
        "the marker's read end must report the write end's handle as its peer"
    );
    // `read`'s OWN handle (a distinct kernel object from `handle` — see `PreparedMarker::
    // read_handle`'s doc comment for why `Marker` needs this instead of re-deriving a peer
    // check later): captured now, while it is certain to succeed, rather than assumed later.
    let Some(read_handle_value) = pipe_handle_of(read.as_fd()) else {
        log::warn!("fd marker: the marker pipe's read end has no readable handle; falling back to the pre-existing containment channel for this mode");
        return None;
    };
    // Same CONTRACT as the write end's handle above, and for the identical reason:
    // `Marker::sweep`'s entry check compares a LIVE read against this exact value, so a zero
    // here would make that check accept any other pipe descriptor that also happens to report
    // a zero handle, defeating the whole point of the entry contract.
    if read_handle_value == 0 {
        log::warn!("fd marker: the marker pipe's read end reported a zero handle; falling back to the pre-existing containment channel for this mode");
        debug_assert!(
            false,
            "fd marker: pipe_handle_of the read end returned 0, the reserved sentinel"
        );
        return None;
    }

    std_cmd.preserved_fds(vec![write]);
    Some(PreparedMarker {
        read: OwnedFd::from(read),
        handle,
        read_handle: read_handle_value,
        fd,
    })
}

// Fault-seam wrappers: each is the ONE place `install`'s corresponding real syscall is called,
// so the `#[cfg(test)]` injection is visibly separated from `install`'s own control flow rather
// than interleaved with it. Each takes the SAME `fault::take_fault()` value implicitly (via its
// own `#[cfg(test)]` check) — see the `fault` module doc for why exactly one of the three fires
// per test, never more.

fn create_pipe() -> std::io::Result<(std::io::PipeReader, std::io::PipeWriter)> {
    #[cfg(test)]
    if fault::take_if(fault::Fault::Pipe) {
        return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
    }
    std::io::pipe()
}

fn place_write_end(write: std::io::PipeWriter, want: RawFd) -> Result<OwnedFd, nix::errno::Errno> {
    #[cfg(test)]
    if fault::take_if(fault::Fault::Place) {
        return Err(nix::errno::Errno::EMFILE);
    }
    let placed = nix::fcntl::fcntl(write.as_fd(), nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(want))?;
    // CONTRACT: POSIX guarantees `F_DUPFD_CLOEXEC(want)` returns a descriptor `>= want`, which
    // is the ENTIRE reason `safe_marker_fd` exists (clearing every reserved child fd and the
    // shell-redirection range). Asserted, not just relied on, so a libc/kernel surprise on this
    // platform would fail loudly here rather than resurface as an inexplicable containment
    // escape much later.
    debug_assert!(
        placed >= want,
        "F_DUPFD_CLOEXEC({want}) returned {placed}, below the floor it was given"
    );
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh descriptor we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(placed) })
}

fn read_handle(fd: BorrowedFd<'_>) -> Option<u64> {
    #[cfg(test)]
    if fault::take_if(fault::Fault::Handle) {
        return None;
    }
    pipe_handle_of(fd)
}

/// Test-only: force the NEXT `install` on THIS thread to take one of its real failure arms, by
/// replacing that step's syscall result. `take_if` is what each fault-seam wrapper above
/// actually calls: it consumes the armed fault ONLY if it matches `want`, leaving it untouched
/// (for a DIFFERENT wrapper's own check) otherwise — so exactly one of the three wrappers in
/// one `install` call ever sees a match, matching the single-fault-per-call contract
/// `each_install_failure_arm_falls_back_and_says_which_step_failed` relies on.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Fault {
        Pipe,
        Place,
        Handle,
    }

    thread_local! {
        static FAULT: Cell<Option<Fault>> = const { Cell::new(None) };
    }

    pub(crate) fn set_fault(f: Option<Fault>) {
        FAULT.with(|c| c.set(f));
    }

    /// True and CONSUMED if the armed fault is exactly `want`; false and left untouched
    /// otherwise.
    pub(crate) fn take_if(want: Fault) -> bool {
        FAULT.with(|c| {
            if c.get() == Some(want) {
                c.set(None);
                true
            } else {
                false
            }
        })
    }

    pub(crate) fn take_fault() -> Option<Fault> {
        FAULT.with(|c| c.take())
    }

    // Test-only: force the NEXT `sweep` on THIS thread to skip the root's identity kill
    // (makes the `kill_tree` handle backstop forcible). Take semantics: `sweep` consumes the
    // flag — arm and call on one thread; assert consumption via `armed`. Mirrors
    // `treewalk::fault::set_force_root_kill_noop`/`take_force_root_kill_noop`/`armed`, which
    // this module's `sweep` does NOT go through (it calls `treewalk::kill_by_identity`
    // directly, not `treewalk::hard_kill`), hence a separate seam here.
    thread_local! {
        static FORCE_ROOT_KILL_NOOP: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn set_force_root_kill_noop(on: bool) {
        FORCE_ROOT_KILL_NOOP.with(|f| f.set(on));
    }

    pub(crate) fn take_force_root_kill_noop() -> bool {
        FORCE_ROOT_KILL_NOOP.with(|f| f.replace(false))
    }

    pub(crate) fn armed() -> bool {
        FORCE_ROOT_KILL_NOOP.with(|f| f.get())
    }

    /// Every `install` failure log line (`"fd marker: pipe() failed"`, etc.) carries no
    /// per-call discriminator — there is no handle yet to key on, since `install` hasn't
    /// succeeded. Two DIFFERENT tests asserting on the same literal text via `log_capture`
    /// (`fdmarker_tests.rs`'s `each_install_failure_arm_falls_back_and_says_which_step_failed`
    /// and `dispatch_tests.rs`'s `a_failed_marker_install_leaves_prepare_without_one`)
    /// would otherwise be able to satisfy each other's `contains_since` check across
    /// threads, since `log_capture` is one process-global buffer and `cargo test` runs each
    /// `#[test]` on its own thread. `FAULT` itself is thread-local (race-free), but the LOG
    /// ASSERTION is not, so both tests must hold this for their whole body instead.
    static LOG_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) fn lock_for_log_assertion() -> std::sync::MutexGuard<'static, ()> {
        LOG_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// The attached mechanism =====

use std::io;

use crate::error::Error;
use crate::identity::{ProcessId, Resolved};

/// The live marker for one contained tree.
pub(crate) struct Marker {
    /// Held for the mechanism's whole life. See the module docs: this is what stops `handle`
    /// from being re-issued to an unrelated pipe once the tree drains.
    read: OwnedFd,
    handle: u64,
    /// `read`'s OWN handle, captured at `install()` time — see `PreparedMarker::read_handle`'s
    /// doc comment. What `sweep`'s entry contract re-checks against `read` at signal time.
    read_handle: u64,
    /// The root's identity, for the ppid-walk channel. `None` when it could not be read at
    /// attach — the marker channel still runs.
    root: Option<ProcessId>,
    /// `true` only when `root` is `None` BECAUSE the OS refused to answer (`Resolved::Unknown`)
    /// — never for a root that had already exited (`Resolved::Gone`, a routine outcome; see
    /// `dispatch.rs`). `sweep_pass` folds this into `incomplete` on every pass for the marker's
    /// whole life, since a denial (unlike a dead root) is a real, standing teardown gap.
    root_denied: bool,
    /// The root's process group, when the requested mode created one. `None` for TreeWalk.
    pgid: Option<i32>,
    /// The descriptor number the marker occupies in the child, copied from
    /// `PreparedMarker::fd`. Exposed to this crate's OWN integration tests (`tests/*.rs`) via
    /// `Child::test_fdmarker_fd`, so a test can be TOLD the exact fd rather than inferring it
    /// from ambient process state (see `tests/macos_fdmarker.rs`'s
    /// `holders_and_folds_cloexec_across_a_holder_with_a_mixed_copy`, and the CI failure that
    /// motivated it, #59).
    own_fd: RawFd,
}

impl std::fmt::Debug for Marker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Marker")
            .field("handle", &format_args!("{:#x}", self.handle))
            .field("pgid", &self.pgid)
            .finish_non_exhaustive()
    }
}

/// Whether a swept pid may be signalled at all. The supervisor is excluded because signalling
/// itself would tear down the caller; pid 0 and pid 1 because neither is ever a tree member
/// and `kill(0, …)` signals the caller's whole process group.
pub(crate) fn is_signalable(pid: RawPid) -> bool {
    pid > 1 && pid != std::process::id()
}

/// Whether `pid`, right now, is a live member of process group `pgid` — the group-signal
/// re-fire gate's anchor (see `Marker::sweep_pass`'s doc for the full argument for why this,
/// and not the root's own identity, is what a later pass checks). `getpgid` fails (`ESRCH`) for
/// a pid that no longer exists, so a successful, matching call is itself the liveness proof; no
/// separate `is_alive()` check is needed or wanted.
fn pid_is_live_group_member(pid: RawPid, pgid: i32) -> bool {
    debug_assert!(
        pid <= i32::MAX as u32,
        "pid {pid} exceeds i32::MAX; pgid comparison would truncate"
    );
    nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(pid as i32)))
        .map(|g| g.as_raw() == pgid)
        .unwrap_or(false)
}

/// Fold two `Error`s from different `sweep` passes (or a pass's group-signal result against
/// the `incomplete` summary) into one, choosing the merged VARIANT by severity rather than by
/// which side happened to be checked first. `is_teardown_mechanism_failure`
/// (`src/child.rs`) is the single source of truth for "is this a genuine mechanism failure,
/// or an ordinary refusal" — reused here rather than re-derived, so this function and the
/// classifier can never quietly drift apart on what counts as which.
///
/// If EITHER side is a genuine mechanism failure, the merged result must be too: a later
/// pass's merely-ordinary refusal must never mask an earlier pass's real plumbing break (or
/// vice versa — an earlier ordinary refusal must never mask a LATER genuine failure). Only
/// when NEITHER side is a mechanism failure does the merged result stay in the ordinary
/// (`Containment`) bucket. Either way, both sides' messages are preserved in the combined
/// `detail`/`io::Error` text — only the final Rust VARIANT is decided by severity, not by
/// which `Error` happened to already exist when the second one arrived.
fn combine_group_errors(first: Error, latest: Error) -> Error {
    let detail = format!("{first}; {latest}");
    if crate::child::is_teardown_mechanism_failure(&first) || crate::child::is_teardown_mechanism_failure(&latest) {
        Error::Io(io::Error::other(detail))
    } else {
        Error::Containment { detail }
    }
}

impl Marker {
    pub(crate) fn new(
        prepared: PreparedMarker,
        root: Option<ProcessId>,
        pgid: Option<i32>,
        root_denied: bool,
    ) -> Marker {
        debug_assert!(
            !(root_denied && root.is_some()),
            "root_denied must only be set when root is None"
        );
        Marker {
            read: prepared.read,
            handle: prepared.handle,
            read_handle: prepared.read_handle,
            root,
            root_denied,
            pgid,
            own_fd: prepared.fd,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))] // consumed by Child::test_marker_handle (test-only)
    pub(crate) fn handle(&self) -> u64 {
        self.handle
    }

    /// The descriptor number the marker occupies in the child. Consumed by
    /// `Child::test_fdmarker_fd`, this crate's own `#[doc(hidden)]` test-only accessor for
    /// `tests/*.rs` (see `own_fd`'s doc comment for why this exists).
    pub(crate) fn own_fd(&self) -> RawFd {
        self.own_fd
    }

    /// Whether this marker carries a pgid to `killpg`/`term_group` on sweep — `true` for
    /// every mode except `TreeWalk` (`pgid: None`, no process group). Exposed so
    /// `Child::kill_tree`/`terminate_tree`'s pgid-recycle precondition assert
    /// (`src/child.rs`, `src/tokio/child.rs`) can extend to `Attached::FdMarker` exactly as
    /// it already covers `Attached::ProcessGroup`: this mechanism fires `killpg` on `self.pgid`
    /// unconditionally on pass 1, so the same recycled-pgid hazard applies to it.
    pub(crate) fn has_pgid(&self) -> bool {
        self.pgid.is_some()
    }

    /// Test-only: force the group channel's pgid, to drive `unix::signal_group`'s real
    /// `pgid <= 0` guard — a real, privilege-free `Error::Unassessable { source: None, .. }`
    /// path — deterministically through the REAL public `Child::kill_tree`/`Drop` path.
    /// Consumed by `Child::test_force_fdmarker_pgid` (`src/child.rs`), which is what a test
    /// outside this module actually calls; see its doc for why this exists.
    #[cfg(test)]
    pub(crate) fn force_pgid_for_test(&mut self, pgid: i32) {
        self.pgid = Some(pgid);
    }

    /// The supervisor's read end. `read()` on it returns EOF exactly when the last holder of
    /// the write end is gone.
    pub(crate) fn read_end(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }

    /// Block until every holder of the marker's write end has EXITED (not reaped), or until
    /// `deadline` — see `marker_eof::block_until_drained`'s own doc for what `deadline` means
    /// and what it guarantees.
    ///
    /// Calls [`check_read_end_still_valid`](Self::check_read_end_still_valid) FIRST, exactly
    /// like `hard_kill`/`terminate` do: `marker_eof::block_until_drained` takes a bare
    /// `BorrowedFd` and has no way to know it is still the SAME kernel object `self` was built
    /// around, only that the number is still open. Skipping this check here would let a
    /// reissued fd (an unrelated pipe with no open write end) deliver `EV_EOF` immediately and
    /// report `AllMembersExited` for a fully live tree — the same false-edge risk `hard_kill`
    /// refuses on, not merely a discrepancy between two code paths.
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<Option<Instant>>,
    ) -> Result<crate::containment::TreeDrain, Error> {
        self.check_read_end_still_valid()?;
        // This process is the supervisor: it must have closed its own copy of the write end at
        // spawn time (`install`'s contract), or the edge could never fire. A deliberately
        // constructed `HeldByUs` condition still needs a real `Err`, not a panic, so the
        // enforcement lives in `refuse_if_write_end_held`'s `Err` return, not here; this assert
        // instead catches a violation of that contract reaching THIS, the crate's own call
        // site, in debug builds — the crate's own code path, not a test deliberately
        // constructing the condition.
        debug_assert_ne!(
            crate::containment::marker_eof::write_end_check(self.read_end()),
            crate::containment::marker_eof::WriteEndCheck::HeldByUs,
            "the supervisor still holds a copy of the marker write end - the tree-drain edge can never fire"
        );
        crate::containment::marker_eof::block_until_drained(self.read_end(), deadline)
    }

    /// `Err` distinguishes a genuine teardown-mechanism failure (`Error::Io`/`Unsupported`,
    /// or `Unassessable` with a `source`) from an ORDINARY outcome — a live member refused
    /// the signal, or could not be fully assessed/reached (`Error::Containment` /
    /// `Error::Unassessable { source: None, .. }`) — the same distinction #61 established
    /// for `ProcessGroup`/`Session` (`src/containment/unix.rs`'s `verify`). Callers, in
    /// particular `is_teardown_mechanism_failure` (`src/child.rs`), rely on that distinction
    /// surviving intact through this return value; see `sweep`'s own doc for where it is
    /// preserved.
    pub(crate) fn hard_kill(&self) -> Result<(), Error> {
        self.check_read_end_still_valid()?;
        let mut seen: std::collections::HashSet<ProcessId> = std::collections::HashSet::new();
        // Folds together across every pass — see `sweep_pass`'s doc for why an earlier pass's
        // failure must not be erased by a later pass's success or vice versa.
        let mut group_result: Result<(), Error> = Ok(());
        // True if ANY pass was blind, ANY marker holder could not be resolved, or ANY signal
        // attempt was refused by the OS — checked exactly once, by `finish_sweep`, regardless
        // of which pass it happened on.
        let mut incomplete = false;
        let mut first_pass = true;
        // Re-snapshots and re-computes after every signalled pass, repeating while a fresh pass
        // BOTH finds identities this sweep has not already signalled AND actually resolves at
        // least one of them (`sweep_pass`'s return value) — no numeric cap (forbidden by this
        // crate's no-arbitrary-loop-limit rule); see `sweep_pass`'s doc for termination.
        loop {
            let progressed = self.sweep_pass(
                nix::sys::signal::Signal::SIGKILL,
                &mut seen,
                &mut group_result,
                &mut incomplete,
                first_pass,
            );
            first_pass = false;
            if !progressed {
                break;
            }
        }
        Self::finish_sweep(self.handle, group_result, incomplete)
    }

    /// See [`hard_kill`](Self::hard_kill)'s doc for what `Err` does and does not mean here, and
    /// `sweep_pass`'s doc for the shared per-pass mechanics. Unlike `hard_kill`, this never
    /// loops: SIGTERM is catchable and ignorable, so a re-snapshot loop could spin forever
    /// against a member that traps it and keeps forking on every delivery, hanging
    /// `terminate_tree()` — a blocking API with no timeout — forever. One pass, matching
    /// `term_group`'s own cooperative, best-effort contract; `hard_kill` (`kill_tree`) is the
    /// guaranteed sweep.
    pub(crate) fn terminate(&self) -> Result<(), Error> {
        self.check_read_end_still_valid()?;
        let mut seen: std::collections::HashSet<ProcessId> = std::collections::HashSet::new();
        let mut group_result: Result<(), Error> = Ok(());
        let mut incomplete = false;
        self.sweep_pass(
            nix::sys::signal::Signal::SIGTERM,
            &mut seen,
            &mut group_result,
            &mut incomplete,
            true,
        );
        Self::finish_sweep(self.handle, group_result, incomplete)
    }

    /// CONTRACT, re-checked on every `hard_kill`/`terminate` call, not just at `Marker::new`
    /// time: `self.read` must STILL be a pipe descriptor naming its OWN recorded handle. Rust
    /// ownership already makes "a sweep cannot run after `self.read` is dropped" a compile error
    /// (both callers borrow `&self`), but that only proves the FD IS STILL OPEN, not that it
    /// still names the SAME kernel object.
    ///
    /// This checks `read`'s OWN handle (`self.read_handle`), NOT its peer's — a peer check
    /// is wrong here and was measured to be wrong: once the LAST write end anywhere closes
    /// (the ordinary, ROUTINE case — the tree drained before `Child::drop` swept it, which
    /// is exactly what `hard_kill_never_reaches_a_pid_that_closed_the_marker_before_the_
    /// sweep` exercises), the read end's PEER handle reports `0` while the read end's OWN
    /// handle stays valid for as long as `read` itself stays open. A peer check here would
    /// fire on that ordinary path; `install()`'s peer check (both ends provably open then)
    /// is where that check belongs, not here.
    ///
    /// **This is not an ordinary internal-consistency assertion, so it is not `debug_assert!`
    /// -only.** Its documented failure mode is the worst outcome this whole design exists to
    /// prevent: a stale `read_handle` means `self.handle`/`self.read_handle` could now name
    /// ANY unrelated live pipe the OS has reissued the identity onto, and `holders()`
    /// matching by raw handle equality would then confirm-and-SIGKILL a stranger with no
    /// indication anything was wrong. A single debug-only line is not enough defense for that
    /// severity; it is checked in EVERY build, and a violation refuses to sweep at all rather
    /// than proceeding on a handle that may no longer mean what `self` claims.
    fn check_read_end_still_valid(&self) -> Result<(), Error> {
        let read_still_valid = matches!(
            fd_pipe_info(std::process::id(), self.read.as_raw_fd()),
            FdPipeInfoQuery::Found(info) if info.pipe_handle == self.read_handle
        );
        debug_assert!(
            read_still_valid,
            "fd marker {:#x}: the read end must still be the same pipe object at sweep time",
            self.handle
        );
        if !read_still_valid {
            let msg = format!(
                "fd marker {:#x}: the read end no longer names its recorded pipe object at \
                 sweep entry — refusing to sweep rather than signal against a handle that may \
                 now name an unrelated live pipe",
                self.handle
            );
            log::error!("{msg}");
            // A genuine mechanism failure (this process's own bookkeeping is stale, not a
            // member's refusal) — `Error::Io` is the correct classification here, not
            // `Containment`/`Unassessable`.
            return Err(Error::Io(io::Error::other(msg)));
        }
        Ok(())
    }

    /// One pass of `hard_kill`/`terminate`: snapshot, compute, signal. Three membership
    /// channels, deduplicated across the whole sweep (via `seen`, carried by the caller across
    /// passes) by IDENTITY, not raw pid — a pid signalled and reaped on one pass can be
    /// recycled by the OS onto a genuinely new fork of a still-live tree member before the next
    /// pass's snapshot, and deduping on the raw pid would then skip that new, never-signalled
    /// process, reintroducing the exact pid-reuse ambiguity `kill_by_identity` exists to close,
    /// one layer up. Resolving identity for a marker-channel candidate happens HERE, at
    /// discovery, not deferred to `kill_holder` — `kill_holder` still re-verifies at signal time
    /// (the window between discovery and signal, not between passes).
    ///
    /// Returns whether this pass made progress: resolved at least one newly-discovered identity
    /// to something other than "OS refused" (killed, already gone, or confirmed not a member all
    /// count; `KillOutcome::NotAttempted`/`MarkerQuery::Denied` do not). `hard_kill` loops on
    /// this — not on "found something new" alone — because this design deliberately leaves some
    /// discovered identities unsignalled (an EPERM-unkillable member, say); if such a member
    /// keeps forking, each child is a genuinely new, never-before-seen identity, so "found
    /// something new" would stay true forever even though nothing is actually being resolved, an
    /// unbounded spin with no numeric cap to stop it (forbidden by this crate's
    /// no-arbitrary-loop-limit rule). A pass where every new discovery is stuck makes no
    /// progress, and `hard_kill` stops, not spins.
    ///
    /// **A single snapshot-compute-signal pass has a check-then-act gap a real tree can hit.**
    /// Between the snapshot and the signal, any live member can `fork` a child that inherits the
    /// marker; that child is in no channel of THIS pass (its ppid edge postdates `parents`, it
    /// isn't in `pids`, and if its parent already left the group it isn't reachable by `killpg`
    /// either). If the parent is then killed, the child reparents to launchd and is lost for
    /// good — precisely the escapee class this mechanism exists to close. `hard_kill`'s
    /// re-snapshot loop is what closes it, over repeated passes; a single `terminate` pass
    /// accepts this gap, matching `term_group`'s own cooperative, non-chasing contract.
    ///
    /// **A blind pass, an unresolvable holder, and a refused signal are all real teardown gaps
    /// — none of them is convergence, and NONE of them may be reported as `Ok(())`.**
    /// `enumerate::snapshot()` returns an empty pid list on its own internal failure (logged
    /// there) — never on a genuinely converged pass (there is always at least launchd and this
    /// process on a real host). Neither the root (`self.root`, already a resolved `ProcessId`)
    /// nor the process group (`self.pgid`, a plain integer) needs a snapshot, so a blind FIRST
    /// pass still attempts both: the root is not yet in `seen`, and pass 1's group signal fires
    /// unconditionally. A blind LATER pass attempts NEITHER: the root is already in `seen` (see
    /// below), and the group signal's re-fire gate needs THIS pass's own holder scan to confirm
    /// a live member — a scan a blind pass never ran. "Not observed" is not "observed absent",
    /// and this function's log messages say so explicitly rather than crediting a channel with
    /// running when it could not have; `*incomplete = true` is what keeps `finish_sweep` from
    /// reporting `Ok(())` regardless. A marker-holder pid that resolves `Resolved::Unknown`
    /// (access denied), a `MarkerQuery::Denied` re-check, and a `kill_by_identity`/`kill_holder`
    /// outcome of `KillOutcome::NotAttempted` (the OS refused to query or signal an identity
    /// that WAS resolved), are each a known member this pass could not verify or reach; the
    /// caller folds every one of them into the same `incomplete` flag, checked exactly once by
    /// `finish_sweep`.
    ///
    /// A `NotAttempted` identity is NOT retried on a later pass — retrying would hit the same OS
    /// refusal again — but it IS already in `seen`, so it does not re-enter `new_walk`/
    /// `new_holders` either; it is simply left running, logged, and folded into `incomplete`,
    /// the same disposition `treewalk::hard_kill`'s single pass already gives it. The same
    /// `seen` membership is why the root itself is never retried on any later pass, blind or
    /// not: pass 1 already inserted it.
    ///
    /// **Deliberately NOT in `incomplete`: `snapshot()`'s bulk denied-ppid-read count.**
    /// `PROC_PIDTBSDINFO` denies for every process this caller does not own — measured on this
    /// host, 327 of 1022 live pids, from an ordinary unprivileged shell, right now. Escalating
    /// that bulk count would make `Ok(())` unreachable on any real multi-user host;
    /// `snapshot()` logs it in aggregate for visibility (matching `holders()`'s own aggregate
    /// `debug!` for the identical class of mostly-irrelevant host-wide denials), and this
    /// function escalates a ppid-read denial only insofar as it prevents a SPECIFIC candidate
    /// from being resolved — which the `Resolved::Unknown`/`Denied`/`NotAttempted` arms above
    /// already cover at the granularity where a denial is actually diagnostic.
    ///
    /// Each channel covers a gap the others have: a member that lost the marker but kept its
    /// ppid chain is caught by the walk; a member that left the group and was reparented is
    /// caught only by the marker; a member that lost the marker AND was reparented but stayed in
    /// the group is caught only by `killpg`.
    ///
    /// **The group signal's re-fire gate.** Pass 1 fires unconditionally, carrying exactly
    /// today's baseline `killpg`/`ProcessGroup` pgid-reuse risk (`src/containment/unix.rs`) — a
    /// resolve-then-signal window this design does not try to close further. A LATER pass
    /// re-fires only when THIS pass's own marker-holder scan (`this_pass_holders`, computed
    /// above, before this block runs) contains a pid that is BOTH signalable and, queried via
    /// `getpgid` right here, reports membership in `self.pgid`. `getpgid` on a gone pid fails
    /// (`ESRCH`), so a successful, matching call is itself live-membership proof — no separate
    /// liveness check is needed, and no zombie can satisfy it: `holders()` only reports pids the
    /// fd-table scan found with an OPEN descriptor, which a zombie cannot hold (every fd closes
    /// before a process becomes a zombie), so this candidate set is narrower than `self.root`'s
    /// own `is_alive()` in exactly the way that matters — this design tried `self.root`'s
    /// identity as the anchor first, and it does not work: pass 1's `killpg` signals the WHOLE
    /// group, including the root itself (the root is always a member of its own `self.pgid`, by
    /// this crate's process-group convention), so `self.root` is already a SIGKILL target the
    /// instant pass 1's group signal is sent — deferring only the walk channel's OWN
    /// `kill_by_identity(root)` call changes nothing, because the root dies from the group
    /// signal regardless of what the walk channel does. And once signalled, a root that has not
    /// yet been reaped reads `Liveness::Dead` (`identity/macos.rs` reports `Dead` for a zombie),
    /// not merely "eventually recycled" — so `root.is_alive()` is false on every later pass of
    /// an ORDINARY teardown, not just an unlucky one, and the group signal would never re-fire
    /// at all. A live, marker-confirmed member has no such flaw: it is not the process pass 1's
    /// own signal necessarily kills, so when the scan finds one, it is real, current evidence,
    /// not a proxy this design's own prior action already invalidated.
    ///
    /// **What this gate proves, and what it does not — stated precisely, not overclaimed.** A
    /// successful, matching `getpgid` call is a real, positive fact: AT THAT INSTANT, a live
    /// process was a confirmed member of `self.pgid`'s group, which — because a process group's
    /// numeric id cannot be freed for reuse while any process remains a member of it — proves
    /// `self.pgid` had not yet been recycled onto an unrelated group at that instant. It does
    /// NOT prove `self.pgid` is still valid microseconds later when `killpg` actually runs: the
    /// `getpgid` check and the `killpg` call are two separate syscalls, and the checked member
    /// could exit (releasing the last hold on `self.pgid`) in the gap between them. This is the
    /// same class of check-then-act window `src/containment/unix.rs` already documents for
    /// `ProcessGroup`'s own one-shot `killpg` — narrowed here to "immediately after a live
    /// member was freshly confirmed," not eliminated, and this module makes no claim beyond
    /// that.
    fn sweep_pass(
        &self,
        signal: nix::sys::signal::Signal,
        seen: &mut std::collections::HashSet<ProcessId>,
        group_result: &mut Result<(), Error>,
        incomplete: &mut bool,
        first_pass: bool,
    ) -> bool {
        // Snapshot FIRST, always — the group-signal-ordering invariant below depends on this
        // pass's snapshot (when one is obtained) predating any signal sent this pass.
        // `_ppid_denied` is intentionally NOT folded into `incomplete` — see this fn's doc.
        let (pids, parents, _ppid_denied) = crate::containment::enumerate::snapshot();
        let blind = pids.is_empty();
        if blind {
            *incomplete = true;
            if first_pass {
                log::warn!(
                    "fd marker {:#x}: the host process table could not be read on the first \
                     pass; the ppid-walk and marker channels are blind (the group signal and \
                     root kill below still run, since neither needs the process table)",
                    self.handle
                );
            } else {
                log::warn!(
                    "fd marker {:#x}: the host process table could not be read this pass; \
                     every channel is blind this pass — the root was already handled on an \
                     earlier pass and is not retried, and the group signal does not re-fire \
                     without a live member freshly confirmed THIS pass (not observed this \
                     pass is not the same as observed absent). This pass performs no teardown \
                     on any channel",
                    self.handle
                );
            }
        }

        // A root that could not be resolved BECAUSE the OS refused (not because it had already
        // exited — see `Marker::root_denied`'s doc) is a standing gap for this marker's whole
        // life: fold it in every pass, the same as a blind pass or an unqueryable holder.
        if self.root_denied {
            *incomplete = true;
        }

        // Channel 1+2: the root (needs no snapshot — already a resolved `ProcessId`) plus its
        // ppid-walk descendants NOT already signalled this sweep (need THIS pass's snapshot;
        // skipped when blind, since there is nothing to walk). `descendants` applies the
        // crate's own token guard against the root.
        let mut new_walk: Vec<ProcessId> = Vec::new();
        if let Some(root) = self.root {
            if seen.insert(root) {
                new_walk.push(root);
            }
            if !blind {
                for id in crate::containment::treewalk::descendants(root, &parents) {
                    if seen.insert(id) {
                        new_walk.push(id);
                    }
                }
            }
        }

        // Channel 3: every marker holder found THIS pass, captured once in full (not just
        // newly-discovered ones) — the group-signal gate below needs to check EVERY confirmed
        // holder this pass, not only the ones this sweep has not already dealt with.
        let this_pass_holders: Vec<Holder> = if blind { Vec::new() } else { holders(self.handle, &pids) };
        let mut new_holders: Vec<ProcessId> = Vec::new();
        for h in &this_pass_holders {
            if !is_signalable(h.pid) {
                // Reaching this branch at all means `h.pid` is the supervisor, pid 0, or pid 1
                // — every one of which is a defect in this process's own marker plumbing (the
                // write end must never reach any of them), not a routine miss. Both the log and
                // the debug-build contract check cover all three, not just the supervisor case.
                log::warn!(
                    "fd marker {:#x}: self-exclusion guard fired for pid {} found in the \
                     holder set (the supervisor or pid 0/1 must never hold its own marker)",
                    self.handle,
                    h.pid
                );
                debug_assert!(
                    false,
                    "fd marker sweep found pid {} in its own holder set (supervisor, pid 0, or \
                     pid 1) — the write-end hand-off must never reach any of them",
                    h.pid
                );
                continue;
            }
            let id = match ProcessId::of(h.pid) {
                Resolved::Found(id) => id,
                Resolved::Gone => continue,
                Resolved::Unknown => {
                    log::warn!(
                        "fd marker {:#x}: holder pid {} could not be queried (access denied?) \
                         - not signaled, left running",
                        self.handle,
                        h.pid
                    );
                    *incomplete = true;
                    continue;
                }
            };
            if seen.insert(id) {
                new_holders.push(id);
            }
        }

        // Group signal: pass 1 unconditionally; a later pass only when this pass's own holder
        // scan just confirmed a live member of `self.pgid` — see this fn's doc for what that
        // does and does not prove. Always after THIS pass's other channels are computed:
        // signalling the process group before a pass's own channels are computed would destroy
        // the channel that pass reads (an intermediate in the group whose child lost the marker
        // below a scrubbing spawn path but still chains by ppid would be killed, reparenting
        // that child to launchd before the snapshot sees it — reachable by no channel at all).
        // `group_result` folds together across passes (a later pass's success does not erase an
        // earlier failure, and vice versa) so a transient failure on one pass is not silently
        // dropped by the next pass's success.
        {
            // `!blind &&`, not merely an empty `this_pass_holders`: a blind pass never ran the
            // scan at all ("not observed"), which must not read the same as a genuine scan that
            // found nobody ("observed absent") — both happen to produce an empty `Vec`, but only
            // the second is evidence the pgid was not confirmed live this pass.
            let live_holder_confirms_pgid = !blind
                && self.pgid.is_some_and(|pgid| {
                    this_pass_holders
                        .iter()
                        .any(|h| is_signalable(h.pid) && pid_is_live_group_member(h.pid, pgid))
                });
            let should_fire = first_pass || live_holder_confirms_pgid;
            if should_fire {
                // `kill_group`/`term_group` already return `crate::error::Error`, carrying
                // #61's own `Error::Containment`/`Error::Unassessable` distinction for an
                // ordinary refusal — preserved as-is here, NOT collapsed into a stringified
                // `io::Error` (see this fn's doc, and `combine_group_errors` below).
                let this_pass_group_result: Result<(), Error> = match (self.pgid, signal) {
                    (Some(pgid), nix::sys::signal::Signal::SIGKILL) => crate::containment::unix::kill_group(pgid),
                    (Some(pgid), _) => crate::containment::unix::term_group(pgid),
                    (None, _) => Ok(()),
                };
                *group_result = match (std::mem::replace(group_result, Ok(())), this_pass_group_result) {
                    (Ok(()), r) => r,
                    (e @ Err(_), Ok(())) => e,
                    (Err(first), Err(latest)) => Err(combine_group_errors(first, latest)),
                };
            } else if self.pgid.is_some() {
                if blind {
                    log::debug!(
                        "fd marker {:#x}: skipping this pass's group signal — the process \
                         table could not be read this pass, so no live member of this pass's \
                         pgid was observed (not: none was found)",
                        self.handle
                    );
                } else {
                    log::debug!(
                        "fd marker {:#x}: skipping this pass's group signal — no live member \
                         confirmed this pass's pgid, so it may have been recycled",
                        self.handle
                    );
                }
            }
        }

        if new_walk.is_empty() && new_holders.is_empty() {
            return false; // converged this pass — nothing left to signal, no progress made.
        }
        let mut progressed = false;
        for id in new_walk {
            // Test-only fault seam: skip the root's identity kill (take semantics — see
            // `fault`), mirroring `treewalk::hard_kill`'s own seam so a test can force the
            // `kill_tree` handle backstop to be the sole killer regardless of which mechanism a
            // given platform actually attaches for a request.
            #[cfg(test)]
            if Some(id) == self.root && fault::take_force_root_kill_noop() {
                continue;
            }
            // `KillOutcome::NotAttempted` means the OS refused to query or signal an identity
            // that WAS resolved — a known member left running, not a gap in discovery. Not
            // retried (see this fn's doc); folded into `incomplete`. Anything else
            // (`Terminated`, `AlreadyGone`) is a real resolution: progress.
            if crate::containment::treewalk::kill_by_identity(id, signal)
                == crate::containment::treewalk::KillOutcome::NotAttempted
            {
                *incomplete = true;
            } else {
                progressed = true;
            }
        }
        for id in new_holders {
            if self.kill_holder(id, signal) {
                *incomplete = true; // NotAttempted or Denied
            } else {
                progressed = true; // NotHeld (resolved) or a signal actually attempted
            }
        }
        progressed
    }

    /// Fold `incomplete` into the final `Result` — see `sweep_pass`'s doc for why a blind pass
    /// or an unresolved member is a real gap, never silently `Ok(())` — merged against
    /// `group_result` with the same severity-aware rule `combine_group_errors` uses between
    /// passes.
    fn finish_sweep(handle: u64, group_result: Result<(), Error>, incomplete: bool) -> Result<(), Error> {
        if incomplete {
            let msg = format!(
                "fd marker {handle:#x}: teardown may be incomplete — the host process table \
                 was unreadable on at least one pass, or at least one known/suspected member \
                 could not be assessed or signalled"
            );
            // `incomplete` alone (no io::Error anywhere in its own tracking — it is a summary
            // bool, not a captured syscall failure) is the SAME kind of ordinary, expected
            // outcome `Error::Unassessable { source: None, .. }` already names for
            // `ProcessGroup`/`Session` (`unix.rs`'s `verify`, `group::state`'s per-member
            // `Refused { unassessable, .. }` arm): specific members left running or
            // unconfirmed, not proof the mechanism's own plumbing broke. `source: None` here
            // is not a downgrade of real information — this path never had a captured
            // `io::Error` to attach; `enumerate::snapshot()` already logs a blind pass itself
            // (see its own module docs) rather than surfacing one to the caller.
            let incomplete_err = Error::Unassessable {
                detail: msg,
                source: None,
            };
            return match group_result {
                Ok(()) => Err(incomplete_err),
                Err(group_err) => Err(combine_group_errors(incomplete_err, group_err)),
            };
        }
        group_result
    }

    /// Kill one marker holder (already identity-resolved by the caller for dedup), closing the
    /// discovery-to-signal window this one pass opens.
    ///
    /// `id` was resolved at discovery time; between then and now it could have exited (its pid
    /// recycled onto a stranger) or genuinely stopped holding the marker (the `close(fd)`
    /// escape). `holds_marker` re-verifies membership against the SAME pid; `kill_by_identity`
    /// then re-verifies the identity once more immediately before signalling, closing the
    /// remaining window exactly as the tree walk does.
    ///
    /// No separate start-token order guard: unlike the ppid-walk channel (where a stale ppid can
    /// point at a recycled root pid, which is what `treewalk`'s token guard defends against),
    /// membership re-checked HERE, at signal time, is already a complete proof — `Marker.handle`
    /// names a kernel object that cannot be reissued while `self.read` is held (the module's
    /// central invariant), so a pid that currently holds an fd naming it can only be a real
    /// inheritor of this marker's write end.
    ///
    /// Uses `holds_marker_query` (the tri-state), not the plain-`bool` `holds_marker`: a
    /// confirmed non-holder and a DENIED re-check are different facts here specifically. The
    /// pid reaching this function was found by `holders()` moments earlier, this same pass —
    /// so a `Denied` result now means a KNOWN member became unqueryable between discovery and
    /// signal (almost always the credential-changing `exec` the module docs name), not the
    /// documented `close(fd)` escape. `holders()`'s own aggregate-only denial logging does not
    /// apply here for exactly that reason: this pid is not an arbitrary host process, it is a
    /// confirmed candidate, so a denial here is worth a `warn!` on its own.
    ///
    /// Returns `true` iff this identity was left unsignalled for a reason that means teardown
    /// may be incomplete — `KillOutcome::NotAttempted` OR a `Denied` re-check — which the
    /// caller folds into `incomplete`. `false` covers every other outcome: a confirmed
    /// non-holder (not incomplete, just resolved), or a signal that was actually attempted
    /// (delivered, or already gone, which `kill_by_identity` treats as success).
    fn kill_holder(&self, id: ProcessId, signal: nix::sys::signal::Signal) -> bool {
        match holds_marker_query(id.pid(), self.handle) {
            MarkerQuery::NotHeld => {
                log::debug!(
                    "fd marker {:#x}: pid {} no longer holds the marker - not signaled",
                    self.handle,
                    id.pid()
                );
                false
            }
            MarkerQuery::Denied => {
                log::warn!(
                    "fd marker {:#x}: pid {} (a confirmed holder this pass) could not be \
                     re-queried before signalling (access denied?) - not signaled, left \
                     running",
                    self.handle,
                    id.pid()
                );
                true
            }
            MarkerQuery::Held => {
                crate::containment::treewalk::kill_by_identity(id, signal)
                    == crate::containment::treewalk::KillOutcome::NotAttempted
            }
        }
    }
}

#[cfg(test)]
#[path = "fdmarker_tests.rs"]
mod fdmarker_tests;
