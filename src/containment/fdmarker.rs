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
//! unqueryable via `PROC_PIDLISTFDS` (`EPERM`) — and this design's disposition for that pid
//! depends on which OTHER channel, if any, can still see it, not on one uniform "logged, left
//! running" answer.** If the ppid-walk channel can still place it as a descendant of the
//! contained root (its own ppid-read is not ALSO denied, nor any ancestor's), `sweep` already
//! folds that gap into `incomplete` via the ppid-walk channel's own denial accounting —
//! `holders()`'s OWN denial for the identical pid is then redundant, correctly left as an
//! aggregate `debug!` (below), not a second `warn!` for the same known gap. But a pid the
//! ppid-walk channel CANNOT place — the double-fork-reparented-to-launchd orphan this whole
//! mechanism exists to reach, the module's own primary scenario — that ALSO becomes
//! `PROC_PIDLISTFDS`-denied has no channel left to catch it at all: `holders()` folds it into
//! the SAME aggregate, never-escalated denial count as ordinary unrelated-host-pid noise
//! (below), so `sweep` can return `Ok(())` while that one pid is a real, live, completely
//! un-swept member. This is deliberately NOT escalated to `incomplete` — doing so would
//! require folding `holders()`'s bulk per-scan denial count in (hundreds of unrelated host
//! pids on a real multi-user host, matching exactly the reasoning `enumerate::snapshot()`'s
//! ppid-denial count is ALSO deliberately excluded from `incomplete`), making `Ok(())`
//! unreachable on any real host. Accepted as a symmetric extension of that already-accepted
//! tradeoff, not a new one — but stated here plainly, since a reparented orphan that ALSO
//! changes credentials is exactly the intersection this module's own name promises to close.
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

use std::os::fd::{AsRawFd, BorrowedFd};

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
    pipe_handle: u64,
    pipe_peerhandle: u64,
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
enum FdPipeInfoQuery {
    Found(PipeFdInfo),
    /// Not a pipe, the fd closed, or the pid is gone — indistinguishable at this layer, and
    /// (unlike `PipeQuery`) not worth separating: nothing calls this hoping to count denials
    /// against a NOT-yet-confirmed candidate the way `holders()`'s outer `pipe_fds_of` does.
    Absent,
    /// The OS refused the query (measured: the same `0`-with-`EPERM` shape as `PROC_PIDLISTFDS`).
    Denied,
}

fn fd_pipe_info(pid: RawPid, fd: libc::c_int) -> FdPipeInfoQuery {
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
enum PipeQuery {
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
        out.push(Holder { pid, clexec: all_clexec });
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
fn pipe_fds_of(pid: RawPid) -> PipeQuery {
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    let needed = clear_errno_and_call(|| unsafe {
        libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    });
    if needed <= 0 {
        return classify_pidlistfds_failure();
    }
    let mut cap = needed as usize / entry + 16;
    loop {
        let mut fds: Vec<libc::proc_fdinfo> = vec![unsafe { std::mem::zeroed() }; cap];
        let buf_bytes = (cap * entry) as libc::c_int;
        // SAFETY: `fds` owns `buf_bytes` writable bytes; proc_pidinfo writes proc_fdinfo records.
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

#[cfg(test)]
#[path = "fdmarker_tests.rs"]
mod fdmarker_tests;
