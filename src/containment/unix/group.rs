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

use nix::sys::signal::Signal;

use crate::containment::{check_number, Root};
use crate::identity::{ProcessId, RawPid};

/// One process-group member as the listing found it, carrying the identity (built from the
/// same record that named the pid) needed to re-verify later that a check still lands on the
/// SAME process (`converge`, below) rather than a zombie or a pid recycled onto someone else.
///
/// `system`: xnu's own `P_SYSTEM` flag (see `identity::kinfo::P_SYSTEM`), read directly from
/// the same `kinfo_proc` record the listing already fetched — no second syscall. Always
/// `false` on Linux and other Unix: their listings carry no equivalent flag, and `killpg`'s
/// own kernel-side exclusion this crate must mirror (see `excluded_from_sigkill_resend`) is
/// specifically xnu's `killpg1` behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) id: ProcessId,
    pub(crate) system: bool,
}

/// Every process the kernel currently lists in process group `pgid`. An empty result means
/// the group holds nothing — not an error.
///
/// macOS: `sysctl(KERN_PROC_PGRP)`, which lists a group belonging to another user
/// unprivileged (verified, this file's Background) and reports each member's start time in
/// the same record as its pid. libproc's `proc_listpgrppids` is deliberately NOT used: it
/// returns a COUNT where its siblings return bytes, and it carries no start time.
#[cfg(target_os = "macos")]
pub(crate) fn members(_kernel: &dyn crate::identity::Kernel, pgid: i32) -> std::io::Result<Vec<Member>> {
    use crate::identity::kinfo::kinfo_proc;

    const RECORD: usize = std::mem::size_of::<kinfo_proc>();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PGRP, pgid];
    // Extra headroom beyond the (padded) sizing query's own answer, doubled on every genuine
    // ENOMEM retry below — NOT a retry cap (the loop itself stays uncapped; only the buffer
    // grows). A single fixed slack, re-derived fresh from a new sizing query on every retry,
    // has no termination argument against a group that keeps growing faster than that
    // one-record margin between the sizing and fetch calls (the sizing-to-fetch gap here is
    // two syscalls back to back, narrower than a full signal-and-relist pass but still real).
    // Doubling `slack` on each ENOMEM guarantees it eventually exceeds any BOUNDED
    // per-iteration growth rate (forking still takes non-zero wall-clock time even in a tight
    // loop), giving a genuine, finite termination argument, not a probability one.
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
        // `identity/macos/kinfo.rs`'s single-pid reader already guards, via its own
        // size-mismatch `contract_violation`. Reject rather than reinterpret at the wrong
        // stride, which would silently produce garbage `p_pid` values that `converge` would
        // then send a real signal to.
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
                id: ProcessId::from_parts(
                    k.kp_proc.p_pid as RawPid,
                    // SAFETY: the kernel's KERN_PROC copy always fills `p_starttime`
                    // (see `identity::macos::token_of_kinfo`, the same formula).
                    unsafe {
                        k.kp_proc.p_un.p_starttime.tv_sec as u64 * 1_000_000 + k.kp_proc.p_un.p_starttime.tv_usec as u64
                    },
                ),
                system: k.kp_proc.p_flag & crate::identity::kinfo::P_SYSTEM != 0,
            })
            .collect());
    }
}

/// Linux: scan the checked `/proc` (`identity::linux::proc_view_with`) and keep the entries whose
/// `stat` field 5 is `pgid`. Each such pid's identity is then made by `ProcessId::of_stat_with`,
/// with a `stat` of its own, and kept only if that `stat` still shows `pgid`: a pid that changed
/// hands since the scan is no member. There is no narrower kernel interface for process-group
/// membership.
///
/// A `/proc` from another pid namespace is an error naming the view, not an empty group. Without
/// `openat2` (Linux < 5.6, or seccomp) no view can be checked: `ErrorKind::Unsupported`. A `stat`
/// read fails the listing unless the pid exited (`ENOENT`/`ESRCH`) or `hidepid` hides it
/// (`EACCES`, or `EPERM` while the checked directory still answers). A member whose pidfd cannot
/// be opened fails the listing too (`ErrorKind::Unsupported` for a refused `pidfd_open`, `Other`
/// for a transient one such as `EMFILE`): its identity is told through the pidfd, and leaving it out
/// could clear a live group.
#[cfg(target_os = "linux")]
pub(crate) fn members(kernel: &dyn crate::identity::Kernel, pgid: i32) -> std::io::Result<Vec<Member>> {
    use crate::identity::stat_parse::parse_pgrp;
    use crate::identity::Resolved;

    let proc_dir =
        crate::identity::proc_view_with(kernel)
            .into_dir()
            .map_err(|why| match why.openat2_requirement() {
                Some(requirement) => std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("containment::unix::group::members: {requirement}, so pgid {pgid} cannot be listed"),
                ),
                None => std::io::Error::other(format!(
                    "containment::unix::group::members: {why}, so its process listing says nothing about pgid {pgid}"
                )),
            })?;
    let mut out = Vec::new();
    // A listing error makes the whole scan unreliable; propagate it.
    for pid in kernel.pids(&proc_dir)? {
        let stat = match crate::identity::pid_stat::read_in_scan(kernel, &proc_dir, pid) {
            Ok(crate::identity::pid_stat::PidStat::Read(bytes)) => bytes,
            // A pid outside a `pgid` listing carries no information about it; the residual (a
            // foreign-uid member of `pgid` itself, hidden by `hidepid`) is documented on
            // `Child::kill_tree`.
            Ok(crate::identity::pid_stat::PidStat::Skipped(e)) => {
                log::debug!(
                    "containment::unix::group::members: /proc/{pid}/stat unreadable ({report}); excluding it",
                    report = crate::error::Report(&e)
                );
                continue;
            }
            // Excluding it could clear a live group.
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "containment::unix::group::members: {e}, so process group {pgid} cannot be listed"
                )));
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
        // The scan's `stat` is a record of whoever held `pid` then. The member's identity is made
        // by a read that pairs it with a `stat` of its own, and the membership is asked again of
        // that one: a pid that exited and was reused since the scan is not a member.
        let (id, own_stat) = match ProcessId::of_stat_with(kernel, pid) {
            (Resolved::Found(read), _) => read,
            (Resolved::Gone, _) => {
                log::debug!("containment::unix::group::members: pid {pid} is gone; excluding it");
                continue;
            }
            // A cause the read knows (an unusable `/proc` view, a refused or exhausted `pidfd_open`)
            // fails the listing, because excluding the member could clear a live group. A record
            // that merely would not parse, as a task exiting mid-read leaves, is excluded.
            (Resolved::Unknown, cause) => match cause.into_error(&format!("pid {pid}")) {
                Some(why) => {
                    // A refusal stays `Unsupported`, as the `openat2` arm above, so the caller
                    // reports the platform's `Unsupported` and not an unassessable group.
                    let kind = match why {
                        crate::error::Error::Unsupported { .. } => std::io::ErrorKind::Unsupported,
                        _ => std::io::ErrorKind::Other,
                    };
                    return Err(std::io::Error::new(
                        kind,
                        format!("containment::unix::group::members: {why}, so process group {pgid} cannot be listed"),
                    ));
                }
                None => {
                    log::debug!(
                        "containment::unix::group::members: pid {pid} matched pgid {pgid} but its identity \
                         could not be read; excluding it"
                    );
                    continue;
                }
            },
        };
        if parse_pgrp(&own_stat) != Some(pgid as u32) {
            log::debug!("containment::unix::group::members: pid {pid} is no longer in pgid {pgid}; excluding it");
            continue;
        }
        out.push(Member { id, system: false });
    }
    Ok(out)
}

/// Other Unix: the crate supports Linux, macOS and Windows (see
/// `containment::enumerate`), so there is no listing here. Reported as
/// unlistable rather than silently empty — an empty group would read as
/// "teardown succeeded".
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
pub(crate) fn members(_kernel: &dyn crate::identity::Kernel, _pgid: i32) -> std::io::Result<Vec<Member>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process-group membership is implemented only for Linux and macOS",
    ))
}

/// What a process group looked like after one signal-and-classify pass.
#[derive(Debug)]
pub(crate) enum GroupState {
    /// Nothing listed is both running (under the identity the listing saw) and beyond our
    /// reach.
    Cleared,
    /// These pids were listed, confirmed `Liveness::Alive` under the SAME identity the
    /// listing saw, and were not reached — the tree is still up. `SIGKILL` delivered
    /// successfully is not itself proof of death (a member wedged in uninterruptible sleep on
    /// a hung mount can accept `SIGKILL` and still not have exited yet) — this is an inherent
    /// limitation of any `kill(2)`-based mechanism, present before this fix and after it;
    /// closing it needs a bounded wait with a caller-supplied timeout, a distinct API-shape
    /// addition. `unassessable` carries any OTHER member whose state could not be determined
    /// at all — never silently dropped just because a confirmed refuser already settles the
    /// overall verdict; a caller reading the error should learn the group's true state may be
    /// WORSE than `refused` alone says, not just that one member refused.
    Refused {
        refused: Vec<RawPid>,
        unassessable: Vec<RawPid>,
    },
    /// The group's membership could not be listed (`source: Some`), or a listed member's
    /// liveness could not be assessed at all (`source: None`) — either way nothing can be
    /// said about whether the group is down. Mirrors `Error::Unassessable`'s own shape.
    Unlistable {
        detail: String,
        source: Option<std::io::Error>,
    },
}

/// Whether a live-confirmed member was actually reached by the signal/probe. A THIRD
/// answer, `Unknown`, is threaded all the way from the deepest primitive up through
/// `classify_member`: collapsing "could not assess" into a binary `bool` at the boundary
/// where the distinction matters most (inside `converge`'s `reached` closure) would silently
/// re-narrow the `Liveness::Unknown` handling `classify_member` otherwise protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
    Yes,
    No,
    Unknown,
}

/// One listed member's fate, decided from its already-read `Liveness` plus (whenever an
/// attempt could still teach us something) whether the real check reached it. Pure — a unit
/// test drives all `Liveness`/`Reached` combinations directly, without needing a real OS
/// condition for `Unknown` (which normally needs a permission-denying host like `hidepid`).
/// `reached` is called for `Liveness::Alive` OR `Liveness::Unknown` — NOT only `Alive`.
/// Gating the attempt on `Alive` alone is guard-then-do backwards for an operation that is
/// idempotent and self-reporting: `SIGKILL`/a probe answers the permission question directly
/// and authoritatively, so gating the ATTEMPT on a separate LIVENESS QUERY that can itself be
/// denied — e.g. under App Sandbox / a hardened runtime, where `is_alive`'s own fallback can
/// legitimately answer `Unknown` for a foreign-uid member — needlessly turns a recoverable
/// teardown into `Error::Unassessable` without ever trying the one call that would have
/// answered the real question. Only a POSITIVE `Liveness::Dead` skips the attempt entirely
/// — there is nothing left to prove for a zombie, a departed pid, or a pid recycled onto an
/// unrelated process, however a signal/probe of the raw pid might answer.
enum MemberOutcome {
    NotASurvivor,
    Survivor(RawPid),
    Unassessable(RawPid),
}

fn classify_member(
    pid: RawPid,
    liveness: crate::identity::Liveness,
    reached: impl FnOnce() -> Reached,
) -> MemberOutcome {
    match liveness {
        crate::identity::Liveness::Dead => MemberOutcome::NotASurvivor,
        crate::identity::Liveness::Alive | crate::identity::Liveness::Unknown => match reached() {
            Reached::Yes => MemberOutcome::NotASurvivor,
            Reached::No => MemberOutcome::Survivor(pid),
            Reached::Unknown => MemberOutcome::Unassessable(pid),
        },
    }
}

/// Re-verify `id` is still the SAME identity, probe it with `kill(pid, 0)`, and classify the
/// answer. The probe sends no signal, which [`OsProcess::signal`](crate::os_process::OsProcess::signal)
/// cannot express, so it is not sent through an opened handle as the `SIGKILL` resend is
/// ([`resend_sigkill`]).
///
/// `EPERM` and only `EPERM` classifies as a confirmed refusal; every other unexpected errno is
/// `Unknown`, not `No` — conservative, and consistent with every other "not EPERM/ESRCH"
/// disposition in this module.
///
/// **The identity check and the probe are two separate syscalls — a narrowed, not eliminated,
/// race.** A pid recycled between the listing and this call is not "never mistakenly probed":
/// the re-verify and the `kill(2)` below are non-atomic, so a recycle in THAT gap (not the
/// earlier, listing-to-here gap the re-verify closes) is still possible. A probe delivers
/// nothing, so a probe of a recycled pid misreports at worst.
fn probe_member(
    kernel: &dyn crate::identity::Kernel,
    pid: RawPid,
    id: crate::identity::ProcessId,
    root: Option<&dyn Root>,
) -> Reached {
    // The listing named the root's group only while the group's number is still the root's: the
    // root's check proves it. The member's identity check, after it and right before the `kill`,
    // guards the probe by the member's pid.
    if let Err(reached) = root_check_before_send(root, pid, None) {
        return reached;
    }
    match crate::identity::ProcessId::of_with(kernel, pid).0 {
        crate::identity::Resolved::Found(live) if live == id => {}
        // Gone — nothing to refuse.
        crate::identity::Resolved::Found(_) => {
            log::debug!(
                "containment::unix::group: pid {pid} now names a different process (recycled \
                 mid-teardown) — not the listed member, so not a survivor"
            );
            return Reached::Yes;
        }
        crate::identity::Resolved::Gone => return Reached::Yes,
        // `Resolved::Unknown` must NOT be treated like `Resolved::Found(_)`'s recycle case
        // above, even though both look like "a pid that no longer names the expected
        // process": `Resolved::Found(_)` is safe BECAUSE identity was resolved and compared
        // (we KNOW it's a different, and therefore not-our-business, process).
        // `Resolved::Unknown` means the re-verify could not be performed AT ALL. Conservative
        // bail: an unverifiable identity is never probed by its bare pid.
        crate::identity::Resolved::Unknown => {
            log::warn!(
                "containment::unix::group: pid {pid} could not be re-verified (access denied?) \
                 — treated as unassessable, not probed"
            );
            return Reached::Unknown;
        }
    }
    let Some(target) = crate::identity::probe::signal_target(pid) else {
        // Defence in depth: a kernel-reported pid is never 0 or overflowing, so this should be
        // unreachable. Logged loudly if it ever is, and treated as unassessable rather than
        // (wrongly) cleared — the conservative direction, matching every other "should never
        // happen" branch in this module.
        log::warn!("containment::unix::group: pid {pid} is not a single-process signal target");
        return Reached::Unknown;
    };
    match super::probe_signal(super::Target::Member(pid), super::Sys::Process(target)) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Reached::Yes,
        Err(nix::errno::Errno::EPERM) => {
            // The expected, common case for a genuine refuser — logged at debug (not warn),
            // but logged: every other "member did not clear" branch in this module records
            // its cause, and this is the one that produces the primary, expected outcome of
            // the whole feature (a confirmed refusal), so it should be no less traceable.
            log::debug!("containment::unix::group: kill({pid}, 0) refused: EPERM");
            Reached::No
        }
        Err(e) => {
            // Neither EPERM nor ESRCH: genuinely anomalous. Not evidence of a refusal, and
            // not evidence the tree came down either — the conservative "we don't know"
            // answer, not a guess in either direction.
            log::warn!(
                "containment::unix::group: kill({pid}, 0) answered {report}, neither EPERM nor ESRCH",
                report = crate::error::Report(&e)
            );
            Reached::Unknown
        }
    }
}

/// The root's check before the resend of `signal` (`None`: the probe) to the listed `pid`
/// ([`check_number`]). `Err` is the member's answer when nothing may go out: a group with no
/// member left holds no listed process, so that process is not a survivor; any other failed check
/// leaves it unassessable.
fn root_check_before_send(root: Option<&dyn Root>, pid: RawPid, signal: Option<Signal>) -> Result<(), Reached> {
    let send = signal.map_or_else(|| "probed".to_owned(), |signal| format!("resent {signal}"));
    match check_number(root) {
        Ok(()) => Ok(()),
        Err(why @ crate::containment::NotItsGroup::Empty) => {
            log::debug!("containment::unix::group: {why}, so pid {pid} is in another group, and is not {send}");
            Err(Reached::Yes)
        }
        Err(why) => {
            log::warn!("containment::unix::group: {why}, so pid {pid} is not {send}; it is unassessable");
            Err(Reached::Unknown)
        }
    }
}

/// The `SIGKILL` resend to a listed member, through the handle
/// [`open_with`](crate::os_process::open_with) opens for its identity and its
/// [`signal`](crate::os_process::OsProcess::signal): the handle names the SAME process the open
/// just confirmed, even if the pid number is reused by something else in between. Linux: a
/// pidfd; macOS: an audit token, which the kernel checks against the process's `p_idversion`.
///
/// The open's answers map to a [`Reached`] as follows:
///
/// - `Ok(None)` (already gone) is `Reached::Yes`. That includes a reaped process-group leader
///   (`pidfd_open` `EINVAL`/`ENOENT`, which a `Pidfs` id takes as lost and a `Ticks` id settles by
///   `id.exists()` saying `Gone`) and a ptraced zombie thread, and a macOS pid that names another
///   process.
/// - `Error::NotThreadGroupLeader` is `Reached::Unknown`, with no fallback. The kernel did answer:
///   this pid is a live thread, not a process. `kill(2)` on a tid signals the whole thread group
///   that owns it, which is not the member that was listed.
/// - `Error::Unsupported` (`pidfd_open` refused), `Error::Io` (a transient `pidfd_open` failure,
///   or a `poll` failure) and `Error::Unassessable` (identity denied, or the pid overflows the
///   pidfd interface) are `Reached::Unknown`, with no fallback to `kill(2)`: the member's identity
///   is told through the handle, so without one nothing proves that its pid still names the
///   listed member, and a bare pid is never signalled on a guess.
///
/// **Why this never signals when `id.exists()` answers `Unknown` inside the open.** (That is the
/// path of a `Ticks` id, on a Linux host before 6.9. A `Pidfs` id is proved by the open pidfd's
/// own inode and reads no `/proc`, so it has no such gap.) This looks tempting — `pidfd_open`
/// already succeeded, so *something* is there — but it does not actually close the gap:
/// `pidfd_open(pid)` binds to WHATEVER process holds that pid NUMBER at the moment it is
/// called, exactly like a bare `kill(2)`. If the member `members()` listed at T0 exited and
/// its pid was recycled onto an unrelated, signalable process before `pidfd_open` runs at T1,
/// `pidfd_open` succeeds — for the WRONG process. `id.exists()`'s subsequent `Unknown` answer
/// is precisely the case where this recycle cannot be ruled out (a permission-denied `/proc`
/// read under `hidepid`, or the platform's equivalent, giving neither a clear "same identity"
/// nor a clear "gone"). The pidfd's real safety property is narrower than "identity-pinned
/// from the moment of listing": it guarantees the target does not change identity AFTER a
/// successful open, not that the identity was already correct AT open time — exactly the gap
/// the open's own `id.exists()` step exists to close, and exactly the gap `Existence::
/// Unknown` says was NOT closed this time. Left as a disclosed, asymmetric gap
/// rather than closed with an unsound fix: on a genuinely `hidepid`-restricted host, a live
/// member whose identity cannot be re-confirmed at delivery time is correctly left unsignalled
/// and reported `Unassessable`, even though the earlier `Liveness::Unknown`-admitting gate
/// (`classify_member`) let it through to the attempt.
fn resend_sigkill(
    kernel: &dyn crate::identity::Kernel,
    id: crate::identity::ProcessId,
    root: Option<&dyn Root>,
) -> Reached {
    use crate::containment::treewalk::KillOutcome;
    use crate::signal::Sig;
    match crate::os_process::open_with(kernel, id).map_err(crate::os_process::OpenFailure::into_open_error) {
        Ok(None) => Reached::Yes, // already gone
        Ok(Some(os)) => match root_check_before_send(root, id.pid(), Some(Signal::SIGKILL)) {
            Err(reached) => reached,
            Ok(()) => {
                let sent = os.signal(Sig::Kill);
                // Where a test records a send, as the resend before it did.
                #[cfg(test)]
                crate::send_log::record_group(crate::send_log::GroupStep::Member(
                    if cfg!(target_os = "linux") {
                        crate::send_log::Route::Pidfd
                    } else {
                        crate::send_log::Route::AuditToken
                    },
                    id.pid(),
                    libc::SIGKILL,
                ));
                match KillOutcome::of(sent) {
                    // Exited between the open and the send, or delivered.
                    KillOutcome::Terminated | KillOutcome::AlreadyGone => Reached::Yes,
                    KillOutcome::NotAttempted(crate::error::Error::Io(refused))
                        if refused.raw_os_error() == Some(libc::EPERM) =>
                    {
                        log::debug!("containment::unix::group: SIGKILL to pid {} refused: EPERM", id.pid());
                        Reached::No
                    }
                    KillOutcome::NotAttempted(e) => {
                        log::warn!(
                            "containment::unix::group: SIGKILL to pid {} answered {report}, neither EPERM nor ESRCH",
                            id.pid(),
                            report = crate::error::Report(&e)
                        );
                        Reached::Unknown
                    }
                }
            }
        },
        Err(e @ crate::error::Error::NotThreadGroupLeader { .. }) => {
            log::warn!(
                "containment::unix::group: pid {} is a live thread, not a thread-group leader, so it \
                 is not signalled: {report}",
                id.pid(),
                report = crate::error::Report(&e)
            );
            Reached::Unknown
        }
        // `Error::Unassessable`, or a variant added later: a statement about the PID itself, which
        // no kill(2) fallback resolves. Conservative, not a guess.
        Err(e) => {
            log::warn!(
                "containment::unix::group: pid {} could not be opened by identity: {report}",
                id.pid(),
                report = crate::error::Report(&e)
            );
            Reached::Unknown
        }
    }
}

/// "Ask forgiveness, one more time": re-confirm a `Survivor` verdict with a SECOND liveness
/// check before it is finalized. Pure and testable in isolation (unlike `converge`'s inline
/// loop it replaced) — a unit test drives all three `recheck` answers directly. The FIRST
/// `Liveness` check (fed into `classify_member`, before the signal/probe ran at all) can go
/// stale in the gap before the signal/probe actually ran: a foreign-uid member that was alive
/// at that check and exits to a zombie microseconds later still answers `EPERM` (measured,
/// this file's Background — a foreign-uid zombie answers identically to a foreign-uid live
/// refuser), so without this re-check a member that finished dying mid-teardown would be
/// misreported as a survivor. Only `Survivor` is re-checked — `NotASurvivor`/`Unassessable`
/// need no second look, since neither claims a definite, still-running refuser. A downgrade
/// is logged: it overturns an `EPERM` already logged once inside `resend_sigkill`, and a
/// debug session starting from "why did teardown report Cleared/Unassessable despite the
/// EPERM in the logs" needs this decision to be visible too, not just the original refusal.
///
/// **Downgrades on `Liveness::Dead` only — `Liveness::Unknown` keeps `Survivor`.** Downgrading
/// on `Unknown` too would throw away STRONGER evidence for WEAKER: the `Survivor` this
/// function receives already carries a REAL, directly-observed `EPERM` from
/// `resend_sigkill`'s own send, or `probe_member`'s `kill(2)` — the kernel's authoritative,
/// first-hand answer to "may this caller signal this process". `recheck`'s liveness query is a
/// WEAKER, independently-deniable signal (the same class of query that can itself answer
/// `Unknown` under `hidepid` or a sandboxed runtime); a denied liveness reconfirmation is not
/// evidence the EPERM was wrong, only that this SECOND, unrelated query could not be answered.
/// `classify_member` already proceeds on `Liveness::Unknown` rather than stopping there, so an
/// `Unknown`-downgrades-too shape here would make that upstream permissiveness produce no
/// benefit for the refusal verdict at all — `Unknown` at the first check could only ever end in
/// `NotASurvivor` or `Unassessable`, never the `Refused` a genuine, already-observed `EPERM`
/// earns. The member was already established not-`Dead` by the first liveness check
/// (`classify_member`'s own gate) before the signal was ever attempted, so `Dead` is the only
/// recheck answer that actually contradicts the `Survivor` verdict; `Unknown` contradicts
/// nothing.
fn reconfirm_survivor(outcome: MemberOutcome, recheck: impl FnOnce() -> crate::identity::Liveness) -> MemberOutcome {
    let MemberOutcome::Survivor(pid) = outcome else {
        return outcome;
    };
    match recheck() {
        crate::identity::Liveness::Alive => MemberOutcome::Survivor(pid),
        crate::identity::Liveness::Dead => {
            log::debug!(
                "containment::unix::group: pid {pid} answered EPERM but has since gone (exited \
                 mid-teardown); downgraded from a confirmed refusal to not-a-survivor"
            );
            MemberOutcome::NotASurvivor
        }
        // A denied reconfirmation does NOT overturn an already-observed, authoritative EPERM
        // — see the doc comment above for why this differs from the Dead arm.
        crate::identity::Liveness::Unknown => MemberOutcome::Survivor(pid),
    }
}

/// List `pgid` once, classify every member, and decide the group's verdict. See this task's
/// design note above for why there is exactly one listing pass, and why `SIGKILL` resends the
/// real signal while every other signal (in practice, only `SIGTERM`) only probes. Runs the
/// loop to completion — a member classified `Unassessable` does NOT short-circuit the pass:
/// on the `SIGKILL` path `converge` is the delivery mechanism itself, so cutting the loop
/// short would silently skip signalling every member listed after it. `decide` (below) is
/// what turns the fully-accumulated result into one verdict.
///
/// A pid excluded from the `SIGKILL` resend (see `excluded_from_sigkill_resend`, just below)
/// classifies `Unassessable`, NOT `Cleared`: it was never actually reached, so folding it into
/// "not a survivor" would manufacture the same false-`Ok` #61 exists to eliminate, just for
/// this pid specifically.
///
/// **The group's number, and each resend.** The listing names members by `pgid`, a number that
/// stays the root's group only while the group has a member: on Linux 6.9+ the root's pidfd shows
/// that exactly, and elsewhere the root's state stands in for it (unreaped). Each `SIGKILL` resend
/// and `SIGTERM` probe checks the root ([`check_number`]) first. A `SIGKILL` resend first opens the
/// member by its identity (a pidfd on Linux, an audit token on macOS), then checks the root, then
/// sends through that handle; a member that cannot be opened is unassessable and not signalled. A
/// `SIGTERM` probe checks the root, then the member's identity right before the probe. A member
/// whose root check fails is unassessable and not signalled; on
/// 6.9+, once the group has no member left, it is in another group that took the number, and is not
/// a survivor. A change between a check and the send is not seen: the window `Child::kill_tree`
/// documents.
pub(crate) fn converge(
    kernel: &dyn crate::identity::Kernel,
    pgid: i32,
    signal: Signal,
    root: Option<&dyn Root>,
) -> std::io::Result<GroupState> {
    #[cfg(test)]
    let listing_pgid = fault::listed(pgid);
    #[cfg(not(test))]
    let listing_pgid = pgid;
    let listed = members(kernel, listing_pgid)?;
    #[cfg(test)]
    fault::run_after_listing();
    let mut refused = Vec::new();
    let mut unassessable = Vec::new();
    for m in &listed {
        let id = m.id;
        let outcome = classify_member(id.pid(), id.is_alive_with(kernel), || {
            if signal == Signal::SIGKILL && excluded_from_sigkill_resend(id.pid(), m.system) {
                log::warn!(
                    "containment::unix::group: pid {pid} in process group {pgid} is excluded \
                     from the SIGKILL resend (mirrors xnu's own killpg1 exclusion for init/ \
                     P_SYSTEM) and reported unassessable, not cleared, since it was never \
                     actually reached",
                    pid = id.pid()
                );
                return Reached::Unknown;
            }
            if signal == Signal::SIGKILL {
                resend_sigkill(kernel, id, root)
            } else {
                // `SIGTERM` is never resent: it is only probed (see this fn's doc).
                probe_member(kernel, id.pid(), id, root)
            }
        });
        match reconfirm_survivor(outcome, || id.is_alive_with(kernel)) {
            MemberOutcome::NotASurvivor => {}
            MemberOutcome::Survivor(pid) => refused.push(pid),
            MemberOutcome::Unassessable(pid) => unassessable.push(pid),
        }
    }
    Ok(decide(pgid, signal, refused, unassessable))
}

/// Mirrors xnu's own `killpg1` exclusion set for the `SIGKILL` resend above: `killpg1` skips
/// `kernproc`, `initproc` (pid 1), and every `P_SYSTEM`-flagged process before it even counts a
/// group as reachable. `kernproc` (pid 0) never appears in a listed group's membership, so only
/// the other two need restating here — this crate's own per-member resend does not inherit
/// `killpg`'s kernel-side exclusion for free, and without it a live `P_SYSTEM` process would
/// receive a real `SIGKILL` that `killpg` itself would have refused to send. Pure, and tested
/// directly against synthetic pid/`system` combinations (`group_tests.rs`) rather than only
/// through `converge`'s live path.
///
/// `system` comes from the listing's own `Member::system` — real on macOS, always `false`
/// elsewhere, where no equivalent kernel flag exists to restate.
fn excluded_from_sigkill_resend(pid: RawPid, system: bool) -> bool {
    pid == 1 || system
}

/// Turn an accumulated pass into one verdict. Pure — a unit test drives all three shapes
/// without a real listing. A known refusal always wins over unresolved members elsewhere in
/// the same group (`Refused` is strictly more informative than a bare `Unlistable`), but the
/// unassessable pids are carried in `Refused`'s own `unassessable` field rather than merely
/// logged: a debug log line alone would be an incomplete payload on the one issue whose entire
/// point is not under-reporting teardown state.
fn decide(pgid: i32, signal: Signal, refused: Vec<RawPid>, unassessable: Vec<RawPid>) -> GroupState {
    if !refused.is_empty() {
        return GroupState::Refused { refused, unassessable };
    }
    if !unassessable.is_empty() {
        let list = unassessable
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return GroupState::Unlistable {
            detail: format!(
                "{n} member(s) of process group {pgid} could not be assessed after {signal} \
                 (pid {list})",
                n = unassessable.len(),
            ),
            source: None,
        };
    }
    GroupState::Cleared
}

/// The friendly wrapper `unix.rs` calls: list `pgid`, converge on delivering `signal`, and
/// turn a listing failure into the same `Unlistable` shape a per-member `Unknown` produces.
///
/// `pgid <= 0` is a `debug_assert!`, not a runtime guard, here: it documents this module's own
/// contract (never called with an unaddressable group id) rather than pretending to be a
/// safety net for a dangerous syscall — the REAL guard, which runs before `killpg` is ever
/// called, is in `unix.rs`'s `signal_group` (this module's only production caller).
pub(crate) fn state(pgid: i32, signal: Signal, root: Option<&dyn Root>) -> GroupState {
    debug_assert!(
        pgid > 0,
        "group::state called with a non-positive pgid ({pgid}); the real guard belongs in the \
         caller, before any signal is sent — see unix.rs::signal_group"
    );
    match converge(&crate::identity::HostKernel, pgid, signal, root) {
        Ok(gs) => gs,
        Err(e) => GroupState::Unlistable {
            detail: format!("process group {pgid} could not be listed after {signal}"),
            source: Some(e),
        },
    }
}

/// Test-only seam inside [`converge`].
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    thread_local! {
        static AFTER_LISTING: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static LIST_INSTEAD: Cell<Option<i32>> = const { Cell::new(None) };
    }

    /// While the guard lives, `converge` on this thread lists process group `pgid` instead of the
    /// one it was given, as it would once another group took the given group's number.
    #[cfg(target_os = "linux")]
    pub(crate) fn list_instead(pgid: i32) -> ListInstead {
        LIST_INSTEAD.with(|l| l.set(Some(pgid)));
        ListInstead(())
    }

    #[cfg(target_os = "linux")]
    #[must_use = "the listing names the given group again as soon as the guard is dropped"]
    pub(crate) struct ListInstead(());

    #[cfg(target_os = "linux")]
    impl Drop for ListInstead {
        fn drop(&mut self) {
            LIST_INSTEAD.with(|l| l.set(None));
        }
    }

    /// The group `converge` lists for `pgid`.
    pub(super) fn listed(pgid: i32) -> i32 {
        LIST_INSTEAD.with(Cell::get).unwrap_or(pgid)
    }

    /// Run `hook` in the NEXT `converge` on this thread, once `members(pgid)` has returned and
    /// before any member is signalled or classified: the window in which a member the listing
    /// saw can still fork a process the listing did not. Whether that fork can succeed is what
    /// tells apart a group that a prior `killpg` has doomed from one that only `converge`'s
    /// per-member resend will reach.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_after_listing(hook: impl FnOnce() + 'static) -> ArmedAfterListing {
        crate::oneshot_hook::arm(&AFTER_LISTING, hook)
    }
    pub(crate) fn run_after_listing() {
        crate::oneshot_hook::fire(&AFTER_LISTING);
    }
    #[cfg(target_os = "linux")]
    pub(crate) type ArmedAfterListing = crate::oneshot_hook::Armed;
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod group_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "group_namespace_tests.rs"]
mod group_namespace_tests;
