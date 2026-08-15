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
/// `classify_member` — this round's review found the previous draft collapsing "could not
/// assess" into a binary `bool` at exactly the boundary where the distinction mattered most
/// (inside `converge`'s `reached` closure), silently re-narrowing the `Liveness::Unknown`
/// handling `classify_member` otherwise protects.
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
/// `reached` is called for `Liveness::Alive` OR `Liveness::Unknown` — NOT only `Alive` (an
/// earlier round of this plan gated it on `Alive` alone; review correctly caught that this
/// is guard-then-do backwards for an operation the plan itself calls idempotent and
/// self-reporting: `SIGKILL`/a probe answers the permission question directly and
/// authoritatively, so gating the ATTEMPT on a separate LIVENESS QUERY that can itself be
/// denied — e.g. under App Sandbox / a hardened runtime, where `is_alive`'s own fallback can
/// legitimately answer `Unknown` for a foreign-uid member — needlessly turns a recoverable
/// teardown into `Error::Unassessable` without ever trying the one call that would have
/// answered the real question). Only a POSITIVE `Liveness::Dead` skips the attempt entirely
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

/// Re-verify `id` is still the SAME identity, deliver-or-probe it, and classify the answer —
/// the ONE implementation both the `SIGKILL` and `SIGTERM` paths use, differing only in
/// `signal` (`Some(SIGKILL)` resends for real; `None` probes with `kill(pid, 0)`).
///
/// **Why this replaced `treewalk::kill_by_identity` from an earlier round of this plan.**
/// That primitive's `KillOutcome::NotAttempted` conflates TWO different causes — a denied
/// identity re-verify, and a genuine `EPERM` from the real `kill(2)` call — into one variant
/// (`src/containment/treewalk.rs:222-256`), with nothing in the return value to tell them
/// apart. An earlier round tried to route around this by pre-checking identity here and
/// *assuming* `kill_by_identity`'s own internal re-check, a moment later, would agree — a
/// probability argument, not a proof, and review correctly rejected it: a transient
/// disagreement in that gap still mislabels "unassessable" as a confirmed refusal. Reusing
/// `kill_by_identity` here cannot be made precise without changing its return type (out of
/// scope — it is a sibling module's primitive), so this performs the identity check AND the
/// `kill(2)` call directly, observing the real errno first-hand. `EPERM` and only `EPERM`
/// classifies as a confirmed refusal; every other unexpected errno is `Unknown`, not `No` —
/// conservative, and consistent with every other "not EPERM/ESRCH" disposition in this
/// module.
///
/// **The identity check and the act are still two separate syscalls on macOS — a narrowed,
/// not eliminated, race.** Review correctly caught an earlier claim here that a pid recycled
/// between the listing and this call is "never mistakenly signalled" — false: the re-verify
/// and the `kill(2)` below are non-atomic, so a recycle in THAT gap (not the earlier,
/// listing-to-here gap the re-verify closes) is still possible. On Linux this is closed for
/// real, not just narrowed: `SIGKILL` delivery goes through `pidfd_open`+`pidfd_send_signal`
/// (`check_or_signal_linux_sigkill`, below), reusing `crate::wait::backend::open_verified`
/// verbatim rather than a second implementation — the fd itself pins the identity at the
/// kernel level, so a pid reused after `pidfd_open` cannot be hit even in principle. macOS has
/// no pidfd equivalent, so `kill(2)` here keeps the same irreducible, ALREADY-ACCEPTED window
/// `src/wait/macos.rs::kill`'s own doc comment documents verbatim ("The window between this
/// check and kill(2) is irreducible on macOS (no pidfd); a recycled pid in that window is a
/// documented best-effort limitation, mirroring treewalk::kill_by_identity") — this function
/// is that same, already-reviewed trade-off, not a new one.
fn check_or_signal(pid: RawPid, id: crate::identity::ProcessId, signal: Option<Signal>) -> Reached {
    // Contract (repo-wide policy, this round): this module's whole design rests on
    // `SIGTERM` never being resent for real (the double-signal-escalation avoidance —
    // `converge`'s design note above) — only `SIGKILL` may be `Some`, everything else must
    // probe (`None`). A future caller passing e.g. `Some(Signal::SIGTERM)` through here would
    // silently violate that without this assert ever making it visible.
    debug_assert!(
        matches!(signal, None | Some(Signal::SIGKILL)),
        "check_or_signal called with {signal:?}; only None (probe) or Some(SIGKILL) (resend) \
         are ever valid here — SIGTERM must never resend, see converge's design note"
    );
    match crate::identity::ProcessId::of(pid) {
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
        // **Reverted this round — a prior round's "ask forgiveness" change here was itself a
        // bug, caught by review.** An earlier version of this arm signalled the bare `pid`
        // for real whenever `signal.is_some()`, reasoning that "a genuinely recycled pid still
        // answers ESRCH/EPERM on its own terms, same as `Resolved::Found(_)`'s recycle case
        // above." That reasoning does not hold: `Resolved::Found(_)` is safe BECAUSE identity
        // was resolved and compared (we KNOW it's a different, and therefore not-our-business,
        // process). `Resolved::Unknown` means the re-verify could not be performed AT ALL — if
        // the pid was recycled onto a process the caller MAY signal, `kill(2)` returns
        // `Ok(())` and a completely unrelated process gets killed, not `ESRCH`/`EPERM`. There
        // is no analogy to lean on; the two cases are opposite, not equivalent. Conservative
        // bail, for BOTH the resend and the probe: an unverifiable identity is never signalled
        // on this platform (no atomic handle exists here — `check_or_signal_linux_sigkill`,
        // below, is the platform where a genuinely atomic alternative exists and is used).
        crate::identity::Resolved::Unknown => {
            log::warn!(
                "containment::unix::group: pid {pid} could not be re-verified (access denied?) \
                 — treated as unassessable, not signalled (an unverified pid is never signalled \
                 on this platform: a recycled pid onto an unrelated, signalable process would \
                 be hit for real, not safely refused)"
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
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(target), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Reached::Yes,
        Err(nix::errno::Errno::EPERM) => {
            // The expected, common case for a genuine refuser — logged at debug (not warn),
            // but logged: every other "member did not clear" branch in this module records
            // its cause, and this is the one that produces the primary, expected outcome of
            // the whole feature (a confirmed refusal), so it should be no less traceable.
            log::debug!("containment::unix::group: kill({pid}, {signal:?}) refused: EPERM");
            Reached::No
        }
        Err(e) => {
            // Neither EPERM nor ESRCH: genuinely anomalous. Not evidence of a refusal, and
            // not evidence the tree came down either — the conservative "we don't know"
            // answer, not a guess in either direction.
            log::warn!("containment::unix::group: kill({pid}, {signal:?}) answered {e}, neither EPERM nor ESRCH");
            Reached::Unknown
        }
    }
}

/// Linux-only, `SIGKILL`-only: the atomic version of `check_or_signal`'s resend, via the
/// crate's own existing pidfd primitive (`src/wait/linux.rs::open_verified` — reused, not
/// reimplemented, per this module's own stated preference; it already does exactly "open a
/// pidfd for this identity, re-verifying, `Ok(None)` if already gone"). `pidfd_send_signal`
/// on the returned fd is guaranteed to hit the SAME process `open_verified` just confirmed,
/// even if the pid number is reused by something else in between — no gap remains, unlike
/// `check_or_signal`'s plain-`kill(2)` path.
///
/// **Falls back to `check_or_signal`'s plain `kill(2)` on `Error::Unsupported` OR
/// `Error::Io`, not `Reached::Unknown`.** `open_verified` returns `Unsupported` when
/// `pidfd_open` answers `ENOSYS` — kernel < 5.3, or a seccomp/sandbox policy blocking the
/// syscall entirely. It returns `Error::Io` for every OTHER `pidfd_open`/`poll` failure —
/// which, in the same seccomp/sandbox case, is exactly what a policy that returns `EPERM`
/// (rather than `ENOSYS`) on the blocked syscall produces instead (verified against
/// `open_verified`'s own match arms in `src/wait/linux.rs`: only `Errno::NOSYS` maps to
/// `Unsupported`; every other errno, including `EPERM`, falls into the generic `Error::Io`
/// arm). A seccomp profile is free to pick either errno for a denied syscall, so treating only
/// `Unsupported` as fallback-eligible silently reclassifies "we couldn't even ask" as
/// `Reached::Unknown` on exactly the containers this fallback exists for (Task 6's setuid
/// helper test runs under Docker's default seccomp profile). Both variants get the SAME
/// treatment: fall back to `check_or_signal`'s plain `kill(2)`, which observes envelopes IT
/// controls directly rather than trusting `open_verified`'s errno classification a second
/// time. Only `Error::Unassessable` — identity genuinely denied by `id.exists()`, or the pid
/// overflows the pidfd interface — stays `Reached::Unknown`: that is a statement about the
/// PID's identity, not about whether the kernel can open a pidfd at all, and no fallback
/// resolves it.
///
/// **Considered and rejected: signalling via the already-open pidfd anyway when `id.exists()`
/// answers `Unknown` inside `open_verified`.** This looks tempting — `pidfd_open` already
/// succeeded, so *something* is there — but it does not actually close the gap, for the same
/// reason `check_or_signal`'s own `Resolved::Unknown` arm (above) must never signal a bare
/// pid: `pidfd_open(pid)` binds to WHATEVER process holds that pid NUMBER at the moment it is
/// called, exactly like a bare `kill(2)`. If the member `members()` listed at T0 exited and
/// its pid was recycled onto an unrelated, signalable process before `pidfd_open` runs at T1,
/// `pidfd_open` succeeds — for the WRONG process. `id.exists()`'s subsequent `Unknown` answer
/// is precisely the case where this recycle cannot be ruled out (a permission-denied `/proc`
/// read under `hidepid`, or the platform's equivalent, giving neither a clear "same identity"
/// nor a clear "gone"). The pidfd's real safety property is narrower than "identity-pinned
/// from the moment of listing": it guarantees the target does not change identity AFTER a
/// successful open, not that the identity was already correct AT open time — exactly the gap
/// `open_verified`'s own `id.exists()` step exists to close, and exactly the gap `Existence::
/// Unknown` says was NOT closed this time. Signalling anyway would reintroduce, on Linux, the
/// identical "unrelated-process-killed" failure mode `check_or_signal`'s reverted "ask
/// forgiveness" arm had on macOS — not a smaller version of it. Left as a disclosed,
/// asymmetric gap (see the report / Verification gaps) rather than closed with an unsound
/// fix: on a genuinely `hidepid`-restricted host, a live member whose identity cannot be
/// re-confirmed at delivery time is correctly left unsignalled and reported `Unassessable`,
/// even though the earlier `Liveness::Unknown`-admitting gate (`classify_member`) let it
/// through to the attempt.
#[cfg(target_os = "linux")]
fn check_or_signal_linux_sigkill(pid: RawPid, id: crate::identity::ProcessId) -> Reached {
    match crate::wait::backend::open_verified(id, "process-group teardown verification") {
        Ok(None) => Reached::Yes, // already gone
        Ok(Some(pidfd)) => match rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL) {
            Ok(()) => Reached::Yes,
            Err(rustix::io::Errno::SRCH) => Reached::Yes, // exited between open and signal
            Err(rustix::io::Errno::PERM) => {
                log::debug!(
                    "containment::unix::group: pidfd_send_signal({}, KILL) refused: EPERM",
                    id.pid()
                );
                Reached::No
            }
            Err(e) => {
                log::warn!(
                    "containment::unix::group: pidfd_send_signal({}, KILL) answered {e}, neither EPERM nor ESRCH",
                    id.pid()
                );
                Reached::Unknown
            }
        },
        Err(e @ (crate::error::Error::Unsupported { .. } | crate::error::Error::Io(_))) => {
            log::debug!(
                "containment::unix::group: pidfd unavailable ({e}) for pid {}; falling back to \
                 kill(2) — same residual race macOS already accepts",
                id.pid()
            );
            check_or_signal(pid, id, Some(Signal::SIGKILL))
        }
        // Only `Error::Unassessable` reaches here: identity genuinely denied by `id.exists()`,
        // or the pid overflows the pidfd interface — a statement about the PID itself, which
        // no kill(2) fallback resolves. Conservative, not a guess.
        Err(e) => {
            log::warn!("containment::unix::group: open_verified for pid {}: {e}", id.pid());
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
/// is logged: it overturns an `EPERM` already logged once inside `check_or_signal`, and a
/// debug session starting from "why did teardown report Cleared/Unassessable despite the
/// EPERM in the logs" needs this decision to be visible too, not just the original refusal.
///
/// **Downgrades on `Liveness::Dead` only — `Liveness::Unknown` keeps `Survivor`, fixed this
/// round.** An earlier version of this match also downgraded on `Unknown`, reasoning that a
/// denied liveness re-check should not be trusted either way. Review correctly caught that
/// this throws away STRONGER evidence for WEAKER: the `Survivor` this function receives
/// already carries a REAL, directly-observed `EPERM` from `check_or_signal`'s own `kill(2)`/
/// `pidfd_send_signal` call — the kernel's authoritative, first-hand answer to "may this
/// caller signal this process". `recheck`'s liveness query is a WEAKER, independently-deniable
/// signal (the same class of query that can itself answer `Unknown` under `hidepid` or a
/// sandboxed runtime); a denied liveness reconfirmation is not evidence the EPERM was wrong,
/// only that this SECOND, unrelated query could not be answered. Combined with `classify_member`
/// proceeding on `Liveness::Unknown` (a separate, correct fix from an earlier round), the
/// prior `Unknown`-downgrades-too shape made that fix produce no benefit for the refusal
/// verdict at all — `Unknown` at the first check could only ever end in `NotASurvivor` or
/// `Unassessable`, never the `Refused` a genuine, already-observed `EPERM` earns. The member
/// was already established not-`Dead` by the first liveness check (`classify_member`'s own
/// gate) before the signal was ever attempted, so `Dead` is the only recheck answer that
/// actually contradicts the `Survivor` verdict; `Unknown` contradicts nothing.
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
/// `pid == 1` is excluded from the `SIGKILL` resend specifically (not the `SIGTERM` probe,
/// which never delivers anything). xnu's own `killpg1` (this file's Background) explicitly
/// excludes `kernproc`, `initproc`, and any `P_SYSTEM` process from group signalling before
/// it even counts `nfound` — a protection `killpg` gave for free that a per-member resend
/// bypasses unless restated here. Only the `initproc`/pid-1 case is covered here (the
/// practically reachable one: `kernproc` is pid 0 and never appears in a user-visible pgroup
/// listing). The broader `P_SYSTEM` flag is NOT filtered — `p_flag` is not currently read
/// from `kinfo_proc`, and guessing its bit value (`P_SYSTEM` is not exposed by the `libc`
/// crate for macOS) rather than measuring it would break this plan's own rule of never
/// resting on an unverified constant. Left as an explicit open question for Anna — see the
/// report — rather than silently shipped as equivalent to xnu's full check. Excluded pid 1
/// classifies `Unassessable`, NOT `Cleared`: it was never actually reached, so folding it
/// into "not a survivor" would manufacture the same false-`Ok` #61 exists to eliminate, just
/// for pid 1 specifically.
///
/// **Interaction with sibling #54 (pgid reuse), read before touching the resend below.** This
/// function does not obtain, trust, or pin `pgid` itself — it is handed the same, still
/// unpinned, group id `unix.rs::signal_group` already passed to `killpg`. #54 tracks that
/// hazard and owns its eventual fix (pinning the pgid against reuse); nothing here changes
/// how `pgid` is obtained or trusted, and the direct-to-leader fallback in `unix.rs` is left
/// exactly as it was. What IS new, and worth stating plainly at the one place it bites
/// hardest: unlike a plain probe, the loop below delivers a REAL `SIGKILL` to every member it
/// classifies alive-and-reachable. If `pgid` was recycled onto an unrelated process group
/// between `killpg`'s own call (in `signal_group`) and this function's `members(pgid)` listing
/// a moment later — #54's race, reoccurring here in a strictly later, second window — this
/// loop can deliver a real `SIGKILL` into that unrelated group, not merely misreport its
/// state. This is a consequence of #54's still-open race showing up on this new code path; it
/// is #54's fix to close (by pinning the pgid before either call), not something this function
/// can safely work around on its own — see the report's sequencing question to Anna.
pub(crate) fn converge(pgid: i32, signal: Signal) -> std::io::Result<GroupState> {
    let listed = members(pgid)?;
    let mut refused = Vec::new();
    let mut unassessable = Vec::new();
    for m in &listed {
        let id = crate::identity::ProcessId::from_parts(m.pid, m.token);
        let outcome = classify_member(m.pid, id.is_alive(), || {
            if signal == Signal::SIGKILL && m.pid == 1 {
                log::warn!(
                    "containment::unix::group: pid 1 (init) listed in process group {pgid}; \
                     excluded from the SIGKILL resend (mirrors xnu's own killpg1 exclusion) \
                     and reported unassessable, not cleared, since it was never actually reached"
                );
                return Reached::Unknown;
            }
            if signal == Signal::SIGKILL {
                // Linux: the atomic pidfd path (see its own doc comment). macOS/other Unix:
                // no pidfd equivalent exists, so `check_or_signal` keeps the same
                // already-accepted residual race `src/wait/macos.rs::kill` documents.
                #[cfg(target_os = "linux")]
                {
                    check_or_signal_linux_sigkill(m.pid, id)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    check_or_signal(m.pid, id, Some(signal))
                }
            } else {
                check_or_signal(m.pid, id, None)
            }
        });
        match reconfirm_survivor(outcome, || id.is_alive()) {
            MemberOutcome::NotASurvivor => {}
            MemberOutcome::Survivor(pid) => refused.push(pid),
            MemberOutcome::Unassessable(pid) => unassessable.push(pid),
        }
    }
    Ok(decide(pgid, signal, refused, unassessable))
}

/// Turn an accumulated pass into one verdict. Pure — a unit test drives all three shapes
/// without a real listing. A known refusal always wins over unresolved members elsewhere in
/// the same group (`Refused` is strictly more informative than a bare `Unlistable`), but the
/// unassessable pids are carried in `Refused`'s own `unassessable` field rather than merely
/// logged — an earlier round of this plan discarded them there with only a debug log line;
/// review correctly called that an incomplete payload on the one issue whose entire point is
/// not under-reporting teardown state.
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
pub(crate) fn state(pgid: i32, signal: Signal) -> GroupState {
    debug_assert!(
        pgid > 0,
        "group::state called with a non-positive pgid ({pgid}); the real guard belongs in the \
         caller, before any signal is sent — see unix.rs::signal_group"
    );
    match converge(pgid, signal) {
        Ok(gs) => gs,
        Err(e) => GroupState::Unlistable {
            detail: format!("process group {pgid} could not be listed after {signal}"),
            source: Some(e),
        },
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod group_tests;
