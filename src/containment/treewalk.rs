//! Identity-aware process-tree teardown — the cross-platform mechanism, used
//! both when requested directly (`ContainMode::TreeWalk`) and as the terminal
//! fallback of `ContainMode::Strongest` (e.g. a Windows job-assign failure, or a
//! host with no kernel container).
//!
//! Unlike a kernel container, this mechanism has no enforced membership: at
//! teardown it takes a `(pid, ppid)` snapshot of the host, walks the ppid chain
//! down from the root, and kills each *genuine* descendant by identity. It is
//! best-effort and reports as [`crate::containment::Containment::TreeWalk`]: it
//! misses reparented orphans (a child whose parent exited before the walk read the
//! child, so its ppid no longer chains to the root) and broker-spawned escapes. On Windows it also
//! misses a genuine descendant whose creator exited and whose creator's pid now belongs to a later
//! in-tree process, with its subtree (see the parent-order rule below).
//!
//! # The PID-reuse / stale-ppid defense (the order-key rule)
//!
//! A `(pid, ppid)` snapshot is racy: a candidate's `pid` may have been recycled,
//! or its `ppid` may name a *recycled* root pid. So a chained ppid alone does not
//! prove descent. The candidate's [`OrderKey`] (where it falls in process creation: Linux
//! jiffies / macOS µs of its start time / Windows its process sequence number), read beside its
//! id, must additionally order correctly against the root's: a genuine descendant was created
//! at-or-after the root acquired its pid. The keep predicate is
//!
//! ```text
//! key > root.key || (allow_equal && key == root.key)
//! ```
//!
//! `allow_equal` is a per-OS `cfg` const ([`ALLOW_EQUAL_ORDER`]): `true` on
//! Linux/macOS, `false` on Windows. Why per-OS:
//!
//! - An impostor — a *stale ppid* pointing at a *recycled* root pid — is always a
//!   process created *before* the root (key **<** root.key), so it is
//!   excluded by both rules.
//! - The rule cannot defend a root whose own pid was recycled: the new owner's children
//!   are created after the root, so they pass it. So the walk takes its snapshot first, then
//!   reads the root's key ([`anchor`]), which also proves it still holds its pid; a root
//!   that does not walks nothing. A root that is gone by the time its key is read walks nothing;
//!   one whose key exists but cannot be read is an error (`Error::Unassessable`), never an empty
//!   walk. On Windows the proof and the key are one read on one handle, so a root that exits
//!   cannot be proved and then found gone with its (unreparented) children unwalked. Elsewhere
//!   the pid is proved and then keyed, two reads for a Linux `pidfs` key (a Linux `ticks` key and
//!   a macOS key are known without a second read): a root gone between them walks nothing, which
//!   loses no one, because its children are reparented at its exit and no longer descend from it.
//! - A `key == root.key` candidate whose current ppid == root.pid can only be
//!   a *genuine* same-tick child: an unrelated same-tick collision that also
//!   happens to carry a recycled ppid equal to root.pid is impossible.
//! - **Linux/macOS** reparent orphans to pid 1 / launchd, so a process whose ppid
//!   still equals root.pid genuinely descends from it — ppid is *authoritative*.
//!   `>=` is therefore safe AND catches same-jiffy immediate children that strict
//!   `>` would silently miss under Linux's coarse 10 ms jiffy clock.
//! - **Windows** keeps strict `>`: sequence numbers are unique (one per process creation) and a
//!   process's exceeds its creator's, so two processes never share a key and strict `>` loses no
//!   genuine child.
//!
//! # The parent-order rule (Windows only)
//!
//! Where the parent field is the *creator* and is never updated (Windows), a ppid can name a pid
//! that a later process holds now, and that process's key can still order after the root's. So
//! there ([`ORDER_AFTER_PARENT`]) a candidate is kept only if its key orders after its accepted
//! parent's key, with the same `allow_equal`. Off elsewhere (see [`ORDER_AFTER_PARENT`]).
//! [`children_of_with`] needs no switch: its parent is the anchor.
//!
//! The rule also drops a genuine descendant whose creator exited and whose creator's pid now belongs
//! to a later in-tree process, with its subtree: from the snapshot alone it cannot be told from a
//! stale-creator impostor.
//!
//! # The creator read (Windows only)
//!
//! A snapshot row's ppid is only a number. The resolver reads the candidate again on one handle: its
//! creator pid (class 0), its id and its order key. A candidate whose creator is not the accepted
//! parent's pid is dropped, and so is one whose accepted parent no longer holds that pid when the
//! read is done. So a descendant whose parent exits while the walk runs is dropped with its
//! subtree: its creator pid still names the dead parent, which the read cannot tell from a pid that
//! changed hands. A creator read that fails leaves the candidate unproved, and it is dropped with a
//! warning that names the `NTSTATUS`.

use crate::error::Error;
use crate::identity::{Existence, Kernel, OrderKey, ProcessId, RawPid, Resolved, UnknownCause};

/// What one identity-verified kill attempt achieved. `AlreadyGone` and `NotAttempted` are
/// both "no signal was delivered", but only the first means there was nothing to deliver one
/// to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillOutcome {
    /// The signal reached the verified identity.
    Terminated,
    /// The pid holds no process, or holds a different one - nothing to kill.
    AlreadyGone,
    /// A live-or-unassessable process we did not signal. The only outcome that can leave a
    /// process running.
    NotAttempted,
}

/// The tree-walk resolver. A pid we may not query is dropped from the walk exactly like a
/// pid that is gone - the walk cannot kill what it cannot verify - but the two are logged
/// apart, because "denied" is an operational signal (run elevated) and "gone" is not.
///
/// `parent` is the process the walk accepted as the parent the snapshot gave `pid`. Where the read of
/// `pid` carries its parent (Linux: the `stat` the id was made with; Windows: the creator pid read
/// on the handle that gives the id), a candidate is dropped when its parent's number is another now,
/// which means the pid changed hands since the snapshot or the same process was orphaned and is no
/// longer in the tree; and when its parent's number no longer holds `parent`, which means the parent
/// was reaped and its number taken by a process whose own children the candidate could be. On macOS
/// the listing has nothing to check it against.
pub(crate) fn resolve_or_drop(kernel: &dyn Kernel, pid: RawPid, parent: ProcessId) -> Option<(ProcessId, OrderKey)> {
    match ProcessId::of_ordered_with(kernel, pid, Some(parent)) {
        (Resolved::Found(read), _) => Some(read),
        (Resolved::Gone, _) => None,
        (Resolved::Unknown, cause) => {
            let parent_blamed = cause.blamed_parent().is_some();
            let why = match unqueryable_read(pid, cause) {
                Error::Unassessable { detail, .. } => detail,
                other => other.to_string(),
            };
            // The pid is IN the message on purpose: `log_capture` is one process-global
            // buffer shared by every parallel test, so a test asserting on this line must be
            // able to pin it to its own fixture rather than to any concurrent teardown. The reason
            // names it when it is the subject, else the blamed parent, and then the pid is named here.
            let dropped = if parent_blamed {
                format!("pid {pid} dropped")
            } else {
                "dropped".to_owned()
            };
            log::warn!("treewalk: {why} - {dropped} from the walk");
            None
        }
    }
}

#[cfg(unix)]
use nix::sys::signal::Signal;

/// Per-OS order-key rule. See the module docs for the full
/// rationale. Linux/macOS reparent orphans → ppid is authoritative → keep
/// same-tick children (`>=`). Windows recycles pids and never reparents → keep
/// strict `>`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const ALLOW_EQUAL_ORDER: bool = true;
#[cfg(windows)]
pub(crate) const ALLOW_EQUAL_ORDER: bool = false;
// Other Unix (e.g. BSD without a tested rule): default to the conservative
// strict-`>` rule. enumerate's compile_error gates real support per OS.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) const ALLOW_EQUAL_ORDER: bool = false;

/// Whether a candidate must also order after its accepted parent, not only after the root. Only
/// Windows, where the parent field is the creator and never updated, so a ppid can name a pid a
/// later process holds now. Off on macOS: it would drop a child whose in-tree tracer started after
/// it, or one forked after a clock step.
#[cfg(windows)]
pub(crate) const ORDER_AFTER_PARENT: bool = true;
#[cfg(not(windows))]
pub(crate) const ORDER_AFTER_PARENT: bool = false;

/// The PID-reuse keep-predicate (the crate's core safety invariant — see the module
/// docs): a candidate genuinely descends from an anchor only if its order key orders
/// at-or-after the anchor's. The single source of this rule, shared by `descendants_with`
/// and `children_of_with`.
pub(crate) fn keeps_order(key: OrderKey, anchor: OrderKey, allow_equal: bool) -> bool {
    key > anchor || (allow_equal && key == anchor)
}

/// Pure descendant filter (host-testable on every OS). Walks `parents` down from
/// `root`, and for each pid whose ppid chains to `root.pid()` resolves its
/// identity and order key via `resolve(pid, parent)`, `parent` being the accepted process whose pid
/// the edge names, and keeps it ONLY if its key orders correctly
/// against `root_key` per `allow_equal` (see module docs). With `parent_order` it must order
/// after the accepted parent's key instead. `resolve` is injected
/// so the filter is pure: live code passes [`resolve_or_drop`], tests pass a stub.
///
/// The root itself is never included (callers kill the root explicitly first).
pub(crate) fn descendants_with(
    root: ProcessId,
    root_key: OrderKey,
    parents: &[(RawPid, RawPid)],
    allow_equal: bool,
    parent_order: bool,
    resolve: impl Fn(RawPid, ProcessId) -> Option<(ProcessId, OrderKey)>,
) -> Vec<ProcessId> {
    // BFS over the ppid forest. `frontier` holds the accepted pids whose children we still
    // need to visit, each with its order key; it starts as just the root. A pid joins the result
    // (and the next frontier) only if its ppid is in the current accepted set AND its
    // order key passes `keeps_order`. No fixed iteration cap: the loop drains a
    // strictly shrinking set of not-yet-visited edges.
    let mut result: Vec<ProcessId> = Vec::new();
    let mut frontier: Vec<(ProcessId, OrderKey)> = vec![(root, root_key)];
    // Remaining (pid, ppid) edges not yet attached to the tree.
    let mut pending: Vec<(RawPid, RawPid)> = parents.to_vec();
    // Pids already accepted, so a duplicate edge (e.g. a snapshot that lists a
    // pid twice) never enumerates/kills the same process twice.
    let mut accepted: std::collections::HashSet<RawPid> = std::collections::HashSet::new();
    // Memoize identity resolution per pid so `resolve(pid)` runs at most once per
    // pid even when an edge is re-examined across frontier iterations or a pid
    // appears in multiple edges; identity is stable for the duration of the walk.
    let mut resolved: std::collections::HashMap<RawPid, Option<(ProcessId, OrderKey)>> =
        std::collections::HashMap::new();

    while !frontier.is_empty() {
        let mut next: Vec<(ProcessId, OrderKey)> = Vec::new();
        // Partition: edges whose ppid is in the current frontier are candidates.
        let mut still_pending: Vec<(RawPid, RawPid)> = Vec::with_capacity(pending.len());
        for (pid, ppid) in pending.drain(..) {
            let Some(&(parent, parent_key)) = frontier.iter().find(|(p, _)| p.pid() == ppid) else {
                still_pending.push((pid, ppid));
                continue;
            };
            // A process is never its own parent; guard against a degenerate
            // pid == ppid self-loop that would otherwise spin the BFS.
            if pid == ppid {
                continue;
            }
            let read = *resolved.entry(pid).or_insert_with(|| resolve(pid, parent));
            let Some((id, key)) = read else {
                log::debug!("treewalk: pid {pid} unresolvable — dropping its subtree");
                continue;
            };
            // Under parent_order the parent's key implies the root's.
            let must_follow = if parent_order { parent_key } else { root_key };
            if !keeps_order(key, must_follow, allow_equal) {
                log::debug!("treewalk: dropping subtree under impostor pid {pid} (recycled pid / stale ppid)");
                continue;
            }
            // `accepted.insert` dedups so a duplicate edge never enumerates/kills the
            // same process twice.
            if accepted.insert(pid) {
                result.push(id);
                next.push((id, key));
            }
        }
        pending = still_pending;
        frontier = next;
    }

    result
}

/// What `read`, the order key of `anchor` for a walk from it, means for the walk. `Ok(None)`: the
/// anchor is gone, so there is nothing to walk (logged at `debug`). [`Error::Unassessable`] (or
/// `Unsupported`) when the key cannot be told: an empty walk there would let a caller kill the
/// anchor and leave its descendants running.
fn settle_anchor(anchor: ProcessId, read: (Resolved<OrderKey>, UnknownCause)) -> Result<Option<OrderKey>, Error> {
    match read {
        (Resolved::Found(key), _) => Ok(Some(key)),
        (Resolved::Gone, _) => {
            log::debug!("treewalk: pid {pid} is gone - walking nothing", pid = anchor.pid());
            Ok(None)
        }
        (Resolved::Unknown, cause) => Err(unqueryable(&format!("pid {}", anchor.pid()), cause)),
    }
}

/// `anchor`'s order key for a walk from it, read after the snapshot: also the proof that it still
/// holds its pid, so a walk takes its edges from the snapshot only for a root that held the pid
/// throughout. On Windows one read serves as both; elsewhere the pid is proved, then keyed (see
/// [`ProcessId::anchor_order_key_with`] and the module docs). Pass the key to
/// [`descendants_from_key`] or [`children_of_from_key`].
///
/// # Errors
///
/// As [`settle_anchor`]: `Ok(None)` when `anchor` is gone or another process holds its pid now,
/// [`Error::Unassessable`] (or `Unsupported`) when that cannot be told.
pub(crate) fn anchor(kernel: &dyn Kernel, anchor: ProcessId) -> Result<Option<OrderKey>, Error> {
    settle_anchor(anchor, anchor.anchor_order_key_with(kernel))
}

/// Live descendants of `root`, whose order key is `root_key`: the pure filter wired to `kernel`'s
/// `ProcessId::of_ordered_with` resolver and the per-OS `ALLOW_EQUAL_ORDER` rule.
pub(crate) fn descendants_from_key(
    kernel: &dyn Kernel,
    root: ProcessId,
    root_key: OrderKey,
    parents: &[(RawPid, RawPid)],
) -> Vec<ProcessId> {
    descendants_with(
        root,
        root_key,
        parents,
        ALLOW_EQUAL_ORDER,
        ORDER_AFTER_PARENT,
        |pid, parent| resolve_or_drop(kernel, pid, parent),
    )
}

/// [`descendants_from_key`] for `root`'s order key, read here with no proof that `root` still holds
/// its pid: the fd marker's sweep, whose root is not asked for. (Elsewhere a walk calls [`anchor`].)
///
/// # Errors
///
/// [`Error::Unassessable`] (or `Unsupported`) when `root`'s order key exists but cannot be read.
/// Empty, not an error, when `root` is gone.
#[cfg(target_os = "macos")]
pub(crate) fn descendants(
    kernel: &dyn Kernel,
    root: ProcessId,
    parents: &[(RawPid, RawPid)],
) -> Result<Vec<ProcessId>, Error> {
    Ok(settle_anchor(root, root.order_key_with(kernel))?
        .map(|root_key| descendants_from_key(kernel, root, root_key, parents))
        .unwrap_or_default())
}

/// Pure one-level child filter (host-testable): keep each pid whose ppid == the parent's
/// pid and whose order key passes `keeps_order` against `parent_key`. `resolve(pid, parent)` is
/// injected for purity. The parent itself is never included.
pub(crate) fn children_of_with(
    parent: ProcessId,
    parent_key: OrderKey,
    parents: &[(RawPid, RawPid)],
    allow_equal: bool,
    resolve: impl Fn(RawPid, ProcessId) -> Option<(ProcessId, OrderKey)>,
) -> Vec<ProcessId> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for &(pid, ppid) in parents {
        if ppid != parent.pid() || pid == ppid {
            continue;
        }
        let Some((id, key)) = resolve(pid, parent) else {
            log::debug!("treewalk: pid {pid} unresolvable — dropped from children");
            continue;
        };
        if !keeps_order(key, parent_key, allow_equal) {
            log::debug!("treewalk: dropping impostor pid {pid} (recycled pid / stale ppid)");
            continue;
        }
        if seen.insert(pid) {
            out.push(id);
        }
    }
    out
}

/// Live one-level children of `parent`, whose order key is `parent_key`: the pure filter wired to
/// `kernel`'s `ProcessId::of_ordered_with` and the per-OS `ALLOW_EQUAL_ORDER` rule.
pub(crate) fn children_of_from_key(
    kernel: &dyn Kernel,
    parent: ProcessId,
    parent_key: OrderKey,
    parents: &[(RawPid, RawPid)],
) -> Vec<ProcessId> {
    children_of_with(parent, parent_key, parents, ALLOW_EQUAL_ORDER, |pid, parent| {
        resolve_or_drop(kernel, pid, parent)
    })
}

/// Linux: signal `id` through a pidfd proved to name it — never a recycled pid. The pidfd pins the
/// process, so a pid reused after the proof cannot be hit. Already gone (`Ok(None)` from the proof,
/// or `ESRCH` from the send) is success. A pidfd that cannot be opened or proved leaves no identity,
/// so nothing is sent: `NotAttempted`, as for a pid that cannot be queried. Best-effort.
#[cfg(target_os = "linux")]
pub(crate) fn kill_by_identity(kernel: &dyn Kernel, id: ProcessId, signal: Signal) -> KillOutcome {
    use std::os::fd::AsFd as _;

    use nix::errno::Errno;

    match crate::os_process::linux::open::open_verified_with(kernel, id) {
        Ok(None) => {
            log::debug!(
                "treewalk: skipping pid {pid} - identity changed or gone since the snapshot",
                pid = id.pid()
            );
            KillOutcome::AlreadyGone
        }
        Ok(Some(pidfd)) => {
            let sent = crate::containment::unix::pidfd_signal_member(pidfd.as_fd(), id.pid(), signal);
            #[cfg(test)]
            crate::send_log::record_by_identity(id.pid(), signal as i32);
            match sent {
                Ok(()) => KillOutcome::Terminated,
                // Reaped after the proof - nothing was left to kill.
                Err(Errno::ESRCH) => KillOutcome::AlreadyGone,
                Err(e) => {
                    log::warn!("treewalk: pidfd_send_signal(pid {}, {signal:?}) failed: {e}", id.pid());
                    KillOutcome::NotAttempted
                }
            }
        }
        Err(e) => {
            log::warn!(
                "treewalk: pid {pid} has no pidfd that proves it - not signaled, left running: {e}",
                pid = id.pid()
            );
            KillOutcome::NotAttempted
        }
    }
}

/// Kill `id` only if the pid STILL resolves to that exact identity — never a
/// recycled pid. Already-gone (`None`, or `ESRCH`) is success. Best-effort.
///
/// Not atomic: the check and the `kill(2)` are two syscalls, so a pid recycled between them is
/// still hit. This is macOS's residual window (no pidfd); Linux signals through the proved pidfd.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn kill_by_identity(kernel: &dyn Kernel, id: ProcessId, signal: Signal) -> KillOutcome {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    // Re-verify identity at the instant of the kill. Three outcomes, not two: a denied
    // re-verify is NOT a confirmed change, and must not be logged as one.
    match ProcessId::of_with(kernel, id.pid()).0 {
        Resolved::Found(live) if live == id => {}
        Resolved::Found(_) | Resolved::Gone => {
            log::debug!(
                "treewalk: skipping pid {pid} - identity changed since the snapshot",
                pid = id.pid()
            );
            return KillOutcome::AlreadyGone;
        }
        Resolved::Unknown => {
            log::warn!(
                "treewalk: pid {pid} could not be queried (access denied?) - not signaled, left running",
                pid = id.pid()
            );
            return KillOutcome::NotAttempted;
        }
    }
    // `nix::unistd::Pid::from_raw` is infallible and accepts 0, and `kill(0, sig)` signals
    // the CALLER-S ENTIRE PROCESS GROUP. Use the same total guard the `sig 0` probe uses.
    let Some(target) = crate::identity::probe::signal_target(id.pid()) else {
        log::warn!(
            "treewalk: pid {} is not a single-process signal target - not signaled",
            id.pid()
        );
        return KillOutcome::NotAttempted;
    };
    let sent = kill(Pid::from_raw(target), signal);
    #[cfg(test)]
    crate::send_log::record_by_identity(id.pid(), signal as i32);
    match sent {
        Ok(()) => KillOutcome::Terminated,
        // Exited between the re-verify and the signal - nothing was left to kill.
        Err(nix::errno::Errno::ESRCH) => KillOutcome::AlreadyGone,
        Err(e) => {
            log::warn!("treewalk: kill(pid {}, {signal:?}) failed: {e}", id.pid());
            KillOutcome::NotAttempted
        }
    }
}

/// Windows: terminate `id` only if the pid STILL resolves to that exact identity.
/// Opens the process for terminate rights and calls `TerminateProcess`. Already
/// gone (unresolvable / unopenable, or exiting when the call came) is success. Best-effort.
#[cfg(windows)]
pub(crate) fn kill_by_identity(id: ProcessId) -> KillOutcome {
    use windows::Win32::System::Threading::{PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE};

    use crate::identity::{
        windows_close, windows_open_classified, windows_terminate_held, HandleIdentity, Opened, Termination,
    };

    // Open for terminate AND query, so the SAME held handle both pins the kernel object
    // (pid-reuse-safe) and lets us re-verify identity before terminating, race-free.
    let handle = match windows_open_classified(id.pid(), PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION) {
        Opened::Found(h) => h,
        Opened::Gone => return KillOutcome::AlreadyGone,
        Opened::Denied(e) => {
            log::warn!(
                "treewalk: pid {} could not be queried (access denied?) - not opened to terminate ({e}), left running",
                id.pid()
            );
            return KillOutcome::NotAttempted;
        }
    };
    let outcome = match crate::identity::windows_handle_identity(handle, id) {
        HandleIdentity::Same => {
            #[cfg(test)]
            fault::run_before_terminate();
            match windows_terminate_held(handle) {
                Termination::Terminated => KillOutcome::Terminated,
                Termination::Exited => KillOutcome::AlreadyGone,
                Termination::Failed(e) => {
                    log::warn!("treewalk: TerminateProcess(pid {}) failed: {e}", id.pid());
                    KillOutcome::NotAttempted
                }
            }
        }
        HandleIdentity::Different => {
            log::debug!(
                "treewalk: skipping pid {} - identity changed since the snapshot",
                id.pid()
            );
            KillOutcome::AlreadyGone
        }
        HandleIdentity::Unreadable(e) => {
            log::warn!(
                "treewalk: pid {} opened but its identity could not be read ({e}) - not terminated",
                id.pid()
            );
            KillOutcome::NotAttempted
        }
    };
    windows_close(handle);
    outcome
}

/// Whether `root` still holds its pid, asked AFTER the snapshot was taken, for a caller that needs
/// no order key (a walk uses [`anchor`], which asks for both). `Ok(false)`: gone or
/// recycled. [`Error::Unassessable`] (or `Unsupported`) when it cannot be told, naming the read's
/// cause.
pub(crate) fn anchor_present(kernel: &dyn Kernel, root: ProcessId) -> Result<bool, Error> {
    match root.exists_with(kernel) {
        (Existence::Present, _) => Ok(true),
        (Existence::Gone, _) => Ok(false),
        (Existence::Unknown, cause) => Err(unqueryable(&format!("pid {}", root.pid()), cause)),
    }
}

/// The error for a `subject` (`pid N` / `ppid N`) that exists but read `Unknown`: the `/proc`
/// view when that is why, else access.
pub(crate) fn unqueryable(subject: &str, cause: UnknownCause) -> Error {
    cause.into_error(subject).unwrap_or_else(|| Error::Unassessable {
        detail: format!("{subject} exists but could not be queried (access denied?)"),
        source: None,
    })
}

/// [`unqueryable`] for the ordered read of `pid` that left `Unknown` with `cause`: the subject is
/// `pid`, or the parent whose proof failed when `cause` blames it.
pub(crate) fn unqueryable_read(pid: RawPid, cause: UnknownCause) -> Error {
    let subject = match cause.blamed_parent() {
        Some(parent) => format!("ppid {parent}"),
        None => format!("pid {pid}"),
    };
    unqueryable(&subject, cause)
}

/// Hard-kill the tree rooted at `root` by identity: snapshot once, compute
/// genuine descendants, kill the root FIRST then each descendant. SIGKILL on
/// Unix; `TerminateProcess` on Windows. Best-effort; already-gone is success.
///
/// # Errors
///
/// [`Error::Unassessable`] when the process snapshot cannot be taken, or `root`'s
/// identity or order key cannot be read after it (a root that exists but cannot be queried).
/// Nothing is killed, the root included: killing the root first would reparent its descendants
/// out of the ppid walk, so a retry could no longer find them. A root that no longer holds its pid
/// is `Ok`, with nothing killed.
///
/// `Ok(false)`: the walk ran but was not complete, because an identity it resolved refused the
/// kill, so members may be left running.
pub(crate) fn hard_kill(kernel: &dyn Kernel, root: ProcessId) -> Result<bool, Error> {
    // Test-only fault seam: skip the root's identity kill (take semantics — see `fault`).
    #[cfg(test)]
    let skip_root = fault::take_force_root_kill_noop();
    #[cfg(not(test))]
    let skip_root = false;
    let parents = crate::containment::enumerate::process_parents(kernel)?;
    let Some(root_key) = anchor(kernel, root)? else {
        return Ok(true);
    };
    #[cfg(test)]
    fault::note_walk(root.pid());
    let mut complete = true;
    #[cfg(test)]
    if fault::take_force_incomplete() {
        complete = false;
    }
    let descendants = descendants_from_key(kernel, root, root_key, &parents);
    #[cfg(unix)]
    {
        if !skip_root {
            complete &= kill_by_identity(kernel, root, Signal::SIGKILL) != KillOutcome::NotAttempted;
        }
        for id in descendants {
            complete &= kill_by_identity(kernel, id, Signal::SIGKILL) != KillOutcome::NotAttempted;
        }
    }
    #[cfg(windows)]
    {
        if !skip_root {
            complete &= kill_by_identity(root) != KillOutcome::NotAttempted;
        }
        for id in descendants {
            complete &= kill_by_identity(id) != KillOutcome::NotAttempted;
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (kernel, root, descendants, skip_root);
    Ok(complete)
}

/// Test-only: force the NEXT `hard_kill` on THIS thread to skip the root's identity kill
/// (makes the `kill_tree` handle backstop forcible). Take semantics: `hard_kill` consumes the
/// flag — arm and call on one thread; assert consumption via [`armed`].
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::{Cell, RefCell};
    thread_local! {
        static FORCE_ROOT_KILL_NOOP: Cell<bool> = const { Cell::new(false) };
        static WALKS: RefCell<Option<Vec<u32>>> = const { RefCell::new(None) };
        static FORCE_INCOMPLETE: Cell<bool> = const { Cell::new(false) };
        #[cfg(windows)]
        static BEFORE_TERMINATE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    /// Run `hook` once on this thread in the next Windows `kill_by_identity`, between the identity
    /// check and `TerminateProcess` (where a member can exit on its own).
    #[cfg(windows)]
    pub(crate) fn set_before_terminate(hook: impl FnOnce() + 'static) {
        BEFORE_TERMINATE.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(windows)]
    pub(super) fn run_before_terminate() {
        if let Some(hook) = BEFORE_TERMINATE.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    /// Make the NEXT `hard_kill` on THIS thread report an incomplete walk, as an unreadable
    /// process table or a refused kill would. Take semantics.
    #[cfg(unix)]
    pub(crate) fn force_incomplete_once() {
        FORCE_INCOMPLETE.with(|f| f.set(true));
    }

    pub(super) fn take_force_incomplete() -> bool {
        FORCE_INCOMPLETE.with(|f| f.replace(false))
    }

    /// From now on every ppid walk from a root's pid on THIS thread (`treewalk::hard_kill` and
    /// `terminate` once `anchor` lets them walk, a macOS fd marker's channel 1+2) records
    /// that pid, so a test can tell a walk ran without a process having to die. The walk itself
    /// still runs.
    #[cfg(unix)]
    pub(crate) fn record_walks() -> WalkRecorder {
        WALKS.with(|w| *w.borrow_mut() = Some(Vec::new()));
        WalkRecorder(())
    }

    #[cfg(unix)]
    #[must_use = "recording stops as soon as the recorder is dropped"]
    pub(crate) struct WalkRecorder(());

    #[cfg(unix)]
    impl WalkRecorder {
        /// The root pids walked since the recorder was made.
        pub(crate) fn walked(&self) -> Vec<u32> {
            WALKS.with(|w| w.borrow().clone().expect("the recorder is live"))
        }
    }

    #[cfg(unix)]
    impl Drop for WalkRecorder {
        fn drop(&mut self) {
            WALKS.with(|w| *w.borrow_mut() = None);
        }
    }

    pub(crate) fn note_walk(root_pid: u32) {
        WALKS.with(|w| {
            if let Some(walked) = w.borrow_mut().as_mut() {
                walked.push(root_pid);
            }
        });
    }
    // On macOS, `Attached::TreeWalk` (and so `hard_kill`) is only reached when the fd marker
    // failed to install or is suppressed (decision 2: the marker otherwise takes priority) —
    // dispatch_tests.rs's backstop tests exercise the always-installed `fdmarker::fault` seam
    // there instead, leaving these two callers-only-on-other-platforms.
    #[cfg_attr(
        target_os = "macos",
        allow(
            dead_code,
            reason = "dispatch_tests.rs uses the fdmarker::fault seam on macOS instead"
        )
    )]
    pub(crate) fn set_force_root_kill_noop(on: bool) {
        FORCE_ROOT_KILL_NOOP.with(|f| f.set(on));
    }
    pub(crate) fn take_force_root_kill_noop() -> bool {
        FORCE_ROOT_KILL_NOOP.with(|f| f.replace(false))
    }
    #[cfg_attr(
        target_os = "macos",
        allow(
            dead_code,
            reason = "dispatch_tests.rs uses the fdmarker::fault seam on macOS instead"
        )
    )]
    pub(crate) fn armed() -> bool {
        FORCE_ROOT_KILL_NOOP.with(|f| f.get())
    }
}

/// Graceful termination of the tree rooted at `root`.
///
/// Unix: the same snapshot + identity walk with SIGTERM (root then descendants) —
/// cooperative shutdown that still re-verifies identity before each signal, so it
/// reaches the whole genuine tree just like `hard_kill`, and errors as it does (`# Errors`).
///
/// Windows: send `CTRL_BREAK_EVENT` to the root's process group (the root was
/// spawned with `CREATE_NEW_PROCESS_GROUP`). This is cooperative only and reaches
/// only processes that share the root's console group; a nested *contained*
/// descendant is spawned into its OWN process group (`CREATE_NEW_PROCESS_GROUP`)
/// and therefore does NOT receive this CTRL_BREAK. THIS WALK cannot reach those
/// nested groups — but their own holder can, through the nested child's own handle
/// (see [`Child::terminate`](crate::Child::terminate)). From a single handle, the
/// identity `hard_kill` (`kill_tree`) remains the only op that reaches every member.
/// Best-effort by design.
///
/// # Errors
///
/// As [`hard_kill`] on Unix. Windows: those of `containment::windows::terminate`.
pub(crate) fn terminate(kernel: &dyn Kernel, root: ProcessId) -> Result<(), Error> {
    #[cfg(unix)]
    {
        let parents = crate::containment::enumerate::process_parents(kernel)?;
        let Some(root_key) = anchor(kernel, root)? else {
            return Ok(());
        };
        #[cfg(test)]
        fault::note_walk(root.pid());
        let descendants = descendants_from_key(kernel, root, root_key, &parents);
        let _ = kill_by_identity(kernel, root, Signal::SIGTERM);
        for id in descendants {
            let _ = kill_by_identity(kernel, id, Signal::SIGTERM);
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = kernel;
        crate::containment::windows::terminate(root.pid())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (kernel, root);
        Ok(())
    }
}

#[cfg(test)]
#[path = "treewalk_tests.rs"]
mod treewalk_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "treewalk_view_tests.rs"]
mod treewalk_view_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "treewalk_pidfs_tests.rs"]
mod treewalk_pidfs_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "treewalk_blind_tests.rs"]
mod treewalk_blind_tests;

#[cfg(all(test, windows))]
#[path = "treewalk_toolhelp_tests.rs"]
mod treewalk_toolhelp_tests;
