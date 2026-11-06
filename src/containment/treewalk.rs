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
//! child, so its ppid no longer chains to the root), a descendant whose parent exits while the walk
//! runs, with its subtree (see the parent read below), and broker-spawned escapes. On Windows it also
//! misses a genuine descendant whose creator exited and whose creator's pid now belongs to a later
//! in-tree process, with its subtree (see the parent-order rule below).
//!
//! # The PID-reuse / stale-ppid defense
//!
//! A `(pid, ppid)` snapshot is racy: a candidate's `pid` may have been recycled, or its `ppid` may
//! name a *recycled* pid. So a chained ppid alone does not prove descent: each candidate is read
//! again, under the parent the walk accepted for it (see the parent read below).
//!
//! The walk cannot defend a root whose own pid was recycled: the new owner's children read as
//! genuine. So it takes its snapshot first, then proves the root still holds its pid ([`anchor`]); a
//! root that does not walks nothing. A root that is gone walks nothing; one that exists but cannot
//! be read is an error (`Error::Unassessable`), never an empty walk.
//!
//! - **Linux/macOS** reparent orphans to pid 1 / launchd, so a process whose ppid, read after its
//!   parent was proved, still equals the parent's pid genuinely descends from it: ppid is
//!   *authoritative*, and no order rule applies. One would drop a child whose in-tree tracer started
//!   after it (XNU's `PT_ATTACH` makes the tracer the parent), or one older than the root that an
//!   in-tree debugger attached to. The root is only proved: one gone between the snapshot and the
//!   proof walks nothing, which loses no one, because its children are reparented at its exit and no
//!   longer descend from it.
//! - **Windows** never reparents, and the parent field is the *creator*, which survives its
//!   creator's exit and can name a pid a later process holds. So the proof of the root and its
//!   [`OrderKey`] (the process sequence number, a creation counter) are one read on one handle: a root
//!   that exits cannot be proved and then found gone with its unreparented children unwalked. The
//!   order key is then the bound of the rule below.
//!
//! # The parent-order rule (Windows only)
//!
//! Where the parent field is the creator ([`ORDER_AFTER_PARENT`]), a candidate is kept only if its
//! key orders strictly after its accepted parent's, the root's for a root's child. An impostor — a
//! *stale ppid* pointing at a *recycled* pid — was created before the pid's later holder, so it
//! orders before it and is dropped. Keys are unique (one per process creation) and a process's
//! exceeds its creator's, so the strict rule loses no genuine child. [`children_of_with`] needs no
//! switch: its parent is the anchor. `ProcessId::parent` follows the same const.
//!
//! [`ORDER_AFTER_PARENT`]: crate::identity::ORDER_AFTER_PARENT
//!
//! The rule also drops a genuine descendant whose creator exited and whose creator's pid now belongs
//! to a later in-tree process, with its subtree: from the snapshot alone it cannot be told from a
//! stale-creator impostor.
//!
//! # The parent read (every platform)
//!
//! A snapshot row's ppid is only a number. The resolver reads the candidate again, and its parent
//! number and id (on Windows, also the order key) all come from that one read, so they describe the
//! same process. A candidate whose parent number is not the accepted parent's pid is dropped, and so is one whose accepted
//! parent no longer holds that pid when the read is done. So a descendant whose parent exits while
//! the walk runs is dropped with its subtree: Linux and macOS reparent it, so its record names its
//! new parent; Windows never updates the creator pid, which still names the dead parent, and the
//! read cannot tell that from a pid that changed hands. On Windows a candidate whose key does not
//! follow the bound (above) is dropped as `Gone` in the same read, before the parent is proved: a
//! process that cannot be the child is not a member the walk failed to assess. A candidate whose own
//! read fails (no record, on Windows no sequence number, or a parent number that cannot be read) goes to the proof of the accepted parent
//! first: a parent that is gone drops it quietly, as `Gone`; one that cannot be proved drops it with
//! a warning naming `ppid N`; and only a held parent lets its own failure stand, dropped with a
//! warning naming the candidate (on Windows, with the `NTSTATUS` of a refused creator-pid or
//! sequence-number query).
//!
//! # A walk that could not assess a member
//!
//! Both of those drops are a candidate the walk could not assess, unlike a `Gone` one, which is
//! not a member and is dropped silently. The walk returns them in [`Walk::unassessed`] beside its
//! members, so no caller takes a short list for the whole tree: [`hard_kill`] reports `Ok(false)`,
//! the fd marker's sweep reports itself incomplete, and `ProcessId::children` is an error.
//!
//! A process the walk cannot read is never taken for one that is not the root's. On Windows that
//! includes a process it cannot open (one the caller may not query), whose creator pid is never
//! updated: if it names the root's pid, because an earlier holder of that pid created it, the walk
//! cannot tell it from a genuine child, so every walk from that root is incomplete for as long as it
//! lives. Only a walk is affected: a Job Object holds its members by membership and never walks.

use crate::error::Error;
use crate::identity::{resolution_of, Kernel, OrderKey, ProcessId, RawPid, Resolution};
use crate::Recursive;

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

/// What a walk found: the genuine members, and the candidates it could not assess.
///
/// A candidate whose identity could not be read stays out of `members` (the walk cannot kill what it
/// cannot verify), and so does its subtree, which the walk cannot reach through it. It is counted in
/// `unassessed`, so a caller never takes a short `members` for the whole tree. A candidate that is
/// gone is in neither.
#[derive(Debug, Default)]
pub(crate) struct Walk {
    pub(crate) members: Vec<ProcessId>,
    /// Each candidate dropped for an `Unknown` read, with why ([`unqueryable_read`](crate::identity::unqueryable_read)):
    /// the candidate's own failure, or the proof of the parent it was read under.
    pub(crate) unassessed: Vec<(RawPid, Error)>,
}

/// The tree-walk resolver. Denied is warned and returned as `Err` (counted in [`Walk::unassessed`]);
/// gone is `Ok(None)`.
///
/// `parent` is the process the walk accepted as the parent the snapshot gave `pid`. Where the read of
/// `pid` carries its parent, a candidate
/// is dropped when its parent's number is another now, which means the pid changed hands since the
/// snapshot or the same process was orphaned and is no longer in the tree; and when its parent's
/// number no longer holds `parent`, which means the parent was reaped and its number taken by a
/// process whose own children the candidate could be. `bound` is the order key the candidate must
/// follow ([`ProcessId::of_ordered_with`]), given only where the platform orders by it: one that
/// does not is dropped as gone, before `parent` is proved.
pub(crate) fn resolve_or_drop(
    kernel: &dyn Kernel,
    pid: RawPid,
    parent: ProcessId,
    bound: Option<OrderKey>,
) -> Resolution {
    let read = ProcessId::of_ordered_with(kernel, pid, Some(parent), None, bound);
    let parent_blamed = read.1.blamed_parent().is_some();
    let resolution = resolution_of("pid", pid, read);
    if let Err(error) = &resolution {
        let why = match error {
            Error::Unassessable { detail, .. } => detail.clone(),
            other => other.to_string(),
        };
        // The reason names the pid when it is the subject, else the blamed parent; then the pid is named here.
        let dropped = if parent_blamed {
            format!("pid {pid} dropped")
        } else {
            "dropped".to_owned()
        };
        log::warn!("treewalk: {why} - {dropped} from the walk");
    }
    resolution
}

#[cfg(unix)]
use nix::sys::signal::Signal;

/// Pure descendant filter (host-testable on every OS). Walks `parents` down from
/// `root`, and for each pid whose ppid chains to `root.pid()` resolves its
/// identity via `resolve(pid, parent, bound)`, `parent` being the accepted process whose pid the
/// edge names, and `bound` the order key the candidate must follow (see module docs): the accepted
/// parent's, which only Windows gives (`root_bound` for the root's children, and the `Option<OrderKey>`
/// each resolution carries for the rest). The resolver answers `Ok(None)` for a candidate that does
/// not follow it. `resolve` is injected so the filter is pure: live code passes [`resolve_or_drop`],
/// tests pass a stub. A candidate the resolver errs on is dropped with its subtree and listed once in
/// [`Walk::unassessed`].
///
/// The root itself is never included (callers kill the root explicitly first).
pub(crate) fn descendants_with(
    root: ProcessId,
    root_bound: Option<OrderKey>,
    parents: &[(RawPid, RawPid)],
    resolve: impl Fn(RawPid, ProcessId, Option<OrderKey>) -> Resolution,
) -> Walk {
    // BFS over the ppid forest. `frontier` holds the accepted pids whose children we still
    // need to visit, each with the bound its children follow; it starts as just the root. A pid joins
    // the result (and the next frontier) only if its ppid is in the current accepted set AND the
    // resolver finds it ordered after the bound. No fixed iteration cap: the loop drains a
    // strictly shrinking set of not-yet-visited edges.
    let mut walk = Walk::default();
    let mut frontier: Vec<(ProcessId, Option<OrderKey>)> = vec![(root, root_bound)];
    // Remaining (pid, ppid) edges not yet attached to the tree.
    let mut pending: Vec<(RawPid, RawPid)> = parents.to_vec();
    // Pids already accepted, so a duplicate edge (e.g. a snapshot that lists a
    // pid twice) never enumerates/kills the same process twice.
    let mut accepted: std::collections::HashSet<RawPid> = std::collections::HashSet::new();
    // Memoize identity resolution per pid so `resolve(pid)` runs at most once per
    // pid even when an edge is re-examined across frontier iterations or a pid
    // appears in multiple edges; identity is stable for the duration of the walk.
    let mut resolved: std::collections::HashMap<RawPid, Option<(ProcessId, Option<OrderKey>)>> =
        std::collections::HashMap::new();

    while !frontier.is_empty() {
        let mut next: Vec<(ProcessId, Option<OrderKey>)> = Vec::new();
        // Partition: edges whose ppid is in the current frontier are candidates.
        let mut still_pending: Vec<(RawPid, RawPid)> = Vec::with_capacity(pending.len());
        for (pid, ppid) in pending.drain(..) {
            let Some(&(parent, bound)) = frontier.iter().find(|(p, _)| p.pid() == ppid) else {
                still_pending.push((pid, ppid));
                continue;
            };
            // A process is never its own parent; guard against a degenerate
            // pid == ppid self-loop that would otherwise spin the BFS.
            if pid == ppid {
                continue;
            }
            let read = *resolved
                .entry(pid)
                .or_insert_with(|| match resolve(pid, parent, bound) {
                    Ok(None) => {
                        log::debug!(
                        "treewalk: pid {pid} gone, or an impostor (recycled pid / stale ppid) - dropping its subtree"
                    );
                        None
                    }
                    Ok(read) => read,
                    // Already warned where the read was made.
                    Err(why) => {
                        walk.unassessed.push((pid, why));
                        None
                    }
                });
            let Some((id, children_bound)) = read else {
                continue;
            };
            // `accepted.insert` dedups so a duplicate edge never enumerates/kills the
            // same process twice.
            if accepted.insert(pid) {
                walk.members.push(id);
                next.push((id, children_bound));
            }
        }
        pending = still_pending;
        frontier = next;
    }

    walk
}

/// `anchor`, proved to hold its pid for a walk from it, and the bound its children follow
/// ([`ProcessId::anchor_bound_with`]): the proof is read after the snapshot, so a walk takes its
/// edges from the snapshot only for a root that held the pid throughout. [`walk_from`] is its only
/// caller.
///
/// # Errors
///
/// `Ok(None)` when `anchor` is gone or another process holds its pid now (logged at `debug`):
/// there is nothing to walk. [`Error::Unassessable`] (or `Unsupported`) when that cannot be told:
/// an empty walk there would let a caller kill the anchor and leave its descendants running.
fn anchor(kernel: &dyn Kernel, anchor: ProcessId) -> Result<Option<AnchorProof>, Error> {
    let proof = resolution_of("pid", anchor.pid(), anchor.anchor_bound_with(kernel))?;
    if proof.is_none() {
        log::debug!("treewalk: pid {pid} is gone - walking nothing", pid = anchor.pid());
    }
    Ok(proof.map(|bound| AnchorProof { bound }))
}

/// A walk's anchor, proved to hold its pid: the bound its children follow (see
/// [`ProcessId::anchor_bound_with`]).
struct AnchorProof {
    bound: Option<OrderKey>,
}

/// Pure one-level child filter (host-testable): keep each pid whose ppid == the parent's
/// pid and which the resolver finds ordered after `parent_bound`: `resolve(pid, parent, bound)` is
/// injected for purity, with `parent_bound` as the bound. The parent itself is never included. A pid
/// the resolver errs on is listed once in [`Walk::unassessed`].
pub(crate) fn children_of_with(
    parent: ProcessId,
    parent_bound: Option<OrderKey>,
    parents: &[(RawPid, RawPid)],
    resolve: impl Fn(RawPid, ProcessId, Option<OrderKey>) -> Resolution,
) -> Walk {
    let mut walk = Walk::default();
    // Each pid is resolved once, so a duplicate edge cannot list a pid twice or be read differently.
    let mut resolved = std::collections::HashSet::new();
    for &(pid, ppid) in parents {
        if ppid != parent.pid() || pid == ppid || !resolved.insert(pid) {
            continue;
        }
        match resolve(pid, parent, parent_bound) {
            Ok(Some((id, _))) => walk.members.push(id),
            Ok(None) => {
                log::debug!(
                    "treewalk: pid {pid} gone, or an impostor (recycled pid / stale ppid) - dropped from children"
                );
            }
            Err(why) => walk.unassessed.push((pid, why)),
        }
    }
    walk
}

/// The walk from `root` over `parents`, a snapshot taken BEFORE this call: the one entry to the
/// live walks. `depth` is `Recursive::No` for `root`'s direct children, `Yes` for its whole subtree:
/// the pure filters wired to [`resolve_or_drop`].
///
/// The anchor rule is here, so no caller can walk from a root it has not proved: `root` is proved
/// to hold its pid now ([`anchor`]), and `Ok(None)` means it is gone or another process holds its
/// pid, so there is nothing to walk.
///
/// # Errors
///
/// [`Error::Unassessable`] (or `Unsupported`) when the anchor cannot be proved.
///
/// `root` needs no row in `parents`: the walk reads only the rows that name it as their parent, and
/// a missing row of `root` says nothing about those. Toolhelp, for one, does not list an exited
/// process whose handle is held, though its children, which Windows does not reparent, run on.
pub(crate) fn walk_from(
    kernel: &dyn Kernel,
    root: ProcessId,
    parents: &[(RawPid, RawPid)],
    depth: Recursive,
) -> Result<Option<Walk>, Error> {
    let Some(AnchorProof { bound: root_bound }) = anchor(kernel, root)? else {
        return Ok(None);
    };
    let resolve = |pid, parent, bound| resolve_or_drop(kernel, pid, parent, bound);
    Ok(Some(match depth {
        Recursive::No => children_of_with(root, root_bound, parents, resolve),
        Recursive::Yes => descendants_with(root, root_bound, parents, resolve),
    }))
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

    use crate::identity::Resolved;
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
    let rights = PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION;
    let handle = match windows_open_classified(id.pid(), rights) {
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
            match windows_terminate_held(handle, rights) {
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

/// Hard-kill the tree rooted at `root` by identity: snapshot once, compute
/// genuine descendants, kill the root FIRST then each descendant. SIGKILL on
/// Unix; `TerminateProcess` on Windows. Best-effort; already-gone is success.
///
/// # Errors
///
/// [`Error::Unassessable`] when the process snapshot cannot be taken, or `root` cannot be proved
/// to hold its pid after it (a root that exists but cannot be queried).
/// Nothing is killed, the root included: killing the root first would reparent its descendants
/// out of the ppid walk, so a retry could no longer find them. A root that no longer holds its pid
/// is `Ok`, with nothing killed.
///
/// `Ok(false)`: the walk ran but was not complete, because an identity it resolved refused the
/// kill, or a candidate's identity could not be read (so it and its subtree were not walked), so
/// members may be left running.
pub(crate) fn hard_kill(kernel: &dyn Kernel, root: ProcessId) -> Result<bool, Error> {
    // Test-only fault seam: skip the root's identity kill (take semantics — see `fault`).
    #[cfg(test)]
    let skip_root = fault::take_force_root_kill_noop();
    #[cfg(not(test))]
    let skip_root = false;
    let parents = crate::containment::enumerate::process_parents(kernel)?;
    let Some(Walk {
        members: descendants,
        unassessed,
    }) = walk_from(kernel, root, &parents, Recursive::Yes)?
    else {
        return Ok(true);
    };
    #[cfg(test)]
    fault::note_walk(root.pid());
    let mut complete = true;
    #[cfg(test)]
    if fault::take_force_incomplete() {
        complete = false;
    }
    // A candidate that could not be read is not killed, and nor is anything under it: not complete.
    complete &= unassessed.is_empty();
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

    /// From now on every ppid walk from a root's pid on THIS thread (`treewalk::hard_kill`,
    /// `terminate`, a macOS fd marker's channel 1+2) records that pid, so a test can tell a walk
    /// ran without a process having to die. The walk itself still runs.
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
/// reaches the whole genuine tree that the walk could assess, and errors as `hard_kill` does
/// (`# Errors`). Unlike `hard_kill` it does not report a candidate the walk could not assess
/// ([`Walk::unassessed`]): that candidate and its subtree are warned of and not signalled, and
/// the result is still `Ok`.
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
        let Some(walk) = walk_from(kernel, root, &parents, Recursive::Yes)? else {
            return Ok(());
        };
        #[cfg(test)]
        fault::note_walk(root.pid());
        // Best effort by contract: a candidate that could not be read was warned and is not signalled.
        let descendants = walk.members;
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
