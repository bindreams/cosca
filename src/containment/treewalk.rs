//! Identity-aware process-tree teardown — the cross-platform mechanism, used
//! both when requested directly (`ContainMode::TreeWalk`) and as the terminal
//! fallback of `ContainMode::Strongest` (e.g. a Windows job-assign failure, or a
//! host with no kernel container).
//!
//! Unlike a kernel container, this mechanism has no enforced membership: at
//! teardown it takes a `(pid, ppid)` snapshot of the host, walks the ppid chain
//! down from the root, and kills each *genuine* descendant by identity. It is
//! best-effort and reports as [`crate::containment::Containment::TreeWalk`]: it
//! misses reparented orphans (a child whose parent already exited, so its ppid no
//! longer chains to the root) and broker-spawned escapes.
//!
//! # The PID-reuse / stale-ppid defense (the token-order rule)
//!
//! A `(pid, ppid)` snapshot is racy: a candidate's `pid` may have been recycled,
//! or its `ppid` may name a *recycled* root pid. So a chained ppid alone does not
//! prove descent. We additionally require the candidate's high-res start token
//! (Linux jiffies / Windows 100 ns FILETIME / macOS µs) to order correctly
//! against the root's: a genuine descendant was created at-or-after the root
//! acquired its pid. The keep predicate is
//!
//! ```text
//! token > root.token || (allow_equal && token == root.token)
//! ```
//!
//! `allow_equal` is a per-OS `cfg` const ([`ALLOW_EQUAL_TOKEN`]): `true` on
//! Linux/macOS, `false` on Windows. Why per-OS:
//!
//! - An impostor — a *stale ppid* pointing at a *recycled* root pid — is always a
//!   process created *before* the root (token **<** root.token), so it is
//!   excluded by both rules. This is the case the token guard exists to defend.
//! - A `token == root.token` candidate whose current ppid == root.pid can only be
//!   a *genuine* same-tick child: an unrelated same-tick collision that also
//!   happens to carry a recycled ppid equal to root.pid is impossible.
//! - **Linux/macOS** reparent orphans to pid 1 / launchd, so a process whose ppid
//!   still equals root.pid genuinely descends from it — ppid is *authoritative*.
//!   `>=` is therefore safe AND catches same-jiffy immediate children that strict
//!   `>` would silently miss under Linux's coarse 10 ms jiffy clock (this also
//!   makes the live integration test deterministic).
//! - **Windows** does not reparent and recycles pids freely, so we keep strict
//!   `>`. Its 100 ns FILETIME clock makes a same-tick *genuine* child
//!   indistinguishable from impossible, so strict `>` loses nothing there.

use crate::identity::{ProcessId, RawPid};

#[cfg(unix)]
use nix::sys::signal::Signal;

/// Per-OS token-order rule (USER DECISION). See the module docs for the full
/// rationale. Linux/macOS reparent orphans → ppid is authoritative → keep
/// same-tick children (`>=`). Windows recycles pids and never reparents → keep
/// strict `>`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const ALLOW_EQUAL_TOKEN: bool = true;
#[cfg(windows)]
pub(crate) const ALLOW_EQUAL_TOKEN: bool = false;
// Other Unix (e.g. BSD without a tested rule): default to the conservative
// strict-`>` rule. enumerate's compile_error gates real support per OS.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) const ALLOW_EQUAL_TOKEN: bool = false;

/// The PID-reuse keep-predicate (the crate's core safety invariant — see the module
/// docs): a candidate genuinely descends from an anchor only if its start token orders
/// at-or-after the anchor's. The single source of this rule, shared by `descendants_with`
/// and `children_of_with`.
pub(crate) fn keeps_token(token: u64, anchor: u64, allow_equal: bool) -> bool {
    token > anchor || (allow_equal && token == anchor)
}

/// Pure descendant filter (host-testable on every OS). Walks `parents` down from
/// `root`, and for each pid whose ppid chains to `root.pid()` resolves its
/// identity via `resolve` and keeps it ONLY if its start token orders correctly
/// against the root's per `allow_equal` (see module docs). `resolve` is injected
/// so the filter is pure: live code passes `ProcessId::of`, tests pass a stub.
///
/// The root itself is never included (callers kill the root explicitly first).
pub(crate) fn descendants_with(
    root: ProcessId,
    parents: &[(RawPid, RawPid)],
    allow_equal: bool,
    resolve: impl Fn(RawPid) -> Option<ProcessId>,
) -> Vec<ProcessId> {
    let root_token = root.start_token_raw();
    let keep = |token: u64| keeps_token(token, root_token, allow_equal);

    // BFS over the ppid forest. `frontier` holds pids whose children we still
    // need to visit; it starts as just the root pid. A pid joins the result (and
    // the next frontier) only if its ppid is in the current accepted set AND its
    // identity passes the token guard. No fixed iteration cap: the loop drains a
    // strictly shrinking set of not-yet-visited edges.
    let mut result: Vec<ProcessId> = Vec::new();
    let mut frontier: Vec<RawPid> = vec![root.pid()];
    // Remaining (pid, ppid) edges not yet attached to the tree.
    let mut pending: Vec<(RawPid, RawPid)> = parents.to_vec();
    // Pids already accepted, so a duplicate edge (e.g. a snapshot that lists a
    // pid twice) never enumerates/kills the same process twice.
    let mut accepted: std::collections::HashSet<RawPid> = std::collections::HashSet::new();
    // Memoize identity resolution per pid so `resolve(pid)` runs at most once per
    // pid even when an edge is re-examined across frontier iterations or a pid
    // appears in multiple edges; identity is stable for the duration of the walk.
    let mut resolved: std::collections::HashMap<RawPid, Option<ProcessId>> = std::collections::HashMap::new();

    while !frontier.is_empty() {
        let mut next: Vec<RawPid> = Vec::new();
        // Partition: edges whose ppid is in the current frontier are candidates.
        let mut still_pending: Vec<(RawPid, RawPid)> = Vec::with_capacity(pending.len());
        for (pid, ppid) in pending.drain(..) {
            if !frontier.contains(&ppid) {
                still_pending.push((pid, ppid));
                continue;
            }
            // A process is never its own parent; guard against a degenerate
            // pid == ppid self-loop that would otherwise spin the BFS.
            if pid == ppid {
                continue;
            }
            let id = *resolved.entry(pid).or_insert_with(|| resolve(pid));
            // Unresolvable (already gone), or resolvable but the token says
            // impostor (recycled pid / stale ppid): drop the whole subtree under it.
            let Some(id) = id else { continue };
            // `keep` (token rule) first; `accepted.insert` dedups so a duplicate
            // edge never enumerates/kills the same process twice (short-circuit
            // means insert runs only for a kept pid — same as the prior guard).
            if keep(id.start_token_raw()) && accepted.insert(pid) {
                result.push(id);
                next.push(pid);
            }
        }
        pending = still_pending;
        frontier = next;
    }

    result
}

/// Live descendants of `root`: the pure filter wired to the host's
/// `ProcessId::of` resolver and per-OS `ALLOW_EQUAL_TOKEN` rule.
pub(crate) fn descendants(root: ProcessId, parents: &[(RawPid, RawPid)]) -> Vec<ProcessId> {
    descendants_with(root, parents, ALLOW_EQUAL_TOKEN, ProcessId::of)
}

/// Pure one-level child filter (host-testable): keep each pid whose ppid == the parent's
/// pid and whose start token passes `keeps_token` against the parent's. `resolve` is
/// injected for purity. The parent itself is never included.
pub(crate) fn children_of_with(
    parent: ProcessId,
    parents: &[(RawPid, RawPid)],
    allow_equal: bool,
    resolve: impl Fn(RawPid) -> Option<ProcessId>,
) -> Vec<ProcessId> {
    let ptoken = parent.start_token_raw();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for &(pid, ppid) in parents {
        if ppid != parent.pid() || pid == ppid {
            continue;
        }
        let Some(id) = resolve(pid) else { continue };
        if keeps_token(id.start_token_raw(), ptoken, allow_equal) && seen.insert(pid) {
            out.push(id);
        }
    }
    out
}

/// Live one-level children of `parent`: the pure filter wired to `ProcessId::of` and the
/// per-OS `ALLOW_EQUAL_TOKEN` rule.
pub(crate) fn children_of(parent: ProcessId, parents: &[(RawPid, RawPid)]) -> Vec<ProcessId> {
    children_of_with(parent, parents, ALLOW_EQUAL_TOKEN, ProcessId::of)
}

/// Kill `id` only if the pid STILL resolves to that exact identity — never a
/// recycled pid. Already-gone (`None`, or `ESRCH`) is success. Best-effort.
#[cfg(unix)]
pub(crate) fn kill_by_identity(id: ProcessId, signal: Signal) {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    // Re-verify identity at the instant of the kill: if the pid was recycled
    // since the snapshot, `of` returns a different (or no) identity and we skip.
    if ProcessId::of(id.pid()) != Some(id) {
        return;
    }
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; signal target cast would truncate",
        id.pid()
    );
    match kill(Pid::from_raw(id.pid() as i32), signal) {
        Ok(()) => {}
        Err(nix::errno::Errno::ESRCH) => {} // already gone between re-verify and kill
        Err(_) => {}                        // best-effort (EPERM etc.): nothing actionable to surface here
    }
}

/// Windows: terminate `id` only if the pid STILL resolves to that exact identity.
/// Opens the process for terminate rights and calls `TerminateProcess`. Already
/// gone (unresolvable / unopenable) is success. Best-effort.
#[cfg(windows)]
pub(crate) fn kill_by_identity(id: ProcessId) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    // Re-verify identity against the live pid before opening it for terminate.
    if ProcessId::of(id.pid()) != Some(id) {
        return;
    }
    // SAFETY: OpenProcess tolerates an invalid/dead pid (returns Err); the handle
    // is closed before return. We re-verified identity just above, so the pid is
    // (was) ours; the worst case under a same-instant recycle is a no-op Err.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, id.pid()) else {
            return; // gone or unopenable => already-dead is success
        };
        let _ = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
    }
}

/// Hard-kill the tree rooted at `root` by identity: snapshot once, compute
/// genuine descendants, kill the root FIRST then each descendant. SIGKILL on
/// Unix; `TerminateProcess` on Windows. Best-effort; already-gone is success.
pub(crate) fn hard_kill(root: ProcessId) {
    let parents = crate::containment::enumerate::process_parents();
    let descendants = descendants(root, &parents);
    #[cfg(unix)]
    {
        kill_by_identity(root, Signal::SIGKILL);
        for id in descendants {
            kill_by_identity(id, Signal::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        kill_by_identity(root);
        for id in descendants {
            kill_by_identity(id);
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (root, descendants);
}

/// Graceful termination of the tree rooted at `root`.
///
/// Unix: the same snapshot + identity walk with SIGTERM (root then descendants) —
/// cooperative shutdown that still re-verifies identity before each signal, so it
/// reaches the whole genuine tree just like `hard_kill`.
///
/// Windows: send `CTRL_BREAK_EVENT` to the root's process group (the root was
/// spawned with `CREATE_NEW_PROCESS_GROUP`). This is cooperative only and reaches
/// only processes that share the root's console group; a nested *contained*
/// descendant is spawned into its OWN process group (`CREATE_NEW_PROCESS_GROUP`)
/// and therefore does NOT receive this CTRL_BREAK. There is no per-process
/// graceful signal on Windows, so graceful `terminate` cannot reach those nested
/// groups — the identity `hard_kill` (`kill_tree`) is the guaranteed sweep that
/// does. Best-effort by design.
pub(crate) fn terminate(root: ProcessId) -> Result<(), crate::error::Error> {
    #[cfg(unix)]
    {
        let parents = crate::containment::enumerate::process_parents();
        let descendants = descendants(root, &parents);
        kill_by_identity(root, Signal::SIGTERM);
        for id in descendants {
            kill_by_identity(id, Signal::SIGTERM);
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        crate::containment::windows::terminate(root.pid()).map_err(crate::error::Error::Io)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = root;
        Ok(())
    }
}

#[cfg(test)]
#[path = "treewalk_tests.rs"]
mod treewalk_tests;
