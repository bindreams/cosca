//! Per-OS containment dispatch (two-phase: prepare before spawn, attach after).
//! Unix process-group branch filled by Task 3; Linux cgroup v2 by Task 4;
//! Windows Job Object by Task 5.

use crate::containment::{ContainMode, ContainRequest, Containment, Nesting};
use crate::error::Error;

/// Decided before spawn (env-marker root detection); later tasks also apply
/// pre-spawn flags / process_group / pre_exec inside `prepare`.
pub(crate) struct Prepared {
    #[allow(dead_code)] // read in #[cfg(unix)] branch of attach()
    pub mode: Option<ContainMode>,
    #[allow(dead_code)] // read in #[cfg(unix)] branch of attach()
    pub is_root: bool,
    /// Pre-created cgroup leaf (Linux only). `Some` means the child must be
    /// placed in the cgroup via the `pre_exec` closure; `None` means fall back
    /// to the process-group mechanism.
    #[cfg(target_os = "linux")]
    pub cgroup_leaf: Option<crate::containment::cgroup::CgroupLeaf>,
}

/// Owns the OS containment resource for a spawned child; `hard_kill`/`terminate`
/// act on the tree, `disarm` neutralizes teardown for `detach()`. `None` =
/// uncontained (lone-process semantics).
#[derive(Debug, Default)]
pub(crate) enum Attached {
    #[default]
    None,
    /// A nested containment member: it joined an ancestor's group/job and owns no
    /// teardown mechanism of its own (the outermost root tears the tree down). Distinct
    /// from `None` (genuinely uncontained) so `_tree` ops can error honestly.
    Delegated,
    #[cfg(unix)]
    ProcessGroup(i32), // pgid (== root pid)
    #[cfg(target_os = "linux")]
    Cgroup(crate::containment::cgroup::CgroupLeaf),
    #[cfg(windows)]
    JobObject(crate::containment::windows::JobHandle),
    /// Identity-aware tree-walk teardown (cross-platform; the root identity is
    /// re-enumerated and killed by identity at teardown). No cfg gate: this is
    /// the universal fallback and a directly-selectable mode on every OS.
    TreeWalk(crate::identity::ProcessId),
}

// CgroupLeaf is not Debug; provide a minimal impl.
#[cfg(target_os = "linux")]
impl std::fmt::Debug for crate::containment::cgroup::CgroupLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CgroupLeaf").finish_non_exhaustive()
    }
}

impl Attached {
    /// Hard-kill the contained tree (best-effort; already-gone is success).
    pub(crate) fn hard_kill(&self) -> Result<(), crate::error::Error> {
        match self {
            Attached::None | Attached::Delegated => Ok(()),
            #[cfg(unix)]
            Attached::ProcessGroup(pgid) => {
                crate::containment::unix::kill_group(*pgid).map_err(crate::error::Error::Io)
            }
            #[cfg(target_os = "linux")]
            Attached::Cgroup(leaf) => {
                leaf.hard_kill();
                Ok(())
            }
            #[cfg(windows)]
            Attached::JobObject(job) => {
                job.hard_kill();
                Ok(())
            }
            Attached::TreeWalk(root) => {
                crate::containment::treewalk::hard_kill(*root);
                Ok(())
            }
        }
    }

    /// Send the graceful termination signal to the group (signal-only).
    pub(crate) fn terminate(&self, _child_pid: u32) -> Result<(), Error> {
        match self {
            Attached::None | Attached::Delegated => {
                debug_assert!(
                    self.is_actionable(),
                    "Attached::terminate on a non-actionable mechanism"
                );
                Err(crate::error::Error::Unsupported {
                    op: "terminate on a non-actionable mechanism".into(),
                    platform: std::env::consts::OS,
                    detail: "internal invariant: a non-actionable mechanism reached terminate".into(),
                })
            }
            #[cfg(unix)]
            Attached::ProcessGroup(pgid) => crate::containment::unix::term_group(*pgid).map_err(Error::Io),
            #[cfg(target_os = "linux")]
            Attached::Cgroup(leaf) => leaf.terminate().map_err(Error::Io),
            #[cfg(windows)]
            Attached::JobObject(_) => crate::containment::windows::terminate(_child_pid).map_err(Error::Io),
            Attached::TreeWalk(root) => crate::containment::treewalk::terminate(*root),
        }
    }

    /// Neutralize teardown so `detach()` leaves the tree running. For Job Objects,
    /// clears `KILL_ON_JOB_CLOSE` so the handle close does not kill the tree.
    /// No-op for mechanisms whose resource-drop does not kill (pgroup/cgroup/none).
    pub(crate) fn disarm(&self) {
        match self {
            Attached::None | Attached::Delegated => {}
            #[cfg(unix)]
            Attached::ProcessGroup(_) => {} // pgroup drop doesn't kill — no-op
            #[cfg(target_os = "linux")]
            Attached::Cgroup(_) => {} // cgroup.kill is explicit — drop doesn't kill
            #[cfg(windows)]
            Attached::JobObject(job) => job.disarm(), // clear KILL_ON_JOB_CLOSE before handle drops
            Attached::TreeWalk(_) => {} // no kernel resource whose drop kills; detach opts out via kill_on_drop
        }
    }

    /// Whether this child holds an actionable tree-teardown mechanism.
    pub(crate) fn is_actionable(&self) -> bool {
        match self {
            Attached::None | Attached::Delegated => false,
            #[cfg(unix)]
            Attached::ProcessGroup(_) => true,
            #[cfg(target_os = "linux")]
            Attached::Cgroup(_) => true,
            #[cfg(windows)]
            Attached::JobObject(_) => true,
            Attached::TreeWalk(_) => true,
        }
    }
}

/// Returns `true` when the current process is the outermost contained root
/// (i.e. the env marker is absent). Pure function: takes the marker-presence
/// flag so it can be unit-tested without touching the process environment.
pub(crate) fn is_nested(marker_present: bool) -> bool {
    marker_present
}

/// Resolve the spawned child's stable identity for the TreeWalk root, or `Err`
/// if it vanished before we could read it. Consistent with the post-attach
/// identity read in `spawn.rs`: the child is freshly spawned and (on Windows)
/// its handle is held by std::process::Child / (on Unix) it is an un-reaped
/// zombie at worst, so this should always succeed; the error path is defensive.
#[cfg(any(unix, windows))]
fn resolve_root_id(child: &std::process::Child) -> Result<crate::identity::ProcessId, Error> {
    crate::identity::ProcessId::of(child.id()).ok_or_else(|| Error::Containment {
        detail: "tree-walk root vanished before its identity could be read".into(),
    })
}

/// Which Unix setup action to apply to a root `Command` for a given mode.
/// Pure function: used by `prepare` and unit-tested separately to verify
/// mutual exclusivity (S3): Session → setsid only; Strongest/default → pgroup
/// only; TreeWalk → neither (it must catch process-group escapees).
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UnixSetup {
    /// Apply `setsid` via `pre_exec` (ContainMode::Session). Must NOT be
    /// combined with ProcessGroup on the same Command (EPERM on a session leader).
    Session,
    /// Apply `process_group(0)` (ContainMode::Strongest or default).
    ProcessGroup,
    /// Apply NO pre-spawn grouping (ContainMode::TreeWalk). TreeWalk's whole
    /// point is to catch children that `setsid`/`setpgid` out of a process group,
    /// so it must not put the root in a group itself; teardown is by identity.
    None,
}

/// Decide which Unix mechanism to apply for `mode` (root spawns only, S3).
/// Keeping this as a pure function makes the mutual-exclusivity invariant
/// directly unit-testable without inspecting `std::process::Command` internals.
#[cfg(unix)]
pub(crate) fn unix_setup_for(mode: Option<ContainMode>) -> UnixSetup {
    match mode {
        Some(ContainMode::Session) => UnixSetup::Session,
        Some(ContainMode::TreeWalk) => UnixSetup::None,
        _ => UnixSetup::ProcessGroup,
    }
}

/// Phase 1 (before spawn): env-marker root detection + pre-spawn OS setup.
pub(crate) fn prepare(std_cmd: &mut std::process::Command, req: &ContainRequest) -> Prepared {
    let mode = req.mode;
    if mode.is_none() {
        return Prepared {
            mode: None,
            is_root: false,
            #[cfg(target_os = "linux")]
            cgroup_leaf: None,
        };
    }
    let marker_present = std::env::var_os(crate::containment::NESTED_ENV).is_some();
    let is_root = !is_nested(marker_present);
    if is_root && req.nesting == Nesting::Mark {
        // Set AFTER any user env ops (env_clear) have been applied to std_cmd by
        // the spawn engine, so the marker survives env_clear (N1). `env` appends.
        std_cmd.env(crate::containment::NESTED_ENV, "1");
    }

    // Linux: session mode or (cgroup v2 + process group).
    // Mechanism selection via `unix_setup_for` (S3 mutual exclusivity):
    // Session → setsid only; Strongest/TreeWalk → process_group(0) + try cgroup.
    #[cfg(target_os = "linux")]
    {
        if is_root && mode.is_some() {
            match unix_setup_for(mode) {
                UnixSetup::Session => {
                    // Session: setsid only — no process_group(0) (would EPERM).
                    crate::containment::unix::set_session(std_cmd);
                    return Prepared {
                        mode,
                        is_root,
                        cgroup_leaf: None, // cgroup not used for Session
                    };
                }
                UnixSetup::None => {
                    // TreeWalk: NO process group / setsid / cgroup — teardown is
                    // by identity so we can catch process-group escapees.
                    return Prepared {
                        mode,
                        is_root,
                        cgroup_leaf: None,
                    };
                }
                UnixSetup::ProcessGroup => {
                    // Strongest: set a new process group + try cgroup.
                    crate::containment::unix::set_process_group(std_cmd);
                }
            }

            let leaf = crate::containment::cgroup::try_create_leaf();
            if let Some(ref l) = leaf {
                // Wire the pre_exec self-placement. The closure captures the raw
                // fd integer (Copy) — not the leaf itself (which stays in Prepared).
                // On error (e.g. EBUSY — "no internal processes" rule), the closure
                // returns Ok so the spawn proceeds and `attach` falls back to the
                // already-configured process group rather than aborting the spawn.
                // Safety: pre_exec runs post-fork, pre-exec; the function is
                // async-signal-safe (libc::write + libc::close, no alloc).
                let procs_fd = l.procs_fd();
                unsafe {
                    use std::os::unix::process::CommandExt;
                    std_cmd.pre_exec(move || {
                        let _ = crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd);
                        Ok(())
                    });
                }
            }
            return Prepared {
                mode,
                is_root,
                cgroup_leaf: leaf,
            };
        }
        return Prepared {
            mode,
            is_root,
            cgroup_leaf: None,
        };
    }

    // Non-Linux Unix: process group or session (mutually exclusive; S3).
    // Mechanism selection via `unix_setup_for`: Session → setsid only;
    // Strongest (= ProcessGroup on macOS) → process_group(0).
    #[cfg(all(unix, not(target_os = "linux")))]
    if is_root && mode.is_some() {
        match unix_setup_for(mode) {
            UnixSetup::Session => crate::containment::unix::set_session(std_cmd),
            UnixSetup::ProcessGroup => crate::containment::unix::set_process_group(std_cmd),
            UnixSetup::None => {} // TreeWalk: no pre-spawn grouping (identity teardown)
        }
    }

    // Windows: clear handle inheritance + apply creation_flags.
    #[cfg(windows)]
    if mode.is_some() {
        crate::containment::windows::clear_std_handle_inheritance();
        if is_root && !matches!(mode, Some(ContainMode::TreeWalk)) {
            // Strongest root: suspend + new process group (job assigned in attach).
            crate::containment::windows::set_root_flags(std_cmd);
        } else {
            // TreeWalk root (no suspend, no job — identity teardown) and all
            // nested spawns: CREATE_NEW_PROCESS_GROUP only, so `terminate` can
            // CTRL_BREAK the root's group.
            crate::containment::windows::set_group_flags(std_cmd);
        }
    }

    #[allow(unreachable_code)]
    Prepared {
        mode,
        is_root,
        #[cfg(target_os = "linux")]
        cgroup_leaf: None,
    }
}

/// Phase 2 (after spawn, before SharedChild::new): attach the mechanism.
/// Consumes `prepared` so Linux cgroup leaf ownership transfers cleanly to
/// `Attached::Cgroup` without requiring interior mutability.
pub(crate) fn attach(child: &std::process::Child, prepared: Prepared) -> Result<(Containment, Attached), Error> {
    // Linux: session, or cgroup v2 / process group.
    #[cfg(target_os = "linux")]
    {
        if prepared.mode.is_some() {
            if prepared.is_root {
                // TreeWalk root: no kernel container / process group; teardown is
                // by identity. Resolve the root identity (consistent with the
                // post-attach identity read in spawn.rs).
                if matches!(prepared.mode, Some(ContainMode::TreeWalk)) {
                    return Ok((Containment::TreeWalk, Attached::TreeWalk(resolve_root_id(child)?)));
                }

                let raw_pid = child.id();
                debug_assert!(
                    raw_pid <= i32::MAX as u32,
                    "pid {raw_pid} exceeds i32::MAX; pgid cast would truncate"
                );
                let pgid = raw_pid as i32;

                // Session mode: setsid was applied pre-spawn; no cgroup (S3).
                // pgid == sid == pid for the session leader; killpg works.
                if matches!(prepared.mode, Some(ContainMode::Session)) {
                    return Ok((Containment::Session, Attached::ProcessGroup(pgid)));
                }

                // Strongest: cgroup v2 if available, else process group.
                if let Some(leaf) = prepared.cgroup_leaf {
                    // Verify placement: the pre_exec write can silently fail
                    // (EBUSY — "no internal processes" rule when the supervisor
                    // is itself an undelegated leaf). Read cgroup.procs to
                    // confirm the child's pid is actually present.
                    if leaf.contains_pid(raw_pid) {
                        return Ok((Containment::CgroupV2, Attached::Cgroup(leaf)));
                    }
                    // Placement failed — the leaf is empty; drop it (triggers
                    // rmdir). The process group set pre-spawn is the real container.
                    drop(leaf);
                    return Ok((Containment::ProcessGroup, Attached::ProcessGroup(pgid)));
                }
                // No cgroup leaf: fall back to process group (set pre-spawn).
                return Ok((Containment::ProcessGroup, Attached::ProcessGroup(pgid)));
            } else {
                // Nested member: it joined the ancestor's cgroup/process group (or the
                // root's tree-walk) rather than creating its own, so it owns no teardown —
                // the outermost root tears the whole tree down.
                return Ok((Containment::Delegated, Attached::Delegated));
            }
        }
    }

    // Non-Linux Unix: process group or session.
    // For Session: setsid was called pre-spawn (not process_group(0)); the child
    // is a session leader with pgid == pid. Teardown via killpg is identical —
    // Attached::ProcessGroup(pgid) is reused since the pgroup == session leader's pid.
    // For Strongest (= ProcessGroup on macOS): process_group(0) was called pre-spawn.
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        if prepared.mode.is_some() {
            if prepared.is_root {
                // TreeWalk root: no process group; identity teardown.
                if matches!(prepared.mode, Some(ContainMode::TreeWalk)) {
                    return Ok((Containment::TreeWalk, Attached::TreeWalk(resolve_root_id(child)?)));
                }
                let raw_pid = child.id();
                debug_assert!(
                    raw_pid <= i32::MAX as u32,
                    "pid {raw_pid} exceeds i32::MAX; pgid cast would truncate"
                );
                let pgid = raw_pid as i32;
                let containment = match prepared.mode {
                    Some(ContainMode::Session) => Containment::Session,
                    _ => Containment::ProcessGroup,
                };
                return Ok((containment, Attached::ProcessGroup(pgid)));
            } else {
                // Nested member: it joined the ancestor's process group (or the root's
                // tree-walk) rather than creating its own, so it owns no teardown — the
                // outermost root tears the whole tree down.
                return Ok((Containment::Delegated, Attached::Delegated));
            }
        }
    }

    // Windows: Job Object (strongest available on this OS), or TreeWalk.
    #[cfg(windows)]
    {
        if prepared.mode.is_some() && prepared.is_root {
            // TreeWalk root: no job (spawned with CREATE_NEW_PROCESS_GROUP only);
            // identity teardown, with CTRL_BREAK to the group as cooperative term.
            if matches!(prepared.mode, Some(ContainMode::TreeWalk)) {
                return Ok((Containment::TreeWalk, Attached::TreeWalk(resolve_root_id(child)?)));
            }
            match crate::containment::windows::attach_job(child) {
                Ok(Some(job)) => return Ok((Containment::JobObject, Attached::JobObject(job))),
                Ok(None) => {
                    // Job assignment failed: fall back to the universal TreeWalk
                    // mechanism rather than silently yielding no containment. The
                    // root was spawned with CREATE_NEW_PROCESS_GROUP (set_root_flags),
                    // so `terminate`'s CTRL_BREAK still reaches the group.
                    return Ok((Containment::TreeWalk, Attached::TreeWalk(resolve_root_id(child)?)));
                }
                Err(e) => return Err(Error::Containment { detail: e.to_string() }),
            }
        } else if prepared.mode.is_some() {
            // Nested member: it inherits the ancestor's job (or the root's tree-walk; no
            // new job is created), so it owns no teardown — the outermost root's job tears
            // the whole tree down.
            return Ok((Containment::Delegated, Attached::Delegated));
        }
    }

    // Uncontained (or unsupported platform).
    let _ = (child, prepared);
    Ok((Containment::None, Attached::None))
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod dispatch_tests;
