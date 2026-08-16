//! Per-OS containment dispatch (two-phase: prepare before spawn, attach after).

use crate::containment::{ContainMode, ContainRequest, Containment, Nesting};
use crate::error::Error;

/// The pre-spawn containment decision produced by `prepare` (env-marker root
/// detection plus per-OS pre-spawn setup).
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
    /// The marker pipe for a contained macOS root. `None` for a nested member, an
    /// uncontained or elevation-derived spawn, or a failed install (which degrades to the
    /// process group).
    #[cfg(target_os = "macos")]
    pub marker: Option<crate::containment::fdmarker::PreparedMarker>,
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
    /// macOS inherited-fd marker: membership survives `setsid`, `setpgid`, reparenting and
    /// `exec`. Owns the supervisor's read end of the marker pipe — which is what keeps the
    /// pipe's kernel identity from being re-issued — plus, when the mode created one, the pgid.
    #[cfg(target_os = "macos")]
    FdMarker(crate::containment::fdmarker::Marker),
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
            Attached::ProcessGroup(pgid) => crate::containment::unix::kill_group(*pgid),
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
            #[cfg(target_os = "macos")]
            Attached::FdMarker(m) => m.hard_kill(),
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
            Attached::ProcessGroup(pgid) => crate::containment::unix::term_group(*pgid),
            #[cfg(target_os = "linux")]
            Attached::Cgroup(leaf) => leaf.terminate().map_err(Error::Io),
            #[cfg(windows)]
            Attached::JobObject(_) => crate::containment::windows::terminate(_child_pid),
            #[cfg(target_os = "macos")]
            Attached::FdMarker(m) => m.terminate(),
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
            // dropping the read end does not kill; detach opts out via kill_on_drop
            #[cfg(target_os = "macos")]
            Attached::FdMarker(_) => {}
            Attached::TreeWalk(_) => {} // no kernel resource whose drop kills; detach opts out via kill_on_drop
        }
    }

    /// Whether this mechanism fires `killpg` against a pgid subject to the reap-then-recycle
    /// hazard `Child::kill_tree`/`terminate_tree`'s precondition assert guards against: the OS
    /// reaping the leader and recycling its pid/pgid onto a different, live process group
    /// before the signal is sent. `ProcessGroup` always carries one; a macOS `FdMarker` does
    /// too, when its mode created one (`Marker::has_pgid` — `None` for `TreeWalk`, which needs
    /// no pgid and stays exempt, matching `Attached::TreeWalk` below). `FdMarker` fires
    /// `killpg` on `self.pgid` unconditionally on pass 1 of every sweep, so the hazard is
    /// identical, not merely analogous — routing every contained macOS root through
    /// `FdMarker` instead of `ProcessGroup` must not silently drop this precondition's coverage.
    #[cfg(unix)]
    pub(crate) fn carries_recyclable_pgid(&self) -> bool {
        match self {
            Attached::ProcessGroup(_) => true,
            #[cfg(target_os = "macos")]
            Attached::FdMarker(m) => m.has_pgid(),
            _ => false,
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
            #[cfg(target_os = "macos")]
            Attached::FdMarker(_) => true,
            Attached::TreeWalk(_) => true,
        }
    }

    /// The supervisor's read end of the marker pipe, when this mechanism is the macOS fd
    /// marker. `None` for every other mechanism (nothing else exposes a kernel drain edge).
    ///
    /// No non-test caller exists yet outside `wait_drained` below — wiring an actual consumer
    /// (`graceful_shutdown_tree`'s conditional escalation) is #62's job, not this accessor's.
    /// `#[allow(dead_code)]` reflects that honestly, mirroring `marker_eof::probe`.
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    pub(crate) fn marker_read_end(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        match self {
            Attached::FdMarker(m) => Some(m.read_end()),
            _ => None,
        }
    }

    /// Block until every member of the contained tree has EXITED (not reaped), or until
    /// `deadline`. `Unsupported` on every mechanism without a kernel drain edge — presently all
    /// of them except the macOS fd marker. The cross-platform surface over this is #62.
    ///
    /// No non-test caller exists yet: wiring `graceful_shutdown_tree`'s conditional escalation
    /// to consult this is #62's deliverable, not #60's. `#[allow(dead_code)]` reflects that
    /// honestly, mirroring `marker_eof::probe`.
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<Option<std::time::Instant>>,
    ) -> Result<crate::containment::marker_eof::TreeDrain, Error> {
        if let Some(read_end) = self.marker_read_end() {
            // This process is the supervisor: it must have closed its own copy of the write
            // end at spawn time (fdmarker::install's contract), or the edge could never fire.
            // A deliberately-constructed HeldByUs condition (Task 2's own unit tests) still
            // needs a real Err, not a panic, so the enforcement lives in
            // `refuse_if_write_end_held`'s Err return, not here; this assert instead catches
            // a violation of that contract reaching THIS, the crate's own call site, in debug
            // builds — the crate's own code path, not a test deliberately constructing the
            // condition.
            debug_assert_ne!(
                crate::containment::marker_eof::write_end_check(read_end),
                crate::containment::marker_eof::WriteEndCheck::HeldByUs,
                "the supervisor still holds a copy of the marker write end - the tree-drain edge can never fire"
            );
            return crate::containment::marker_eof::block_until_drained(read_end, deadline);
        }
        Err(Error::Unsupported {
            op: "wait for the contained tree to drain".into(),
            platform: std::env::consts::OS,
            detail: "this child's containment mechanism exposes no kernel edge for tree drain".into(),
        })
    }
}

/// Returns `true` when the current process is the outermost contained root
/// (i.e. the env marker is absent). Pure function: takes the marker-presence
/// flag so it can be unit-tested without touching the process environment.
pub(crate) fn is_nested(marker_present: bool) -> bool {
    marker_present
}

/// Resolve the spawned root's identity by pid. **Precondition:** the caller holds the owning
/// `Child` (sync `std::process::Child` / async `::tokio::process::Child`) across this call — it
/// pins the pid against reuse, so the by-pid resolve is race-free (the freshly spawned root is
/// un-reaped, and on Windows still suspended, hence resolvable).
#[cfg(any(unix, windows))]
fn resolve_root_id(pid: u32) -> Result<crate::identity::ProcessId, Error> {
    match crate::identity::ProcessId::of(pid) {
        crate::identity::Resolved::Found(id) => Ok(id),
        crate::identity::Resolved::Gone => Err(Error::Containment {
            detail: "tree-walk root vanished before its identity could be read".into(),
        }),
        crate::identity::Resolved::Unknown => Err(Error::Unassessable {
            detail: format!("tree-walk root pid {pid} identity could not be read"),
            source: None,
        }),
    }
}

/// Which Unix setup action to apply to a root `Command` for a given mode.
/// Pure function: used by `prepare` and unit-tested separately to verify
/// mutual exclusivity: Session → setsid only; Strongest/default → pgroup
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

/// Decide which Unix mechanism to apply for `mode` (root spawns only).
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

/// The Windows pre-spawn containment decision, shared by the std `prepare` path and the raw
/// `CreateProcessW` backend. Encodes ONLY the decision; the caller applies it (`creation_flags`
/// onto the command, the root env marker, `clear_std_handle_inheritance`).
#[cfg(windows)]
pub(crate) struct WindowsContain {
    /// Creation flags to OR into the spawn: `root_flags` (suspend + new group) for a Strongest
    /// root, `group_flags` (new group only) otherwise; `0` when uncontained (`mode` is `None`).
    pub creation_flags: u32,
    /// Whether this spawn must set the inherited root marker so descendants join THIS group.
    pub marker_env: bool,
}

/// Decide the Windows pre-spawn containment flags + marker for `req`/`is_root`. Pure — directly
/// unit-testable. Returns `{ creation_flags: 0, marker_env: false }` when `req.mode` is `None`.
#[cfg(windows)]
pub(crate) fn windows_contain_setup(req: &ContainRequest, is_root: bool) -> WindowsContain {
    let Some(mode) = req.mode else {
        return WindowsContain {
            creation_flags: 0,
            marker_env: false,
        };
    };
    let creation_flags = if is_root && !matches!(mode, ContainMode::TreeWalk) {
        // Strongest root: suspend + new process group (job assigned in attach).
        crate::containment::windows::root_flags()
    } else {
        // TreeWalk root (no suspend, no job — identity teardown) and all nested spawns:
        // CREATE_NEW_PROCESS_GROUP only, so `terminate` can CTRL_BREAK the root's group.
        crate::containment::windows::group_flags()
    };
    WindowsContain {
        creation_flags,
        marker_env: is_root && req.nesting == Nesting::Mark,
    }
}

/// Phase 1 (before spawn): env-marker root detection + pre-spawn OS setup.
///
/// `reserved_fds` and `marker_suppressed` drive the macOS fd-marker install only; every
/// other platform ignores them.
pub(crate) fn prepare(
    std_cmd: &mut std::process::Command,
    req: &ContainRequest,
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] reserved_fds: &[i32],
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] marker_suppressed: bool,
) -> Prepared {
    let mode = req.mode;
    if mode.is_none() {
        return Prepared {
            mode: None,
            is_root: false,
            #[cfg(target_os = "linux")]
            cgroup_leaf: None,
            #[cfg(target_os = "macos")]
            marker: None,
        };
    }
    let marker_present = std::env::var_os(crate::containment::NESTED_ENV).is_some();
    let is_root = !is_nested(marker_present);
    if is_root && req.nesting == Nesting::Mark {
        // Set AFTER any user env ops (env_clear) have been applied to std_cmd by
        // the spawn engine, so the marker survives env_clear. `env` appends.
        std_cmd.env(crate::containment::NESTED_ENV, "1");
    }

    // Linux: session mode or (cgroup v2 + process group).
    // Mechanism selection via `unix_setup_for` (setsid/pgroup mutual exclusivity):
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

    // Non-Linux Unix: process group or session (mutually exclusive).
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

    // macOS: install the inherited-fd marker for every contained root, regardless of the
    // requested mode (decision: the marker survives what the mode-specific mechanism above
    // does not). `marker_wanted` gates on root/mode/suppression; `install` degrades to `None`
    // on any failure rather than failing the spawn.
    #[cfg(target_os = "macos")]
    let marker = if crate::containment::fdmarker::marker_wanted(mode, is_root, marker_suppressed) {
        crate::containment::fdmarker::install(std_cmd, reserved_fds)
    } else {
        None
    };

    // Windows: clear handle inheritance + apply creation_flags. The flag/marker decision
    // lives in `windows_contain_setup` (shared with the raw `CreateProcessW` backend); the
    // root marker itself is applied above (shared with the Unix path), so only the creation
    // flags are applied here.
    #[cfg(windows)]
    if mode.is_some() {
        use std::os::windows::process::CommandExt;
        crate::containment::windows::clear_std_handle_inheritance();
        let setup = windows_contain_setup(req, is_root);
        std_cmd.creation_flags(setup.creation_flags);
    }

    #[allow(unreachable_code)]
    Prepared {
        mode,
        is_root,
        #[cfg(target_os = "linux")]
        cgroup_leaf: None,
        #[cfg(target_os = "macos")]
        marker,
    }
}

/// Phase 2 (after spawn, before SharedChild::new): attach the mechanism.
/// Consumes `prepared` so Linux cgroup leaf ownership transfers cleanly to
/// `Attached::Cgroup` without requiring interior mutability.
pub(crate) fn attach(
    pid: u32,
    #[cfg(windows)] proc_handle: std::os::windows::io::RawHandle,
    prepared: Prepared,
) -> Result<(Containment, Attached), Error> {
    // Linux: session, or cgroup v2 / process group.
    #[cfg(target_os = "linux")]
    {
        if prepared.mode.is_some() {
            if prepared.is_root {
                // TreeWalk root: no kernel container / process group; teardown is
                // by identity. Resolve the root identity (consistent with the
                // post-attach identity read in spawn.rs).
                if matches!(prepared.mode, Some(ContainMode::TreeWalk)) {
                    return Ok((Containment::TreeWalk, Attached::TreeWalk(resolve_root_id(pid)?)));
                }

                let raw_pid = pid;
                debug_assert!(
                    raw_pid <= i32::MAX as u32,
                    "pid {raw_pid} exceeds i32::MAX; pgid cast would truncate"
                );
                let pgid = raw_pid as i32;

                // Session mode: setsid was applied pre-spawn; no cgroup.
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
                // macOS fd marker: installed for every contained root regardless of mode, so
                // it takes priority over the mode-specific mechanism below — it is what
                // survives setsid/reparenting/exec that the mode-specific mechanism does not.
                #[cfg(target_os = "macos")]
                if let Some(marker) = prepared.marker {
                    // `Gone` is routine, not an anomaly: `SharedChild::new`'s internal
                    // `try_wait` can reap a fast-exiting child inside `spawn()` itself (#61) —
                    // `debug!`, no `incomplete`. The marker and group channels below don't need
                    // `root`, so a reparented-away live descendant stays reachable through them.
                    // `Unknown` means the OS refused to answer — a real gap — so it is `warn!`
                    // and carries `root_denied` into `Marker`, the only way `sweep_pass` can
                    // tell "denied" apart from an ordinary `Gone` on every later pass.
                    let (root, root_denied) = match crate::identity::ProcessId::of(pid) {
                        crate::identity::Resolved::Found(id) => (Some(id), false),
                        crate::identity::Resolved::Gone => {
                            log::debug!(
                                "fd marker: the root exited before its identity could be read; \
                                 the sweep runs without its ppid-walk channel (the marker and \
                                 group channels do not need it)"
                            );
                            (None, false)
                        }
                        crate::identity::Resolved::Unknown => {
                            log::warn!(
                                "fd marker: the root's identity could not be read (access \
                                 denied); the sweep runs without its ppid-walk channel, and \
                                 every pass reports this marker as incomplete"
                            );
                            (None, true)
                        }
                    };
                    let pgid = match prepared.mode {
                        Some(ContainMode::TreeWalk) => None,
                        _ => {
                            debug_assert!(
                                pid <= i32::MAX as u32,
                                "pid {pid} exceeds i32::MAX; pgid cast would truncate"
                            );
                            Some(pid as i32)
                        }
                    };
                    return Ok((
                        Containment::FdMarker,
                        Attached::FdMarker(crate::containment::fdmarker::Marker::new(
                            marker,
                            root,
                            pgid,
                            root_denied,
                        )),
                    ));
                }
                // TreeWalk root: no process group; identity teardown.
                if matches!(prepared.mode, Some(ContainMode::TreeWalk)) {
                    return Ok((Containment::TreeWalk, Attached::TreeWalk(resolve_root_id(pid)?)));
                }
                let raw_pid = pid;
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
                #[cfg(target_os = "macos")]
                if prepared.marker.is_some() {
                    log::warn!(
                        "fd marker: a nested spawn's prepare() unexpectedly produced a marker; \
                         a nested member must inherit the root's marker, never create its own \
                         — discarding it"
                    );
                    debug_assert!(
                        false,
                        "a nested member inherits the root's marker and must never create one"
                    );
                }
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
                return Ok((Containment::TreeWalk, Attached::TreeWalk(resolve_root_id(pid)?)));
            }
            match crate::containment::windows::attach_job(proc_handle) {
                Ok(Some(job)) => return Ok((Containment::JobObject, Attached::JobObject(job))),
                Ok(None) => {
                    // Job assignment failed: fall back to the universal TreeWalk
                    // mechanism rather than silently yielding no containment. The
                    // root was spawned with CREATE_NEW_PROCESS_GROUP (root_flags),
                    // so `terminate`'s CTRL_BREAK still reaches the group.
                    return Ok((Containment::TreeWalk, Attached::TreeWalk(resolve_root_id(pid)?)));
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
    let _ = prepared;
    Ok((Containment::None, Attached::None))
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod dispatch_tests;
