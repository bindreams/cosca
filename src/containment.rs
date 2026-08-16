//! Process-tree containment. Spawn a child as a kill-group root and tear the
//! whole tree down as a unit. Mechanisms, strongest first, all *best-effort in
//! their own way* (the variant names the teardown method, not a quality grade):
//!
//! - [`Containment::CgroupV2`] (Linux): leaf cgroup + `cgroup.kill` — fork-proof.
//! - [`Containment::JobObject`] (Windows): Job + `KILL_ON_JOB_CLOSE`.
//! - [`Containment::ProcessGroup`]/[`Containment::Session`] (Unix): `killpg`.
//! - [`Containment::FdMarker`] (macOS): inherited-fd marker sweep — survives setsid/reparenting.
//! - [`Containment::TreeWalk`] (all): identity-aware descendant kill at teardown.
//! - [`Containment::Delegated`]: a nested member — the outermost root tears it down.
//! - [`Containment::None`]: not contained — lone-process semantics.
//!
//! This is NOT a security sandbox: a determined child escapes every mechanism
//! (broker-spawned helpers, privilege, `setsid` out of a process group). It
//! reliably tears down *cooperative* trees and reports the achieved guarantee.

use std::fmt;

/// The teardown mechanism actually achieved for a spawned child (queried via
/// `Child::containment()`). Runtime-detected — the same binary meets hosts with
/// and without cgroup v2 / inside and outside an existing job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Containment {
    /// Linux cgroup v2 leaf + `cgroup.kill`. Fork-proof; a confined child can't leave.
    CgroupV2,
    /// Windows Job Object + `KILL_ON_JOB_CLOSE`. Kernel-enforced for direct descendants.
    JobObject,
    /// Unix process group (`setpgid`/`process_group(0)`) + `killpg`. A `setsid` child escapes.
    ProcessGroup,
    /// Unix session (`setsid`) + `killpg`. A nested-`setsid` child escapes.
    Session,
    /// macOS inherited-fd marker: every descendant carries an inherited pipe descriptor, so
    /// membership survives `setsid`, `setpgid`, double-fork reparenting to launchd and `exec`.
    /// Teardown kills the union of three channels: marker holders and the ppid walk each
    /// verify the target's identity before signalling; the process group (when one was
    /// created) is signalled by `killpg(pgid)` with no additional re-verification beyond what
    /// `Attached::ProcessGroup` already does — the same pgid-reuse caveat documented in
    /// `src/containment/unix.rs` applies to the FIRST group signal exactly as it does today.
    /// `kill_tree` (SIGKILL) re-snapshots the host and repeats until nothing new appears AND
    /// each pass makes actual progress (no fixed pass count); a LATER pass re-signals the group
    /// too (closing a gap the single-shot `ProcessGroup` mechanism does not need to close: a
    /// process joining the group strictly between passes), but ONLY when that pass's own
    /// marker-holder scan just confirmed a live, `getpgid`-verified member of the group — proof
    /// the pgid had not yet been recycled at that instant — so a later pass never adds a NEW,
    /// unconditional instance of the reuse risk beyond pass 1's existing one (see
    /// `Marker::sweep_pass`, `src/containment/fdmarker.rs`, for the full argument and its
    /// stated limits). `terminate_tree` (SIGTERM, catchable and ignorable) takes exactly one
    /// pass and does not chase forks.
    ///
    /// Naive-child containment, not a sandbox. A member leaves the set by closing the
    /// descriptor, by being spawned through a path that scrubs inherited descriptors (Python's
    /// `subprocess`, Node's `child_process`, `POSIX_SPAWN_CLOEXEC_DEFAULT`), by changing
    /// credentials (e.g. `exec`ing a setuid binary makes its fd table unqueryable), or by being
    /// otherwise unqueryable — a holder whose identity or fd table the OS refuses to report is
    /// left running rather than signalled blind. The marker descriptor is inherited-only, not
    /// an IPC channel: a member that writes to it blocks (nothing drains it), and after
    /// `detach()` a write raises `SIGPIPE` instead. A spawn elevated THROUGH a `sudo`/`doas`/
    /// `pkexec` wrapper never reports this variant, since that wrapper closes every descriptor
    /// >= 3 before exec; an already-elevated caller's spawn has no such wrapper and can.
    FdMarker,
    /// Identity-aware descendant enumeration at teardown. Misses reparented orphans.
    TreeWalk,
    /// A nested member of an ancestor's containment group/job: this child joined the
    /// tree the outermost root owns, so it drives no teardown itself (`can_teardown()`
    /// is `false`) and its `_tree` ops return `Unsupported`. The root tears the tree down.
    Delegated,
    /// No containment — `kill`/drop act on the lone process.
    None,
}

impl Containment {
    /// Whether this handle can drive tree teardown (`kill_tree`/`terminate_tree` act
    /// rather than returning `Unsupported`).
    pub fn can_teardown(&self) -> bool {
        match self {
            Containment::CgroupV2
            | Containment::JobObject
            | Containment::ProcessGroup
            | Containment::Session
            | Containment::FdMarker
            | Containment::TreeWalk => true,
            Containment::None | Containment::Delegated => false,
        }
    }
}

/// Guard for the `_tree` operations, shared by the sync and async `Child`: they act on the
/// containment group's teardown mechanism, so a child whose mechanism is a no-op has no tree
/// to act on.
pub(crate) fn require_contained(containment: Containment, attached: &Attached) -> Result<(), crate::error::Error> {
    debug_assert_eq!(
        containment.can_teardown(),
        attached.is_actionable(),
        "Containment/Attached actionability diverged"
    );
    if !attached.is_actionable() {
        return Err(crate::error::Error::Unsupported {
            op: "tree teardown (kill_tree / terminate_tree)".into(),
            platform: std::env::consts::OS,
            detail: "this child holds no actionable tree-teardown mechanism (uncontained, \
                     or a nested member of an ancestor's containment group). Use kill() for a \
                     lone process, or tear down the tree via the outermost .contain()ed handle."
                .into(),
        });
    }
    Ok(())
}

impl fmt::Display for Containment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Containment::CgroupV2 => "cgroup v2",
            Containment::JobObject => "job object",
            Containment::ProcessGroup => "process group",
            Containment::Session => "session",
            Containment::FdMarker => "inherited-fd marker",
            Containment::TreeWalk => "process-tree walk",
            Containment::Delegated => "delegated",
            Containment::None => "none",
        })
    }
}

/// The teardown strategy a caller *requests* via `Command::contain_with`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContainMode {
    /// The strongest kernel container available on this host, falling back
    /// (cgroup → job → process group → …) to [`ContainMode::TreeWalk`] rather
    /// than to no containment.
    Strongest,
    /// Identity-aware process-tree walk at teardown — selectable directly (e.g.
    /// for a child known to `setsid` out of a process group).
    TreeWalk,
    /// Unix session containment via `setsid`: the child becomes a session leader
    /// and process-group leader, detached from any controlling terminal.
    /// Teardown sends `SIGKILL`/`SIGTERM` to the process group (which equals the
    /// session's initial process group). Useful for daemon-like children that
    /// must not inherit the parent's controlling terminal.
    ///
    /// **Mutual exclusivity:** `setsid` makes the child a session *and*
    /// process-group leader simultaneously; `setpgid`/`process_group(0)` on a
    /// session leader fails with `EPERM`. Therefore `Session` applies `setsid`
    /// *instead of* `process_group(0)` — never both.
    ///
    /// **Self-`setsid` escape:** a child that calls `setsid` itself (or
    /// `setpgid`) can leave the session. This is documented and applies equally
    /// to `ProcessGroup` containment. `Session` provides TTY detach and
    /// session grouping; it is not a security sandbox.
    ///
    /// On non-Unix platforms this request is silently treated as `Strongest`.
    Session,
}

/// Whether a kill-group root marks its descendants as already-contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nesting {
    /// Mark descendants (default): nested contained spawns join THIS group.
    #[default]
    Mark,
    /// Leave descendants unmarked: a contained child's own contained spawns
    /// create their own groups (which nest inside this one on Windows).
    Opaque,
}

/// The resolved containment request carried on a `Command` (crate-internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContainRequest {
    /// `None` = not contained.
    pub mode: Option<ContainMode>,
    pub nesting: Nesting,
}

impl Default for ContainRequest {
    fn default() -> ContainRequest {
        ContainRequest {
            mode: None,
            nesting: Nesting::Mark,
        }
    }
}

/// The reserved, inherited env marker for kill-group root detection. Windows
/// jobs nest but Unix process groups do not, so only the OUTERMOST `.contain()`
/// creates a group; descendants inherit this marker and join it. **Reserved and
/// load-bearing: nothing outside this crate may set it.**
pub(crate) const NESTED_ENV: &str = "__COSCA_GROUP_ROOT";

#[cfg(unix)]
#[path = "containment/unix.rs"]
pub(crate) mod unix;

#[path = "containment/cgroup.rs"]
pub(crate) mod cgroup;

#[cfg(windows)]
#[path = "containment/windows.rs"]
pub(crate) mod windows;

#[path = "containment/enumerate.rs"]
pub(crate) mod enumerate;

#[cfg(target_os = "macos")]
#[path = "containment/fdmarker.rs"]
pub(crate) mod fdmarker;

#[path = "containment/treewalk.rs"]
pub(crate) mod treewalk;

#[path = "containment/dispatch.rs"]
pub(crate) mod dispatch;
#[allow(unused_imports)]
pub(crate) use dispatch::{attach, prepare, Attached, Prepared};

#[cfg(target_os = "macos")]
#[path = "containment/marker_eof.rs"]
pub(crate) mod marker_eof;

#[cfg(test)]
#[path = "containment_tests.rs"]
mod containment_tests;
