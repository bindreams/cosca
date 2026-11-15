//! Linux cgroup v2 leaf containment.
//!
//! When cgroup v2 is mounted, delegated, and writable with `cgroup.kill`
//! support, the spawned child is placed in a freshly created leaf sub-cgroup.
//! Teardown writes `"1"` to `cgroup.kill` — the kernel atomically kills every
//! process in the leaf (fork-proof). Which mode fails and which degrades is in `ContainMode`'s
//! docs; see `leaf_if_offered` and `try_create_leaf`.
//!
//! # Delegation prerequisite
//! cgroup v2 requires "no internal processes": a non-root cgroup may not
//! contain processes AND child cgroups simultaneously. This implementation
//! creates the leaf as a direct child of the supervisor's cgroup, which works
//! correctly only when the supervisor's cgroup is already an inner node (i.e.
//! it contains no processes itself). This is the normal case in properly
//! delegated slices (systemd user slices, container environments). On hosts
//! where the supervisor IS a leaf (root cgroup, or an undelegated slice), the
//! child's `cgroup.procs` write will fail with EBUSY/EINVAL. Under `Strongest` the child stops
//! before `exec` and the spawn fails, naming the cgroup; under `BestEffort` the placement
//! step falls back to the process-group mechanism without aborting the spawn.
//!
//! # Async-signal-safety
//! `placement_step` is one of the steps of the spawn core's child (after the clone, before
//! `exec`; see `child::spawn::fork_exec`). The only async-signal-safe operations there
//! are raw `libc::write` and `libc::close` — no allocation, no `format!`, no `String`. Its
//! outcome crosses back as a report record on the core's status channel.
//!
//! # Placement reports: when one is final, and what cosca may kill
//! Every decision about a leaf rests on these rules. `take_placement`,
//! `abandon_without_child` and `Drop` each apply them; none has a rule of its own.
//!
//! **The record.** After its `cgroup.procs` write the child writes one *report* record on the
//! status channel — `Placed` or the write's errno — before its ready record, and never waits for
//! the parent. It writes nothing else for the leaf, and nothing after `exec`.
//!
//! **Final.** The spawn's clone suspends the parent until the child's `exec` or exit, so every
//! record the child wrote is in the channel when the clone returns: the spawn reads them, and
//! records the report on the leaf (`record_placement`). What it recorded is all there will ever
//! be, and no verdict waits for anything.
//!
//! **One verdict.** The leaf's verdict is taken exactly once: `take_placement` after the spawn
//! (the attach, or a failed spawn that still holds its child), or `abandon_without_child` (and
//! `Drop`) for a spawn that never reached it. Both read the one recorded report.
//!
//! **Absence.** Nothing of the child's is in the leaf only when there is proof of it:
//! - a recorded report other than `Placed` or `Unknown` — the child either never entered (its write failed,
//!   and a lenient slot's program then runs outside the leaf), or ended before reporting (its
//!   placement may have been interrupted between the write and the record). Either way it never ran a
//!   program that could fork into the leaf; or
//! - the leaf's own removal — `rmdir` succeeds only on a leaf with no live member.
//!
//! `Unknown` is the report of a channel the spawn could not read: it is no proof of either, so the
//! attach builds nothing on it (it fails the spawn), the leaf is killed through, and the child's
//! process group is its containment too.
//!
//! **Kill.** cosca kills through a leaf whenever it lacks proof of absence, and never when it has
//! it: an occupant of a leaf that provably holds nothing of the child's is not cosca's to kill.
//! The one exception is a tree its caller opted out of teardown (`detach`, `kill_on_drop(false)`):
//! that leaf is disarmed, and its `Drop` never kills. A child cosca gives up on is also killed
//! itself, through its pidfd, whatever the leaf's kill returned — it may have left the leaf, or
//! never entered it — and, when it exec'd outside the leaf, as the process group it leads. An
//! elevation front is sent nothing: an exited one is reaped, and one its leaf's kill reached is
//! waited for (see `tear_down_held`, which looks at it through the leaf's `Subtree`).
//!
//! **Ownership.** The child is this process's own, but another reaper in the process may reap it
//! (see `Command::contain`), so cosca looks at it through its handle before anything it sends by
//! number. It leads its own process group (`process_group(0)`), and anything it forks after `exec`
//! starts in that group. A process group's id cannot name another group while its leader is
//! unreaped. cosca reaps a child only when no handle owns it — an abandoned spawn whose runtime
//! dropped it — and, but for an elevation front, only after signalling it directly. It does so
//! through an [`OwnedChild`](crate::child::owned::OwnedChild) over the child's pidfd, never by
//! its pid.

#[path = "cgroup/parse.rs"]
mod parse;
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        unused_imports,
        reason = "parse's items are dead off-linux (see parse.rs), so this glob re-export has nothing live to carry"
    )
)]
pub(crate) use parse::*;

#[path = "cgroup/degrade.rs"]
mod degrade;
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        unused_imports,
        reason = "degrade's items are dead off-linux (see degrade.rs), so this glob re-export has nothing live to carry"
    )
)]
pub(crate) use degrade::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/dir.rs"]
mod dir;
#[cfg(target_os = "linux")]
pub(crate) use dir::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/drain.rs"]
mod drain;
#[cfg(target_os = "linux")]
pub(crate) use drain::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/watcher.rs"]
mod watcher;
#[cfg(target_os = "linux")]
pub(crate) use watcher::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/kill_record.rs"]
mod kill_record;
#[cfg(target_os = "linux")]
pub(crate) use kill_record::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/reach.rs"]
mod reach;
#[cfg(target_os = "linux")]
pub(crate) use reach::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/own.rs"]
mod own;
#[cfg(target_os = "linux")]
pub(crate) use own::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/leaf.rs"]
mod leaf;
#[cfg(target_os = "linux")]
pub(crate) use leaf::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/contains.rs"]
mod contains;

/// Test-only fault seams for the leaf-creation steps a temp directory cannot reach.
///
/// Thread-local with take semantics — arm and call on one thread, then assert the flag was
/// consumed — so parallel tests in this binary cannot arm each other's faults, matching
/// `treewalk::fault` and `fdmarker::fault`.
#[cfg(all(target_os = "linux", test))]
#[path = "cgroup/fault.rs"]
pub(crate) mod fault;

#[cfg(all(target_os = "linux", test))]
#[path = "cgroup/test_support.rs"]
pub(crate) mod test_support;

// Selection only: the cgroup lane runs this module's tests whole.
#[cfg(test)]
skuld::default_labels!(crate::test_harness::CGROUP);
