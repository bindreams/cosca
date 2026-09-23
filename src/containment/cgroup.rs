//! Linux cgroup v2 leaf containment.
//!
//! When cgroup v2 is mounted, delegated, and writable with `cgroup.kill`
//! support, the spawned child is placed in a freshly created leaf sub-cgroup.
//! Teardown writes `"1"` to `cgroup.kill` — the kernel atomically kills every
//! process in the leaf (fork-proof). Falls back to the process-group mechanism
//! when any precondition fails (see `try_create_leaf`).
//!
//! # Delegation prerequisite
//! cgroup v2 requires "no internal processes": a non-root cgroup may not
//! contain processes AND child cgroups simultaneously. This implementation
//! creates the leaf as a direct child of the supervisor's cgroup, which works
//! correctly only when the supervisor's cgroup is already an inner node (i.e.
//! it contains no processes itself). This is the normal case in properly
//! delegated slices (systemd user slices, container environments). On hosts
//! where the supervisor IS a leaf (root cgroup, or an undelegated slice), the
//! child's `cgroup.procs` write will fail with EBUSY/EINVAL; the `pre_exec`
//! closure handles this gracefully by falling back to the process-group
//! mechanism without aborting the spawn.
//!
//! # Async-signal-safety
//! `place_self_in_cgroup_pre_exec` is called inside a `pre_exec` closure
//! (after `fork`, before `exec`). The only async-signal-safe operations there
//! are raw `libc::write`, `libc::close` and `libc::send` — no allocation, no
//! `format!`, no `String`. Its outcome crosses back through a socket pair
//! (`ReportChannel`).
//!
//! # Placement reports: when one is final, and what cosca may kill
//! Every decision about a leaf rests on these rules. `take_placement`, `decide_unwaitable`,
//! `abandon` and `Drop` each apply them; none has a rule of its own.
//!
//! **Final.** The child sends at most one report, before `exec`. A report is final once it has
//! been received, or once the child can no longer send one: it has exited (seen through a pidfd
//! or `waitid`), or the leaf is removed (a removed leaf admits no member, so the child's write
//! fails). Until then the report is in flight, whatever `spawn` returned — std's `spawn` can
//! return before the child has run any `pre_exec`. Nothing received is not "not entered".
//!
//! **Absence.** Nothing of the child's is in the leaf only when there is proof of it:
//! - a final report other than `Placed` — the child either never entered, or exited before
//!   reporting (its placement may have been interrupted between the write and the send). Either
//!   way it never exec'd, so it never ran a program that could fork into the leaf; or
//! - the leaf's own removal — `rmdir` succeeds only on a leaf with no live member.
//!
//! **Kill.** cosca kills through a leaf whenever it lacks proof of absence, and never when it has
//! it: an occupant of a leaf that provably holds nothing of the child's is not cosca's to kill. So an
//! occupied leaf whose report is still in flight is killed through, and then removed — killed
//! again for as long as anything re-enters it before the removal lands.
//!
//! **Ownership.** Until `spawn` returns, the child is this process's own unreaped child, and cosca
//! is the only thing that may signal it (see `Command::contain`). It leads its own process group
//! (`process_group(0)`), and anything it forks after `exec` starts in that group. A child cosca
//! gives up on is killed as a group: its descendants are its to answer for, in or out of the
//! leaf. The group's id cannot name another group while the child is unreaped — a pid number is
//! not reused while any task, a zombie leader or a group member, still holds it.

#[path = "cgroup/parse.rs"]
mod parse;
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
pub(crate) use parse::*;

#[path = "cgroup/degrade.rs"]
mod degrade;
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
pub(crate) use degrade::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/channel.rs"]
mod channel;
#[cfg(target_os = "linux")]
pub(crate) use channel::*;

#[cfg(target_os = "linux")]
#[path = "cgroup/leaf.rs"]
mod leaf;
#[cfg(target_os = "linux")]
pub(crate) use leaf::*;

/// Test-only fault seams for the leaf-creation steps a temp directory cannot reach.
///
/// Thread-local with take semantics — arm and call on one thread, then assert the flag was
/// consumed — so parallel tests in this binary cannot arm each other's faults, matching
/// `treewalk::fault` and `fdmarker::fault`.
#[cfg(all(target_os = "linux", test))]
#[path = "cgroup/fault.rs"]
pub(crate) mod fault;

#[cfg(test)]
#[path = "cgroup_tests.rs"]
mod cgroup_tests;
