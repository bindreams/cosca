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
//! `fail_closed`, `abandon_before_verdict` and `Drop` each apply them; none has a rule of its own.
//!
//! **Messages.** In its `pre_exec` the child sends, in order: an *intent*, carrying a pidfd for
//! itself when it can open one, before it touches the leaf; then, after its `cgroup.procs` write,
//! its *report* — `Placed` or the write's errno. It sends nothing else, and nothing after `exec`.
//! The pidfd is the leaf's one source of truth about which process is its child: unlike a pid, it
//! cannot come to name another process, whoever reaps the child.
//!
//! **One verdict.** The parent ends the exchange exactly once, by one of two acts:
//! - *Decide.* `take_placement` reads the report — waiting for it, or for the child's exit — or
//!   decides without it; then it sends *proceed* and closes the channel. A child whose send fails
//!   because the parent has decided finds *proceed* queued, and carries on.
//! - *Abandon.* A spawn that failed before its verdict shuts the channel for reading. Every
//!   message sent before that is still read; every send after it fails with no *proceed* queued,
//!   and the child exits without `exec`. After abandonment no child execs, in or out of a leaf.
//!
//! **Final.** After either act, what was received is all there will ever be. Before it, a report
//! is final once received, or once the child has exited (seen through a pidfd or `waitid`) or
//! the leaf is removed (a removed leaf admits no member). Otherwise it is in flight, whatever
//! `spawn` returned — std's `spawn` can return before the child has run any `pre_exec`.
//!
//! **Absence.** Nothing of the child's is in the leaf only when there is proof of it:
//! - a final report other than `Placed` — the child either never entered, or exited before
//!   reporting (its placement may have been interrupted between the write and the send). Either
//!   way it never exec'd, so it never ran a program that could fork into the leaf; or
//! - the leaf's own removal — `rmdir` succeeds only on a leaf with no live member.
//!
//! **Kill.** cosca kills through a leaf whenever it lacks proof of absence, and never when it has
//! it: an occupant of a leaf that provably holds nothing of the child's is not cosca's to kill.
//! A child cosca gives up on is also killed itself, through its pidfd and as the process group it
//! leads, whatever the leaf's kill returned — it may have left the leaf, or never entered it.
//!
//! **Ownership.** Until `spawn` returns, the child is this process's own unreaped child, and cosca
//! is the only thing that may signal it (see `Command::contain`). It leads its own process group
//! (`process_group(0)`), and anything it forks after `exec` starts in that group. A process group's
//! id cannot name another group while its leader is unreaped. cosca reaps a child only when no
//! handle owns it — an abandoned spawn whose runtime dropped it — only through its pidfd, and only
//! after signalling it directly: a wait on anything else could block, or reap another's child.

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
