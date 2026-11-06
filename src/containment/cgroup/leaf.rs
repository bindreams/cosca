//! The leaf itself: creating it, placing the child in it, deciding membership, killing
//! through it and removing it.

use std::fmt;
use std::io;
use std::path::PathBuf;

use super::*;

#[cfg(target_os = "linux")]
use crate::child::owned::teardown::{Disposition, Expect, HandleTeardown, Kill, Left, Past, Reach};
#[cfg(target_os = "linux")]
use crate::child::owned::OwnedChild;
#[cfg(target_os = "linux")]
use crate::child::spawn::held_teardown::{look_at_failed_spawn_front, tear_down_expecting};
#[cfg(target_os = "linux")]
use crate::error::ChildFate;
#[cfg(target_os = "linux")]
use crate::os_process::linux::LinuxProcess;
#[cfg(target_os = "linux")]
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Process-wide monotonic counter; combined with the pid, gives a unique leaf
/// name even when the same process spawns on multiple threads simultaneously.
#[cfg(target_os = "linux")]
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Whether `e` is the kernel's proof that this leaf's `cgroup.events` node is already gone —
/// either because the whole path was already removed (`ENOENT`, on a fresh `open` through the
/// now-unlinked leaf directory) or because THIS fd was opened before removal and the
/// underlying kernfs node has since been deactivated (`ENODEV`, on `seek`/`read` through an
/// already-open fd). `rmdir` on a cgroup v2 leaf — whether `Drop`'s own retry or an external
/// cgroup manager's cleanup of an empty leaf — succeeds ONLY once `populated` has already read
/// 0 (see `CgroupLeaf::wait_drained`'s doc); observing the leaf's removal is therefore always
/// proof every member had already exited, never proof of anything else, so no other errno is
/// folded in here (a genuine mechanism failure — `EACCES`, `EIO`, ...— must still surface as
/// `Error::Io`, not be silently reinterpreted as a drain).
#[cfg(target_os = "linux")]
pub(crate) fn removed_after_drain(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENODEV) | Some(libc::ENOENT))
}

/// Seek to the start of `file` (a `cgroup.events` handle) and read its current `populated`
/// value. The one read of a held `cgroup.events`, behind [`DrainWatch::populated`].
///
/// A leaf removed after every member has exited (see [`removed_after_drain`]) is reported as
/// `Ok(false)`: the leaf's own removal is itself proof of a full drain, indistinguishable in
/// meaning from an explicit `populated 0`.
#[cfg(target_os = "linux")]
pub(crate) fn read_populated(file: &mut File, buf: &mut String) -> Result<bool, crate::error::Error> {
    use std::io::{Read, Seek, SeekFrom};

    buf.clear();
    if let Err(e) = file.seek(SeekFrom::Start(0)) {
        return if removed_after_drain(&e) {
            Ok(false)
        } else {
            Err(crate::error::Error::Io(e))
        };
    }
    if let Err(e) = file.read_to_string(buf) {
        return if removed_after_drain(&e) {
            Ok(false)
        } else {
            Err(crate::error::Error::Io(e))
        };
    }
    parse_populated(buf).ok_or_else(|| {
        crate::error::Error::Io(io::Error::other(
            "cgroup.events has no 'populated' field — unexpected kernel format",
        ))
    })
}

/// The state letter of `child`, or `None` when it is unknown; the cause is logged at debug (see
/// [`StateUnknown`]). Only the pidfd says `Z`: the child exited, which separates "the placement
/// write failed" from "the child exited before membership was checked".
///
/// The pidfd is checked before and after the `/proc` read: a child unexited at the second check held
/// `pid` throughout, so the read is its own; otherwise the state is `Z`.
///
/// A `/proc` state of `Z` or `X` with the pidfd unexited is a thread-group leader that exited while
/// other threads run: the group has not exited, so that is no state of the child.
#[cfg(target_os = "linux")]
fn proc_state(kernel: &dyn crate::identity::Kernel, child: crate::containment::ChildHandle<'_>) -> Option<char> {
    let crate::containment::ChildHandle { pid, pidfd } = child;
    let exited = |when: &str| match crate::os_process::poll::is_readable(pidfd) {
        Ok(exited) => Some(exited),
        Err(e) => {
            log::debug!("cgroup leaf: whether pid {pid} had exited {when} its state was read is unknown: {e}");
            None
        }
    };
    if exited("before")? {
        return Some('Z');
    }
    #[cfg(test)]
    fault::run_before_state_read();
    let state = read_proc_state(kernel, pid);
    if exited("after")? {
        return Some('Z');
    }
    match state {
        Ok('Z' | 'X' | 'x') => {
            log::debug!("cgroup leaf: pid {pid}'s leader exited, group lives");
            None
        }
        Ok(state) => Some(state),
        Err(why) => {
            log::debug!("cgroup leaf: pid {pid}'s state is unknown: {why}");
            None
        }
    }
}

/// Why [`read_proc_state`] has no state letter.
#[cfg(target_os = "linux")]
#[derive(Debug)]
enum StateUnknown {
    /// `/proc` is an outer pid namespace's, or could not be verified to be this process's own.
    View(crate::identity::ViewUnreadable),
    /// `<pid>/stat` could not be read.
    Unreadable(std::io::Error),
    /// `<pid>/stat` has no state field.
    Unparsable(Vec<u8>),
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for StateUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::View(why) => write!(f, "the /proc view cannot be relied on: {why}"),
            Self::Unreadable(e) => write!(f, "its stat could not be read: {e}"),
            Self::Unparsable(stat) => write!(f, "its stat has no state field: {:?}", String::from_utf8_lossy(stat)),
        }
    }
}

/// `pid`'s state letter. Any failure, the pidfd-bracketed read's included, means the state is
/// unknown.
#[cfg(target_os = "linux")]
fn read_proc_state(kernel: &dyn crate::identity::Kernel, pid: u32) -> Result<char, StateUnknown> {
    let proc_dir = crate::identity::proc_view_with(kernel)
        .into_dir()
        .map_err(StateUnknown::View)?;
    let stat = crate::identity::pid_stat::read_stat_file(kernel, &proc_dir, pid).map_err(StateUnknown::Unreadable)?;
    state_from_stat(stat)
}

#[cfg(target_os = "linux")]
fn state_from_stat(stat: Vec<u8>) -> Result<char, StateUnknown> {
    crate::identity::stat_parse::parse_state(&stat)
        .map(char::from)
        .ok_or(StateUnknown::Unparsable(stat))
}

/// What [`CgroupLeaf::drain_step`] found.
#[cfg(target_os = "linux")]
pub(crate) enum DrainStep {
    /// The wait's answer.
    Done(crate::containment::TreeDrain),
    /// Block on `listener` until `deadline` (`None`: unbounded), then step again. Carries the
    /// caller's instant, not a duration: a duration would go stale between computing it and
    /// starting the wait.
    Block {
        listener: event_listener::EventListener,
        deadline: Option<std::time::Instant>,
    },
}

/// A live leaf sub-cgroup created for a single spawned process tree. See
/// [`place_self_in_cgroup_pre_exec`] for the placement write's contract.
///
/// [`CgroupLeaf::take_placement`] releases the `cgroup.procs` fd and the report channel: the child
/// needs them only until its `exec`.
///
/// `Drop` removes the leaf directory, but only if the child reported entering it. If the leaf is
/// still occupied, it fires `cgroup.kill` itself — but only while still armed (not
/// [`disarm`](Self::disarm)ed) — then, either way a kill is now in flight (its own, or one the
/// caller already made through [`kill_tree`](Self::kill_tree)/[`hard_kill`](Self::hard_kill)),
/// waits for the leaf to drain, removes its child cgroups, and tries the `rmdir` once more.
#[cfg(target_os = "linux")]
pub(crate) struct CgroupLeaf {
    /// Absolute path to the leaf directory, e.g. `/sys/fs/cgroup/…/cosca-<pid>`, for reports.
    /// Nothing is done through it: see [`LeafDir`].
    pub(super) leaf_path: PathBuf,
    /// The leaf's directory and its parent, held from creation.
    dir: LeafDir,
    /// The leaf's drain watch, held from creation so that no wait on it ever lacks one. Read by
    /// the pump this watcher owns, which broadcasts each change to every wait.
    /// Boxed: its pump would make every `Attached` as large as a leaf.
    watch: Box<Watcher>,
    /// Pre-opened `cgroup.procs` fd for the `pre_exec` write. Close-on-exec: the write happens
    /// between `fork` and `exec`, and no program this process starts may inherit it. Numbered
    /// 3 or above, so it never shares a number with the child's stdio. `None` once the
    /// placement verdict is taken.
    procs_fd: Option<OwnedFd>,
    /// Where the forked child reports whether its self-placement write succeeded. `None` once
    /// the placement verdict is taken.
    pub(super) report: Option<ReportChannel>,
    /// Whether the child reported entering the leaf, recorded when `report` is released.
    pub(super) entered: bool,
    /// The leaf's unified-hierarchy path, as `/proc/<pid>/cgroup` prints it. `None` for a leaf
    /// created outside the cgroup filesystem.
    cgroup_path: Option<String>,
    /// Whether the leaf is already dealt with, so `Drop` has nothing left to do: the spawn was
    /// abandoned before its verdict, an async `Drop` released it
    /// ([`release_without_waiting`](Self::release_without_waiting)), or it was torn down.
    pub(super) abandoned: bool,
    /// Whether the caller still wants cosca to manage the tree. Cleared by `disarm`, for
    /// `detach()` and `kill_on_drop(false)`. `Drop` kills only while this and `entered` both hold.
    armed: AtomicBool,
    /// Whether [`hard_kill`](Self::hard_kill) wrote `cgroup.kill`. A disarmed `Drop` reads it to
    /// tell a tree the caller killed, whose leaf has not drained yet, from one left running.
    /// [`terminate`](Self::terminate) does not set it: a SIGTERM can be caught.
    killed: std::sync::Arc<AtomicBool>,
    /// The elevation front this leaf's child is, by pid, whose place is recorded in `placed` before
    /// each `rmdir` (see [`watch_front`](Self::watch_front)).
    watched: Option<u32>,
    /// Where the watched front was when the leaf was last about to be removed, shared with the
    /// leaf's [`Subtree`]s.
    placed: super::PlacedAtRemoval,
    /// Whether a [`hard_kill`](Self::hard_kill) call failed for a real mechanism reason (not
    /// "leaf already gone", which sets `killed` above instead). A disarmed `Drop` reads it to
    /// `warn` that the caller's own `kill_tree()` never actually reached this leaf, rather than
    /// silently folding a genuine failure into the same `debug` note used for a tree the caller
    /// never asked to kill at all.
    kill_attempt_failed: AtomicBool,
}

/// Why a spawn-side resource of a [`CgroupLeaf`] is missing.
#[cfg(target_os = "linux")]
const RELEASED: &str = "the leaf's spawn-side resources are released once its placement verdict is taken";

/// `listener.wait_deadline(at)` — the only call site for it, so the seam that records `at` (test
/// builds only) can never drift from what's actually passed: both come from the same parameter,
/// in the same function, with nothing between them to retarget one without the other. Closes
/// `event_listener::Listener::wait_deadline`'s own gap — it consumes the listener and exposes no
/// way to read back what it was armed with — from the caller's side instead.
#[cfg(target_os = "linux")]
fn wait_deadline_seamed(listener: event_listener::EventListener, at: std::time::Instant) -> bool {
    use event_listener::Listener as _;

    #[cfg(test)]
    fault::notify_wait_deadline_arg(at);
    listener.wait_deadline(at).is_some()
}

/// What `hard_kill` writes to `cgroup.kill`.
#[cfg(target_os = "linux")]
pub(crate) const KILL_PAYLOAD: &[u8] = b"1";

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// Whether the placement verdict is still to be taken: the exchange has not ended.
    pub(crate) fn holds_verdict_to_take(&self) -> bool {
        self.report.is_some()
    }

    /// Returns the raw `cgroup.procs` fd for the in-child placement step. Only before the
    /// placement verdict is taken.
    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs_fd.as_ref().expect(RELEASED).as_raw_fd()
    }

    /// Whether the child reported entering this leaf, once the verdict is taken.
    pub(crate) fn child_entered(&self) -> bool {
        debug_assert!(self.report.is_none(), "the verdict is not taken yet");
        self.entered
    }

    /// Neutralize `Drop`'s kill, for `detach()`.
    ///
    /// Dropping a `CgroupLeaf` is NOT inert, which is what makes this necessary: `Drop` fires
    /// `cgroup.kill` whenever the first `rmdir` fails, and over a live detached tree that
    /// `rmdir` always fails (`EBUSY`). `Child::drop` opting out via `kill_on_drop` does not
    /// help — the leaf is a field of that `Child` and its own `Drop` runs regardless.
    ///
    /// A disarmed `Drop` never fires `cgroup.kill` itself, and gives up the leaf without
    /// retrying when the tree was never killed (noted at `debug`, never `warn`) — whether or not
    /// it is still live. But it does not give up on a kill the caller already made through
    /// `kill_tree()`/`hard_kill()`: that kill's drain is waited for exactly as an armed `Drop`'s
    /// is, so the `rmdir` retries once the leaf drains, and only reports the leaf as left behind
    /// if it still fails after that.
    pub(crate) fn disarm(&self) {
        self.armed.store(false, Ordering::Relaxed);
    }

    /// The leaf's directory: names the leaf in a caller's own message, since `hard_kill` returns
    /// the kernel's error unwrapped (a message wrapper would erase `raw_os_error()`), and finds
    /// this leaf and no other in tests.
    pub(crate) fn path(&self) -> &Path {
        &self.leaf_path
    }

    /// Remove a leaf that holds nothing of its child's: close the fd and `rmdir`, never
    /// `cgroup.kill`.
    ///
    /// The child's final report is not `Placed`, so it never exec'd a program that could fork
    /// into the leaf (see the module's report contract).
    /// Whatever keeps the `rmdir` from succeeding, cosca did not put there, and killing it would
    /// kill a process cosca was never asked to contain.
    pub(crate) fn remove_unentered(self) {
        debug_assert!(!self.child_entered(), "remove_unentered on a leaf its child entered");
    }

    /// A `Copy` handle to this leaf's placement-report slot, for the in-child placement step.
    /// Only before the placement verdict is taken.
    pub(crate) fn placement_slot(&self) -> ReportSlot {
        self.report.as_ref().expect(RELEASED).slot()
    }

    /// Whether `child` entered this leaf: `Ok` when its own write into it succeeded.
    ///
    /// Used once, post-spawn (parent side). Blocks until the report is final — `spawn` returning
    /// does not make it so (see [`ReportChannel`], which also says why the wait goes through the
    /// child's pidfd). The child's report is the verdict: `cgroup.procs` lists only live tasks, so
    /// a placed child that has already exited reads back absent from it. Only a child that reported
    /// no successful write has `cgroup.procs` and its state read, to diagnose why — see
    /// [`NotPlaced`].
    ///
    /// Taking the verdict closes the `cgroup.procs` fd and the report channel: nothing
    /// needs either after the child's `exec`, and otherwise every live contained child would
    /// hold three fds in the supervisor.
    pub(crate) fn take_placement(&mut self, child: crate::containment::ChildHandle<'_>) -> Result<(), NotPlaced> {
        #[cfg(test)]
        fault::run_on_take_placement();
        let mut channel = self.report.take().expect(RELEASED);
        self.procs_fd = None;
        let report = channel.wait(child.pidfd);
        channel.proceed();
        self.entered = report == PlacementReport::Placed;
        let report = match report {
            PlacementReport::Placed => return Ok(()),
            PlacementReport::NotReported => NotEntered::NotReported,
            PlacementReport::WriteFailed(errno) => NotEntered::WriteFailed(errno),
        };
        let path = self.leaf_path.join("cgroup.procs");
        let child_state = proc_state(&crate::identity::HostKernel, child);
        Err(match self.dir.read("cgroup.procs") {
            Ok(procs) => NotPlaced::Absent {
                pid: child.pid,
                path,
                procs,
                report,
                child_state,
            },
            Err(source) => NotPlaced::Unreadable {
                pid: child.pid,
                path,
                source,
                report,
            },
        })
    }

    /// Whether `pid` (which `pidfd` names, when there is one) is in this leaf or a cgroup under it,
    /// for a kill through it.
    pub(crate) fn holds_member(&self, pid: u32, pidfd: Option<std::os::fd::BorrowedFd<'_>>) -> io::Result<bool> {
        self.names(pid, pidfd)
    }

    /// Whether the task `pid` (which `pidfd` names, when there is one) is in this leaf or a cgroup
    /// under it (see [`Subtree::holds`]).
    pub(crate) fn names(&self, pid: u32, pidfd: Option<std::os::fd::BorrowedFd<'_>>) -> io::Result<bool> {
        self.subtree()?.holds(pid, pidfd)
    }

    /// The leaf's cgroup id (see [`cgroup_id`](super::cgroup_id)).
    pub(crate) fn id(&self) -> io::Result<u64> {
        #[cfg(test)]
        if let Some(errno) = fault::cgroup_id_fails() {
            return Err(io::Error::from_raw_os_error(errno));
        }
        self.dir.id()
    }

    /// The leaf as a place to read a task's membership in, once the leaf may be gone: its own
    /// cgroup id, its directory, its path, what its sweep removed, and whether a kill through it
    /// has landed.
    pub(crate) fn subtree(&self) -> io::Result<Subtree> {
        #[cfg(test)]
        if let Some(errno) = fault::subtree_fails() {
            return Err(io::Error::from_raw_os_error(errno));
        }
        Ok(self.subtree_with(Some(self.id()?)))
    }

    /// The leaf's [`Subtree`] with the cgroup id `leaf_id`; `None` places every task through `/proc`.
    fn subtree_with(&self, leaf_id: Option<u64>) -> Subtree {
        Subtree::new(
            leaf_id,
            Some(self.dir.shared()),
            self.cgroup_path.clone(),
            self.dir.swept(),
            self.placed.clone(),
            std::sync::Arc::clone(&self.killed),
        )
    }

    /// Watch the elevation front `pid`, this leaf's child: its place is recorded before each
    /// `rmdir` of the leaf, while the leaf's own path still reads without ` (deleted)` (see
    /// [`Subtree::holds`]).
    pub(crate) fn watch_front(&mut self, pid: u32) {
        debug_assert!(
            self.watched.is_none_or(|watched| watched == pid),
            "a leaf watches one front: {:?}, then {pid}",
            self.watched
        );
        self.watched = Some(pid);
    }

    /// Record where the watched front is, by `/proc/<pid>/cgroup`, before the leaf may be removed.
    /// At an `rmdir` that succeeds, the leaf holds no live task, so a front recorded in it is past
    /// leaving its cgroup and can no longer be moved, and a front recorded outside it can no
    /// longer enter it: the record stays true once the leaf is gone.
    ///
    /// While the leaf is live its own path reads plainly: a front that reads it with ` (deleted)`
    /// after it is in a live cgroup of that name beside it, and recorded outside. If the leaf is
    /// already gone (removed by someone else), or whether it is live cannot be read, that path is
    /// undecidable, and nothing is recorded.
    fn record_watched_place(&self) {
        let (Some(pid), Some(path)) = (self.watched, &self.cgroup_path) else {
            return;
        };
        // Outside only when the leaf's own file opens: the leaf is live. Any error, its removal or
        // any other, leaves the path undecided.
        let outside_if_live = || {
            #[cfg(test)]
            let opened = match fault::liveness_read_fails() {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => self.dir.open("cgroup.events", rustix::fs::OFlags::PATH),
            };
            #[cfg(not(test))]
            let opened = self.dir.open("cgroup.events", rustix::fs::OFlags::PATH);
            opened.ok().map(|_| false)
        };
        match super::proc_names(path, pid, outside_if_live, false) {
            Ok(inside) => self.placed.record(pid, inside),
            Err(e) => {
                log::debug!(
                    "cgroup v2: elevation front pid {pid}'s place before its leaf's removal cannot be read ({e})"
                );
                self.placed.clear();
            }
        }
    }

    fn rmdir_leaf(&self) -> io::Result<()> {
        self.record_watched_place();
        #[cfg(test)]
        fault::record_leaf_step(|| {
            let events = self.dir.read("cgroup.events").unwrap_or_default();
            format!("rmdir {}", events.lines().next().unwrap_or("(no cgroup.events)"))
        });
        #[cfg(test)]
        if let Some(result) = fault::run_rmdir_hook(&self.leaf_path) {
            return result;
        }
        self.dir.rmdir()
    }

    /// Hard-kill all processes in the cgroup via `cgroup.kill` (kernel ≥ 5.14).
    ///
    /// `Ok` means the tree is dead: either the atomic kill fired, or the leaf was already gone
    /// ([`removed_after_drain`]), which is itself proof every member had exited — `rmdir` on a
    /// cgroup v2 leaf succeeds only once `populated` reads 0.
    ///
    /// Every other errno means the atomic kill did NOT happen — the tree may still be running
    /// (a delegated subtree whose `cgroup.kill` stopped being writable after a privilege drop,
    /// or a cgroupfs remounted `ro`). That is a teardown-mechanism failure and is returned, the
    /// same way every sibling mechanism's is (`Attached::hard_kill`): a caller that reads
    /// `Child::kill_tree() -> Ok(())` over a live tree has been told the opposite of the truth.
    ///
    /// The kill is complete only on kernels with the `cgroup.kill` fork-race fix (`b69bb476dee9`);
    /// see [`Command::kill_on_drop`](crate::Command::kill_on_drop).
    pub(crate) fn hard_kill(&self) -> Result<(), crate::error::Error> {
        let path = self.leaf_path.join("cgroup.kill");
        #[cfg(test)]
        fault::run_before_kill_write();
        #[cfg(test)]
        let written = if fault::kill_writes_fail() || fault::take_next_kill_write_failure() {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        } else {
            self.dir.write("cgroup.kill", KILL_PAYLOAD)
        };
        #[cfg(not(test))]
        let written = self.dir.write("cgroup.kill", KILL_PAYLOAD);
        match written {
            Ok(()) => {
                #[cfg(test)]
                fault::record_leaf_step(|| "kill".to_string());
                self.killed.store(true, Ordering::Relaxed);
                #[cfg(test)]
                fault::run_after_kill_write();
                Ok(())
            }
            Err(e) if removed_after_drain(&e) => {
                log::debug!("cgroup.kill: leaf {} is already gone", path.display());
                Ok(())
            }
            Err(e) => {
                self.kill_attempt_failed.store(true, Ordering::Relaxed);
                Err(crate::error::Error::Io(e))
            }
        }
    }

    /// Block until every process in the leaf has EXITED (not reaped) — `cgroup.events`'s
    /// `populated` reads 0, or the leaf is removed — or until `deadline` (see
    /// [`crate::wait::remaining`]). Reads the leaf first, and answers from that read if it has
    /// drained or the deadline has passed, starting nothing. Otherwise listens to the leaf's
    /// [`Watcher`], starting its pump, reads the leaf again, and blocks until the next broadcast:
    /// no interval, and a wait holds nothing another needs. The watch wakes on the leaf's removal as well as on `populated`,
    /// since the kernel can cancel the one notification a drain sends. A removed leaf holds
    /// nothing: `rmdir` succeeds only on a drained leaf ([`removed_after_drain`]).
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        use event_listener::Listener as _;

        #[cfg(feature = "tokio")]
        crate::bounded::assert_may_block("waiting for a cgroup leaf to drain");

        // Only the bounded arm advances the frozen clock, so only it is checked.
        #[cfg(test)]
        let mut check = crate::wait::test_clock::RoundCheck::new("wait_drained");
        loop {
            match self.drain_step(deadline)? {
                DrainStep::Done(drain) => return Ok(drain),
                DrainStep::Block {
                    listener,
                    deadline: None,
                } => {
                    listener.wait();
                    #[cfg(test)]
                    fault::notify_wait_site_park(fault::WaitSitePark {
                        deadline: None,
                        woken: true,
                    });
                }
                // A timeout is looked at by the next step, which reads the leaf once more.
                DrainStep::Block {
                    listener,
                    deadline: Some(at),
                } => {
                    #[cfg(test)]
                    check.round();
                    #[cfg(test)]
                    let call_start = std::time::Instant::now();
                    #[cfg_attr(
                        not(test),
                        allow(unused_variables, reason = "`woken` is read only by the test-only recording below")
                    )]
                    let woken = wait_deadline_seamed(listener, at);
                    // Bounds what would otherwise be an unbounded spin under a mock clock a test
                    // forgot to advance: `at` is a real `Instant`, so once real time passes it
                    // this returns immediately every iteration, and only a frozen `remaining()`
                    // that never catches up would keep re-arming the same, already-past
                    // deadline forever. See `test_clock::advance_by_elapsed_if_frozen`'s own doc.
                    // A no-op outside tests and whenever the clock isn't frozen.
                    #[cfg(test)]
                    crate::wait::test_clock::advance_by_elapsed_if_frozen(call_start.elapsed());
                    #[cfg(test)]
                    fault::notify_wait_site_park(fault::WaitSitePark {
                        deadline: Some(at),
                        woken,
                    });
                }
            }
        }
    }

    /// One step of a wait on the leaf's drain, shared by the sync and async waits: read the leaf,
    /// and answer if it has drained or `deadline` has passed. Otherwise listen, starting the pump
    /// (which can itself take real time — spawning its thread), and read it again: a change
    /// after that read is always heard, so the caller may block on the returned listener until
    /// `deadline`, then take another step. Returns `deadline`'s own instant unchanged, in
    /// `Block` — see its doc for why. Reads the clock via [`crate::wait::remaining`], which
    /// honours the test clock in test builds, so a test can pin the zero-remaining shortcut's
    /// boundary exactly without a real one.
    pub(crate) fn drain_step(&self, deadline: Option<std::time::Instant>) -> Result<DrainStep, crate::error::Error> {
        self.drain_step_on(deadline, crate::wait::now)
    }

    /// [`drain_step`](Self::drain_step) reading `now` from `clock`, for a wait whose timer runs
    /// on another clock (tokio's).
    pub(crate) fn drain_step_on(
        &self,
        deadline: Option<std::time::Instant>,
        clock: impl FnOnce() -> std::time::Instant,
    ) -> Result<DrainStep, crate::error::Error> {
        use crate::containment::TreeDrain;

        if let Some(drain) = self.drain_seen()? {
            return Ok(DrainStep::Done(drain));
        }
        if crate::wait::remaining_at(deadline, clock()) == Some(std::time::Duration::ZERO) {
            #[cfg(test)]
            fault::notify_drain_zero_remaining();
            return Ok(DrainStep::Done(TreeDrain::MembersRemain));
        }
        let listener = self.watch.listen().map_err(crate::error::Error::Io)?;
        if let Some(drain) = self.drain_seen()? {
            return Ok(DrainStep::Done(drain));
        }
        #[cfg(test)]
        fault::notify_drain_blocking();
        Ok(DrainStep::Block { listener, deadline })
    }

    /// `Some(AllMembersExited)` if the leaf has drained or is gone; `None` if it still holds a
    /// member; an error if the pump that would report a change has stopped.
    fn drain_seen(&self) -> Result<Option<crate::containment::TreeDrain>, crate::error::Error> {
        use crate::containment::TreeDrain;

        if self.watch.saw_removal() || self.drain_now()? == TreeDrain::AllMembersExited {
            return Ok(Some(TreeDrain::AllMembersExited));
        }
        match self.watch.failure() {
            Some(why) => Err(crate::error::Error::Io(io::Error::other(format!(
                "the drain of cgroup leaf {} can no longer be watched: {why}",
                self.leaf_path.display()
            )))),
            None => Ok(None),
        }
    }

    /// Whether the leaf has drained, read now through the held leaf directory, without the watch.
    pub(crate) fn drain_now(&self) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        use crate::containment::TreeDrain;

        let events = match self.dir.read("cgroup.events") {
            Ok(events) => events,
            Err(e) if removed_after_drain(&e) => return Ok(TreeDrain::AllMembersExited),
            Err(e) => return Err(crate::error::Error::Io(e)),
        };
        match parse_populated(&events) {
            Some(true) => Ok(TreeDrain::MembersRemain),
            Some(false) => Ok(TreeDrain::AllMembersExited),
            None => Err(crate::error::Error::Io(io::Error::other(
                "cgroup.events has no 'populated' field — unexpected kernel format",
            ))),
        }
    }

    /// SIGTERM every process listed in `cgroup.procs` that is still in the leaf.
    ///
    /// An already-gone leaf is `Ok`, on the same proof [`hard_kill`](Self::hard_kill) rests on
    /// ([`removed_after_drain`]): there is no member left to signal. The two halves must agree
    /// about one leaf — a caller doing terminate-then-kill would otherwise take an error from
    /// the graceful half and success from the hard one over the identical directory.
    ///
    /// Each listed pid is pinned by a pidfd, shown to be in the leaf (or under it) and still
    /// running, then signalled through the pidfd, so a pid that exited and was reused after the read
    /// is left alone. A member that leaves the leaf after that check still gets the `SIGTERM`: it is
    /// the process that was checked. A member that cannot be pinned or placed gets no `SIGTERM` and
    /// makes the call an error (see [`terminate_tree`](crate::Child::terminate_tree)); `cgroup.kill`
    /// still reaches it.
    ///
    /// A listed member that got no `SIGTERM` for any reason but its exit is logged at `warn`, naming
    /// the leaf and the pid, and makes the call an error once every member was tried:
    /// [`Error::Containment`](crate::error::Error::Containment) if a send failed, otherwise
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) for members that could not be
    /// pinned or placed, a listed pid `0` (a member in a pid namespace this process cannot see), or
    /// a `cgroup.procs` line that is no pid.
    pub(crate) fn terminate(&self) -> Result<(), crate::error::Error> {
        let path = self.leaf_path.join("cgroup.procs");
        let content = match self.dir.read("cgroup.procs") {
            Ok(c) => c,
            Err(e) if removed_after_drain(&e) => {
                log::debug!("cgroup terminate: leaf {} is already gone", path.display());
                return Ok(());
            }
            Err(e) => return Err(crate::error::Error::Io(e)),
        };
        #[cfg(test)]
        fault::run_after_procs_read();
        self.terminate_listed(&content)
    }

    /// [`terminate`](Self::terminate) for the members `procs` lists, in `cgroup.procs`' format.
    fn terminate_listed(&self, procs: &str) -> Result<(), crate::error::Error> {
        let mut pids = Vec::new();
        let mut unproven = Vec::new();
        for line in procs.lines() {
            match line.trim().parse::<u32>() {
                // A live member outside this process's pid namespace: it has no number here to
                // pin or signal.
                Ok(0) => {
                    unproven.push("pid 0: it is a member in a pid namespace this process cannot see".to_owned());
                }
                Ok(pid) => pids.push(pid),
                Err(_) => unproven.push(format!("cgroup.procs line {line:?} is no pid")),
            }
        }
        if pids.is_empty() && unproven.is_empty() {
            return Ok(());
        }
        // One subtree for every member. Where the leaf's id cannot be read, the pidfd route cannot
        // place a member, and `/proc` does.
        let subtree = self.subtree_with(match self.id() {
            Ok(id) => Some(id),
            Err(e) => {
                log::debug!(
                    "cgroup terminate: leaf {}'s cgroup id cannot be read ({e}); its members are placed through /proc",
                    self.leaf_path.display()
                );
                None
            }
        });
        let mut failed = Vec::new();
        for pid in pids {
            match self.terminate_member(pid, &subtree) {
                Ok(()) => {}
                Err(Unsignalled::Failed(why)) => failed.push(format!("pid {pid}: {why}")),
                Err(Unsignalled::Unproven(why)) => unproven.push(format!("pid {pid}: {why}")),
            }
        }
        if failed.is_empty() && unproven.is_empty() {
            return Ok(());
        }
        let leaf = self.leaf_path.display();
        let mut parts = Vec::new();
        if !failed.is_empty() {
            parts.push(format!(
                "the SIGTERM failed for {} ({})",
                failed.len(),
                failed.join("; ")
            ));
        }
        if !unproven.is_empty() {
            parts.push(format!(
                "{} could not be shown to be members, and were not signalled ({})",
                unproven.len(),
                unproven.join("; ")
            ));
        }
        let detail = format!(
            "cgroup leaf {leaf}: listed members got no SIGTERM: {}",
            parts.join("; ")
        );
        log::warn!("cgroup terminate: {detail}");
        Err(if failed.is_empty() {
            crate::error::Error::Unassessable { detail, source: None }
        } else {
            crate::error::Error::Containment { detail }
        })
    }

    /// [`terminate`](Self::terminate)'s `SIGTERM` to the listed `pid`, if it is still a running
    /// member of the leaf. `Ok` once sent, or for a pid that is gone or not a running member, which
    /// it logs at `debug`; `Err` says why a pid that may be a member got none.
    fn terminate_member(&self, pid: u32, subtree: &Subtree) -> Result<(), Unsignalled> {
        use std::os::fd::AsFd as _;
        let pidfd = match pin_member(pid) {
            Ok(pidfd) => pidfd,
            Err(rustix::io::Errno::SRCH) => {
                log::debug!("cgroup terminate: pid {pid} is gone; not signalled");
                return Ok(());
            }
            Err(e) => return Err(Unsignalled::Unproven(format!("it could not be pinned ({e})"))),
        };
        #[cfg(test)]
        fault::run_after_terminate_pin();
        // The exit check follows the read: a process still running after it held `pid` throughout,
        // so the read was its own and not a reused pid's.
        let inside = match subtree.holds(pid, Some(pidfd.as_fd())) {
            Ok(inside) => inside,
            // A member that exited and was reaped since its pin has no place left to read
            // (`ENOENT` from `/proc`, `ESRCH` from `PIDFD_GET_INFO`): its pidfd tells it apart.
            Err(e) => match member_exited(pidfd.as_fd()) {
                Ok(true) => {
                    log::debug!("cgroup terminate: pid {pid} exited before it was placed ({e}); not signalled");
                    return Ok(());
                }
                Ok(false) => return Err(Unsignalled::Unproven(format!("it could not be placed ({e})"))),
                Err(exited) => {
                    return Err(Unsignalled::Unproven(format!(
                        "it could not be placed ({e}), nor its exit read ({exited})"
                    )))
                }
            },
        };
        if !inside {
            log::debug!("cgroup terminate: pid {pid} is not a member of the leaf; not signalled");
            return Ok(());
        }
        match member_exited(pidfd.as_fd()) {
            Ok(false) => {}
            Ok(true) => {
                log::debug!("cgroup terminate: pid {pid} has exited; not signalled");
                return Ok(());
            }
            Err(e) => return Err(Unsignalled::Unproven(format!("its exit could not be read ({e})"))),
        }
        match send_term(pidfd.as_fd(), pid) {
            Ok(()) => Ok(()),
            Err(nix::errno::Errno::ESRCH) => {
                log::debug!("cgroup terminate: pid {pid} exited before its SIGTERM");
                Ok(())
            }
            Err(e) => Err(Unsignalled::Failed(format!("{e}"))),
        }
    }
}

/// A pidfd that pins the process `pid` names, for [`CgroupLeaf::terminate`]; a test build lets a
/// `fail_terminate` seam answer in its place.
fn pin_member(pid: u32) -> rustix::io::Result<std::os::fd::OwnedFd> {
    #[cfg(test)]
    if let Some(errno) = fault::terminate_fails(fault::TerminateStep::Pin) {
        return Err(rustix::io::Errno::from_raw_os_error(errno));
    }
    rustix::process::Pid::from_raw(pid as i32)
        .ok_or(rustix::io::Errno::INVAL)
        .and_then(|raw| rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty()))
}

/// Whether [`CgroupLeaf::terminate`]'s member has exited, reaped or not: its pidfd turns readable at
/// exit and stays so. A test build lets a `fail_terminate` seam answer in its place.
fn member_exited(pidfd: std::os::fd::BorrowedFd<'_>) -> io::Result<bool> {
    #[cfg(test)]
    if let Some(errno) = fault::terminate_fails(fault::TerminateStep::Exited) {
        return Err(io::Error::from_raw_os_error(errno));
    }
    crate::os_process::poll::is_readable(pidfd)
}

/// [`CgroupLeaf::terminate`]'s `SIGTERM` to the member `pidfd` pins, and the kernel's answer. It goes
/// through the shared send, which a test build notes the route of. A test build lets a
/// `fail_terminate` seam answer in its place without sending.
fn send_term(pidfd: std::os::fd::BorrowedFd<'_>, pid: u32) -> nix::Result<()> {
    use crate::containment::unix::{send_signal, Sys, Target};
    #[cfg(test)]
    if let Some(errno) = fault::terminate_fails(fault::TerminateStep::Send) {
        return Err(nix::errno::Errno::from_raw(errno));
    }
    send_signal(
        Target::LeafMember(pid),
        Sys::Pidfd(pidfd, 0),
        nix::sys::signal::Signal::SIGTERM,
    )
}

/// Why [`CgroupLeaf::terminate`] sent a listed pid no `SIGTERM`.
enum Unsignalled {
    /// The send failed.
    Failed(String),
    /// Nothing showed the pid to be a running member, so it was not signalled.
    Unproven(String),
}

#[cfg(all(target_os = "linux", test))]
impl CgroupLeaf {
    /// Test-only placeholder pointing at no real cgroup. Safe to construct and drop —
    /// `remove_dir` of a nonexistent path is a harmless no-op — so it is
    /// usable ONLY for variant-level assertions, never for an operation that touches the
    /// fd or path.
    ///
    /// Its path is shared by every caller, so a test asserting on LOG RECORDS must not use
    /// it: `log_capture` is process-wide, trials can overlap (`--nocapture` with
    /// `--test-threads` > 1), and records from a concurrent sibling would be indistinguishable from its own. Such a test
    /// names its own leaf through [`for_test_at`](Self::for_test_at).
    pub(crate) fn placeholder_for_test() -> CgroupLeaf {
        CgroupLeaf::for_test_at(PathBuf::from("/nonexistent/cosca-cgroup-placeholder"))
    }

    /// Test-only leaf pointing at `leaf_path`, which a test shapes with ordinary files and
    /// directories. Every operation that reads or writes the leaf path (`hard_kill`,
    /// `take_placement`, `Drop`) then runs for real against the kernel's own errnos, on any
    /// Linux host and without a cgroupfs. It has no `cgroup.procs` fd.
    pub(crate) fn for_test_at(leaf_path: PathBuf) -> CgroupLeaf {
        let dir = LeafDir::open_for_test(&leaf_path);
        CgroupLeaf {
            watch: Box::new(Watcher::new(
                DrainWatch::arm(&dir).expect("arm a test leaf's drain watch"),
                dir.name().to_os_string(),
            )),
            dir,
            leaf_path,
            procs_fd: None,
            report: Some(ReportChannel::new().expect("open a placement-report channel")),
            entered: false,
            cgroup_path: None,
            abandoned: false,
            armed: AtomicBool::new(true),
            killed: std::sync::Arc::new(AtomicBool::new(false)),
            watched: None,
            placed: super::PlacedAtRemoval::default(),
            kill_attempt_failed: AtomicBool::new(false),
        }
    }

    /// Give a test leaf the unified-hierarchy path `/proc/<pid>/cgroup` prints for it.
    pub(crate) fn set_cgroup_path_for_test(&mut self, path: String) {
        self.cgroup_path = Some(path);
    }

    /// The record of the watched front's place, as the leaf's subtrees read it.
    pub(crate) fn placed_for_test(&self) -> super::PlacedAtRemoval {
        self.placed.clone()
    }

    /// Whether the leaf still holds its `cgroup.procs` fd or its report channel.
    pub(crate) fn holds_spawn_resources(&self) -> bool {
        self.procs_fd.is_some() || self.report.is_some()
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        self.tear_down(&mut NoWarn);
    }
}

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// What [`Drop`] does, with `warn` for each wait for the drain; `Drop` does nothing after it.
    fn tear_down(&mut self, warn: &mut dyn TeardownWarn) {
        // The pump the leaf owns stops and is joined before anything else: the teardown below
        // uses the watch itself.
        self.watch.stop_pump();
        self.procs_fd = None;
        // Before the verdict — a spawn that failed, maybe after its fork — end the exchange.
        if self.report.is_some() {
            self.abandon_without_child(warn);
        }
        if std::mem::replace(&mut self.abandoned, true) {
            return;
        }
        // Remove the leaf. If still occupied (e.g. hard_kill not yet called), fire cgroup.kill,
        // wait for the leaf to drain, then retry — but only if the child entered it: a final
        // report other than `Placed` proves nothing of the child's is there. A leaf that outlives
        // the removal is reported.
        let Err(first) = self.rmdir_leaf() else {
            return;
        };
        // `Drop` kills only when the child entered the leaf and it is still armed:
        //
        // | entered | armed | killed | Drop                                                                        |
        // |---------|-------|--------|-----------------------------------------------------------------------------|
        // | true    | true  | –      | rmdir; if it fails, cgroup.kill, drain, sweep, rmdir                        |
        // | true    | false | true   | rmdir; if it fails, re-fire cgroup.kill, wait for the drain, sweep, rmdir   |
        // | true    | false | false  | rmdir; if `populated 0` already, sweep, rmdir; else one rmdir, left running |
        // | false   | –     | –      | one rmdir: the child never entered the leaf                                 |
        if !self.child_entered() {
            if !removed_after_drain(&first) {
                warn_leaf_left_behind(
                    &self.leaf_path,
                    format_args!("rmdir failed ({first}); cgroup.kill not written: nothing of the child's is in it"),
                );
            }
            return;
        }
        // Opted out (see `disarm`): Drop itself never fires `cgroup.kill`. But opting out of
        // Drop's own teardown is not opting out of a kill the caller already did through
        // `kill_tree()`/`hard_kill()`: that kill is real and its drain is exactly as awaitable as
        // the armed path's. An `ENOENT` or `ENODEV` from the first `rmdir` proves the leaf is
        // already gone ([`removed_after_drain`]). Otherwise, a tree the caller killed has not
        // drained yet (`cgroup.kill` is asynchronous) — wait for it, then retry, as the armed path
        // does. A tree left running (never killed) keeps its leaf by request, with no retry.
        if !self.armed.load(Ordering::Relaxed) {
            if removed_after_drain(&first) {
                return;
            }
            if self.killed.load(Ordering::Relaxed) {
                // A stale `killed` flag must not make this wait forever: re-fire the kill before
                // waiting on its drain. An occupant that migrated in after the first kill was
                // never targeted, and on a kernel before 6.14 a process that forked while that
                // kill was in flight could escape it (`cgroup: fix race between fork and
                // cgroup.kill`, Linux 6.14) — either way, `drain_and_remove(None, ..)` re-runs
                // `hard_kill()` first, exactly as the armed path's own kill-then-wait does.
                self.drain_and_remove(
                    None,
                    "after an explicit kill through a handle that opted out of Drop's own teardown",
                    warn,
                );
                return;
            }
            // Never killed: the caller asked for this tree to be left running, and Drop honors
            // that — it does not kill. But "left running" and "already exited on its own" are
            // different questions: a leaf whose `cgroup.events` already reads `populated 0` has
            // nothing left to wait for, so its empty child cgroups are worth one sweep and one
            // more `rmdir`, exactly as a killed leaf's are, before anything is reported. A leaf
            // that is still populated keeps the old single-rmdir, debug-only behaviour — the
            // caller asked for this, so it is not a leak.
            match self.drain_now() {
                Ok(crate::containment::TreeDrain::AllMembersExited) => {
                    self.sweep_and_retry_rmdir("after a caller-opted-out tree exited on its own");
                }
                // Still populated (or unreadable): the tree was never killed. If the caller's own
                // kill_tree()/hard_kill() had actually been attempted and failed, that is not the
                // "opted out and left running" case this leaf's own doc promises — it is a
                // mechanism failure, reported exactly as loudly as the armed path's own kill
                // failure is.
                _ if self.kill_attempt_failed.load(Ordering::Relaxed) => {
                    warn_leaf_left_behind(
                        &self.leaf_path,
                        format_args!(
                            "rmdir failed ({first}); its cgroup.kill failed, so the tree that \
                             opted out of Drop's own teardown is still running"
                        ),
                    );
                }
                _ => {
                    log::debug!(
                        "cgroup leaf {} is left behind for a tree that opted out of teardown ({first})",
                        self.leaf_path.display()
                    );
                }
            }
            return;
        }
        // Armed: kill through the leaf, wait for it to drain, and only then remove it. A leaf
        // that is already gone left nothing behind.
        if !removed_after_drain(&first) {
            self.drain_and_remove(None, "after its handle's teardown", warn);
        }
    }
}

/// How an abandoned spawn's child ended up (see [`CgroupLeaf::abandon_before_verdict`]).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Abandoned {
    /// The child's teardown collected it: nothing of it is owed more. Says what became of it.
    Ended(ChildFate),
    /// The teardown of the child left it uncollected (its kill refused and it running, a wait or
    /// look that failed). Says what the teardown found: its clause, for the caller's one warn,
    /// which the failed spawn's label leads, and what its warn asserts, for the caller to log
    /// through [`Left::warn`].
    Uncollected(Left),
    /// The child is an elevation front, which was sent no signal of its own (see
    /// [`CgroupLeaf::abandon_before_verdict`]), and this is what became of it.
    Front(crate::child::spawn::FrontFate),
}

#[cfg(target_os = "linux")]
impl Abandoned {
    /// The answer for a child torn down through its pidfd as `torn` says. A child the teardown
    /// collected is `Ended`, and the teardown's clause is said as a failed spawn's. One it left
    /// uncollected is [`Uncollected`](Abandoned::Uncollected), with the clause as the one warn the
    /// caller logs, and the teardown's verdict. `why`, what the abandonment found wrong on the way,
    /// leads that one warn, or is logged on its own if the teardown has none.
    fn of_teardown(torn: HandleTeardown, why: &mut crate::child::spawn::Diagnosis) -> Abandoned {
        match torn.uncollected() {
            Ok(mut left) => {
                left.clause = why.fold(&left.clause);
                Abandoned::Uncollected(left)
            }
            Err(collected) => Abandoned::Ended(collected.say_as_failed_spawn(why).fate),
        }
    }
}

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// End the exchange of a spawn that failed before its verdict (see the module's contract),
    /// and answer for its `child`: kill it, kill through the leaf if it entered, reap it, and
    /// remove the leaf.
    ///
    /// Idempotent: the channel is taken once, and `Drop` does nothing after it.
    ///
    /// `child` is the pidfd the spawn's handshake holds for the child, with what the handshake
    /// knows became of it ([`Past`]). The leaf is its one owner from here. A spawn path that
    /// still holds its child takes the verdict first, so only a spawn whose child no handle owns
    /// reaches this: tokio drops a child it forked and then failed to set up, neither killed nor
    /// reaped. A spawn that has no child to give (`std` collected it, or none was forked) ends
    /// through [`abandon_without_child`](Self::abandon_without_child).
    ///
    /// A child that exec'd outside the leaf is killed as the process group it leads first
    /// ([`kill_group_outside_leaf`]). Then, whatever the child, the leaf is killed through if the
    /// child entered it (the write is retried once, before the child is looked at), the child is torn down (a kill its pidfd refuses is reaped if the leaf's
    /// kill reached it), and only then is the leaf removed: a child that entered but whose report
    /// the shut beat is still in the leaf until it is gone. A leaf whose id cannot be read places
    /// the child through `/proc`.
    ///
    /// A child that is an elevation `front` (see [`crate::elevation::front`]) is sent no signal of
    /// its own, which would orphan its elevated program: it is looked at instead, and waited for
    /// if the leaf's kill reached it.
    ///
    /// `warn` is for the wait for the leaf's drain and for the child's exit.
    pub(crate) fn abandon_before_verdict(
        &mut self,
        front: bool,
        (pidfd, past): (OwnedFd, Past),
        warn: &mut dyn TeardownWarn,
    ) -> Abandoned {
        let Some(received) = self.shut_exchange() else {
            debug_assert!(false, "the leaf answers for a child once");
            return Abandoned::Ended(ChildFate::Unknown);
        };
        let owned = OwnedChild::new(Box::new(LinuxProcess::new(received.pid, pidfd)));
        // What the abandonment finds wrong on the way, owed to the event's one warn.
        let mut why = crate::child::spawn::Diagnosis::default();
        // A child that never named itself is no front. Only a child that reported goes on to
        // `exec`: one that named itself and sent no report never runs the program, and is answered
        // as any child.
        let front_pid = received.pid.filter(|_| front && received.report.is_some());
        if let Some(pid) = front_pid {
            self.watch_front(pid);
        } else if let (Some(pid), Some(PlacementReport::WriteFailed(_))) = (received.pid, received.report) {
            if let Some(refused) = kill_group_outside_leaf(&owned, pid) {
                why.add(refused);
            }
        }
        // A kill through the leaf can reach something only if the child entered it. An id that
        // cannot be read leaves the subtree to place a task through `/proc`.
        let subtree = self.entered.then(|| {
            self.subtree().unwrap_or_else(|e| {
                log::debug!("cgroup v2: an abandoned spawn's leaf subtree cannot be read ({e}); placing by /proc");
                self.subtree_with(None)
            })
        });
        let killed = self.kill_entered();
        let tree = subtree.as_ref().map(|subtree| subtree as &dyn Reach);
        // The leaf stays until the child is gone: a child that entered it but whose report the shut
        // beat is not counted entered, and its leaf cannot be removed while it runs.
        let abandoned = if front_pid.is_some() {
            let (fate, torn) = look_at_failed_spawn_front(&owned, None, Ok(tree), Disposition::Leave, warn.due());
            HandleTeardown::new(torn, Expect::of(&owned, past)).say_as_failed_spawn(&mut why);
            Abandoned::Front(fate)
        } else {
            let kill = Kill {
                disposition: Disposition::Leave,
                tree,
            };
            Abandoned::of_teardown(tear_down_expecting(&owned, None, kill, past, warn.due()), &mut why)
        };
        self.remove_abandoned(killed, warn);
        abandoned
    }

    /// End the exchange of a spawn that has no child to give the leaf (see
    /// [`abandon_before_verdict`](Self::abandon_before_verdict)): kill through the leaf if the
    /// child entered it, and remove the leaf. Nothing is sent to the child, which nothing here
    /// holds. Answers whether the child sent its intent, naming a process that may have been
    /// forked and, if `std` did not collect it, left unreaped.
    ///
    /// Idempotent: the channel is taken once, and `Drop` does nothing after it.
    pub(crate) fn abandon_without_child(&mut self, warn: &mut dyn TeardownWarn) -> bool {
        let Some(received) = self.shut_exchange() else {
            return true;
        };
        let killed = self.kill_entered();
        self.remove_abandoned(killed, warn);
        received.pid.is_some()
    }

    /// Takes and shuts the report channel, and records whether the child entered the leaf: what an
    /// abandonment starts with. `None` once an abandonment has done it.
    fn shut_exchange(&mut self) -> Option<Received> {
        let channel = self.report.take()?;
        self.procs_fd = None;
        self.abandoned = true;
        let received = channel.shut();
        self.entered = received.placement() == PlacementReport::Placed;
        Some(received)
    }

    /// Kills through the leaf if the child entered it, once more if the first write failed, as the
    /// removal does for a kill not yet made: `None` if there was none to make, else what the last
    /// write answered. It is made before anything looks at the child, so a look that asks whether
    /// the kill landed ([`Subtree`]) reads the retry's answer, and the removal does not kill again.
    fn kill_entered(&self) -> Option<Result<(), crate::error::Error>> {
        self.entered.then(|| self.hard_kill().or_else(|_| self.hard_kill()))
    }

    /// Removes the abandoned leaf: killed through, if `killed` holds the kill's answer, and
    /// otherwise holding nothing of the child's.
    fn remove_abandoned(&mut self, killed: Option<Result<(), crate::error::Error>>, warn: &mut dyn TeardownWarn) {
        match killed {
            Some(killed) => self.remove_killing_through(killed, "after its spawn was abandoned", warn),
            None => self.remove_holding_nothing(),
        }
    }

    /// Remove a leaf its child entered: killed through, drained, its empty child cgroups removed,
    /// then removed once, a failure reported (see [`drain_and_remove`](Self::drain_and_remove)). `killed`
    /// is the answer of the caller's own kill through it; `context` says what removal this
    /// is, for the report of a leaf left behind; `warn`, for the wait for the drain.
    fn remove_killing_through(
        &mut self,
        killed: Result<(), crate::error::Error>,
        context: &str,
        warn: &mut dyn TeardownWarn,
    ) {
        match self.rmdir_leaf() {
            Ok(()) => {}
            Err(e) if removed_after_drain(&e) => {}
            Err(_) => self.drain_and_remove(Some(killed), context, warn),
        }
    }

    /// [`remove_killing_through`](Self::remove_killing_through) after an `rmdir` that failed.
    ///
    /// Kills through the leaf unless `killed` holds the answer of a kill the caller made (a failed
    /// one is reported), waits however long the drain takes, with `warn`
    /// ([`wait_drained_then_warn`](Self::wait_drained_then_warn)), removes the
    /// leaf's child cgroups, and makes one more `rmdir`. Any failure of that `rmdir` is final and
    /// reported: after the drain and the sweep, an `EBUSY` means something another party did
    /// since ([`LEFT_BEHIND_CAUSES`]), which another attempt would only make rarer, never
    /// impossible.
    fn drain_and_remove(
        &mut self,
        killed: Option<Result<(), crate::error::Error>>,
        context: &str,
        warn: &mut dyn TeardownWarn,
    ) {
        if let Err(e) = killed.unwrap_or_else(|| self.hard_kill()) {
            return warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed {context}; cgroup.kill failed ({e})"),
            );
        }
        if let Err(e) = self.wait_drained_then_warn(warn) {
            return warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed {context}; its drain could not be watched ({e})"),
            );
        }
        if let Err(e) = self.dir.remove_children() {
            return warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed {context}; a child cgroup could not be removed ({e})"),
            );
        }
        match self.rmdir_leaf() {
            Ok(()) => {}
            Err(e) if removed_after_drain(&e) => {}
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed ({e}) {context}, after its kill, drain and sweep: {LEFT_BEHIND_CAUSES}"),
            ),
            Err(e) => warn_leaf_left_behind(&self.leaf_path, format_args!("rmdir failed ({e}) {context}")),
        }
    }

    /// Remove a leaf [`drain_now`](Self::drain_now) already found at `populated 0` on its own —
    /// nothing was killed, so nothing needs waiting for. Removes the leaf's now-empty child
    /// cgroups and makes one more `rmdir`; any failure of that `rmdir` other than the leaf already
    /// being gone is reported, the same way [`drain_and_remove`](Self::drain_and_remove)'s own
    /// post-drain sweep is.
    fn sweep_and_retry_rmdir(&mut self, context: &str) {
        if let Err(e) = self.dir.remove_children() {
            return warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed {context}; a child cgroup could not be removed ({e})"),
            );
        }
        match self.rmdir_leaf() {
            Ok(()) => {}
            Err(e) if removed_after_drain(&e) => {}
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed ({e}) {context}, after its sweep: {LEFT_BEHIND_CAUSES}"),
            ),
            Err(e) => warn_leaf_left_behind(&self.leaf_path, format_args!("rmdir failed ({e}) {context}")),
        }
    }

    /// Remove an abandoned leaf that holds nothing of its child's: never killed through — an
    /// occupant is not cosca's — though its empty child cgroups are removed.
    fn remove_holding_nothing(&mut self) {
        let first = match self.rmdir_leaf() {
            Ok(()) => return,
            Err(e) if removed_after_drain(&e) => return,
            Err(e) => e,
        };
        let why = match self.dir.remove_children() {
            Ok(removed) if removed > 0 => match self.rmdir_leaf() {
                Ok(()) => return,
                Err(e) if removed_after_drain(&e) => return,
                Err(e) => format!("its child cgroups were removed, but rmdir failed again ({e})"),
            },
            Ok(_) => "cgroup.kill not written: nothing of the child's is in it".to_string(),
            Err(e) => format!("a child cgroup could not be removed ({e})"),
        };
        warn_leaf_left_behind(
            &self.leaf_path,
            format_args!("rmdir failed ({first}) after its spawn was abandoned; {why}"),
        );
    }
}

/// `SIGKILL` the process group the abandoned spawn's child `pid` leads, through its handle `child`:
/// a child that reported a failed placement exec'd outside the leaf, so what it forked is reached
/// only as that group. Through the child's pidfd, which names the group exactly while the group has a
/// member (Linux 6.9+); by `pid` only where the kernel refuses that, right after a check that the
/// child is still unreaped through its handle. A group that has no member left is logged at
/// `debug`. One the kill is refused or not sent to is returned, worded for the abandonment's one
/// warn, which the caller owes: its members may be left running. Sent before anything else is,
/// while the child is as it was.
#[cfg(target_os = "linux")]
fn kill_group_outside_leaf(child: &OwnedChild, pid: u32) -> Option<String> {
    let Some(pgid) = i32::try_from(pid).ok().filter(|pgid| *pgid > 0) else {
        debug_assert!(false, "a received pid names a process: {pid}");
        return None;
    };
    let sent = {
        let held = child.hold(pid);
        crate::containment::unix::send_to_group(pgid, nix::sys::signal::Signal::SIGKILL, &held.group())
    };
    let refused = match sent {
        Ok(Ok(())) => return None,
        Ok(Err(nix::errno::Errno::ESRCH)) => {
            log::debug!("cgroup v2: an abandoned spawn's child's process group {pid} has no member left");
            return None;
        }
        Ok(Err(e)) => e.to_string(),
        Err(e) => e.to_string(),
    };
    Some(format!(
        "cgroup v2: could not kill an abandoned spawn's child's process group {pid} ({refused}); its members may be left running"
    ))
}

/// What can make a leaf refuse its `rmdir` after its tree was killed and drained and its child
/// cgroups removed. cgroupfs refuses with `EBUSY` only while the leaf holds a process or a child
/// cgroup (`cgroup_destroy_locked`, kernel v6.12), and the VFS gives the same errno, before
/// cgroupfs is asked, for a directory something is mounted on.
#[cfg(target_os = "linux")]
pub(crate) const LEFT_BEHIND_CAUSES: &str = "another party did something since: a process moved into it after the \
     kill, a child cgroup created in it after the sweep, or a mount on it or on a child cgroup";

/// Report a `cosca-*` leaf cosca failed to remove. Nothing revisits a leaf by name, so this
/// record, made as it happens, is all a host accumulating them has to go on.
#[cfg(target_os = "linux")]
fn warn_leaf_left_behind(leaf_path: &Path, what_failed: fmt::Arguments<'_>) {
    log::warn!(
        "cgroup leaf {} was not removed: {what_failed}; it stays on this host until a cgroup \
         manager reaps it",
        leaf_path.display()
    );
}

/// Detect the current process's cgroup v2 path and create a leaf sub-cgroup
/// for containment. Returns the failing step on any failure, so the caller can
/// fall back to the process-group mechanism *and say why it had to*.
///
/// Failure conditions include: cgroup v2 not mounted at `/sys/fs/cgroup`,
/// current process not in a v2 cgroup (v1-only system), leaf directory not
/// writable (undelegated slice), or `cgroup.kill` absent (kernel < 5.14).
#[cfg(target_os = "linux")]
pub(crate) fn try_create_leaf() -> Result<CgroupLeaf, LeafError> {
    let cgroup_file = fs::read_to_string("/proc/self/cgroup").map_err(LeafError::ReadProcSelfCgroup)?;
    let rel_path = parse_v2_relative_path(&cgroup_file).ok_or_else(|| {
        let (line_count, controllers) = summarize_cgroup_controllers(&cgroup_file);
        LeafError::NoUnifiedLine {
            line_count,
            controllers,
        }
    })?;

    let mut leaf = create_leaf_under(&Path::new("/sys/fs/cgroup").join(rel_path.trim_start_matches('/')))?;
    let name = leaf.leaf_path.file_name().expect("a leaf has a name").to_string_lossy();
    leaf.cgroup_path = Some(format!("{}/{name}", rel_path.trim_end_matches('/')));
    Ok(leaf)
}

/// A new leaf's name: `cosca-<pid>-<seq>-<random>`. The pid and sequence number name the spawn for
/// a reader; the 64 random bits keep the name from recurring, as the pid and sequence do across
/// pid namespaces sharing a delegated parent and across processes reusing a pid. `rmdir` relies
/// on it: see [`LeafDir::rmdir`].
#[cfg(target_os = "linux")]
pub(crate) fn leaf_name() -> io::Result<String> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    Ok(format!(
        "cosca-{}-{seq}-{:016x}",
        std::process::id(),
        u64::from_ne_bytes(random)
    ))
}

/// Create a containment leaf directly under `current` — the supervisor's own cgroup in
/// production, and a temp directory in the tests that fail each precondition for real.
///
/// Every early return names its step: the caller degrades either way, but never silently.
#[cfg(target_os = "linux")]
pub(crate) fn create_leaf_under(current: &Path) -> Result<CgroupLeaf, LeafError> {
    let leaf_name = leaf_name().map_err(|source| LeafError::CreateLeafDir {
        path: current.join("cosca-*"),
        source,
    })?;
    let leaf_path = current.join(&leaf_name);

    let dir = LeafDir::create(current, &leaf_name).map_err(|source| LeafError::CreateLeafDir {
        path: leaf_path.clone(),
        source,
    })?;

    // Every failure past this point removes the leaf it just created, and reports one it could
    // not remove.
    let fail = |leaf_path: &Path, err: LeafError| -> LeafError {
        #[cfg(test)]
        if fault::take_force_occupy_before_unwind() {
            fs::create_dir(leaf_path.join("occupant")).expect("occupy the leaf");
        }
        if let Err(e) = dir.rmdir() {
            if !removed_after_drain(&e) {
                warn_leaf_left_behind(
                    leaf_path,
                    format_args!("rmdir failed ({e}) after its creation failed ({err})"),
                );
            }
        }
        err
    };

    // Require cgroup.kill (kernel ≥ 5.14); without it there is no atomic kill. A lookup that
    // fails is not an absent file, and is reported with its own errno.
    let kill_path = leaf_path.join("cgroup.kill");
    // Test-only fault seam: treat the leaf as kill-capable (take semantics — see `fault`).
    let kill_exists = || match rustix::fs::statat(dir.dir(), "cgroup.kill", rustix::fs::AtFlags::empty()) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(io::Error::from(e)),
    };
    #[cfg(test)]
    let kill_supported = if fault::take_force_kill_supported() {
        Ok(true)
    } else if let Some(errno) = fault::take_force_kill_check_errno() {
        Err(io::Error::from_raw_os_error(errno))
    } else {
        kill_exists()
    };
    #[cfg(not(test))]
    let kill_supported = kill_exists();
    match kill_supported {
        Ok(true) => {}
        Ok(false) => {
            return Err(fail(
                &leaf_path,
                LeafError::KillUnsupported {
                    path: leaf_path.clone(),
                },
            ))
        }
        Err(source) => {
            return Err(fail(
                &leaf_path,
                LeafError::CheckKill {
                    path: kill_path,
                    source,
                },
            ))
        }
    }

    // The report channel is opened before the procs fd so a failure here unwinds nothing but
    // the directory: a leaf whose child could not report its placement outcome would reopen
    // exactly the silence this module is reporting its way out of.
    let report = match ReportChannel::new() {
        Ok(r) => r,
        Err(e) => return Err(fail(&leaf_path, LeafError::OpenReportChannel(e))),
    };

    // Open cgroup.procs for writing, close-on-exec: the child's pre_exec write runs after fork
    // and before exec, where the fd is still open.
    //
    // Then move it to fd 3 or above. `open` takes the lowest free number, so with 0, 1 or 2
    // closed here the fd would share its number with one of the child's stdio slots, which std
    // `dup2`s into place before any pre_exec runs: the placement write would land in the
    // caller's stdio target instead, and report a placement that never happened.
    let procs_path = leaf_path.join("cgroup.procs");
    let procs_fd = dir
        .open("cgroup.procs", rustix::fs::OFlags::WRONLY)
        .and_then(crate::above_stdio::above_stdio);
    let procs_fd = match procs_fd {
        Ok(fd) => fd,
        Err(source) => {
            return Err(fail(
                &leaf_path,
                LeafError::OpenProcs {
                    path: procs_path,
                    source,
                },
            ))
        }
    };

    // Armed now, so that no teardown of this leaf can later find itself without a watch.
    let watch = match DrainWatch::arm(&dir) {
        Ok(Some(watch)) => watch,
        // The leaf has no `cgroup.events`: another party removed it since the `mkdir`.
        Ok(None) => {
            return Err(fail(
                &leaf_path,
                LeafError::WatchDrain {
                    path: leaf_path.join("cgroup.events"),
                    source: io::Error::from_raw_os_error(libc::ENOENT),
                },
            ))
        }
        Err(source) => {
            return Err(fail(
                &leaf_path,
                LeafError::WatchDrain {
                    path: leaf_path.join("cgroup.events"),
                    source,
                },
            ))
        }
    };

    Ok(CgroupLeaf {
        leaf_path,
        dir,
        watch: Box::new(Watcher::new(Some(watch), leaf_name.clone().into())),
        procs_fd: Some(procs_fd),
        report: Some(report),
        entered: false,
        cgroup_path: None,
        abandoned: false,
        armed: AtomicBool::new(true),
        killed: std::sync::Arc::new(AtomicBool::new(false)),
        watched: None,
        placed: super::PlacedAtRemoval::default(),
        kill_attempt_failed: AtomicBool::new(false),
    })
}

/// The status an abandoned spawn's child exits with, from inside its hook.
#[cfg(target_os = "linux")]
pub(crate) const ABANDONED_EXIT: i32 = 125;

/// The placement hook a contained spawn registers: close the forked child's inherited copy of the
/// parent's end, then place the child (see [`place_self_in_cgroup_pre_exec`]).
///
/// A spawn the parent abandoned makes the child `_exit` here, with [`ABANDONED_EXIT`], instead of
/// returning an error to `std`. A child that never execs needs no error channel, and `std` would
/// write its error record to the number its channel had — which, once `std`'s spawn returned
/// early because two of fds 0–2 were closed, is one of the child's own stdio slots.
///
/// # Safety
/// As [`place_self_in_cgroup_pre_exec`], in a forked child only.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn placement_hook(procs_fd: RawFd, slot: ReportSlot) -> io::Result<()> {
    // Safety: the caller's guarantee: this is the forked child.
    unsafe { slot.close_parents_end() };
    #[cfg(test)]
    fault::die_if_at(fault::ChildDeath::BeforeIntent);
    // Safety: the caller's guarantee.
    match unsafe { place_self_in_cgroup_pre_exec(procs_fd, slot) } {
        // Safety: `_exit` is async-signal-safe, and runs nothing of this process's.
        Err(e) if e.raw_os_error() == Some(libc::ECANCELED) => unsafe { libc::_exit(ABANDONED_EXIT) },
        other => other,
    }
}

/// Place the calling process into the pre-created cgroup leaf by writing `"0"`
/// to `procs_fd`, then close the fd so it does not propagate to grandchildren.
///
/// Called inside a `pre_exec` closure (post-fork, pre-exec), whose `Err` aborts the spawn. It is
/// the child's half of the placement exchange (see the module's contract): it sends its intent,
/// makes the write, and sends its report.
///
/// A failed write (e.g. `EBUSY` when the supervisor's cgroup is itself a leaf — the "no internal
/// processes" rule) returns `Ok`: the child proceeds in the process group already set up, and the
/// parent degrades on the report. So does a parent that decided without the exchange: the child
/// then skips whatever of it is left. `Err` is a spawn the parent abandoned (`ECANCELED`), or a
/// message that could not be sent: a parent still waiting for it would misread the child for its
/// whole life, so the spawn fails instead.
///
/// # Safety
/// Must be called only from a `pre_exec` closure. `procs_fd` must be a valid,
/// open, writable fd in the child process, and `slot`'s channel must still be open.
/// Async-signal-safe: raw `libc` syscalls, no allocation, no format strings.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn place_self_in_cgroup_pre_exec(procs_fd: RawFd, slot: ReportSlot) -> io::Result<()> {
    static ZERO: &[u8] = b"0";
    let abandoned = || io::Error::from_raw_os_error(libc::ECANCELED);
    // The intent goes first, before the leaf is touched: a child the parent has abandoned never
    // enters it.
    // Safety: the caller guarantees the slot's channel is open.
    let intent = unsafe { slot.send_intent() };
    if !matches!(intent, Ok(Delivery::Queued)) {
        // Safety: procs_fd is valid; close is async-signal-safe.
        unsafe { libc::close(procs_fd) };
        return match intent? {
            Delivery::Abandoned => Err(abandoned()),
            _ => Ok(()),
        };
    }
    #[cfg(test)]
    fault::die_if_at(fault::ChildDeath::BeforeReport);
    // Test-only fault seam: a write that returns this instead of writing (take semantics — see
    // `fault`), so a failed placement leaves the child out of the leaf, as a real one does.
    #[cfg(test)]
    let forced = fault::take_force_placement_write_result();
    // Safety: ZERO is a valid buffer; procs_fd is valid (caller guarantees).
    let write = || unsafe { libc::write(procs_fd, ZERO.as_ptr().cast(), ZERO.len()) };
    #[cfg(test)]
    let ret = forced.unwrap_or_else(write);
    #[cfg(not(test))]
    let ret = write();
    // Read errno before `close`, which is free to clobber it.
    // Safety: errno is this thread's own; `__errno_location` is async-signal-safe.
    let errno = if ret == -1 {
        unsafe { *libc::__errno_location() }
    } else {
        0
    };
    // Always close the fd — even on error — so it does not propagate to children.
    // Safety: procs_fd is valid; close is async-signal-safe.
    unsafe { libc::close(procs_fd) };
    let report = match ret {
        // Only the whole write is a placement.
        _ if ret == ZERO.len() as isize => REPORT_PLACED,
        // `write(2)` only ever sets a positive errno, but a report of -1 means "placed", so a
        // nonsensical value is mapped to EIO rather than read back as a fabricated placement.
        -1 if errno > 0 => errno,
        // A write that returned without writing (0) sets no errno.
        _ => libc::EIO,
    };
    // Safety: the caller guarantees the slot's channel is open.
    match unsafe { slot.send_report(report) }? {
        Delivery::Abandoned => Err(abandoned()),
        Delivery::Queued | Delivery::Decided => Ok(()),
    }
}

#[cfg(all(feature = "tokio", target_os = "linux"))]
#[path = "leaf/release.rs"]
mod release;

#[cfg(target_os = "linux")]
#[path = "leaf/slow_drain.rs"]
mod slow_drain;
#[cfg(target_os = "linux")]
pub(crate) use slow_drain::*;

#[cfg(all(test, target_os = "linux"))]
#[path = "leaf/group_kill_tests.rs"]
mod group_kill_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "leaf/of_teardown_tests.rs"]
mod of_teardown_tests;

#[cfg(test)]
#[path = "leaf_tests.rs"]
mod leaf_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "leaf_state_tests.rs"]
mod leaf_state_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "placement_reuse_tests.rs"]
mod placement_reuse_tests;

#[cfg(all(test, target_os = "linux", feature = "tokio"))]
#[path = "leaf/slow_teardown_tests.rs"]
mod slow_teardown_tests;

#[cfg(all(test, target_os = "linux", feature = "tokio"))]
#[path = "leaf/abandon_drain_tests.rs"]
mod abandon_drain_tests;
