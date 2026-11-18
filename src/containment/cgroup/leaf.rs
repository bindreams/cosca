//! The leaf itself: creating it, placing the child in it, deciding membership, killing
//! through it and removing it.

use std::fmt;
use std::io;
use std::path::PathBuf;

use super::*;
use crate::containment::tree_kill::Unnamed;
use crate::containment::SendOutcome;
use crate::identity::ProcessId;

#[cfg(target_os = "linux")]
use crate::child::spawn::fork_exec::Reporter;
#[cfg(target_os = "linux")]
use std::fs::File;
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
            log::debug!(
                "cgroup leaf: whether pid {pid} had exited {when} its state was read is unknown: {report}",
                report = crate::error::Report(&e)
            );
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
            log::debug!(
                "cgroup leaf: pid {pid}'s state is unknown: {report}",
                report = crate::error::Report(&why)
            );
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
    /// The pid exited, or `hidepid` hides it: [`pid_file::read`](crate::identity::pid_file::read)
    /// answered [`Exited`](crate::identity::pid_file::ReadOutcome::Exited) or
    /// [`Hidden`](crate::identity::pid_file::ReadOutcome::Hidden). The error is why.
    Skipped(std::io::Error),
    /// `<pid>/stat` could not be read: the `openat2` was refused. The error says what cosca requires.
    Refused(crate::error::Error),
    /// `<pid>/stat` could not be read, for another reason: the failure as
    /// [`Unreadable::into_cause`](crate::identity::pid_file::Unreadable::into_cause) makes it, with the
    /// pid's own `EPERM` beside a failed re-check.
    Unreadable(crate::error::Error),
    /// `<pid>/stat` has no state field.
    Unparsable(Vec<u8>),
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for StateUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::View(_) => f.write_str("the /proc view cannot be relied on"),
            Self::Skipped(_) => f.write_str("its stat is not there for us"),
            Self::Refused(_) => f.write_str("its stat read was refused"),
            Self::Unreadable(_) => f.write_str("its stat could not be read"),
            Self::Unparsable(stat) => write!(f, "its stat has no state field: {:?}", String::from_utf8_lossy(stat)),
        }
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for StateUnknown {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::View(why) => Some(why),
            Self::Skipped(e) => Some(e),
            Self::Refused(e) => Some(e),
            Self::Unreadable(e) => Some(e),
            Self::Unparsable(_) => None,
        }
    }
}

/// `pid`'s state letter. Any failure, the pidfd-bracketed read's included, means the state is
/// unknown.
///
/// The only consumer, [`proc_state`], logs why at `debug` and drops no member: an unknown state only
/// leaves a failed placement undiagnosed. So the failure of the `stat` read stays as
/// [`pid_file::read`](crate::identity::pid_file::read) classed it.
#[cfg(target_os = "linux")]
fn read_proc_state(kernel: &dyn crate::identity::Kernel, pid: u32) -> Result<char, StateUnknown> {
    use crate::identity::pid_file::{self, ReadOutcome};

    let proc_dir = crate::identity::proc_view_with(kernel)
        .into_dir()
        .map_err(StateUnknown::View)?;
    match pid_file::read(kernel, &proc_dir, pid, "stat") {
        Ok(ReadOutcome::Read(stat)) => state_from_stat(stat),
        Ok(ReadOutcome::Exited(e) | ReadOutcome::Hidden(e)) => Err(StateUnknown::Skipped(e)),
        Ok(ReadOutcome::Refused(refusal)) => Err(StateUnknown::Refused(
            refusal.unsupported(format!("reading pid {pid}'s stat")),
        )),
        Err(unreadable) => Err(StateUnknown::Unreadable(unreadable.into_cause())),
    }
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

/// A member [`CgroupLeaf::list_members`] found in the leaf's subtree: its identity, and the cgroup id
/// that placed it there (`None` where `/proc` did, or the kernel gives no id), which a check made
/// after a kill compares with the member's id then, so that a member that has not moved is not
/// walked for.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Listed {
    pub(crate) id: ProcessId,
    seen: Option<u64>,
}

/// A live leaf sub-cgroup created for a single spawned process tree. See
/// [`place_self_in_cgroup`] for the placement write's contract.
///
/// [`CgroupLeaf::take_placement`] releases the `cgroup.procs` fd and takes the placement verdict: the
/// child needs the fd only until its `exec`.
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
    /// The kernel its spawn started with, which every read by a task's number asks (`/proc`, a pidfd):
    /// a clone of the child box's, since a failed spawn tears the leaf down before any box exists and
    /// `Child` drops its box before its tree.
    pub(super) kernel: crate::identity::SpawnKernel,
    /// The leaf's drain watch, held from creation so that no wait on it ever lacks one. Read by
    /// the pump this watcher owns, which broadcasts each change to every wait.
    /// Boxed: its pump would make every `Mechanism` as large as a leaf.
    watch: Box<Watcher>,
    /// Pre-opened `cgroup.procs` fd for the `pre_exec` write. Close-on-exec: the write happens
    /// between `fork` and `exec`, and no program this process starts may inherit it. Numbered
    /// 3 or above, so it never shares a number with the child's stdio. `None` once the
    /// placement verdict is taken.
    procs_fd: Option<OwnedFd>,
    /// What the spawn read of the child's placement report ([`record_placement`](Self::record_placement)):
    /// [`NotReported`](PlacementReport::NotReported) until it records one. `Some` until the placement
    /// verdict is taken.
    pub(super) verdict: Option<PlacementReport>,
    /// Whether the child may be in the leaf (it reported entering it, or the spawn could not read its
    /// report), recorded when the verdict is taken: the leaf is killed through unless it is false.
    pub(super) entered: bool,
    /// Whether `entered` rests on an unreadable report rather than the child's own: the child may be
    /// outside the leaf, in its process group, so the leaf is not its whole containment.
    pub(super) unproven: bool,
    /// The leaf's unified-hierarchy path, as `/proc/<pid>/cgroup` prints it. `None` for a leaf
    /// created outside the cgroup filesystem.
    cgroup_path: Option<String>,
    /// Whether the leaf is already dealt with, so `Drop` has nothing left to do: the spawn was
    /// abandoned before its verdict, or it was torn down.
    pub(super) abandoned: bool,
    /// Whether the caller still wants cosca to manage the tree. Cleared by `disarm`, for
    /// `detach()` and `kill_on_drop(false)`. `Drop` kills only while this and `entered` both hold.
    armed: AtomicBool,
    /// What [`hard_kill`](Self::hard_kill)'s `cgroup.kill` writes answered. A teardown of the leaf
    /// reads it, and writes only if none was made. A disarmed `Drop` reads it to tell a tree the
    /// caller killed, whose leaf has not drained yet, from one left running, and a kill that failed
    /// from one never made. [`terminate`](Self::terminate) does not set it: a SIGTERM can be caught.
    kill: std::sync::Arc<KillRecord>,
    /// The elevation front this leaf's child is, by pid, whose place is recorded in `placed` before
    /// each `rmdir` (see [`watch_front`](Self::watch_front)).
    watched: Option<u32>,
    /// Where the watched front was when the leaf was last about to be removed, shared with the
    /// leaf's [`Subtree`]s.
    placed: super::PlacedAtRemoval,
    /// Whether this leaf's own `rmdir` removed the directory. A later removal is a no-op: it would
    /// read the place of a front in a leaf that is gone, and could clear what `placed` recorded.
    removed: AtomicBool,
    /// This long into each of its waits for the leaf's drain, a teardown of the leaf (its [`Drop`],
    /// or its abandonment) warns once and keeps waiting (principle 2); `None`: it does not. The
    /// spawn's policy sets it when the leaf is created.
    teardown_warn_after: Option<std::time::Duration>,
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
    pub(crate) fn holds_verdict_to_take(&self) -> bool {
        self.verdict.is_some()
    }

    /// Records what the spawn read of the child's placement report. Only before the verdict is taken
    /// (a later one is a breach: asserted in debug builds, ignored otherwise); the first report stands.
    pub(crate) fn record_placement(&mut self, report: PlacementReport) {
        let Some(verdict) = self.verdict.as_mut() else {
            debug_assert!(
                false,
                "a placement report ({report}) was recorded after its verdict was taken"
            );
            return;
        };
        if *verdict == PlacementReport::NotReported {
            *verdict = report;
        }
    }

    /// Takes `report` as the verdict's answer: whether the child may be in the leaf, and whether that
    /// is only because the report could not be read.
    fn settle(&mut self, report: PlacementReport) {
        self.entered = matches!(report, PlacementReport::Placed | PlacementReport::Unknown(_));
        self.unproven = matches!(report, PlacementReport::Unknown(_));
    }

    /// Returns the raw `cgroup.procs` fd for the in-child placement step. Only before the
    /// placement verdict is taken.
    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs_fd.as_ref().expect(RELEASED).as_raw_fd()
    }

    /// Whether the child may be in this leaf, once the verdict is taken: it reported entering it, or its
    /// report could not be read.
    pub(crate) fn child_entered(&self) -> bool {
        debug_assert!(self.verdict.is_none(), "the verdict is not taken yet");
        self.entered
    }

    /// Whether the child reported entering this leaf, so that the leaf is its whole containment, once
    /// the verdict is taken. `false` for a child whose report could not be read: it may be in its
    /// process group instead.
    pub(crate) fn child_proven_in(&self) -> bool {
        debug_assert!(self.verdict.is_none(), "the verdict is not taken yet");
        self.entered && !self.unproven
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

    /// Whether `child` entered this leaf: `Ok` when its own write into it succeeded.
    ///
    /// Used once, post-spawn (parent side), over what the spawn recorded
    /// ([`record_placement`](Self::record_placement)). The child's report is the verdict:
    /// `cgroup.procs` lists only live tasks, so a placed child that has already exited reads back
    /// absent from it. Only a child that reported no successful write has `cgroup.procs` and its state
    /// read, to diagnose why — see [`NotPlaced`].
    ///
    /// Taking the verdict closes the `cgroup.procs` fd: nothing needs it after the child's `exec`,
    /// and otherwise every live contained child would hold one fd in the supervisor.
    pub(crate) fn take_placement(&mut self, child: crate::containment::ChildHandle<'_>) -> Result<(), NotPlaced> {
        #[cfg(test)]
        fault::run_on_take_placement();
        let report = self.verdict.take().expect(RELEASED);
        self.procs_fd = None;
        self.settle(report);
        let report = match report {
            PlacementReport::Placed => return Ok(()),
            PlacementReport::NotReported => NotEntered::NotReported,
            PlacementReport::WriteFailed(errno) => NotEntered::WriteFailed(errno),
            PlacementReport::Unknown(errno) => NotEntered::Unknown(errno),
        };
        let path = self.leaf_path.join("cgroup.procs");
        let child_state = proc_state(&*self.kernel, child);
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
    pub(crate) fn subtree(&self) -> Result<Subtree, crate::error::Error> {
        #[cfg(test)]
        if let Some(errno) = fault::subtree_fails() {
            return Err(io::Error::from_raw_os_error(errno).into());
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
            std::sync::Arc::clone(&self.kill),
        )
    }

    /// The warn of this leaf's own waits for its drain, as its spawn's policy says.
    pub(crate) fn warn(&self) -> WarnAfter {
        WarnAfter(self.teardown_warn_after)
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
        match super::proc_names(&*self.kernel, path, pid, outside_if_live, false) {
            Ok(inside) => self.placed.record(pid, inside),
            Err(e) => {
                log::debug!(
                    "cgroup v2: {}'s place before its leaf's removal cannot be read ({report})",
                    crate::elevation::front::front_named(Some(pid)),
                    report = crate::error::Report(&e)
                );
                self.placed.clear();
            }
        }
    }

    /// Removes the leaf's directory, once: after a removal that succeeded, `Ok` without touching it.
    fn rmdir_leaf(&self) -> io::Result<()> {
        if self.removed.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.record_watched_place();
        #[cfg(test)]
        fault::record_leaf_step(|| {
            let events = self.dir.read("cgroup.events").unwrap_or_default();
            format!("rmdir {}", events.lines().next().unwrap_or("(no cgroup.events)"))
        });
        #[cfg(test)]
        let removed = match fault::run_rmdir_hook(&self.leaf_path) {
            Some(result) => result,
            None => self.dir.rmdir(),
        };
        #[cfg(not(test))]
        let removed = self.dir.rmdir();
        if removed.is_ok() {
            self.removed.store(true, Ordering::Relaxed);
        }
        removed
    }

    /// Hard-kill all processes in the cgroup via `cgroup.kill` (kernel ≥ 5.14).
    ///
    /// `Ok` means the kill was delivered, not that the members have exited yet (see
    /// [`wait_drained`](CgroupLeaf::wait_drained)): either the atomic kill fired, or the leaf was
    /// already gone ([`removed_after_drain`]), which is itself proof every member had exited —
    /// `rmdir` on a cgroup v2 leaf succeeds only once `populated` reads 0.
    ///
    /// Every other errno means the atomic kill did NOT happen — the tree may still be running
    /// (a delegated subtree whose `cgroup.kill` stopped being writable after a privilege drop,
    /// or a cgroupfs remounted `ro`). That is a teardown-mechanism failure and is returned, an
    /// [`Error::Containment`](crate::error::Error::Containment) over the kernel's error, the
    /// same way every sibling mechanism's is ([`Contains::send_kill`](crate::containment::Contains::send_kill)): a caller that reads
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
        let gone = written.as_ref().err().is_some_and(removed_after_drain);
        // Every answer is recorded here, a gone leaf's included: it is the teardown's one write.
        self.kill.record(match &written {
            Err(e) if !gone => Err(e),
            _ => Ok(()),
        });
        match written {
            Ok(()) => {
                #[cfg(test)]
                fault::record_leaf_step(|| "kill".to_string());
                #[cfg(test)]
                fault::run_after_kill_write();
                Ok(())
            }
            Err(_) if gone => {
                log::debug!("cgroup.kill: leaf {} is already gone", path.display());
                Ok(())
            }
            Err(e) => Err(crate::error::Error::Containment {
                detail: format!("the kernel refused the write of {}", path.display()),
                source: Some(crate::error::Error::io_cause(e)),
            }),
        }
    }

    /// Whether a `cgroup.kill` write on this leaf landed, or found the leaf gone, by any handle's
    /// teardown. A failed write after it does not undo it: the landed kill still bounds the leaf's
    /// drain. Every reader that asks whether a kill landed asks here.
    pub(crate) fn kill_landed(&self) -> bool {
        self.kill.landed()
    }

    /// The leaf's one `cgroup.kill` write per teardown: the answer of a write already made, landed
    /// or failed, else the answer of the write [`hard_kill`](Self::hard_kill) makes now. Every
    /// teardown of the leaf asks here.
    pub(crate) fn kill_unless_written(&self) -> KillAnswer {
        self.kill.answer().unwrap_or_else(|| {
            // The write records its answer, as the text of the OS error's whole chain, which every
            // teardown of the leaf reads: the writer words its failure as a later one does.
            _ = self.hard_kill();
            self.kill.answer().expect("`hard_kill` records its answer")
        })
    }

    /// The first step of the leaf's teardown, which [`Drop`] and an awaited teardown both take: the
    /// first `rmdir`, and, if the leaf is occupied, the `cgroup.kill` write ([`kill_unless_written`])
    /// when the child entered the leaf and it is armed. A leaf that is empty is removed and records
    /// no kill. The awaited teardown awaits the drain this kill bounds before it drops the leaf, so
    /// the drop finds it drained. `Err` is the `rmdir`'s failure; a failed write is the teardown's
    /// answer, which the drop reports.
    pub(crate) fn remove_else_kill(&self) -> io::Result<()> {
        let first = self.rmdir_leaf();
        if let Err(e) = &first {
            if !removed_after_drain(e) && self.child_entered() && self.armed.load(Ordering::Relaxed) {
                _ = self.kill_unless_written();
            }
        }
        first
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
                    #[cfg(test)]
                    crate::wait::block_probe::blocking(None, crate::wait::block_probe::WaitObject::Drain);
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
                    crate::wait::block_probe::blocking(
                        Some(at.saturating_duration_since(std::time::Instant::now())),
                        crate::wait::block_probe::WaitObject::Drain,
                    );
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
    /// on another clock (tokio's). `clock` is read once, after the first read of the leaf and before
    /// the listener, and only if that read found the leaf populated.
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
            Some(failure) => {
                let context = format!(
                    "the drain of cgroup leaf {} can no longer be watched: {}",
                    self.leaf_path.display(),
                    failure.words
                );
                Err(crate::error::Error::Io(crate::error::io_context_or_other(
                    context,
                    failure.cause.as_ref().map(crate::error::shared_io),
                )))
            }
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

    /// Send `signal` to every process listed in `cgroup.procs` that is still in the leaf.
    ///
    /// An already-gone leaf is `Ok`, on the same proof [`hard_kill`](Self::hard_kill) rests on
    /// ([`removed_after_drain`]): there is no member left to signal. The two halves must agree
    /// about one leaf — a caller doing terminate-then-kill would otherwise take an error from
    /// the graceful half and success from the hard one over the identical directory.
    ///
    /// Each listed pid is pinned by a pidfd, shown to be in the leaf (or under it) and still
    /// running, then signalled through the pidfd, so a pid that exited and was reused after the read
    /// is left alone. A member that leaves the leaf after that check still gets the signal: it is
    /// the process that was checked. A member that cannot be pinned or placed gets no signal and
    /// makes the call an error (see [`terminate_tree`](crate::Child::terminate_tree)); `cgroup.kill`
    /// still reaches it.
    ///
    /// A listed member that got no signal for any reason but its exit is logged at `warn`, naming
    /// the leaf and the pid, and makes the call an error once every member was tried:
    /// [`Error::Containment`](crate::error::Error::Containment) if a send failed, otherwise
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) for members that could not be
    /// pinned or placed, a listed pid `0` (a member in a pid namespace this process cannot see), or
    /// a `cgroup.procs` line that is no pid.
    ///
    /// [`NotSent`](SendOutcome::NotSent) is a `cgroup.procs` that could not be read: no member was
    /// listed, so nothing was sent. Past it the signal went out, and [`Sent`](SendOutcome::Sent) is what
    /// the sends found. Never [`RootExited`](SendOutcome::RootExited): the leaf looks at no walk.
    pub(crate) fn terminate(&self, signal: crate::signal::Signal) -> SendOutcome {
        let path = self.leaf_path.join("cgroup.procs");
        let content = match self.dir.read("cgroup.procs") {
            Ok(c) => c,
            Err(e) if removed_after_drain(&e) => {
                log::debug!("cgroup terminate: leaf {} is already gone", path.display());
                return SendOutcome::Sent(Ok(()));
            }
            Err(e) => return SendOutcome::NotSent(crate::error::Error::Io(e)),
        };
        #[cfg(test)]
        fault::run_after_procs_read();
        SendOutcome::Sent(self.terminate_listed(&content, signal))
    }

    /// [`terminate`](Self::terminate) for the members `procs` lists, in `cgroup.procs`' format.
    fn terminate_listed(&self, procs: &str, signal: crate::signal::Signal) -> Result<(), crate::error::Error> {
        use crate::error::Error;
        let mut pids = Vec::new();
        let mut unproven: Vec<Error> = Vec::new();
        for line in procs.lines() {
            match line.trim().parse::<u32>() {
                // A live member outside this process's pid namespace: it has no number here to
                // pin or signal.
                Ok(0) => unproven.push(Error::Unassessable {
                    detail: "pid 0: it is a member in a pid namespace this process cannot see".to_owned(),
                    source: None,
                }),
                Ok(pid) => pids.push(pid),
                Err(_) => unproven.push(Error::Unassessable {
                    detail: format!("cgroup.procs line {line:?} is no pid"),
                    source: None,
                }),
            }
        }
        if pids.is_empty() && unproven.is_empty() {
            return Ok(());
        }
        let subtree = self.listing_subtree();
        let mut failed: Vec<Error> = Vec::new();
        for pid in pids {
            match self.terminate_member(pid, &subtree, signal) {
                Ok(()) => {}
                Err(Unsignalled::Failed(unsent)) => failed.push(unsent),
                Err(Unsignalled::Unproven(unsent)) => unproven.push(unsent),
            }
        }
        if failed.is_empty() && unproven.is_empty() {
            return Ok(());
        }
        let leaf = self.leaf_path.display();
        let mut parts = Vec::new();
        if !failed.is_empty() {
            parts.push(format!("the {} failed for {}", signal.name(), failed.len()));
        }
        if !unproven.is_empty() {
            parts.push(format!(
                "{} could not be shown to be members, and were not signalled",
                unproven.len()
            ));
        }
        let detail = format!(
            "cgroup leaf {leaf}: listed members got no {}: {}",
            signal.name(),
            parts.join("; ")
        );
        // Each member says its own pid and cause: one is the call's `source`, and two or more are a
        // `Several`, the failed sends first.
        let any_failed = !failed.is_empty();
        let source = crate::error::Failures::collect(failed.into_iter().chain(unproven).map(std::sync::Arc::new))
            .map(crate::error::Failures::into_cause);
        let error = if any_failed {
            Error::Containment { detail, source }
        } else {
            Error::Unassessable { detail, source }
        };
        log::warn!("cgroup terminate: {}", crate::error::Report(&error));
        Err(error)
    }

    /// The one subtree a pass over the listed members places each of them in. Where the leaf's id
    /// cannot be read, the pidfd route places a member only by the id of a cgroup the listing's walk
    /// visited; `/proc` places any other.
    fn listing_subtree(&self) -> Subtree {
        self.subtree_with(match self.id() {
            Ok(id) => Some(id),
            Err(e) => {
                log::debug!(
                    "cgroup: leaf {}'s cgroup id cannot be read ({report}); its members are placed through /proc",
                    self.leaf_path.display(),
                    report = crate::error::Report(&e)
                );
                None
            }
        })
    }

    /// The members `cgroup.procs` lists now, in the leaf and in every cgroup under it, for the wait
    /// over a kill that follows. Each is pinned by its own pidfd, shown to be in the leaf through it,
    /// and its identity read from it, so a pid reused since `cgroup.procs` was read is not listed;
    /// the pidfd is then closed, so no descriptor is held per member. `root`, the root's pid, is left
    /// out: its owner waits for it. A leaf already gone has no member. A member that cannot be named,
    /// or the listing itself failing, is returned as an error saying its exit cannot be observed, with
    /// its pid where it has one; the kill goes ahead regardless.
    pub(crate) fn list_members(&self, root: Option<u32>) -> (Vec<Listed>, Vec<Unnamed>) {
        use crate::error::Error;

        let content = match self.dir.read("cgroup.procs") {
            Ok(c) => c,
            Err(e) if removed_after_drain(&e) => return (Vec::new(), Vec::new()),
            Err(e) => {
                let why = Error::Unassessable {
                    detail: format!(
                        "cgroup leaf {}: its members could not be listed before the kill, so their exit cannot be observed",
                        self.leaf_path.display()
                    ),
                    source: Some(Error::io_cause(e)),
                };
                return (Vec::new(), vec![Unnamed::nameless(why)]);
            }
        };
        // `cgroup.kill` reaches the cgroups under the leaf too, so their members are listed as well.
        let (nested, failure) = self.dir.nested_procs();
        let subtree = self.listing_subtree();
        let (mut members, mut unobserved) = (Vec::new(), Vec::new());
        if let Some(e) = failure {
            unobserved.push(Unnamed::nameless(Error::Unassessable {
                detail: format!(
                    "cgroup leaf {}: the cgroups under it could not all be listed before the kill, so the exit of \
                     their members cannot be observed",
                    self.leaf_path.display()
                ),
                source: Some(Error::io_cause(e)),
            }));
        }
        for line in content.lines().chain(nested.iter().map(String::as_str)) {
            match line.trim().parse::<u32>() {
                Ok(0) => unobserved.push(Unnamed::nameless(Error::Unassessable {
                    detail: "a member of the leaf in a pid namespace this process cannot see was killed, but its exit \
                             cannot be observed"
                        .to_owned(),
                    source: None,
                })),
                Ok(pid) if Some(pid) == root => {}
                Ok(pid) => match self.listed_member(pid, &subtree) {
                    Ok(Some(id)) => members.push(id),
                    Ok(None) => {}
                    Err(why) => unobserved.push(Unnamed::member(pid, why)),
                },
                Err(_) => unobserved.push(Unnamed::nameless(Error::Unassessable {
                    detail: format!("cgroup.procs line {line:?} is no pid, so that member's exit cannot be observed"),
                    source: None,
                })),
            }
        }
        (members, unobserved)
    }

    /// The listed `pid`, if it is a member of the leaf now: `None` for a pid that is gone or not in the
    /// leaf (it is no member the kill reaches).
    fn listed_member(&self, pid: u32, subtree: &Subtree) -> Result<Option<Listed>, crate::error::Error> {
        use std::os::fd::AsFd as _;

        use crate::error::Error;
        use crate::identity::Resolved;

        let pidfd = match pin_member(&*self.kernel, pid) {
            Ok(pidfd) => pidfd,
            Err(rustix::io::Errno::SRCH) => return Ok(None),
            Err(e) => return Err(Error::Io(io::Error::from_raw_os_error(e.raw_os_error()))),
        };
        let held = subtree.holds_seen(&*self.kernel, pid, Some(pidfd.as_fd()), None);
        let seen = match placed_or_exited(pidfd.as_fd(), held)? {
            PlacedOrExitedOutcome::Placed((true, seen)) => seen,
            _ => return Ok(None),
        };
        match ProcessId::of_held_with(&*self.kernel, pid, pidfd.as_fd()) {
            (Resolved::Found(id), _) => Ok(Some(Listed { id, seen })),
            (Resolved::Gone, _) => Ok(None),
            (Resolved::Unknown, cause) => Err(crate::identity::unqueryable(&format!("pid {pid}"), cause)),
        }
    }

    /// Of the `members` [`list_members`](Self::list_members) named before a `cgroup.kill` that landed,
    /// those the kill reached, which exit whatever their credentials, and the members whose place
    /// cannot be told, as errors saying their exit cannot be observed. Each is opened by identity and
    /// placed through its pidfd ([`Subtree::reached_by`]). One still in the leaf or under it was
    /// reached. One found outside is taken to have left before the kill: it is no part of the tree, so
    /// it is neither waited for nor, by this check, known to have been killed. One another process
    /// moved out after the kill reached it reads the same: it was sent `SIGKILL` and is not waited
    /// for (a stated limit, see [`Child::kill_tree`](crate::Child::kill_tree)). One already gone was in
    /// the tree and has exited: it is kept, and its wait ends at once.
    pub(crate) fn reached_by_kill(&self, members: Vec<Listed>) -> (Vec<ProcessId>, Vec<Unnamed>) {
        let subtree = self.listing_subtree();
        let (mut reached, mut unobserved) = (Vec::new(), Vec::new());
        for member in members {
            match kill_reached(&*self.kernel, &subtree, member) {
                Ok(true) => reached.push(member.id),
                Ok(false) => {}
                Err(why) => unobserved.push(Unnamed::member(member.id.pid(), why)),
            }
        }
        (reached, unobserved)
    }

    /// [`terminate`](Self::terminate)'s `signal` to the listed `pid`, if it is still a running
    /// member of the leaf. `Ok` once sent, or for a pid that is gone or not a running member, which
    /// it logs at `debug`; `Err` says why a pid that may be a member got none.
    fn terminate_member(&self, pid: u32, subtree: &Subtree, signal: crate::signal::Signal) -> Result<(), Unsignalled> {
        use std::os::fd::AsFd as _;
        let pidfd = match pin_member(&*self.kernel, pid) {
            Ok(pidfd) => pidfd,
            Err(rustix::io::Errno::SRCH) => {
                log::debug!("cgroup terminate: pid {pid} is gone; not signalled");
                return Ok(());
            }
            Err(e) => {
                return Err(Unsignalled::Unproven(crate::error::Error::of_member(
                    pid,
                    "it could not be pinned",
                    crate::error::Error::Io(std::io::Error::from(e)),
                    true,
                )))
            }
        };
        #[cfg(test)]
        fault::run_after_terminate_pin();
        // The exit check follows the read: a process still running after it held `pid` throughout,
        // so the read was its own and not a reused pid's.
        let held = subtree.holds(&*self.kernel, pid, Some(pidfd.as_fd()));
        let inside = match placed_or_exited(pidfd.as_fd(), held) {
            Ok(PlacedOrExitedOutcome::Placed(inside)) => inside,
            Ok(PlacedOrExitedOutcome::Exited(placement)) => {
                log::debug!(
                    "cgroup terminate: pid {pid} exited before it was placed ({report}); not signalled",
                    report = crate::error::Report(&placement)
                );
                return Ok(());
            }
            Err(e) => {
                return Err(Unsignalled::Unproven(crate::error::Error::of_member(
                    pid,
                    "it could not be placed",
                    e,
                    true,
                )))
            }
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
            Err(e) => {
                return Err(Unsignalled::Unproven(crate::error::Error::of_member(
                    pid,
                    "its exit could not be read",
                    crate::error::Error::Io(e),
                    true,
                )))
            }
        }
        match send_to_member(pidfd.as_fd(), pid, signal) {
            Ok(()) => Ok(()),
            Err(nix::errno::Errno::ESRCH) => {
                log::debug!("cgroup terminate: pid {pid} exited before its {}", signal.name());
                Ok(())
            }
            Err(e) => Err(Unsignalled::Failed(crate::error::Error::of_member(
                pid,
                &format!("the {} could not be sent", signal.name()),
                crate::error::Error::Io(std::io::Error::from(e)),
                false,
            ))),
        }
    }
}

/// Whether a `cgroup.kill` that landed reached the listed `member`: it is opened by identity and asked
/// of [`Subtree::reached_by`] through its pidfd, with the cgroup id it had when listed. One that is
/// gone was in the tree and has exited, so a wait finds nothing to wait on.
fn kill_reached(
    kernel: &dyn crate::identity::Kernel,
    subtree: &Subtree,
    member: Listed,
) -> Result<bool, crate::error::Error> {
    let pid = member.id.pid();
    let Some(os) =
        crate::os_process::open_with(kernel, member.id).map_err(crate::os_process::OpenFailure::into_open_error)?
    else {
        return Ok(true);
    };
    let pidfd = os.os_handle();
    match placed_or_exited(pidfd, subtree.reached_by(kernel, pid, Some(pidfd), member.seen))? {
        PlacedOrExitedOutcome::Placed(false) => {
            log::debug!(
                "cgroup kill: pid {pid} is outside the leaf after the kill, so it is taken to have left it before, \
                 is no part of the tree and is not waited for"
            );
            Ok(false)
        }
        PlacedOrExitedOutcome::Placed(true) | PlacedOrExitedOutcome::Exited(_) => Ok(true),
    }
}

/// How [`placed_or_exited`] went.
enum PlacedOrExitedOutcome<T> {
    /// The placement's answer.
    Placed(T),
    /// The placement failed with this error because the process exited and was reaped.
    Exited(crate::error::Error),
}

/// `Exited` if the placement of the process `pidfd` pins failed because the process exited and was
/// reaped since its pin, which leaves no place to read (`ENOENT` from `/proc`, `ESRCH` from
/// `PIDFD_GET_INFO`): its pidfd tells that apart. The error of one that failed while the exit cannot
/// be read either is an `Unassessable` whose source is both failures, the placement's first, as an
/// [`Error::Several`](crate::error::Error::Several).
fn placed_or_exited<T>(
    pidfd: std::os::fd::BorrowedFd<'_>,
    placed: Result<T, crate::error::Error>,
) -> Result<PlacedOrExitedOutcome<T>, crate::error::Error> {
    use crate::error::Error;
    match placed {
        Ok(placed) => Ok(PlacedOrExitedOutcome::Placed(placed)),
        Err(e) => match member_exited(pidfd) {
            Ok(true) => Ok(PlacedOrExitedOutcome::Exited(e)),
            Ok(false) => Err(e),
            Err(exited) => Err(Error::Unassessable {
                detail: "its placement and its exit could not be read".to_owned(),
                source: Some(
                    crate::error::Failures::new(std::sync::Arc::new(e), [Error::io_cause(exited)]).into_cause(),
                ),
            }),
        },
    }
}

/// A pidfd that pins the process `pid` names, opened through `kernel`, for [`CgroupLeaf::terminate`];
/// a test build lets a `fail_terminate` seam answer in its place.
fn pin_member(kernel: &dyn crate::identity::Kernel, pid: u32) -> rustix::io::Result<std::os::fd::OwnedFd> {
    #[cfg(test)]
    if let Some(errno) = fault::terminate_fails(fault::TerminateStep::Pin) {
        return Err(rustix::io::Errno::from_raw_os_error(errno));
    }
    rustix::process::Pid::from_raw(pid as i32)
        .ok_or(rustix::io::Errno::INVAL)
        .and_then(|raw| kernel.pidfd_open(raw, rustix::process::PidfdFlags::empty()))
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

/// [`CgroupLeaf::terminate`]'s `signal` to the member `pidfd` pins, and the kernel's answer. It goes
/// through the shared send, which a test build notes the route of. A test build lets a
/// `fail_terminate` seam answer in its place without sending.
fn send_to_member(pidfd: std::os::fd::BorrowedFd<'_>, pid: u32, signal: crate::signal::Signal) -> nix::Result<()> {
    use crate::containment::unix::{send_signal, Sys, Target};
    #[cfg(test)]
    if let Some(errno) = fault::terminate_fails(fault::TerminateStep::Send) {
        return Err(nix::errno::Errno::from_raw(errno));
    }
    send_signal(Target::LeafMember(pid), Sys::Pidfd(pidfd, 0), signal.as_nix())
}

/// Why [`CgroupLeaf::terminate`] sent a listed pid no signal: the error of that member, naming its
/// pid, with the error of the call that failed as its `source`.
enum Unsignalled {
    /// The send failed: a [`Containment`](crate::error::Error::Containment).
    Failed(crate::error::Error),
    /// Nothing showed the pid to be a running member, so it was not signalled: an
    /// [`Unassessable`](crate::error::Error::Unassessable).
    Unproven(crate::error::Error),
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
        CgroupLeaf::for_test_warning_after(leaf_path, None)
    }

    /// [`for_test_at`](Self::for_test_at) for a leaf whose spawn's policy warns `teardown_warn_after`
    /// into each wait for its drain.
    pub(crate) fn for_test_warning_after(
        leaf_path: PathBuf,
        teardown_warn_after: Option<std::time::Duration>,
    ) -> CgroupLeaf {
        let dir = LeafDir::open_for_test(&leaf_path);
        CgroupLeaf {
            watch: Box::new(Watcher::new(
                DrainWatch::arm(&dir).expect("arm a test leaf's drain watch"),
                dir.name().to_os_string(),
            )),
            kernel: std::sync::Arc::new(crate::identity::HostKernel),
            dir,
            leaf_path,
            procs_fd: None,
            verdict: Some(PlacementReport::NotReported),
            entered: false,
            unproven: false,
            cgroup_path: None,
            abandoned: false,
            armed: AtomicBool::new(true),
            kill: std::sync::Arc::default(),
            watched: None,
            placed: super::PlacedAtRemoval::default(),
            removed: AtomicBool::new(false),
            teardown_warn_after,
        }
    }

    /// Give a test leaf the unified-hierarchy path `/proc/<pid>/cgroup` prints for it.
    pub(crate) fn set_cgroup_path_for_test(&mut self, path: String) {
        self.cgroup_path = Some(path);
    }

    /// A test leaf that asks `kernel`, as a spawn's leaf asks the kernel the spawn started with.
    pub(crate) fn asking_for_test(mut self, kernel: crate::identity::SpawnKernel) -> Self {
        self.kernel = kernel;
        self
    }

    /// The record of the watched front's place, as the leaf's subtrees read it.
    pub(crate) fn placed_for_test(&self) -> super::PlacedAtRemoval {
        self.placed.clone()
    }

    pub(crate) fn holds_spawn_resources(&self) -> bool {
        self.procs_fd.is_some() || self.verdict.is_some()
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        let mut warn = self.warn();
        self.tear_down(&mut warn);
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
        // Before the verdict — a spawn that failed, maybe after its clone — abandon it. A spawn that
        // gave the leaf its child took the verdict already, so this is a spawn with none, or one whose
        // child the spawn tore down through its pidfd: it is not ours to reap.
        if self.verdict.is_some() {
            self.abandon_without_child(warn);
        }
        if std::mem::replace(&mut self.abandoned, true) {
            return;
        }
        // Remove the leaf. If still occupied, fire cgroup.kill (unless a write was made, whose
        // answer stands: one write per teardown), wait for the leaf to drain, then retry — but only
        // if the child entered it: a final report other than `Placed` proves nothing of the
        // child's is there. A leaf that outlives the removal is reported.
        //
        // The kill is not written again after one landed. A leaf that repopulates after it (a
        // fork-race escapee on a kernel without `b69bb476dee9`, or a process that migrated in)
        // makes the drain wait for that process to exit, warned past 1 s. A migrant came from a
        // party that already controls the subtree (see `LeafDir::rmdir`), and the fork race is the
        // documented assumption of `Command::kill_on_drop`.
        let Err(first) = self.remove_else_kill() else {
            return;
        };
        // `Drop` kills only when the child entered the leaf and it is still armed:
        //
        // | entered | armed | killed | Drop                                                                        |
        // |---------|-------|--------|-----------------------------------------------------------------------------|
        // | true    | true  | –      | rmdir; if it fails, cgroup.kill unless written, drain, sweep, rmdir         |
        // | true    | false | true   | rmdir; if it fails, wait for the drain, sweep, rmdir                        |
        // | true    | false | false  | rmdir; if `populated 0` already, sweep, rmdir; else one rmdir, left running |
        // | false   | –     | –      | one rmdir: the child never entered the leaf                                 |
        if !self.child_entered() {
            if !removed_after_drain(&first) {
                self.report_left_unkilled(false, &first, None);
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
            if self.kill_landed() {
                self.drain_and_remove(
                    "after an explicit kill through a handle that opted out of Drop's own teardown",
                    warn,
                    false,
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
                // Still populated (or unreadable): the tree was never killed.
                Ok(_) => self.report_left_unkilled(true, &first, None),
                Err(e) => self.report_left_unkilled(true, &first, Some(&e)),
            }
            return;
        }
        // Armed: kill through the leaf, wait for it to drain, and only then remove it. A leaf
        // that is already gone left nothing behind.
        if !removed_after_drain(&first) {
            self.drain_and_remove("after its handle's teardown", warn, false);
        }
    }
}

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// Take the verdict of a spawn that has no child to give the leaf (a spawn failed before its
    /// attach, and the spawn already tore the child down through its pidfd, or none was cloned): kill
    /// through the leaf if the child entered it, and remove the leaf. The child, if there was one, is
    /// not the leaf's to reap.
    ///
    /// Called once per leaf: a repeat is a breach, which debug builds assert. `Drop` does nothing
    /// after it.
    pub(crate) fn abandon_without_child(&mut self, warn: &mut dyn TeardownWarn) {
        let Some(report) = self.verdict.take() else {
            debug_assert!(false, "the leaf answers for a child once");
            return;
        };
        self.procs_fd = None;
        self.abandoned = true;
        self.settle(report);
        // What the abandonment finds wrong on the way, warned once when it ends.
        let mut why = crate::child::spawn::Diagnosis::default();
        self.kill_entered(&mut why);
        self.remove_abandoned(warn);
    }

    /// Kills through the leaf if the child entered it ([`kill_unless_written`](Self::kill_unless_written)).
    /// It is made before anything looks at the child, so a look that asks whether the kill landed
    /// ([`Subtree`]) reads its answer, and the removal does not kill again. A failed write is owed
    /// to `why` here, where it is known, so whichever warn of the abandonment folds `why` carries
    /// it, and the removal does not report it ([`remove_abandoned`](Self::remove_abandoned)). After
    /// a failed write the removal neither waits for the drain nor sweeps child cgroups: the leaf is
    /// left behind (see [`drain_and_remove`](Self::drain_and_remove)).
    fn kill_entered(&self, why: &mut crate::child::spawn::Diagnosis) {
        if !self.entered {
            return;
        }
        if let Err(e) = self.kill_unless_written() {
            why.add(format_args!(
                "cgroup leaf {}: cgroup.kill failed ({e})",
                self.leaf_path.display()
            ));
        }
    }

    /// Removes the abandoned leaf: killed through if its child entered it ([`kill_entered`](Self::kill_entered)
    /// did so, and owes its failure to the abandonment's one warn), and otherwise holding nothing
    /// of the child's.
    fn remove_abandoned(&mut self, warn: &mut dyn TeardownWarn) {
        if self.entered {
            self.remove_killing_through("after its spawn was abandoned", warn, true);
        } else {
            self.remove_holding_nothing();
        }
    }

    /// Remove a leaf its child entered: killed through, drained, its empty child cgroups removed,
    /// then removed once, a failure reported (see [`drain_and_remove`](Self::drain_and_remove)).
    /// `context` says what removal this is, for the report of a leaf left behind; `warn`, for the
    /// wait for the drain; `kill_owed`, whether a failed `cgroup.kill` is reported by the caller.
    fn remove_killing_through(&mut self, context: &str, warn: &mut dyn TeardownWarn, kill_owed: bool) {
        match self.rmdir_leaf() {
            Ok(()) => {}
            Err(e) if removed_after_drain(&e) => {}
            Err(_) => self.drain_and_remove(context, warn, kill_owed),
        }
    }

    /// [`remove_killing_through`](Self::remove_killing_through) after an `rmdir` that failed.
    ///
    /// Kills through the leaf, in one write ([`kill_unless_written`](Self::kill_unless_written));
    /// a failed write is final and
    /// reported: the removal then neither waits for the drain nor sweeps child cgroups, and the
    /// leaf is left behind, reported as "cgroup.kill failed". After a landed write it waits
    /// however long the drain takes, with `warn`
    /// ([`wait_drained_then_warn`](Self::wait_drained_then_warn)), removes the leaf's child
    /// cgroups, and makes one more `rmdir`. Any failure of that `rmdir` is final and reported:
    /// after the drain and the sweep, an `EBUSY` means something another party did since
    /// ([`LEFT_BEHIND_CAUSES`]), which another attempt would only make rarer, never impossible.
    ///
    /// `kill_owed` says the caller reports a failed `cgroup.kill` itself (the abandonment's one
    /// warn), so the report of the leaf left behind does not repeat why.
    fn drain_and_remove(&mut self, context: &str, warn: &mut dyn TeardownWarn, kill_owed: bool) {
        if let Err(e) = self.kill_unless_written() {
            let failed = if kill_owed {
                "the kill through it failed, as reported with the abandonment".to_string()
            } else {
                format!("cgroup.kill failed ({e})")
            };
            warn_leaf_left_behind(&self.leaf_path, format_args!("rmdir failed {context}; {failed}"));
            return;
        }
        if let Err(e) = self.wait_drained_then_warn(warn) {
            warn_leaf_left_behind(
                &self.leaf_path,
                format_args!(
                    "rmdir failed {context}; its drain could not be watched ({})",
                    crate::error::Report(&e)
                ),
            );
            return;
        }
        if let Err(e) = self.dir.remove_children() {
            warn_leaf_left_behind(
                &self.leaf_path,
                format_args!(
                    "rmdir failed {context}; a child cgroup could not be removed ({})",
                    crate::error::Report(&e)
                ),
            );
            return;
        }
        match self.rmdir_leaf() {
            Ok(()) => {}
            Err(e) if removed_after_drain(&e) => {}
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => warn_leaf_left_behind(
                &self.leaf_path,
                format_args!(
                    "rmdir failed ({}) {context}, after its kill, drain and sweep: {LEFT_BEHIND_CAUSES}",
                    crate::error::Report(&e)
                ),
            ),
            Err(e) => warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed ({}) {context}", crate::error::Report(&e)),
            ),
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
                format_args!(
                    "rmdir failed {context}; a child cgroup could not be removed ({})",
                    crate::error::Report(&e)
                ),
            );
        }
        match self.rmdir_leaf() {
            Ok(()) => {}
            Err(e) if removed_after_drain(&e) => {}
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => warn_leaf_left_behind(
                &self.leaf_path,
                format_args!(
                    "rmdir failed ({}) {context}, after its sweep: {LEFT_BEHIND_CAUSES}",
                    crate::error::Report(&e)
                ),
            ),
            Err(e) => warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed ({}) {context}", crate::error::Report(&e)),
            ),
        }
    }

    /// Says what is to be said of a leaf whose `rmdir` failed with `first`, that this teardown did
    /// not kill through and does not wait for. The one table for [`tear_down`](Self::tear_down):
    ///
    /// | child entered | a kill failed | said                                                  |
    /// |---------------|---------------|-------------------------------------------------------|
    /// | no            | –             | warn: nothing of the child's is in it                 |
    /// | yes           | yes           | warn: the tree that opted out is still running        |
    /// | yes           | no            | debug: left behind for a tree that opted out          |
    ///
    /// `entered` is what the caller branched on ([`child_entered`](Self::child_entered)).
    /// `unread` is why the leaf's drain could not be read, if it could not; it is added to the
    /// last two.
    fn report_left_unkilled(&self, entered: bool, first: &io::Error, unread: Option<&crate::error::Error>) {
        if !entered {
            return warn_leaf_left_behind(
                &self.leaf_path,
                format_args!(
                    "rmdir failed ({}); cgroup.kill not written: nothing of the child's is in it",
                    crate::error::Report(first)
                ),
            );
        }
        let unread = unread.map_or(String::new(), |e| {
            format!("; its drain could not be read ({})", crate::error::Report(e))
        });
        if self.kill.failure().is_some() {
            warn_leaf_left_behind(
                &self.leaf_path,
                format_args!(
                    "rmdir failed ({}); its cgroup.kill failed, so the tree that opted out of \
                     Drop's own teardown is still running{unread}",
                    crate::error::Report(first)
                ),
            );
        } else {
            log::debug!(
                "cgroup leaf {} is left behind for a tree that opted out of teardown ({}){unread}",
                self.leaf_path.display(),
                crate::error::Report(first)
            );
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
                Err(e) => format!(
                    "its child cgroups were removed, but rmdir failed again ({})",
                    crate::error::Report(&e)
                ),
            },
            Ok(_) => "cgroup.kill not written: nothing of the child's is in it".to_string(),
            Err(e) => format!("a child cgroup could not be removed ({})", crate::error::Report(&e)),
        };
        warn_leaf_left_behind(
            &self.leaf_path,
            format_args!(
                "rmdir failed ({}) after its spawn was abandoned; {why}",
                crate::error::Report(&first)
            ),
        );
    }
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
/// for containment, as `ContainMode::BestEffort` does. Returns the failing step on any failure, so
/// the caller can fall back to the process-group mechanism *and say why it had to*.
///
/// Failure conditions include: cgroup v2 not mounted at `/sys/fs/cgroup`,
/// current process not in a v2 cgroup (v1-only system), leaf directory not
/// writable (undelegated slice), or `cgroup.kill` absent (kernel < 5.14).
#[cfg(target_os = "linux")]
pub(crate) fn try_create_leaf(
    kernel: &crate::identity::SpawnKernel,
    teardown_warn_after: Option<std::time::Duration>,
) -> Result<CgroupLeaf, LeafError> {
    create_leaf_in(&find_own_cgroup()?, kernel, teardown_warn_after)
}

/// Create a leaf sub-cgroup of `own`, the supervisor's own cgroup. The failing step on any failure.
#[cfg(target_os = "linux")]
pub(crate) fn create_leaf_in(
    own: &OwnCgroup,
    kernel: &crate::identity::SpawnKernel,
    teardown_warn_after: Option<std::time::Duration>,
) -> Result<CgroupLeaf, LeafError> {
    let mut leaf = create_leaf_under(own.dir(), kernel, teardown_warn_after)?;
    let name = leaf.leaf_path.file_name().expect("a leaf has a name").to_string_lossy();
    leaf.cgroup_path = Some(format!("{}/{name}", own.rel_path().trim_end_matches('/')));
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
/// Every early return names its step: the caller fails or degrades, but never silently.
/// `teardown_warn_after`: see [`CgroupLeaf`]'s field of that name. The leaf owns a clone of `kernel`.
#[cfg(target_os = "linux")]
pub(crate) fn create_leaf_under(
    current: &Path,
    kernel: &crate::identity::SpawnKernel,
    teardown_warn_after: Option<std::time::Duration>,
) -> Result<CgroupLeaf, LeafError> {
    // The own cgroup is held and its `cgroup.procs` opened for writing before anything is made: a
    // refusal here leaves nothing to remove. Moving the child into the leaf writes that file too
    // (the own cgroup is the common ancestor of the child's cgroup and the leaf's).
    let own_refused = |path: PathBuf, source: io::Error| LeafError::OpenOwnCgroup { path, source };
    let parent = LeafDir::open_parent(current).map_err(|source| own_refused(current.to_path_buf(), source))?;
    rustix::fs::openat(
        &parent,
        "cgroup.procs",
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| own_refused(current.join("cgroup.procs"), source.into()))?;

    let leaf_name = leaf_name().map_err(|source| LeafError::CreateLeafDir {
        path: current.join("cosca-*"),
        source,
    })?;
    let leaf_path = current.join(&leaf_name);

    let dir = LeafDir::create(parent, &leaf_name).map_err(|source| LeafError::CreateLeafDir {
        path: leaf_path.clone(),
        source,
    })?;

    // Every failure past this point removes the leaf it just created, and reports one it could
    // not remove.
    let fail = |leaf_path: &Path, err: LeafError| -> LeafError {
        #[cfg(test)]
        if fault::take_force_occupy_before_unwind() {
            std::fs::create_dir(leaf_path.join("occupant")).expect("occupy the leaf");
        }
        if let Err(e) = dir.rmdir() {
            if !removed_after_drain(&e) {
                warn_leaf_left_behind(
                    leaf_path,
                    format_args!(
                        "rmdir failed ({}) after its creation failed ({})",
                        crate::error::Report(&e),
                        crate::error::Report(&err)
                    ),
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

    // Open cgroup.procs for writing, close-on-exec: the child's placement write runs after the clone
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
        kernel: std::sync::Arc::clone(kernel),
        watch: Box::new(Watcher::new(Some(watch), leaf_name.clone().into())),
        procs_fd: Some(procs_fd),
        verdict: Some(PlacementReport::NotReported),
        entered: false,
        unproven: false,
        cgroup_path: None,
        abandoned: false,
        armed: AtomicBool::new(true),
        kill: std::sync::Arc::default(),
        watched: None,
        placed: super::PlacedAtRemoval::default(),
        removed: AtomicBool::new(false),
        teardown_warn_after,
    })
}

/// The report of a child whose placement write succeeded; any other value is the write's errno
/// (which is never 0).
#[cfg(target_os = "linux")]
const REPORT_PLACED: u16 = 0;

/// The child's placement step, one of the steps of the spawn core's child (see
/// `child::spawn::in_child`): place the child ([`place_self_in_cgroup`]) and report the outcome on the
/// core's status channel ([`Reporter::report`]), which the spawn reads as a [`PlacementReport`].
///
/// A failed write (e.g. `EBUSY` when the supervisor's cgroup is itself a leaf — the "no internal
/// processes" rule) is `Ok`: the child proceeds in the process group already set up, and the parent
/// degrades on the report. A `refusing` slot's failed write is `Err` with the write's errno, after
/// the report: the program never runs, and the spawn reads the cause from the report. A report that
/// cannot be written is `Err` with its errno too: a child whose report the parent cannot read must not
/// run its program, because a missing report is the parent's proof that it never ran.
///
/// Waits for nothing.
///
/// # Safety
/// As [`place_self_in_cgroup`], called in the spawn core's child only (as a step: see
/// [`Reporter::report`]).
#[cfg(target_os = "linux")]
pub(crate) unsafe fn placement_step(procs_fd: RawFd, refusing: bool, reporter: Reporter) -> io::Result<()> {
    // Safety: the caller's guarantee.
    let report = unsafe { place_self_in_cgroup(procs_fd) };
    // Safety: the caller's guarantee.
    let reported = unsafe { reporter.report(report) };
    reported.map_err(io::Error::from_raw_os_error)?;
    if refusing && report != REPORT_PLACED {
        return Err(io::Error::from_raw_os_error(i32::from(report)));
    }
    Ok(())
}

/// Place the calling process into the pre-created cgroup leaf by writing `"0"`
/// to `procs_fd`, then close the fd so it does not propagate to grandchildren. Returns what the child
/// reports: [`REPORT_PLACED`] (0) for a write of the whole `"0"`, else the write's errno.
///
/// # Safety
/// Must be called only in a forked child, before its `exec`. `procs_fd` must be a valid,
/// open, writable fd in the child process.
/// Async-signal-safe: raw `libc` syscalls, no allocation, no format strings.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn place_self_in_cgroup(procs_fd: RawFd) -> u16 {
    static ZERO: &[u8] = b"0";
    // Test-only fault seam: a write that returns this instead of writing (take semantics — see
    // `fault`), so a failed placement leaves the child out of the leaf, as a real one does.
    #[cfg(test)]
    let forced = fault::take_force_placement_write_result();
    // Safety: ZERO is a valid buffer; procs_fd is valid (caller guarantees).
    let write = || unsafe { libc::write(procs_fd, ZERO.as_ptr().cast(), ZERO.len()) };
    #[cfg(test)]
    let ret = match forced {
        // The failed write the kernel would have answered with this errno.
        Some(fault::ForcedWrite::FailsWith(errno)) => {
            // Safety: errno is this thread's own.
            unsafe { *libc::__errno_location() = errno };
            -1
        }
        Some(fault::ForcedWrite::Returns0) => 0,
        None => write(),
    };
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
    match ret {
        // Only the whole write is a placement.
        _ if ret == ZERO.len() as isize => REPORT_PLACED,
        // `write(2)` only ever sets a positive errno, but a report of 0 means "placed", so a
        // nonsensical value is mapped to EIO rather than read back as a fabricated placement.
        // An errno fits 16 bits.
        -1 if errno > 0 && errno <= i32::from(u16::MAX) => errno as u16,
        // A write that returned without writing (0) sets no errno.
        _ => libc::EIO as u16,
    }
}

#[cfg(target_os = "linux")]
#[path = "leaf/slow_drain.rs"]
mod slow_drain;
#[cfg(target_os = "linux")]
pub(crate) use slow_drain::*;

#[cfg(test)]
#[path = "leaf_tests.rs"]
mod leaf_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "leaf_state_tests.rs"]
mod leaf_state_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "leaf_kernel_tests.rs"]
mod leaf_kernel_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "placement_reuse_tests.rs"]
mod placement_reuse_tests;

#[cfg(all(test, target_os = "linux", feature = "tokio"))]
#[path = "leaf/abandon_drain_tests.rs"]
mod abandon_drain_tests;
