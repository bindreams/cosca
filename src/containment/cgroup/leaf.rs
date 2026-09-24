//! The leaf itself: creating it, placing the child in it, deciding membership, killing
//! through it and removing it.

use std::fmt;
use std::io;
use std::path::PathBuf;

use super::*;

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

#[cfg(target_os = "linux")]
use nix::sys::signal::{kill, Signal};
#[cfg(target_os = "linux")]
use nix::unistd::Pid;

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

/// The kernel's current state letter for `pid`, or `None` when `/proc/<pid>/stat` cannot be
/// read or parsed. A not-yet-reaped child reads as `Z`, which is what separates "the
/// placement write failed" from "the child exited before membership was checked".
#[cfg(target_os = "linux")]
fn proc_state(pid: u32) -> Option<char> {
    parse_proc_stat_state(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// A live leaf sub-cgroup created for a single spawned process tree. See
/// [`place_self_in_cgroup_pre_exec`] for the placement write's contract.
///
/// [`CgroupLeaf::take_placement`] releases the `cgroup.procs` fd and the report channel: the child
/// needs them only until its `exec`.
///
/// `Drop` removes the leaf directory. If the leaf is still occupied, it fires `cgroup.kill`, waits
/// for the leaf to drain, removes its child cgroups and tries once more — but only if the child reported entering it and the leaf was not
/// [`disarm`](Self::disarm)ed.
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
    /// Whether the spawn was abandoned before its verdict: the leaf is already dealt with.
    pub(super) abandoned: bool,
    /// Whether the caller still wants cosca to manage the tree. Cleared by `disarm`, for
    /// `detach()` and `kill_on_drop(false)`. `Drop` kills only while this and `entered` both hold.
    armed: AtomicBool,
    /// Whether [`hard_kill`](Self::hard_kill) wrote `cgroup.kill`. A disarmed `Drop` reads it to
    /// tell a tree the caller killed, whose leaf has not drained yet, from one left running.
    /// [`terminate`](Self::terminate) does not set it: a SIGTERM can be caught.
    killed: AtomicBool,
}

/// Why a spawn-side resource of a [`CgroupLeaf`] is missing.
#[cfg(target_os = "linux")]
const RELEASED: &str = "the leaf's spawn-side resources are released once its placement verdict is taken";

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// Whether the placement verdict is still to be taken: the exchange has not ended.
    pub(crate) fn holds_verdict_to_take(&self) -> bool {
        self.report.is_some()
    }

    /// Returns the raw `cgroup.procs` fd for capture in a `pre_exec` closure. Only before the
    /// placement verdict is taken.
    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs_fd.as_ref().expect(RELEASED).as_raw_fd()
    }

    /// Whether the child reported entering this leaf, once the verdict is taken.
    fn child_entered(&self) -> bool {
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
    /// A disarmed `Drop` still tries the `rmdir` once — detach gives up the kill, not the
    /// tidying — and notes at `debug`, never `warn`, when the live tree keeps the leaf.
    pub(crate) fn disarm(&self) {
        self.armed.store(false, Ordering::Relaxed);
    }

    /// The leaf's directory, for a test that must find this leaf and no other. Its one user is the
    /// tokio spawn's post-fork failure seam.
    #[cfg(all(test, feature = "tokio"))]
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

    /// A `Copy` handle to this leaf's placement-report slot, for capture by the `pre_exec`
    /// closure. Only before the placement verdict is taken.
    pub(crate) fn placement_slot(&self) -> ReportSlot {
        self.report.as_ref().expect(RELEASED).slot()
    }

    /// Whether `pid` entered this leaf: `Ok` when its own write into it succeeded.
    ///
    /// Used once, post-spawn (parent side). Blocks until the report is final — `spawn` returning
    /// does not make it so (see [`ReportChannel`]) — or, when it cannot wait, decides without it
    /// (see [`CgroupLeaf::decide_unwaitable`]). The child's report is the verdict: `cgroup.procs`
    /// lists only live tasks, so a placed child that has already exited reads back absent from
    /// it. Only a child that reported no successful write has `cgroup.procs` and its `/proc`
    /// state read, to diagnose why — see [`NotPlaced`].
    ///
    /// Taking the verdict closes the `cgroup.procs` fd and the report channel: nothing
    /// needs either after the child's `exec`, and otherwise every live contained child would
    /// hold three fds in the supervisor.
    ///
    /// The outer `Err` is a spawn that must fail: membership could not be decided, so the child
    /// was killed (see [`CgroupLeaf::decide_unwaitable`]).
    pub(crate) fn take_placement(&mut self, pid: u32) -> Result<Result<(), NotPlaced>, crate::error::Error> {
        let mut channel = self.report.take().expect(RELEASED);
        self.procs_fd = None;
        let report = match channel.wait(pid) {
            Ok(report) => report,
            Err(source) => return self.decide_unwaitable(pid, channel, source),
        };
        channel.proceed();
        self.entered = report == PlacementReport::Placed;
        let report = match report {
            PlacementReport::Placed => return Ok(Ok(())),
            PlacementReport::NotReported => NotEntered::NotReported,
            PlacementReport::WriteFailed(errno) => NotEntered::WriteFailed(errno),
        };
        let path = self.leaf_path.join("cgroup.procs");
        let child_state = proc_state(pid);
        Ok(Err(match self.dir.read("cgroup.procs") {
            Ok(procs) => NotPlaced::Absent {
                pid,
                path,
                procs,
                report,
                child_state,
            },
            Err(source) => NotPlaced::Unreadable {
                pid,
                path,
                source,
                report,
            },
        }))
    }

    /// Decide membership for a child whose report has not arrived and cannot be waited for:
    /// `pidfd_open` failed with `source`, and waiting on the channel's EOF could block forever
    /// (see [`ReportChannel`]).
    ///
    /// The leaf is removed. `rmdir` succeeds only on a leaf with no live member, and a removed
    /// leaf admits none: the child's later `cgroup.procs` write fails with `ENODEV`. So:
    /// - removed, no `Placed` sent: the child is not in the leaf and never will be — degrade;
    /// - removed, `Placed` sent: the child entered, and every member has since exited;
    /// - `EBUSY` with the child's own `/proc/<pid>/cgroup` inside the leaf: it entered;
    /// - anything else: the child may still enter a leaf cosca can neither wait on nor close.
    ///   It is killed and the spawn fails (see [`CgroupLeaf::fail_closed`]).
    ///
    /// Every outcome but the last is a decision, so the child is sent *proceed*: one whose report
    /// then fails to send carries on to `exec` under the verdict.
    pub(super) fn decide_unwaitable(
        &mut self,
        pid: u32,
        mut channel: ReportChannel,
        source: io::Error,
    ) -> Result<Result<(), NotPlaced>, crate::error::Error> {
        let remove = || self.rmdir_leaf();
        // Test-only fault seam: a leaf that is busy with another process.
        #[cfg(test)]
        let removed = match fault::take_force_leaf_busy() {
            true => Err(io::Error::from_raw_os_error(libc::EBUSY)),
            false => remove(),
        };
        #[cfg(not(test))]
        let removed = remove();
        let why = match removed {
            Ok(()) => None,
            Err(e) if removed_after_drain(&e) => None,
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => match self.holds(pid) {
                Ok(true) => {
                    log::debug!(
                        "cgroup v2: pidfd_open failed ({source}), but child {pid} is already in its leaf {}",
                        self.leaf_path.display()
                    );
                    self.entered = true;
                    channel.proceed();
                    return Ok(Ok(()));
                }
                Ok(false) => Some(format!("its leaf is occupied ({e}) but not by the child")),
                // Unknown membership is not absence: deciding "not the child" on it would leave a
                // child that may be in the leaf unkilled. Undecided fails closed.
                Err(read) => Some(format!(
                    "its leaf is occupied ({e}) and the child's membership could not be read ({read})"
                )),
            },
            Err(e) => Some(format!("its leaf could not be removed ({e})")),
        };
        let Some(why) = why else {
            self.entered = channel.read_final() == PlacementReport::Placed;
            channel.proceed();
            return Ok(if self.entered {
                Ok(())
            } else {
                Err(NotPlaced::Unwaitable { pid, source })
            });
        };
        Err(self.fail_closed(pid, channel, &format!("pidfd_open failed ({source}) and {why}")))
    }

    /// Whether `pid`'s own cgroup is this leaf or nested under it, or why that could not be read.
    /// A leaf with no known unified-hierarchy path (a test leaf) holds nothing.
    fn holds(&self, pid: u32) -> io::Result<bool> {
        let Some(leaf) = &self.cgroup_path else {
            return Ok(false);
        };
        #[cfg(test)]
        if fault::take_force_membership_unreadable() {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let path = parse_v2_relative_path(&text)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no cgroup v2 `0::` line"))?;
        Ok(is_at_or_under(path, leaf))
    }

    /// Fail a spawn whose membership cannot be decided: kill the child as a group and shut the
    /// channel, which end its chance to enter the leaf and make its report final, then apply the
    /// module's report contract — kill through the leaf only on `Placed`.
    ///
    /// The group, not only the pid: between the last look at the report and the kill, the child
    /// can report, exec and fork, and its descendants start in its process group, outside the
    /// leaf. The pid too: a child killed before its own `setpgid` leads no group yet.
    ///
    /// There is no pidfd here — its failure is why the verdict is undecidable — so the child is
    /// signalled by number. That is sound while `pid` is this process's own unreaped child (see
    /// [`Command::contain`](crate::Command::contain)): the kernel does not reuse a pid, nor so a
    /// process-group id, while any task holds it, and the unreaped child does. A child something
    /// else already reaped is detected and never signalled; one reaped between that check and the
    /// kill — only possible when the precondition is broken — is not.
    pub(super) fn fail_closed(&mut self, pid: u32, channel: ReportChannel, why: &str) -> crate::error::Error {
        use nix::sys::wait::{waitid, Id, WaitPidFlag};

        let child = Pid::from_raw(i32::try_from(pid).expect("a spawned child's pid is a positive i32"));
        // Whether `pid` is still this process's child, live or exited, without reaping it.
        let ours = loop {
            match waitid(
                Id::Pid(child),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
            ) {
                Err(nix::errno::Errno::EINTR) => continue,
                Err(nix::errno::Errno::ECHILD) => break false,
                _ => break true,
            }
        };
        debug_assert!(
            ours,
            "{child} is not an unreaped child of this process: something else reaped it"
        );
        // How the child itself was signalled.
        enum Signalled {
            Killed,
            // cosca changes no credentials before the placement hook, so a child it may not
            // signal has exec'd a program that runs as someone else, and its report, sent before
            // `exec`, is final. Waiting for it would last that program's whole life.
            Denied(nix::errno::Errno),
            NotOurs,
        }
        let signalled = if ours {
            #[cfg(test)]
            let denied = fault::take_force_signal_denied();
            #[cfg(not(test))]
            let denied = false;
            let killed = if denied {
                Err(nix::errno::Errno::EPERM)
            } else {
                kill(child, Signal::SIGKILL)
            };
            // The child leads its group; the unreaped child holds the group's id.
            if !denied {
                let _ = nix::sys::signal::killpg(child, Signal::SIGKILL);
            }
            match killed {
                Ok(()) => {
                    // Its exit, not its reaping: the spawn's error path reaps it.
                    while let Err(nix::errno::Errno::EINTR) =
                        waitid(Id::Pid(child), WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT)
                    {}
                    Signalled::Killed
                }
                // ESRCH cannot happen to an unreaped child, so this is EPERM.
                Err(e) => Signalled::Denied(e),
            }
        } else {
            Signalled::NotOurs
        };
        // Shut, then read: a send after the read fails with no *proceed* queued, and its child exits
        // without `exec` — so the report read is final, whether or not the kill landed.
        self.entered = channel.shut().placement() == PlacementReport::Placed;
        // Test-only fault seam: a child's send landing after the read.
        #[cfg(test)]
        fault::run_after_final_read(pid);
        // Only a placed child's tree is in the leaf; `cgroup.kill` needs no credential to kill it.
        let through_leaf = self.entered.then(|| {
            self.hard_kill()
                .map_err(|e| format!("cgroup.kill failed ({e})"))
                .and_then(|()| {
                    // Every member was just sent SIGKILL, so the leaf drains; `Drop` then removes it.
                    self.block_until_drained()
                        .map_err(|e| format!("cgroup.kill succeeded, but its drain could not be watched ({e})"))
                })
        });
        let fate = match (signalled, through_leaf) {
            (Signalled::Killed, None) => {
                "the child and its process group were killed, and it had not entered its leaf".to_string()
            }
            (Signalled::Killed, Some(Ok(()))) => {
                "the child and its process group were killed, and its leaf was killed through".to_string()
            }
            (Signalled::Killed, Some(Err(leaf))) => {
                format!("the child and its process group were killed; through its leaf, {leaf}")
            }
            (Signalled::Denied(e), Some(Ok(()))) => {
                format!("the child could not be signalled ({e}), but was killed through its leaf")
            }
            (Signalled::Denied(e), Some(Err(leaf))) => {
                format!("the child could not be signalled ({e}); through its leaf, {leaf}")
            }
            (Signalled::Denied(e), None) => format!(
                "the child could not be signalled ({e}): it exec'd a program this process may not kill, and \
                 is left running outside its leaf"
            ),
            (Signalled::NotOurs, leaf) => format!(
                "the child was already reaped by something else in this process, so it was not signalled, \
                 and {}",
                match leaf {
                    None => "it had not entered its leaf".to_string(),
                    Some(Ok(())) => "its leaf was killed through".to_string(),
                    Some(Err(leaf)) => format!("through its leaf, {leaf}"),
                }
            ),
        };
        crate::error::Error::Containment {
            detail: format!("cannot tell whether child {pid} entered its cgroup leaf: {why}; {fate}"),
        }
    }

    fn rmdir_leaf(&self) -> io::Result<()> {
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
    pub(crate) fn hard_kill(&self) -> Result<(), crate::error::Error> {
        let path = self.leaf_path.join("cgroup.kill");
        match self.dir.write("cgroup.kill", b"1") {
            Ok(()) => {
                #[cfg(test)]
                fault::record_leaf_step(|| "kill".to_string());
                self.killed.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(e) if removed_after_drain(&e) => {
                log::debug!("cgroup.kill: leaf {} is already gone", path.display());
                Ok(())
            }
            Err(e) => Err(crate::error::Error::Io(e)),
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
        deadline: Option<Option<std::time::Instant>>,
    ) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        use event_listener::Listener as _;

        use crate::containment::TreeDrain;

        loop {
            if let Some(drain) = self.drain_seen()? {
                return Ok(drain);
            }
            let remaining = crate::wait::remaining(deadline);
            if remaining == Some(std::time::Duration::ZERO) {
                return Ok(TreeDrain::MembersRemain);
            }
            // Listen, then read: a change after this read is always heard.
            let listener = self.watch.listen().map_err(crate::error::Error::Io)?;
            if let Some(drain) = self.drain_seen()? {
                return Ok(drain);
            }
            #[cfg(test)]
            fault::notify_drain_blocking();
            match remaining {
                None => listener.wait(),
                // A timeout is looked at by the next round, which reads the leaf once more.
                Some(left) => drop(listener.wait_timeout(left)),
            }
        }
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn watcher(&self) -> &Watcher {
        &self.watch
    }

    /// `Some(AllMembersExited)` if the leaf has drained or is gone; `None` if it still holds a
    /// member; an error if the pump that would report a change has stopped.
    pub(crate) fn drain_seen(&self) -> Result<Option<crate::containment::TreeDrain>, crate::error::Error> {
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

    /// Block until the leaf drains, on the watch held since creation.
    fn block_until_drained(&mut self) -> Result<(), crate::error::Error> {
        // Stops and joins the pump first: the watch is then this `Drop`'s alone.
        match self.watch.get_mut() {
            Some(watch) => watch.wait(None).map(drop),
            None => Ok(()),
        }
    }

    /// SIGTERM every pid currently listed in `cgroup.procs`.
    ///
    /// An already-gone leaf is `Ok`, on the same proof [`hard_kill`](Self::hard_kill) rests on
    /// ([`removed_after_drain`]): there is no member left to signal. The two halves must agree
    /// about one leaf — a caller doing terminate-then-kill would otherwise take an error from
    /// the graceful half and success from the hard one over the identical directory.
    ///
    /// # PID-reuse window
    /// This reads the pid list then signals each entry. Between the read and
    /// the signal a pid may exit and be recycled, potentially signalling an
    /// unrelated process. This is the same race as the process-group `SIGTERM`
    /// path; the cgroup mechanism's advantage (atomic, pid-free kill) applies
    /// only to `hard_kill` via `cgroup.kill`.
    pub(crate) fn terminate(&self) -> io::Result<()> {
        let path = self.leaf_path.join("cgroup.procs");
        let content = match self.dir.read("cgroup.procs") {
            Ok(c) => c,
            Err(e) if removed_after_drain(&e) => {
                log::debug!("cgroup terminate: leaf {} is already gone", path.display());
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        for line in content.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            }
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", test))]
impl CgroupLeaf {
    /// Test-only placeholder pointing at no real cgroup. Safe to construct and drop —
    /// `remove_dir` of a nonexistent path is a harmless no-op — so it is
    /// usable ONLY for variant-level assertions, never for an operation that touches the
    /// fd or path.
    ///
    /// Its path is shared by every caller, so a test asserting on LOG RECORDS must not use
    /// it: `log_capture` is process-wide, libtest runs this binary's tests in parallel, and
    /// records from a concurrent sibling would be indistinguishable from its own. Such a test
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
            killed: AtomicBool::new(false),
        }
    }

    /// Whether the leaf still holds its `cgroup.procs` fd or its report channel.
    pub(crate) fn holds_spawn_resources(&self) -> bool {
        self.procs_fd.is_some() || self.report.is_some()
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        // The pump the leaf owns stops and is joined before anything else: the teardown below
        // uses the watch itself.
        self.watch.stop_pump();
        self.procs_fd = None;
        // Before the verdict — a spawn that failed, maybe after its fork — end the exchange.
        if self.report.is_some() {
            self.abandon_before_verdict();
        }
        if self.abandoned {
            return;
        }
        // Remove the leaf. If still occupied (e.g. hard_kill not yet called), fire cgroup.kill,
        // wait for the leaf to drain, then retry — but only if the child entered it: a final
        // report other than `Placed` proves nothing of the child's is there. A leaf that outlives
        // the removal is reported.
        let Err(first) = self.rmdir_leaf() else {
            return;
        };
        // `Drop` kills only when both hold:
        //
        // | entered | armed | Drop                                                 |
        // |---------|-------|------------------------------------------------------|
        // | true    | true  | rmdir; if it fails, cgroup.kill, drain, sweep, rmdir |
        // | true    | false | one rmdir: the caller opted the tree out             |
        // | false   | true  | one rmdir: the child never entered the leaf          |
        // | false   | false | one rmdir: the child never entered the leaf          |
        if !self.child_entered() {
            if !removed_after_drain(&first) {
                warn_leaf_left_behind(
                    &self.leaf_path,
                    format_args!("rmdir failed ({first}); cgroup.kill not written: nothing of the child's is in it"),
                );
            }
            return;
        }
        // Opted out (see `disarm`): the single `rmdir` above is all Drop may do. An `ENOENT` or
        // `ENODEV` from it proves the leaf is gone ([`removed_after_drain`]). Otherwise a tree
        // the caller killed has not drained yet (`cgroup.kill` is asynchronous), and its leaf is a
        // leak like any other; a tree left running keeps its leaf by request.
        if !self.armed.load(Ordering::Relaxed) {
            if removed_after_drain(&first) {
                return;
            }
            if self.killed.load(Ordering::Relaxed) {
                warn_leaf_left_behind(
                    &self.leaf_path,
                    format_args!("rmdir failed ({first}) before the killed tree drained; the handle opted out of teardown, so Drop did not retry"),
                );
            } else {
                log::debug!(
                    "cgroup leaf {} is left behind for a tree that opted out of teardown ({first})",
                    self.leaf_path.display()
                );
            }
            return;
        }
        // Armed: kill through the leaf, wait for it to drain, and only then remove it. A leaf
        // that is already gone left nothing behind.
        if !removed_after_drain(&first) {
            self.drain_and_remove(false, "after its handle's teardown");
        }
    }
}

/// How an abandoned spawn's child ended up (see [`CgroupLeaf::abandon_before_verdict`]).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Abandoned {
    /// Nothing of the child's runs, and it is reaped or will be: it was killed, or had already
    /// exited and been reaped.
    Ended,
    /// The child sent nothing, so nothing names it: there may be none, or one that exits at its
    /// first send, before `exec` and outside the leaf — but that nothing here holds the pid to reap.
    MaybeUnreaped,
    /// The child may be running, and cosca could not kill it: it has no pidfd or refused the
    /// signal, and its leaf does not hold it.
    OutOfReach,
}

/// What became of the child itself when its spawn was abandoned.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildFate {
    /// Never sent its intent: if it exists, it exits at its first send, never entering the leaf,
    /// and nothing here can reap it.
    NeverReached,
    /// Already exited and reaped by whoever failed the spawn (std reaps the child of a spawn it
    /// failed).
    Gone,
    /// Killed through its pidfd, with its process group, and reaped.
    Killed,
    /// Could not be killed: no pidfd, or the signal was refused.
    Unkillable,
}

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// End the exchange of a spawn that failed before its verdict (see the module's contract),
    /// and answer for its child: kill it and its group, kill through the leaf if it entered, reap
    /// it if no handle owns it, and remove the leaf.
    ///
    /// Idempotent: the channel is taken once, and `Drop` does nothing after it.
    ///
    /// Only a spawn whose child no handle owns may reach this with the child unreaped: tokio drops
    /// a child it forked and then failed to set up, neither killed nor reaped. A spawn path that
    /// still holds its child takes the verdict first, and one whose child `std` reaped leaves
    /// nothing to reap here.
    pub(crate) fn abandon_before_verdict(&mut self) -> Abandoned {
        let Some(channel) = self.report.take() else {
            return Abandoned::Ended;
        };
        self.procs_fd = None;
        self.abandoned = true;
        let received = channel.shut();
        self.entered = received.placement() == PlacementReport::Placed;
        // The child first, by its pidfd and as its group, whatever the leaf's own kill does: it
        // may have left the leaf, or never entered it.
        let fate = end_child(&received);
        let through_leaf = self.entered.then(|| self.hard_kill());
        if self.entered {
            self.remove_killing_through(
                through_leaf.as_ref().is_some_and(Result::is_ok),
                "after its spawn was abandoned",
            );
        } else {
            self.remove_holding_nothing();
        }
        match (fate, through_leaf) {
            (ChildFate::NeverReached, _) => Abandoned::MaybeUnreaped,
            (ChildFate::Gone | ChildFate::Killed, _) => Abandoned::Ended,
            // `cgroup.kill` needs no credential, so a placed child is killed through its leaf.
            (ChildFate::Unkillable, Some(Ok(()))) => Abandoned::Ended,
            (ChildFate::Unkillable, _) => Abandoned::OutOfReach,
        }
    }

    /// Remove a leaf its child entered: killed through, drained, its empty child cgroups removed,
    /// then removed once, a failure reported (see [`drain_and_remove`](Self::drain_and_remove)). `killed`
    /// says whether the caller's own kill through it succeeded; `context` says what removal this
    /// is, for the report of a leaf left behind.
    fn remove_killing_through(&mut self, killed: bool, context: &str) {
        match self.rmdir_leaf() {
            Ok(()) => {}
            Err(e) if removed_after_drain(&e) => {}
            Err(_) => self.drain_and_remove(killed, context),
        }
    }

    /// [`remove_killing_through`](Self::remove_killing_through) after an `rmdir` that failed.
    ///
    /// Kills through the leaf, waits however long the drain takes (a [`DrainWatch`]), removes the
    /// leaf's child cgroups, and makes one more `rmdir`. Any failure of that `rmdir` is final and
    /// reported: after the drain and the sweep, an `EBUSY` means something another party did
    /// since ([`LEFT_BEHIND_CAUSES`]), which another attempt would only make rarer, never
    /// impossible.
    fn drain_and_remove(&mut self, killed: bool, context: &str) {
        if !killed {
            if let Err(e) = self.hard_kill() {
                return warn_leaf_left_behind(
                    &self.leaf_path,
                    format_args!("rmdir failed {context}; cgroup.kill failed ({e})"),
                );
            }
        }
        if let Err(e) = self.block_until_drained() {
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

/// Answer for an abandoned spawn's child: kill it and the group it leads, then reap it — it is
/// killed directly, so the wait ends with its exit, and no handle owns it (see
/// [`CgroupLeaf::abandon_before_verdict`]).
///
/// The child is named by the handle its intent carried — a pidfd, or its `/proc/<pid>` directory —
/// never by its number alone. Which path failed the spawn does not need knowing: `std` reaps the
/// child of a spawn it fails, and tokio's post-fork failure never does, but tokio reports both as
/// one error. The handle answers instead: a process `std` reaped opens nothing through it, however
/// its number has been reused since. An intent with no handle names nothing cosca may signal.
///
/// A child it may not signal (`EPERM`) is handed to a background reaper, so it is reaped once it
/// exits, however that comes.
#[cfg(target_os = "linux")]
fn end_child(received: &Received) -> ChildFate {
    use std::os::fd::{AsFd, AsRawFd};

    use rustix::process::{pidfd_send_signal, waitid, WaitId, WaitIdOptions};

    let Some(pid) = received
        .pid
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(rustix::process::Pid::from_raw)
    else {
        return ChildFate::NeverReached;
    };
    let Some(handle) = received.pidfd.as_ref().or(received.proc_dir.as_ref()) else {
        log::warn!("cgroup v2: an abandoned spawn's child sent no handle on itself ({pid:?}); it is not signalled");
        return ChildFate::Unkillable;
    };
    // The reap names the child by its pidfd, or — with its `/proc` directory proving the number is
    // still its own, and it unreaped — by its pid.
    let id = || match &received.pidfd {
        Some(pidfd) => WaitId::PidFd(pidfd.as_fd()),
        None => WaitId::Pid(pid),
    };
    // Still unreaped? A process `std` reaped is gone: its pidfd waits on nothing, its `/proc`
    // directory opens nothing.
    let unreaped = match &received.pidfd {
        Some(_) => loop {
            match waitid(
                id(),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ) {
                Err(rustix::io::Errno::INTR) => continue,
                Err(rustix::io::Errno::CHILD) => break false,
                _ => break true,
            }
        },
        None => {
            // Safety: a NUL-terminated name relative to an open directory; the result is closed.
            let stat = unsafe { libc::openat(handle.as_raw_fd(), c"stat".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if stat >= 0 {
                // Safety: the descriptor just opened, closed once.
                unsafe { libc::close(stat) };
            }
            stat >= 0
        }
    };
    if !unreaped {
        return ChildFate::Gone;
    }
    #[cfg(test)]
    fault::run_between_check_and_kill();
    #[cfg(test)]
    let denied = fault::take_force_child_kill_denied();
    #[cfg(not(test))]
    let denied = false;
    // Through the handle: the kernel takes a `/proc/<pid>` directory as a pidfd here.
    let killed = if denied {
        Err(rustix::io::Errno::PERM)
    } else {
        pidfd_send_signal(handle, rustix::process::Signal::KILL)
    };
    let killed = match killed {
        // Reaped since the check — only a reaper the crate's contract forbids can have — so it is
        // gone, and its number is not signalled.
        Err(rustix::io::Errno::SRCH) => return ChildFate::Gone,
        // `pidfd_send_signal` itself refused, as a seccomp filter can: the identity was proven a
        // moment ago, and only this process may reap the child, so its pid still names it.
        Err(rustix::io::Errno::NOSYS) | Err(rustix::io::Errno::PERM) if !denied => {
            #[cfg(test)]
            fault::record_signalled_by_pid();
            rustix::process::kill_process(pid, rustix::process::Signal::KILL)
        }
        other => other,
    };
    // The group it leads: an unreaped leader pins the group's id, so this names its group alone.
    if !denied {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    if let Err(e) = killed {
        log::warn!("cgroup v2: could not kill an abandoned spawn's child ({e}); it is reaped once it exits");
        reap_in_background(id_owned(received, pid));
        return ChildFate::Unkillable;
    }
    let status = loop {
        match waitid(id(), WaitIdOptions::EXITED) {
            Err(rustix::io::Errno::INTR) => continue,
            other => break other,
        }
    };
    match status {
        Ok(status) => {
            log::debug!("cgroup v2: reaped an abandoned spawn's child: {status:?}");
            #[cfg(test)]
            fault::record_reaped_orphan(
                received.pid.unwrap_or(0),
                status.and_then(|status| status.terminating_signal()),
            );
        }
        // Nothing else may reap it: the child was unreaped a moment ago, and no handle owns it.
        Err(e) => {
            log::warn!("cgroup v2: could not reap an abandoned spawn's child: {e}");
            debug_assert!(false, "an abandoned spawn's child could not be reaped: {e}");
        }
    }
    ChildFate::Killed
}

/// What names a child to its reaper: its own pidfd, or its pid once its `/proc` directory proved
/// the number its own (see [`end_child`]).
#[cfg(target_os = "linux")]
enum ChildId {
    PidFd(OwnedFd),
    Pid(rustix::process::Pid),
}

#[cfg(target_os = "linux")]
fn id_owned(received: &Received, pid: rustix::process::Pid) -> ChildId {
    match received.pidfd.as_ref().and_then(|pidfd| pidfd.try_clone().ok()) {
        Some(pidfd) => ChildId::PidFd(pidfd),
        None => ChildId::Pid(pid),
    }
}

/// Reap `child` on a detached thread once it exits on its own — a child cosca could not kill.
/// The thread blocks on the child's exit, an event outside this process's control; nothing waits
/// for the thread. This stands in until the crate's spawn teardown has one shared reaper.
#[cfg(target_os = "linux")]
fn reap_in_background(child: ChildId) {
    use std::os::fd::AsFd;

    use rustix::process::{waitid, WaitId, WaitIdOptions};

    #[cfg(test)]
    let notify = fault::take_background_reap_notifier();
    let spawned = std::thread::Builder::new().name("cosca-reap".into()).spawn(move || {
        let id = || match &child {
            ChildId::PidFd(pidfd) => WaitId::PidFd(pidfd.as_fd()),
            ChildId::Pid(pid) => WaitId::Pid(*pid),
        };
        loop {
            match waitid(id(), WaitIdOptions::EXITED) {
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => log::warn!("cgroup v2: background reap of an abandoned spawn's child failed: {e}"),
                Ok(_) =>
                {
                    #[cfg(test)]
                    if let Some(notify) = &notify {
                        let _ = notify.send(());
                    }
                }
            }
            break;
        }
    });
    if let Err(e) = spawned {
        log::warn!("cgroup v2: could not start a thread to reap an abandoned spawn's child, which stays unreaped: {e}");
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

/// Create a containment leaf directly under `current` — the supervisor's own cgroup in
/// production, and a temp directory in the tests that fail each precondition for real.
///
/// Every early return names its step: the caller degrades either way, but never silently.
#[cfg(target_os = "linux")]
pub(crate) fn create_leaf_under(current: &Path) -> Result<CgroupLeaf, LeafError> {
    // Unique leaf name: pid + monotonic sequence counter avoids collisions when
    // the same process spawns on multiple threads simultaneously (same pid, but
    // different seq values mean different leaf names).
    // Safety: getpid() is always valid.
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let leaf_name = format!("cosca-{}-{}", unsafe { libc::getpid() }, seq);
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
        .and_then(|file| Ok(rustix::io::fcntl_dupfd_cloexec(&file, 3)?));
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
        killed: AtomicBool::new(false),
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
    // Test-only fault seam: wait for the test's go-ahead (async-signal-safe: one `read`).
    #[cfg(test)]
    if let Some(gate) = fault::take_hook_gate() {
        let mut byte = 0u8;
        // Safety: a one-byte buffer on this frame; `gate` is this child's inherited copy.
        while unsafe { libc::read(gate, (&raw mut byte).cast(), 1) } == -1
            && unsafe { *libc::__errno_location() } == libc::EINTR
        {}
    }
    // Safety: the caller's guarantee: this is the forked child.
    unsafe { slot.close_parents_end() };
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

#[cfg(test)]
#[path = "leaf_tests.rs"]
mod leaf_tests;
