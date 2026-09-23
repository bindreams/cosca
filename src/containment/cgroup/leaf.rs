//! The leaf itself: creating it, placing the child in it, deciding membership, killing
//! through it and removing it.

use std::fmt;
use std::io;
use std::path::PathBuf;

use super::*;

#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};

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
/// value. Shared verbatim by `CgroupLeaf::wait_drained`'s sync loop and its tokio twin,
/// `cgroup_wait_tree_drained` — the only difference between the two callers is how each awaits
/// the next readiness edge, not how either reads or classifies the file.
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

/// A live leaf sub-cgroup created for a single spawned process tree.
///
/// The `pre_exec` closure writes `"0"` to `procs_fd` to place the forked
/// child into the leaf, then immediately closes the fd so it does not
/// propagate to grandchildren. If the write fails (e.g. EBUSY — the
/// supervisor's cgroup is itself a leaf, violating the "no internal processes"
/// rule), the closure returns an error and the spawn falls back to the
/// process-group mechanism.
///
/// [`CgroupLeaf::take_placement`] releases the `cgroup.procs` fd and the report channel: the child
/// needs them only until its `exec`.
///
/// `Drop` removes the leaf directory. If the leaf is still occupied, it fires `cgroup.kill` and
/// retries — but only if the child reported entering it.
#[cfg(target_os = "linux")]
pub(crate) struct CgroupLeaf {
    /// Absolute path to the leaf directory, e.g. `/sys/fs/cgroup/…/cosca-<pid>`.
    pub(super) leaf_path: PathBuf,
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
}

/// Why a spawn-side resource of a [`CgroupLeaf`] is missing.
#[cfg(target_os = "linux")]
const RELEASED: &str = "the leaf's spawn-side resources are released once its placement verdict is taken";

#[cfg(target_os = "linux")]
impl CgroupLeaf {
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

    /// The leaf's `cgroup.events` path — the drain edge. Both watches open it for themselves:
    /// the sync one polls it directly, while the reactor-native async one cannot reuse that
    /// `poll(2)` loop and registers the descriptor instead.
    pub(crate) fn events_path(&self) -> PathBuf {
        self.leaf_path.join("cgroup.events")
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
            Err(source) => return self.decide_unwaitable(pid, &mut channel, source),
        };
        self.entered = report == PlacementReport::Placed;
        let report = match report {
            PlacementReport::Placed => return Ok(Ok(())),
            PlacementReport::NotReported => NotEntered::NotReported,
            PlacementReport::WriteFailed(errno) => NotEntered::WriteFailed(errno),
        };
        let path = self.leaf_path.join("cgroup.procs");
        let child_state = proc_state(pid);
        Ok(Err(match fs::read_to_string(&path) {
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
    ///   It is killed and the spawn fails (see [`CgroupLeaf::abandon`]).
    pub(super) fn decide_unwaitable(
        &mut self,
        pid: u32,
        channel: &mut ReportChannel,
        source: io::Error,
    ) -> Result<Result<(), NotPlaced>, crate::error::Error> {
        let why = match fs::remove_dir(&self.leaf_path) {
            Ok(()) => None,
            Err(e) if removed_after_drain(&e) => None,
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => match self.holds(pid) {
                Ok(true) => {
                    log::debug!(
                        "cgroup v2: pidfd_open failed ({source}), but child {pid} is already in its leaf {}",
                        self.leaf_path.display()
                    );
                    self.entered = true;
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
            return Ok(if self.entered {
                Ok(())
            } else {
                Err(NotPlaced::Unwaitable { pid, source })
            });
        };
        Err(self.abandon(pid, channel, &format!("pidfd_open failed ({source}) and {why}")))
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

    /// Fail a spawn whose membership cannot be decided: kill the child as a group, which ends its
    /// chance to enter the leaf and makes its report final, then apply the module's report
    /// contract — kill through the leaf only on `Placed`.
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
    pub(super) fn abandon(&mut self, pid: u32, channel: &mut ReportChannel, why: &str) -> crate::error::Error {
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
        // The child has exited or exec'd, so its report is final.
        self.entered = channel.read_final() == PlacementReport::Placed;
        // Only a placed child's tree is in the leaf; `cgroup.kill` needs no credential to kill it.
        let through_leaf = self.entered.then(|| {
            self.hard_kill()
                .map_err(|e| format!("cgroup.kill failed ({e})"))
                .and_then(|()| {
                    // Every member was just sent SIGKILL, so the leaf drains; `Drop` then removes it.
                    self.wait_drained(None)
                        .map(drop)
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
        match fs::write(&path, b"1") {
            Ok(()) => Ok(()),
            Err(e) if removed_after_drain(&e) => {
                log::debug!("cgroup.kill: leaf {} is already gone", path.display());
                Ok(())
            }
            Err(e) => Err(crate::error::Error::Io(e)),
        }
    }

    /// Block until every process in the leaf has EXITED (not reaped), observed via
    /// `cgroup.events`'s `populated` key — the kernel flips it 1→0 exactly when the leaf's
    /// last task exits, fork-proof (no cooperation from the tree, no re-enumeration race).
    ///
    /// Read-before-arm: `populated` is checked BEFORE every `poll`, not only after — a
    /// transition that already happened (leaf drained between a caller's previous check and
    /// this call) must be observed on the read, not require a fresh kernel edge that will
    /// never fire again. `POLLPRI` fires on every transition (both 1→0 and 0→1), so an
    /// intervening 0→1 (a leaf that reused-then-repopulated between reads) is also picked up
    /// by looping back to re-read rather than trusting readiness to imply the value dropped.
    ///
    /// `deadline` follows the crate's watch convention (see [`crate::wait::remaining`]). No
    /// interval is chosen anywhere in this path: every round blocks in one `poll(2)` call for
    /// exactly the caller's own remaining time, and returns as soon as either the kernel
    /// reports a transition or the deadline is reached.
    ///
    /// Leaf-removal race: `rmdir` on this leaf (`Drop`'s own retry, or an external cgroup
    /// manager cleaning up an empty leaf — either succeeds only once `populated` has already
    /// read 0) can land at any point after the last member exits, including between this
    /// call's own `poll` waking on the 1→0 transition and its very next read. Once that
    /// happens, `open`/`seek`/`read` on this leaf's `cgroup.events` fail (`ENOENT` for a fresh
    /// `open` through the now-unlinked directory; `ENODEV` for a syscall through an fd that was
    /// opened before removal, once the kernel deactivates the underlying kernfs node) — proof
    /// the leaf is gone, which is itself proof every member had already exited (removal can
    /// never precede full drain), not a failure. See [`removed_after_drain`].
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<Option<std::time::Instant>>,
    ) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        use rustix::event::{poll, PollFd, PollFlags};

        use crate::containment::TreeDrain;
        use crate::error::Error;

        let mut file = match File::open(self.events_path()) {
            Ok(f) => f,
            Err(e) if removed_after_drain(&e) => return Ok(TreeDrain::AllMembersExited),
            Err(e) => return Err(Error::Io(e)),
        };
        let mut buf = String::new();
        loop {
            if !read_populated(&mut file, &mut buf)? {
                return Ok(TreeDrain::AllMembersExited);
            }
            let remaining = crate::wait::remaining(deadline);
            if remaining == Some(std::time::Duration::ZERO) {
                return Ok(TreeDrain::MembersRemain);
            }
            let ts = remaining.map(|d| rustix::event::Timespec {
                tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
                tv_nsec: d.subsec_nanos() as _,
            });
            let mut fds = [PollFd::new(&file, PollFlags::PRI)];
            match poll(&mut fds, ts.as_ref()) {
                Ok(0) => return Ok(TreeDrain::MembersRemain), // genuinely timed out
                Ok(_) => continue,                            // a transition fired — re-read
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(Error::Io(io::Error::from(e))),
            }
        }
    }

    /// SIGTERM every pid currently listed in `cgroup.procs`.
    ///
    /// # PID-reuse window
    /// This reads the pid list then signals each entry. Between the read and
    /// the signal a pid may exit and be recycled, potentially signalling an
    /// unrelated process. This is the same race as the process-group `SIGTERM`
    /// path; the cgroup mechanism's advantage (atomic, pid-free kill) applies
    /// only to `hard_kill` via `cgroup.kill`.
    pub(crate) fn terminate(&self) -> io::Result<()> {
        let content = fs::read_to_string(self.leaf_path.join("cgroup.procs"))?;
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
    pub(crate) fn placeholder_for_test() -> CgroupLeaf {
        CgroupLeaf::for_test_at(PathBuf::from("/nonexistent/cosca-cgroup-placeholder"))
    }

    /// Test-only leaf pointing at `leaf_path`, which a test shapes with ordinary files and
    /// directories. Every operation that reads or writes the leaf path (`hard_kill`,
    /// `take_placement`, `Drop`) then runs for real against the kernel's own errnos, on any
    /// Linux host and without a cgroupfs. It has no `cgroup.procs` fd.
    pub(crate) fn for_test_at(leaf_path: PathBuf) -> CgroupLeaf {
        CgroupLeaf {
            leaf_path,
            procs_fd: None,
            report: Some(ReportChannel::new().expect("open a placement-report channel")),
            entered: false,
            cgroup_path: None,
        }
    }

    /// The leaf's directory, for a test that must find this leaf and no other. Its one user is the
    /// tokio spawn's post-fork failure seam.
    #[cfg(feature = "tokio")]
    pub(crate) fn path_for_test(&self) -> &Path {
        &self.leaf_path
    }

    /// Whether the leaf still holds its `cgroup.procs` fd or its report channel.
    pub(crate) fn holds_spawn_resources(&self) -> bool {
        self.procs_fd.is_some() || self.report.is_some()
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        self.procs_fd = None;
        // Before the verdict — a spawn that failed, maybe after its fork — the report is final
        // only if it arrived: the child's pid is not known here to wait for it.
        if let Some(mut channel) = self.report.take() {
            channel.write = None;
            match channel.read_final() {
                PlacementReport::NotReported => return self.remove_with_report_in_flight(),
                report => self.entered = report == PlacementReport::Placed,
            }
        }
        // Remove the leaf. If still occupied (e.g. hard_kill not yet called), fire cgroup.kill
        // to drain it, then retry — but only if the child entered it: a final report other than
        // `Placed` proves nothing of the child's is there. A leaf that outlives the removal is
        // reported.
        let Err(first) = fs::remove_dir(&self.leaf_path) else {
            return;
        };
        if !self.child_entered() {
            if !removed_after_drain(&first) {
                warn_leaf_left_behind(
                    &self.leaf_path,
                    format_args!("rmdir failed ({first}); cgroup.kill not written: nothing of the child's is in it"),
                );
            }
            return;
        }
        let kill = self.hard_kill();
        let Err(second) = fs::remove_dir(&self.leaf_path) else {
            return;
        };
        // A leaf that is GONE is not a leak: `rmdir` on a cgroup v2 leaf succeeds only once it
        // is empty, so another party having removed it means it left nothing behind here.
        if removed_after_drain(&second) {
            return;
        }
        warn_leaf_left_behind(
            &self.leaf_path,
            format_args!(
                "first rmdir failed ({first}), cgroup.kill {}, second rmdir failed ({second})",
                match kill {
                    Ok(()) => "succeeded".to_string(),
                    Err(e) => format!("failed ({e})"),
                }
            ),
        );
    }
}

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// Remove a leaf whose child's report is still in flight (see the module's report contract):
    /// nothing proves the child absent, so an occupied leaf is killed through, drained, and
    /// removed — again for as long as anything re-enters it before the removal lands. Once
    /// removed, it admits no member, so the in-flight report no longer matters.
    ///
    /// `rmdir` gives the same `EBUSY` for a leaf holding a child cgroup as for a populated one,
    /// and killing removes no directory. So a drained leaf's empty child cgroups are removed too,
    /// and a leaf `rmdir` still refuses with nothing left to kill or remove is reported, not
    /// retried.
    fn remove_with_report_in_flight(&mut self) {
        // Whether the last round killed, drained and removed no child cgroup: a refusal after
        // that is progress only if something re-entered the leaf.
        let mut stalled = false;
        loop {
            let occupied = match fs::remove_dir(&self.leaf_path) {
                Ok(()) => return,
                Err(e) if removed_after_drain(&e) => return,
                Err(e) => e,
            };
            if stalled {
                match self.repopulated() {
                    Ok(true) => {}
                    Ok(false) => {
                        return warn_leaf_left_behind(
                            &self.leaf_path,
                            format_args!(
                                "rmdir failed ({occupied}) with the child's report in flight; nothing \
                                 was left to kill or remove"
                            ),
                        )
                    }
                    Err(e) => {
                        return warn_leaf_left_behind(
                            &self.leaf_path,
                            format_args!(
                                "rmdir failed ({occupied}) with the child's report in flight; whether \
                                 it was re-entered could not be read ({e})"
                            ),
                        )
                    }
                }
            }
            let why = match self.hard_kill() {
                // Every member was just sent SIGKILL, so the leaf drains.
                Ok(()) if occupied.raw_os_error() == Some(libc::EBUSY) => match self.wait_drained(None) {
                    Ok(_) => match remove_child_cgroups(&self.leaf_path) {
                        Ok(removed) => {
                            stalled = removed == 0;
                            continue;
                        }
                        Err(e) => format!("a child cgroup could not be removed ({e})"),
                    },
                    Err(e) => format!("its drain could not be watched ({e})"),
                },
                // Not a leaf `rmdir` refuses for its members: killing again cannot remove it.
                Ok(()) => "cgroup.kill succeeded".to_string(),
                Err(e) => format!("cgroup.kill failed ({e})"),
            };
            return warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed ({occupied}) with the child's report in flight; {why}"),
            );
        }
    }

    /// Whether the leaf has members again, read once from `cgroup.events`.
    fn repopulated(&self) -> Result<bool, crate::error::Error> {
        let mut file = File::open(self.events_path()).map_err(crate::error::Error::Io)?;
        read_populated(&mut file, &mut String::new())
    }
}

/// Remove every child cgroup under `dir`, deepest first, and count those removed. A child that
/// `rmdir` refuses as busy — something re-entered it — is left for the caller's next kill.
#[cfg(target_os = "linux")]
fn remove_child_cgroups(dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        // A cgroup's own interface files are files; its child cgroups are its directories.
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let child = entry.path();
        removed += remove_child_cgroups(&child)?;
        match fs::remove_dir(&child) {
            Ok(()) => removed += 1,
            Err(e) if removed_after_drain(&e) || e.raw_os_error() == Some(libc::EBUSY) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

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

    fs::create_dir(&leaf_path).map_err(|source| LeafError::CreateLeafDir {
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
        if let Err(e) = fs::remove_dir(leaf_path) {
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
    #[cfg(test)]
    let kill_supported = if fault::take_force_kill_supported() {
        Ok(true)
    } else {
        kill_path.try_exists()
    };
    #[cfg(not(test))]
    let kill_supported = kill_path.try_exists();
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
    let procs_fd = OpenOptions::new()
        .write(true)
        .open(&procs_path)
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

    Ok(CgroupLeaf {
        leaf_path,
        procs_fd: Some(procs_fd),
        report: Some(report),
        entered: false,
        cgroup_path: None,
    })
}

/// Place the calling process into the pre-created cgroup leaf by writing `"0"`
/// to `procs_fd`, then close the fd so it does not propagate to grandchildren.
///
/// Called inside a `pre_exec` closure (post-fork, pre-exec), whose `Err` aborts the spawn.
///
/// The outcome — success, or the exact errno — is sent to `slot`, the only way it reaches the
/// parent. A failed write (e.g. `EBUSY` when the supervisor's cgroup is itself a leaf — the "no
/// internal processes" rule) returns `Ok`: the child proceeds in the process group already set
/// up, and the parent degrades on the report. `Err` is a report that could not be sent: a parent
/// still waiting for it would read a child that may be in its leaf as never placed, for the
/// child's whole life, so the spawn fails instead (see [`ReportSlot::report`]).
///
/// # Safety
/// Must be called only from a `pre_exec` closure. `procs_fd` must be a valid,
/// open, writable fd in the child process, and `slot`'s channel must still be open.
/// Async-signal-safe: raw `libc::write`, `libc::close` and `libc::send`, no allocation, no
/// format strings.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn place_self_in_cgroup_pre_exec(procs_fd: RawFd, slot: ReportSlot) -> io::Result<()> {
    static ZERO: &[u8] = b"0";
    // Safety: ZERO is a valid buffer; procs_fd is valid (caller guarantees).
    let ret = unsafe { libc::write(procs_fd, ZERO.as_ptr().cast(), ZERO.len()) };
    // Test-only fault seam: replace the write's return value (take semantics — see `fault`).
    #[cfg(test)]
    let ret = fault::take_force_placement_write_result().unwrap_or(ret);
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
    unsafe { slot.report(report) }
}
