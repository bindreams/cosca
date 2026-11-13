//! Whether a task is in a leaf's cgroup subtree, by reads that each end: none waits on the task.
//!
//! - **Linux 6.13+:** `PIDFD_GET_INFO`'s cgroup id, through the task's pidfd, compared with the
//!   leaf's own id. Another id is looked for among the cgroups under the leaf: those its sweep
//!   removed, then those a walk of the leaf's descendants finds.
//! - **Otherwise:** `/proc/<pid>/cgroup`'s path, compared with the leaf's. A `hidepid` `/proc`
//!   hides it for a task of another user (a root front), so an elevated spawn that would need it
//!   is refused (see [`front_placement`]).
//!
//! What a read says of a task killed through the leaf and then moved by someone else is on
//! [`Command::contain`](crate::Command::contain).

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use super::parse::{is_at_or_under, parse_v2_relative_path};
use super::KillRecord;
use crate::child::owned::teardown::Reach;
use crate::os_process::child::PeekOutcome;
use crate::os_process::linux::fork::{fork_with_pidfd, Fork, Path};
use crate::wait::exit_only::linux::peek;
use crate::wait::exit_only::Target;

/// `_IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)`, with the 64-byte first version of the struct.
/// The request is the same 32 bits under glibc's `unsigned long` and musl's `int`.
const PIDFD_GET_INFO: libc::Ioctl = 0xC040_FF0B_u32 as libc::Ioctl;
const PIDFD_INFO_CGROUPID: u64 = 1 << 2;

/// The first version of `struct pidfd_info`, whose size is in [`PIDFD_GET_INFO`].
#[repr(C)]
#[derive(Default)]
struct PidfdInfo {
    mask: u64,
    cgroupid: u64,
    rest: [u32; 12],
}

/// The cgroup id of the task `pidfd` names, or `None` on a kernel with no `PIDFD_GET_INFO` (before
/// 6.13). An error is a refusal of a kernel that has it, such as `ESRCH` for a task already reaped.
pub(crate) fn pidfd_cgroup_id(pidfd: BorrowedFd<'_>) -> io::Result<Option<u64>> {
    #[cfg(test)]
    if super::fault::pidfd_info_missing() {
        return Ok(None);
    }
    #[cfg(test)]
    if let Some(errno) = super::fault::pidfd_info_fails() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    #[cfg(test)]
    if let Some(id) = super::fault::forced_pidfd_cgroup_id() {
        return Ok(Some(id));
    }
    let mut info = PidfdInfo {
        mask: PIDFD_INFO_CGROUPID,
        ..PidfdInfo::default()
    };
    // SAFETY: `info` is a valid, writable `struct pidfd_info` of the size the request encodes.
    let rc = unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_INFO, &mut info as *mut PidfdInfo) };
    if rc == 0 {
        if info.mask & PIDFD_INFO_CGROUPID == 0 {
            return Ok(None);
        }
        return Ok(Some(info.cgroupid));
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        // Not a pidfs ioctl this kernel knows.
        Some(libc::ENOTTY) | Some(libc::EINVAL) => Ok(None),
        _ => Err(e),
    }
}

/// Whether `/proc/<pid>/cgroup` names `leaf_path` (a unified-hierarchy path) or a cgroup under it
/// (see [`names_leaf`]): `other_id` says the task's pidfd gave a cgroup id other than the leaf's,
/// and `recorded` answers for the leaf's own path with ` (deleted)` after it.
///
/// Reads through [`HostKernel`](crate::identity::HostKernel) and the containment `fault` hooks,
/// not a `Kernel` the caller passes: this is containment's own read.
pub(crate) fn proc_names(
    leaf_path: &str,
    pid: u32,
    recorded: impl FnOnce() -> Option<bool>,
    other_id: bool,
) -> io::Result<bool> {
    #[cfg(test)]
    if let Some(errno) = super::fault::proc_hidden_as() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    let proc_dir = match crate::identity::proc_view_with(&crate::identity::HostKernel) {
        crate::identity::ProcView::Same(dir) => dir,
        crate::identity::ProcView::Diverged => {
            return Err(io::Error::other(format!(
                "{}, so pid {pid}'s cgroup cannot be read",
                crate::identity::DIVERGED_REASON
            )));
        }
        crate::identity::ProcView::Unassessable(why) => return Err(view_unreadable(pid, why)),
    };
    let text = proc_dir.read_to_string(&format!("{pid}/cgroup"))?;
    let path = parse_v2_relative_path(&text)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no cgroup v2 `0::` line"))?;
    names_leaf(path, leaf_path, other_id, recorded)
}

/// The error of reading `pid`'s cgroup through a `/proc` view that could not be established, `why`:
/// of the view's error's kind, with that error as its source.
fn view_unreadable(pid: u32, why: crate::identity::ViewUnreadable) -> io::Error {
    let context = format!(
        "the /proc view could not be established, so pid {pid}'s cgroup cannot be read: {}",
        why.reason
    );
    crate::error::io_context_or_other(context, why.source)
}

/// What `/proc/<pid>/cgroup` prints after the path of a removed cgroup.
const DELETED: &str = " (deleted)";

/// Whether the cgroup `path` (from `/proc/<pid>/cgroup`) is the leaf at `leaf_path` or under it.
///
/// A removed cgroup's path is printed with [`DELETED`] after it, which a live cgroup may also have
/// in its name. A path under the leaf is under it either way. The leaf's own path with the suffix
/// is the removed leaf or a live cgroup of that name beside it, which no read of `/proc` can tell
/// apart: it is answered by `recorded`, the task's place recorded just before the leaf's removal,
/// while the leaf's own path still read without the suffix (see [`PlacedAtRemoval`]). With no
/// record it is undecidable. It is never the leaf when `other_id` says the task's pidfd gave a
/// cgroup id other than the leaf's.
pub(crate) fn names_leaf(
    path: &str,
    leaf_path: &str,
    other_id: bool,
    recorded: impl FnOnce() -> Option<bool>,
) -> io::Result<bool> {
    if is_at_or_under(path, leaf_path) {
        return Ok(true);
    }
    if path.strip_suffix(DELETED) != Some(leaf_path) || other_id {
        return Ok(false);
    }
    recorded().ok_or_else(|| {
        io::Error::other(format!(
            "{path} is either the removed leaf or a live cgroup of that name, and the task's place was not \
             recorded before the leaf's removal"
        ))
    })
}

/// Where a leaf's watched elevation front was just before the leaf's last `rmdir`, by pid (see
/// `CgroupLeaf::watch_front`), shared by the leaf and its subtrees.
#[derive(Debug, Clone, Default)]
pub(crate) struct PlacedAtRemoval(Arc<std::sync::Mutex<Option<(u32, bool)>>>);

impl PlacedAtRemoval {
    pub(crate) fn record(&self, pid: u32, inside: bool) {
        *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some((pid, inside));
    }

    pub(crate) fn clear(&self) {
        *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Whether `pid` was recorded inside the leaf; `None` without a record for it.
    pub(crate) fn of(&self, pid: u32) -> Option<bool> {
        match *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
            Some((recorded, inside)) if recorded == pid => Some(inside),
            _ => None,
        }
    }
}

/// A leaf's subtree, captured while the leaf exists, so a task can be placed in it even once the
/// leaf is removed: the leaf's own cgroup id (`None` if unreadable: tasks are then placed through
/// `/proc`), its directory, its unified-hierarchy path, the ids of the cgroups known to be under it
/// (see [`Swept`](super::Swept)), its front's place before its removal, and whether a kill through
/// it has landed (the leaf's own record).
#[derive(Debug)]
pub(crate) struct Subtree {
    leaf_id: Option<u64>,
    dir: Option<Arc<OwnedFd>>,
    path: Option<String>,
    swept: super::Swept,
    placed: PlacedAtRemoval,
    killed: Arc<KillRecord>,
}

impl Subtree {
    pub(crate) fn new(
        leaf_id: Option<u64>,
        dir: Option<Arc<OwnedFd>>,
        path: Option<String>,
        swept: super::Swept,
        placed: PlacedAtRemoval,
        killed: Arc<KillRecord>,
    ) -> Subtree {
        Subtree {
            leaf_id,
            dir,
            path,
            swept,
            placed,
            killed,
        }
    }

    /// Whether the task `pid`, which `pidfd` names when there is one, is in this subtree. A task
    /// keeps its cgroup until it is freed, so a killed task on its way out, or a zombie, still has
    /// the leaf's id, and a task moved out has its new cgroup's. Where the kernel gives a pidfd's
    /// cgroup id (6.13+) and the leaf's own id is known, the task is in the subtree if that id is the
    /// leaf's, or one known to be under it, or one a walk of the leaf's descendants finds;
    /// outside if the walk finds it nowhere (see [`walk_places`](Self::walk_places)). Otherwise,
    /// before 6.13 or when the walk cannot tell, by `/proc/<pid>/cgroup`'s path. A subtree with no
    /// unified-hierarchy path (a test leaf) holds nothing that read would place.
    pub(crate) fn holds(&self, pid: u32, pidfd: Option<BorrowedFd<'_>>) -> io::Result<bool> {
        self.holds_seen(pid, pidfd, None).map(|(inside, _)| inside)
    }

    /// [`holds`](Self::holds), also giving the cgroup id that placed the task (the leaf's, a known
    /// one, one the walk found under the leaf, or `seen`; `None` where `/proc` placed it or it is
    /// outside), and told `seen`, the id the task had when an id placed it in this subtree: a task
    /// still in that cgroup is where it was, so no walk of the leaf's descendants is made for it, and
    /// the leaf's own id is not needed. Where the leaf's id is unknown, the pidfd route answers only
    /// from `seen` or a known id, and `/proc` places any other task; an `ESRCH` from the pidfd is the
    /// task's exit and is returned.
    pub(crate) fn holds_seen(
        &self,
        pid: u32,
        pidfd: Option<BorrowedFd<'_>>,
        seen: Option<u64>,
    ) -> io::Result<(bool, Option<u64>)> {
        let mut elsewhere = false;
        let id = match pidfd {
            Some(pidfd) if self.leaf_id.is_some() || seen.is_some() || !self.swept.is_empty() => {
                match pidfd_cgroup_id(pidfd) {
                    Ok(id) => id,
                    // With no leaf id the pidfd's only shortcuts to `seen` or a known id: a refusal
                    // places by `/proc`, as a task with neither is. `ESRCH` is the task's exit, which
                    // the caller reads.
                    Err(e) if self.leaf_id.is_none() && e.raw_os_error() != Some(libc::ESRCH) => {
                        log::debug!(
                            "the cgroup id of pid {pid} could not be read ({report}), so it is placed through /proc",
                            report = crate::error::Report(&e)
                        );
                        None
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => None,
        };
        if let Some(id) = id {
            if self.leaf_id == Some(id) || self.swept.holds(id) || seen == Some(id) {
                return Ok((true, Some(id)));
            }
            if self.leaf_id.is_some() {
                if let Some(under) = self.walk_places(id) {
                    return Ok((under, under.then_some(id)));
                }
                elsewhere = true;
            }
        }
        let Some(path) = &self.path else {
            return Ok((false, None));
        };
        proc_names(path, pid, || self.placed.of(pid), elsewhere)
            .map(|inside| (inside, None))
            .map_err(|e| {
                if elsewhere {
                    crate::error::io_context(
                        format!(
                            "pid {pid} is in another cgroup than its leaf, maybe one under it, and that cgroup's path \
                             cannot be read"
                        ),
                        e,
                    )
                } else {
                    e
                }
            })
    }

    /// Whether the cgroup `id`, not the leaf's own, is under the leaf, by a walk of the leaf's
    /// descendants (see [`find_descendant`](super::find_descendant)). `None` when the walk cannot
    /// tell: the leaf cannot be read or is removed, a cgroup under it cannot be listed, or one is
    /// removed but not yet freed, which no walk lists. The last is read after the walk: a cgroup
    /// the task is in stays, live or dying, until the task is freed, so one under the leaf that the
    /// walk missed is dying by then.
    fn walk_places(&self, id: u64) -> Option<bool> {
        let dir = self.dir.as_ref()?;
        match super::find_descendant(dir.as_fd(), id) {
            super::Walked::Found => Some(true),
            super::Walked::Absent => match self.dying() {
                Ok(Some(0)) => Some(false),
                Ok(dying) => {
                    log::debug!(
                        "the cgroups under a leaf were all walked without finding cgroup {id}, but {} are removed \
                         and not yet freed, so it is not shown to be outside",
                        dying.map_or("an unknown number".to_owned(), |n| n.to_string())
                    );
                    None
                }
                Err(e) => {
                    log::debug!(
                        "the cgroups under a leaf were all walked without finding cgroup {id}, but its cgroup.stat \
                         cannot be read ({report}), so it is not shown to be outside",
                        report = crate::error::Report(&e)
                    );
                    None
                }
            },
            super::Walked::Unknown(e) => {
                log::debug!(
                    "the cgroups under a leaf could not all be walked ({report})",
                    report = crate::error::Report(&e)
                );
                None
            }
        }
    }

    /// How many cgroups under the leaf are removed but not yet freed, by its `cgroup.stat`; `None`
    /// if that holds no such count. An error if the file cannot be read, as once the leaf is
    /// removed.
    fn dying(&self) -> io::Result<Option<u64>> {
        let dir = self
            .dir
            .as_ref()
            .ok_or_else(|| io::Error::other("the subtree holds no leaf directory"))?;
        let file = rustix::fs::openat(
            dir.as_fd(),
            "cgroup.stat",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let text = io::read_to_string(std::fs::File::from(file))?;
        Ok(dying_in(&text))
    }

    /// Whether a kill through the leaf landed and reached the task `pid` (see [`holds`](Self::holds)):
    /// only then does the task's exit follow, so only then may it be waited for. `seen` is as in
    /// [`holds_seen`](Self::holds_seen): the pidfd route answers from it when the leaf's id is
    /// unknown. This is the one check that a kill reached a task.
    pub(crate) fn reached_by(&self, pid: u32, pidfd: Option<BorrowedFd<'_>>, seen: Option<u64>) -> io::Result<bool> {
        if !self.killed.landed() {
            return Ok(false);
        }
        self.holds_seen(pid, pidfd, seen).map(|(inside, _)| inside)
    }
}

impl Reach for Subtree {
    /// [`Subtree::reached_by`], asked with the child's pid and pidfd. A child with no pid cannot be placed: it
    /// has no number to ask `/proc` with, so whether the kill reached it is not known.
    fn reached(&self, child: &crate::child::owned::OwnedChild) -> io::Result<bool> {
        match child.pid() {
            Some(pid) => self.reached_by(pid, child.pidfd(), None),
            None => Err(io::Error::other("the child's pid is not known, so it cannot be placed")),
        }
    }
}

/// `nr_dying_descendants` in a `cgroup.stat`'s `text`.
fn dying_in(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("nr_dying_descendants ")?.trim().parse::<u64>().ok())
}

/// Whether this host can place an elevation front after a cgroup kill, decided before any front is
/// spawned. Placement is by a pidfd's cgroup id on Linux 6.13 and later, else by `/proc/<pid>/cgroup`
/// of a non-dumpable child, since `hidepid` hides such a process as it hides a root `sudo` front.
/// The leaf's id must be readable: `ENOSYS`, `EOPNOTSUPP` or `EPERM` is `Unsupported` naming the
/// errno, and any other error is `Io`. Where `PIDFD_GET_INFO` is missing, the probe's fork also
/// needs a free descriptor number for the child's pidfd, beyond the `/proc` handle and the socket's
/// two ends: with none, the spawn is refused with `Io` (`EMFILE`), before anything runs.
///
/// `Err` is the spawn's refusal.
pub(crate) fn front_placement(
    kernel: &dyn crate::identity::Kernel,
    leaf_id: impl FnOnce() -> io::Result<u64>,
) -> Result<(), crate::error::Error> {
    use std::os::fd::AsFd;

    if let Err(e) = leaf_id() {
        return Err(match e.raw_os_error() {
            Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM) => unplaceable(
                "this host gives no cgroup's id by name_to_handle_at, as a kernel without CONFIG_FHANDLE, a \
                 filesystem without export operations or a seccomp filter refuses it"
                    .to_owned(),
                Some(e),
            ),
            _ => crate::error::Error::Io(crate::error::io_context(
                "the cgroup id of the elevated front's leaf",
                e,
            )),
        });
    }
    let own = rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty())
        .map_err(|e| crate::error::Error::Io(crate::error::io_context("pidfd_open of this process", e.into())))?;
    // Closed before the probe forks, which needs descriptors of its own.
    let own_id = pidfd_cgroup_id(own.as_fd());
    drop(own);
    match own_id {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(e) => {
            return Err(unplaceable(
                "PIDFD_GET_INFO failed on this process's own pidfd".to_owned(),
                Some(e),
            ))
        }
    }
    untraceable_cgroup_readable(kernel).map_err(refusal)
}

/// The spawn's refusal for `why` the cgroup of a process this one may not trace is unreadable,
/// on a kernel with no `PIDFD_GET_INFO`.
fn refusal(why: Unreadable) -> crate::error::Error {
    match why {
        Unreadable::Hidden(e) => unplaceable(
            "this kernel has no PIDFD_GET_INFO (Linux 6.13 or later), and /proc hides the cgroup of a process \
             this one may not trace, as a hidepid /proc does: it would hide the elevated front's too"
                .to_owned(),
            Some(e),
        ),
        Unreadable::View(why, cause) => unplaceable(
            format!("this kernel has no PIDFD_GET_INFO (Linux 6.13 or later), and {why}"),
            cause,
        ),
        Unreadable::Probe(e) => crate::error::Error::Io(crate::error::io_context(
            "probing whether /proc shows the cgroup of a process this one may not trace",
            e,
        )),
    }
}

/// The spawn's refusal for `why`, caused by the failed call `cause`, if there was one.
fn unplaceable(why: String, cause: Option<io::Error>) -> crate::error::Error {
    crate::error::Error::Unsupported {
        op: "contain() on an elevated command".into(),
        platform: "linux",
        detail: format!(
            "{why}. cosca could not tell whether a cgroup kill reached the elevated front, so the spawn is \
             refused before anything is spawned"
        ),
        source: cause.map(crate::error::Error::io_cause),
    }
}

/// Why [`untraceable_cgroup_readable`] could not read.
#[derive(Debug)]
enum Unreadable {
    /// `/proc` hid it.
    Hidden(io::Error),
    /// This process's `/proc` view is not its own pid namespace's, or could not be told: what it
    /// says, and the error behind it, if there is one.
    View(String, Option<io::Error>),
    /// The probe itself failed: its socket, fork or reap.
    Probe(io::Error),
}

/// The probe child's exit status once its parent sent it the release byte.
const RELEASED: i32 = 0;
/// The probe child's exit status when it was not released: its socket closed or failed with no
/// byte, its descriptors could not be set up, or its parent was gone.
const ABANDONED: i32 = 1;

/// A forked probe child (see [`fork_probe`]). Dropped without [`end`](Self::end), as by an unwind,
/// it is ended all the same: no probe process outlives it.
struct Probe {
    pid: libc::pid_t,
    /// Names the child from the fork, to kill and reap it.
    pidfd: OwnedFd,
    /// The parent's end of the one socket between them. The child reports on it whether it is
    /// dumpable and its parent-death signal, a byte each; its end closes when it exits. The child
    /// exits by itself once it reads a byte from it, or once it closes, so a failed kill still ends
    /// it ([`release_probe`]). `None` once the probe is ended.
    channel: Option<std::os::unix::net::UnixStream>,
}

impl Probe {
    /// The parent's end of the socket.
    fn channel(&self) -> &std::os::unix::net::UnixStream {
        self.channel.as_ref().expect("a probe is not ended while it is read")
    }

    /// Kills the child, releases it and reaps it (see [`kill_and_reap`]).
    fn end(mut self) -> io::Result<ProbeEnd> {
        let channel = self.channel.take().expect("a probe is ended once");
        kill_and_reap(self.pid, &self.pidfd, channel)
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let Some(channel) = self.channel.take() else {
            return;
        };
        if let Err(e) = kill_and_reap(self.pid, &self.pidfd, channel) {
            log::warn!(
                "containment::cgroup: the placement probe's child {} could not be reaped ({report})",
                self.pid,
                report = crate::error::Report(&e)
            );
        }
    }
}

/// Forks the probe child of `parent`, this process's pid as recorded before the fork. The child
/// keeps only its end of the socket, where it is, is made non-dumpable (`dumpable`: left so, for a
/// test), reports `PR_GET_DUMPABLE` and `PR_GET_PDEATHSIG` on it, and waits to be killed or
/// released. It dies with its parent: `PR_SET_PDEATHSIG` is set before it reports, and a parent
/// that died before that took effect is no longer `parent`, so the child exits instead. `proc` is
/// this process's `/proc`, through which the child lists its descriptors where `close_range` is
/// refused. The child's pidfd comes from the fork ([`fork_with_pidfd`]), so it names the probe for
/// good; a fork that cannot make one is the fork's errno.
fn fork_probe(proc: &crate::identity::ProcDir, parent: libc::pid_t, dumpable: bool) -> io::Result<Probe> {
    use std::os::fd::AsRawFd;

    // Under the spawn lock, so no other fork of cosca's copies the child's end; a later probe child
    // copies this parent end and closes it first.
    let guard = crate::child::spawn::spawn_lock();
    let (channel, child_end) = std::os::unix::net::UnixStream::pair()?;
    let ends = Ends {
        child: child_end.as_raw_fd(),
        parent: channel.as_raw_fd(),
    };
    // SAFETY: this thread holds `spawn_lock`, and the child makes only async-signal-safe calls and
    // never returns into Rust.
    let forked = unsafe { fork_with_pidfd() }.map_err(io::Error::from_raw_os_error)?;
    let new = match forked {
        // SAFETY: this is the forked child.
        Fork::Child => unsafe { probe_child(proc, parent, dumpable, ends) },
        Fork::Parent(new) => new,
    };
    drop(child_end);
    // A user's logger runs outside the process-wide lock.
    drop(guard);
    if new.path == Path::Clone {
        log::debug!(
            "containment::cgroup: the placement probe's child was made by clone(CLONE_PIDFD): clone3 was refused"
        );
    }
    Ok(Probe {
        pid: new.pid,
        pidfd: new.pidfd,
        channel: Some(channel),
    })
}

/// The two ends of the probe's socket, as the forked child sees them.
#[derive(Clone, Copy)]
struct Ends {
    /// The child's end.
    child: libc::c_int,
    /// The parent's end.
    parent: libc::c_int,
}

/// The probe child's body (see [`fork_probe`]): keeps only `ends.child` ([`keep_only_own`]),
/// reports, and waits for the release byte or the socket's close.
///
/// # Safety
///
/// Called only in the child of [`fork_with_pidfd`], and bound by its contract: raw system calls only.
unsafe fn probe_child(proc: &crate::identity::ProcDir, parent: libc::pid_t, dumpable: bool, ends: Ends) -> ! {
    // SAFETY: async-signal-safe calls in the forked child.
    unsafe {
        if !keep_only_own(proc, ends) {
            libc::_exit(ABANDONED);
        }
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        if libc::getppid() != parent {
            libc::_exit(ABANDONED);
        }
        if !dumpable {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        // What the parent checks: this child is not dumpable, as a front is not, and dies with
        // its parent.
        let mut pdeathsig: libc::c_int = 0;
        libc::prctl(libc::PR_GET_PDEATHSIG, (&raw mut pdeathsig) as libc::c_ulong, 0, 0, 0);
        let report = [libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) as u8, pdeathsig as u8];
        libc::write(ends.child, report.as_ptr().cast(), report.len());
        let mut byte = 0u8;
        let read = loop {
            let n = libc::read(ends.child, (&raw mut byte).cast(), 1);
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break n;
        };
        libc::_exit(if read == 1 { RELEASED } else { ABANDONED });
    }
}

/// Closes every descriptor of this forked child but `ends.child`, which stays where it is: by
/// `close_range` (Linux 5.9), else by a walk of its `/proc/self/fd`. A fork copies every descriptor
/// of the process, another probe's parent end included, which would otherwise stay open as long as
/// this child. Needs no descriptor beyond the ones the parent holds: the parent's end is closed
/// first, which leaves the walk's directory a free number. That directory is opened before any
/// range is closed, which may close the `/proc` handle it opens through, and no range closes it: a
/// range that fails after another succeeded leaves the walk its directory. `false` if the directory
/// cannot be opened, or the walk fails.
///
/// # Safety
///
/// As [`probe_child`]'s.
unsafe fn keep_only_own(proc: &crate::identity::ProcDir, ends: Ends) -> bool {
    use std::os::fd::IntoRawFd;

    // SAFETY: async-signal-safe calls in the forked child, on descriptors it holds.
    unsafe {
        libc::close(ends.parent);
        #[cfg(test)]
        let opened = if super::fault::probe_fd_dir_fails() {
            None
        } else {
            proc.open_own_fd_dir().ok()
        };
        #[cfg(not(test))]
        let opened = proc.open_own_fd_dir().ok();
        let Some(dir) = opened.map(IntoRawFd::into_raw_fd) else {
            return false;
        };
        let close_range = |first: libc::c_uint, last: libc::c_uint| {
            #[cfg(test)]
            if super::fault::probe_close_range_refused() {
                return false;
            }
            libc::syscall(libc::SYS_close_range, first, last, 0 as libc::c_uint) == 0
        };
        let ranges = ranges_around(ends.child as libc::c_uint, dir as libc::c_uint);
        if ranges.iter().flatten().all(|&(first, last)| close_range(first, last)) {
            libc::close(dir);
            return true;
        }
        close_by_walk(dir, ends.child)
    }
}

/// The non-empty ranges of descriptors, in order, that cover every number but `kept` and `dir`:
/// below the lower, between, above the higher. `close_range` refuses an empty range.
fn ranges_around(kept: libc::c_uint, dir: libc::c_uint) -> [Option<(libc::c_uint, libc::c_uint)>; 3] {
    debug_assert_ne!(kept, dir, "the walk's directory is not the kept descriptor");
    let (low, high) = (kept.min(dir), kept.max(dir));
    [
        low.checked_sub(1).map(|last| (0, last)),
        (high - low > 1).then(|| (low + 1, high - 1)),
        high.checked_add(1).map(|first| (first, libc::c_uint::MAX)),
    ]
}

/// Closes every descriptor `dir` (this child's `/proc/self/fd`) lists but `keep` and `dir`, then
/// `dir`. A pass that closed any starts the listing over, as glibc's `closefrom` fallback does; the
/// walk ends at a pass that closes none. `false` if the listing failed.
///
/// # Safety
///
/// As [`probe_child`]'s.
unsafe fn close_by_walk(dir: libc::c_int, keep: libc::c_int) -> bool {
    /// `getdents64`'s buffer, aligned for its records.
    #[repr(C, align(8))]
    struct Buf([u8; 1024]);
    // `struct linux_dirent64`: `d_ino` (8), `d_off` (8), `d_reclen` (2), `d_type` (1), `d_name`.
    const RECLEN: usize = 16;
    const NAME: usize = 19;

    let mut buf = Buf([0; 1024]);
    // SAFETY: async-signal-safe calls in the forked child; the kernel fills `buf` with whole records.
    unsafe {
        loop {
            let n = libc::syscall(libc::SYS_getdents64, dir, buf.0.as_mut_ptr(), buf.0.len());
            if n < 0 {
                libc::close(dir);
                return false;
            }
            if n == 0 {
                break;
            }
            let mut closed = false;
            let mut at = 0;
            while at < n as usize {
                let reclen = usize::from(u16::from_ne_bytes([buf.0[at + RECLEN], buf.0[at + RECLEN + 1]]));
                let name = &buf.0[at + NAME..at + reclen];
                at += reclen;
                let mut fd: libc::c_int = 0;
                let mut digits = 0;
                for &b in name.iter().take_while(|&&b| b != 0) {
                    if !b.is_ascii_digit() {
                        digits = 0;
                        break;
                    }
                    fd = fd.wrapping_mul(10).wrapping_add(libc::c_int::from(b - b'0'));
                    digits += 1;
                }
                if digits == 0 || fd == dir || fd == keep {
                    continue;
                }
                libc::close(fd);
                closed = true;
            }
            if closed && libc::lseek(dir, 0, libc::SEEK_SET) < 0 {
                libc::close(dir);
                return false;
            }
        }
        libc::close(dir);
    }
    true
}

/// How a probe's child ended, as its reap saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeEnd {
    Signal(i32),
    Exit(i32),
    /// Reaped by another reaper, or by the kernel with `SIGCHLD` ignored (`ECHILD`).
    Elsewhere,
}

/// Kills the probe's child `pid` through its `pidfd`, releases it ([`release_probe`]) and reaps it;
/// no probe process is left unless the reap itself fails. `ECHILD` at the reap is not a failure.
/// A kill that answers `ESRCH` finds the child already dead or reaped; any
/// other failure is a `warn`, and the release ends the child.
fn kill_and_reap(pid: libc::pid_t, pidfd: &OwnedFd, channel: std::os::unix::net::UnixStream) -> io::Result<ProbeEnd> {
    #[cfg(test)]
    let seam = super::fault::run_before_probe_kill(pid).map(rustix::io::Errno::from_raw_os_error);
    #[cfg(not(test))]
    let seam: Option<rustix::io::Errno> = None;
    match kill_probe(pidfd.as_fd(), seam) {
        Ok(()) => {}
        Err(rustix::io::Errno::SRCH) => log::debug!(
            "containment::cgroup: the placement probe's child {pid} had already exited, or was reaped by another reaper in this process, when it was to be killed"
        ),
        Err(e) => log::warn!(
            "containment::cgroup: the kill of the placement probe's child {pid} failed ({report}); it is released to exit by itself",
            report = crate::error::Report(&e)
        ),
    }
    release_probe(pid, channel);
    reap_through(pid, pidfd)
}

/// Sends the probe's child `SIGKILL` through its `pidfd` and returns the kernel's answer; in a test
/// build `seam`, if set, answers in its place.
fn kill_probe(pidfd: BorrowedFd<'_>, seam: Option<rustix::io::Errno>) -> rustix::io::Result<()> {
    use rustix::process::{pidfd_send_signal, Signal};
    let sent = match seam {
        Some(errno) => Err(errno),
        None => pidfd_send_signal(pidfd, Signal::KILL),
    };
    #[cfg(test)]
    super::fault::record_probe_step(super::fault::ProbeStep::Kill(Signal::KILL.as_raw()));
    sent
}

/// Sends the probe's child `pid` its release byte and closes `channel`. Unlike the close, the byte
/// ends the child even if a process forked meanwhile holds a copy of `channel`. `MSG_NOSIGNAL`: a
/// child already gone answers `EPIPE`, not `SIGPIPE`.
fn release_probe(pid: libc::pid_t, channel: std::os::unix::net::UnixStream) {
    let sent = loop {
        match rustix::net::send(&channel, &[0], rustix::net::SendFlags::NOSIGNAL) {
            Err(rustix::io::Errno::INTR) => continue,
            other => break other,
        }
    };
    match sent {
        Ok(_) | Err(rustix::io::Errno::PIPE | rustix::io::Errno::CONNRESET) => {}
        Err(e) => log::warn!(
            "containment::cgroup: the placement probe's child {pid} could not be released ({report}); it exits once every copy of its socket closes",
            report = crate::error::Report(&e)
        ),
    }
}

/// Reaps the probe's child `pid`, which `pidfd` names, waiting for it to exit.
fn reap_through(pid: libc::pid_t, pidfd: &OwnedFd) -> io::Result<ProbeEnd> {
    let end = loop {
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED,
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::CHILD) => {
                reaped_elsewhere(pid);
                break ProbeEnd::Elsewhere;
            }
            Err(e) => return Err(io::Error::from(e)),
            Ok(Some(status)) => match status.terminating_signal() {
                Some(signo) => break ProbeEnd::Signal(signo),
                None => break ProbeEnd::Exit(status.exit_status().unwrap_or(-1)),
            },
            Ok(None) => unreachable!("a waitid without WNOHANG returns a status"),
        }
    };
    #[cfg(test)]
    super::fault::record_probe_step(super::fault::ProbeStep::Reap(end));
    Ok(end)
}

/// Notes that the probe's child `pid` was reaped elsewhere (`ECHILD` cannot tell another reaper from
/// an ignored `SIGCHLD`): nothing of the probe is left.
fn reaped_elsewhere(pid: libc::pid_t) {
    log::debug!(
        "containment::cgroup: the placement probe's child {pid} was reaped by another reaper in this process or, with SIGCHLD ignored, by the kernel as it exited"
    );
}

/// What the probe's child's `end` says of it, in words.
fn describe_end(end: ProbeEnd) -> String {
    match end {
        ProbeEnd::Signal(signo) => format!("killed by signal {signo}"),
        ProbeEnd::Exit(ABANDONED) => format!(
            "exited ABANDONED ({ABANDONED}): it could not set up its descriptors, its socket closed with no release byte, or its parent was gone"
        ),
        ProbeEnd::Exit(status) => format!("exited with status {status}"),
        ProbeEnd::Elsewhere => {
            "reaped by another reaper or, with SIGCHLD ignored, by the kernel as it exited, so its status is lost"
                .to_owned()
        }
    }
}

/// Logs how the probe's child `pid` ended: `debug` for the ends the probe makes (the kill, the
/// release), `warn` for any other, which is the child's own doing.
fn log_probe_end(pid: libc::pid_t, end: ProbeEnd) {
    match end {
        ProbeEnd::Signal(libc::SIGKILL) | ProbeEnd::Exit(RELEASED) => {
            log::debug!(
                "containment::cgroup: the placement probe's child {pid} ended: {}",
                describe_end(end)
            );
        }
        // `reaped_elsewhere` logged it.
        ProbeEnd::Elsewhere => {}
        other => log::warn!(
            "containment::cgroup: the placement probe's child {pid} ended on its own: {}",
            describe_end(other)
        ),
    }
}

/// What the probe learned from its child, before the child's end is known.
enum ProbeRead {
    /// The child reported and its cgroup read stands: the verdict, or why there is none.
    Answer(Result<(), Unreadable>),
    /// The child ended before it reported, or before the read was confirmed to have named it: these
    /// words, then its status once it is reaped, say why.
    Gone(&'static str),
}

/// Reads the cgroup of a non-dumpable child of this process (see [`front_placement`]).
fn untraceable_cgroup_readable(kernel: &dyn crate::identity::Kernel) -> Result<(), Unreadable> {
    let proc_dir = match crate::identity::proc_view_with(kernel) {
        crate::identity::ProcView::Same(dir) => dir,
        crate::identity::ProcView::Diverged => {
            return Err(Unreadable::View(
                format!(
                    "{}, so no process's cgroup can be read by its pid",
                    crate::identity::DIVERGED_REASON
                ),
                None,
            ))
        }
        crate::identity::ProcView::Unassessable(why) => {
            return Err(Unreadable::View(
                format!("this process's /proc view could not be established ({})", why.reason),
                why.source,
            ))
        }
    };
    #[cfg(test)]
    let dumpable = super::fault::probe_kept_dumpable();
    #[cfg(not(test))]
    let dumpable = false;
    let probe =
        fork_probe(&proc_dir, rustix::process::getpid().as_raw_nonzero().get(), dumpable).map_err(Unreadable::Probe)?;
    let pid = probe.pid;
    let mut ready = [0u8; 2];
    let readied = loop {
        match std::io::Read::read(&mut probe.channel(), &mut ready) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            other => break other,
        }
    };
    // A `/proc` that hides the child answers `ENOENT` under `hidepid=2`, `EPERM` under `hidepid=1`
    // (measured on Linux 7.0); a test forces one.
    #[cfg(test)]
    let hidden = super::fault::proc_hidden_as();
    #[cfg(not(test))]
    let hidden: Option<i32> = None;
    let read = match readied {
        Ok(2) if ready[0] != 0 => ProbeRead::Answer(Err(Unreadable::Probe(io::Error::other(
            "the probe's child could not make itself non-dumpable",
        )))),
        Ok(2) if i32::from(ready[1]) != libc::SIGKILL => ProbeRead::Answer(Err(Unreadable::Probe(io::Error::other(
            "the probe's child could not ask to die with its parent",
        )))),
        // The child is this process's own and unreaped, so its `/proc` entry exists: an error that
        // says otherwise, or refuses, is `/proc` hiding it. The read is by the child's number, so it
        // counts only if the child, which its pidfd names, had not exited by the time it was made: an
        // exited child may be reaped elsewhere and its number taken.
        Ok(2) => {
            let read = match hidden {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => kernel
                    .read(&proc_dir, &format!("{pid}/cgroup"))
                    .and_then(crate::identity::utf8)
                    .map(drop),
            }
            .map_err(|e| match e.raw_os_error() {
                Some(libc::ENOENT | libc::EPERM | libc::EACCES) => Unreadable::Hidden(e),
                _ => Unreadable::Probe(e),
            });
            match peek(&Target::PidFd(probe.pidfd.as_fd())) {
                Ok(PeekOutcome::Running) => ProbeRead::Answer(read),
                Ok(PeekOutcome::Exit(_) | PeekOutcome::Foreign(_)) => ProbeRead::Gone(
                    "the probe's child had exited by the time its cgroup read was confirmed, so the read may describe another process",
                ),
                Err(e) => ProbeRead::Answer(Err(Unreadable::Probe(e))),
            }
        }
        Ok(_) => ProbeRead::Gone("the probe's child died before it was ready"),
        Err(e) => ProbeRead::Answer(Err(Unreadable::Probe(e))),
    };
    let end = probe.end().map_err(Unreadable::Probe)?;
    log_probe_end(pid, end);
    match read {
        ProbeRead::Answer(answer) => answer,
        ProbeRead::Gone(why) => Err(Unreadable::Probe(io::Error::other(format!(
            "{why}: it {}",
            describe_end(end)
        )))),
    }
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod reach_tests;
