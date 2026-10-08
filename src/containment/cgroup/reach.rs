//! Whether a task is in a leaf's cgroup subtree, by reads that each end: none waits on the task.
//!
//! - **Linux 6.13+:** `PIDFD_GET_INFO`'s cgroup id, through the task's pidfd, compared with the
//!   leaf's own id. A task keeps its cgroup until it is freed, so a killed task on its way out, or
//!   a zombie, still has the leaf's id; a task moved out has its new cgroup's. Measured on Linux
//!   7.0. Another id is looked for among the cgroups under the leaf: those its sweep removed, then
//!   those a walk of the leaf's descendants finds.
//! - **Otherwise:** `/proc/<pid>/cgroup`'s path, compared with the leaf's. A `hidepid` `/proc`
//!   hides it for a task of another user (a root front), so an elevated spawn that would need it
//!   is refused (see [`front_placement`]).
//!
//! A task killed through the leaf and then moved by someone else before it exits reads as moved
//! before its kill, by either read.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::parse::{is_at_or_under, parse_v2_relative_path};

/// `_IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)`, with the 64-byte first version of the struct.
/// The request is the same 32 bits under glibc's `unsigned long` and musl's `int`.
const PIDFD_GET_INFO: libc::Ioctl = 0xC040_FF0B_u32 as libc::Ioctl;
/// `PIDFD_INFO_CGROUPID`.
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
    if super::fault::pidfd_info_fails() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
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
/// (see [`names_leaf`]), with `leaf` and `parent` the leaf's directory and its parent's.
pub(crate) fn proc_names(
    leaf_path: &str,
    pid: u32,
    leaf: Option<BorrowedFd<'_>>,
    parent: Option<BorrowedFd<'_>>,
) -> io::Result<bool> {
    #[cfg(test)]
    if let Some(errno) = super::fault::proc_hidden_as() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    let proc_dir = match crate::identity::proc_view() {
        crate::identity::ProcView::Same(dir) => dir,
        crate::identity::ProcView::Diverged => {
            return Err(io::Error::other(format!(
                "this process's /proc is an outer pid namespace's, so pid {pid}'s cgroup cannot be read"
            )));
        }
        crate::identity::ProcView::Unassessable(why) => {
            let kind = why.source.as_ref().map_or(io::ErrorKind::Other, io::Error::kind);
            return Err(io::Error::new(
                kind,
                format!(
                    "the /proc view could not be established, so pid {pid}'s cgroup cannot be read: {}",
                    why.reason
                ),
            ));
        }
    };
    let text = proc_dir.read_to_string(&format!("{pid}/cgroup"))?;
    let path = parse_v2_relative_path(&text)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no cgroup v2 `0::` line"))?;
    names_leaf(
        path,
        leaf_path,
        || leaf.map_or(Ok(false), removed),
        || {
            let name = leaf_path.rsplit('/').next().unwrap_or(leaf_path);
            parent.map_or(Ok(false), |parent| exists(parent, &format!("{name}{DELETED}")))
        },
    )
}

/// What `/proc/<pid>/cgroup` prints after the path of a removed cgroup.
const DELETED: &str = " (deleted)";

/// Whether the cgroup `path` (from `/proc/<pid>/cgroup`) is the leaf at `leaf_path` or under it.
/// A removed cgroup's path is printed with [`DELETED`] after it, which a live cgroup may also have
/// in its name. A path under the leaf is under it either way. The leaf's own path with the suffix
/// is the leaf only if `leaf_removed` says the leaf is gone; and then only if
/// `sibling_named_so` says no live cgroup beside it has that name, else it is undecidable.
pub(crate) fn names_leaf(
    path: &str,
    leaf_path: &str,
    leaf_removed: impl FnOnce() -> io::Result<bool>,
    sibling_named_so: impl FnOnce() -> io::Result<bool>,
) -> io::Result<bool> {
    if is_at_or_under(path, leaf_path) {
        return Ok(true);
    }
    if path.strip_suffix(DELETED) != Some(leaf_path) || !leaf_removed()? {
        return Ok(false);
    }
    if sibling_named_so()? {
        return Err(io::Error::other(format!(
            "{path} is either the removed leaf or the live cgroup beside it of that name"
        )));
    }
    Ok(true)
}

/// Whether the cgroup directory `dir` holds is removed: its files are gone with it.
fn removed(dir: BorrowedFd<'_>) -> io::Result<bool> {
    match rustix::fs::openat(
        dir,
        "cgroup.events",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(_) => Ok(false),
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NODEV) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// Whether `name` is in `dir`.
fn exists(dir: BorrowedFd<'_>, name: &str) -> io::Result<bool> {
    match rustix::fs::statat(dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// A leaf's subtree, captured while the leaf exists, so a task can be placed in it even once the
/// leaf is removed: the leaf's own cgroup id, its directory and its parent's, its unified-hierarchy
/// path, the ids of the cgroups its sweep removed, and whether a kill through it has landed (the
/// leaf's own record).
#[derive(Debug)]
pub(crate) struct Subtree {
    leaf_id: u64,
    dir: Option<Arc<OwnedFd>>,
    parent: Option<Arc<OwnedFd>>,
    path: Option<String>,
    swept: super::Swept,
    killed: Arc<AtomicBool>,
}

impl Subtree {
    pub(crate) fn new(
        leaf_id: u64,
        dir: Option<Arc<OwnedFd>>,
        parent: Option<Arc<OwnedFd>>,
        path: Option<String>,
        swept: super::Swept,
        killed: Arc<AtomicBool>,
    ) -> Subtree {
        Subtree {
            leaf_id,
            dir,
            parent,
            path,
            swept,
            killed,
        }
    }

    /// Whether the task `pid`, which `pidfd` names when there is one, is in this subtree. Where the
    /// kernel gives a pidfd's cgroup id (6.13+), it is in the subtree if that id is the leaf's, or
    /// one the leaf's sweep removed, or one a walk of the leaf's descendants finds; outside if the
    /// walk finds it nowhere (see [`walk_places`](Self::walk_places)). Otherwise, before 6.13 or
    /// when the walk cannot tell, by `/proc/<pid>/cgroup`'s path. A subtree with no
    /// unified-hierarchy path (a test leaf) holds nothing that read would place. Every read is
    /// bounded: the walk by the cgroups under the leaf, which are finite.
    pub(crate) fn holds(&self, pid: u32, pidfd: Option<BorrowedFd<'_>>) -> io::Result<bool> {
        let mut elsewhere = false;
        if let Some(pidfd) = pidfd {
            if let Some(id) = pidfd_cgroup_id(pidfd)? {
                if id == self.leaf_id || self.swept.holds(id) {
                    return Ok(true);
                }
                if let Some(under) = self.walk_places(id) {
                    return Ok(under);
                }
                elsewhere = true;
            }
        }
        let Some(path) = &self.path else {
            return Ok(false);
        };
        let (leaf, parent) = (
            self.dir.as_deref().map(AsFd::as_fd),
            self.parent.as_deref().map(AsFd::as_fd),
        );
        proc_names(path, pid, leaf, parent).map_err(|e| {
            if elsewhere {
                io::Error::new(
                    e.kind(),
                    format!(
                        "pid {pid} is in another cgroup than its leaf, maybe one under it, and that cgroup's path \
                         cannot be read ({e})"
                    ),
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
            super::Walked::Absent => (self.dying() == Some(0)).then_some(false),
            super::Walked::Unknown(e) => {
                log::debug!("the cgroups under a leaf could not all be walked ({e})");
                None
            }
        }
    }

    /// How many cgroups under the leaf are removed but not yet freed, by its `cgroup.stat`; `None`
    /// if that cannot be read, as once the leaf is removed.
    fn dying(&self) -> Option<u64> {
        let dir = self.dir.as_ref()?;
        let file = rustix::fs::openat(
            dir.as_fd(),
            "cgroup.stat",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .ok()?;
        let text = io::read_to_string(std::fs::File::from(file)).ok()?;
        dying_in(&text)
    }

    /// Whether a kill through the leaf landed and reached the task `pid` (see [`holds`](Self::holds)):
    /// only then does the task's exit follow, so only then may it be waited for.
    pub(crate) fn reached(&self, pid: u32, pidfd: Option<BorrowedFd<'_>>) -> io::Result<bool> {
        if !self.killed.load(Ordering::Relaxed) {
            return Ok(false);
        }
        self.holds(pid, pidfd)
    }
}

/// `nr_dying_descendants` in a `cgroup.stat`'s `text`.
fn dying_in(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("nr_dying_descendants ")?.trim().parse::<u64>().ok())
}

/// Whether this host can place an elevation front after a cgroup kill, decided before any front is
/// spawned: on Linux 6.13 and later by a pidfd's cgroup id, which no `/proc` mount option hides;
/// before, by `/proc/<pid>/cgroup` of a process this one may not trace, as it may not trace a
/// front: sudo runs as root, and a setuid program is not dumpable. `hidepid` hides exactly such a
/// process, whatever its user, from a caller without `CAP_SYS_PTRACE` (measured on Linux 7.0: a
/// non-dumpable child of this process and a sudo front alike, `ENOENT` under `hidepid=2`, `EPERM`
/// under `hidepid=1`, and readable without it or by root). The process read is a child forked for
/// it, made non-dumpable (which it reports), then killed and reaped. Neither read depends on when the
/// front would run: no front exists yet.
///
/// `Err` is the spawn's refusal: `Unsupported`, naming the cause.
pub(crate) fn front_placement() -> Result<(), crate::error::Error> {
    use std::os::fd::AsFd;

    let own = rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty())
        .map_err(|e| crate::error::Error::Io(crate::error::io_context("pidfd_open of this process", e.into())))?;
    match pidfd_cgroup_id(own.as_fd()) {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(e) => {
            return Err(unplaceable(format!(
                "PIDFD_GET_INFO failed on this process's own pidfd ({e})"
            )))
        }
    }
    untraceable_cgroup_readable().map_err(refusal)
}

/// The spawn's refusal for `why` the cgroup of a process this one may not trace is unreadable,
/// on a kernel with no `PIDFD_GET_INFO`.
fn refusal(why: Unreadable) -> crate::error::Error {
    match why {
        Unreadable::Hidden(e) => unplaceable(format!(
            "this kernel has no PIDFD_GET_INFO (Linux 6.13 or later), and /proc hides the cgroup of a process \
             this one may not trace ({e}), as a hidepid /proc does: it would hide the elevated front's too"
        )),
        Unreadable::View(why) => unplaceable(format!(
            "this kernel has no PIDFD_GET_INFO (Linux 6.13 or later), and {why}"
        )),
        Unreadable::Probe(e) => crate::error::Error::Io(crate::error::io_context(
            "probing whether /proc shows the cgroup of a process this one may not trace",
            e,
        )),
    }
}

fn unplaceable(why: String) -> crate::error::Error {
    crate::error::Error::Unsupported {
        op: "contain() on an elevated command".into(),
        platform: "linux",
        detail: format!(
            "{why}. cosca could not tell whether a cgroup kill reached the elevated front, so the spawn is \
             refused before anything is spawned"
        ),
    }
}

/// Why [`untraceable_cgroup_readable`] could not read.
#[derive(Debug)]
enum Unreadable {
    /// `/proc` hid it.
    Hidden(io::Error),
    /// This process's `/proc` view is not its own pid namespace's, or could not be told.
    View(String),
    /// The probe itself failed: its pipe, fork or reap.
    Probe(io::Error),
}

/// Reads the cgroup of a non-dumpable child of this process (see [`front_placement`]).
fn untraceable_cgroup_readable() -> Result<(), Unreadable> {
    use std::os::fd::AsRawFd;

    let proc_dir = match crate::identity::proc_view() {
        crate::identity::ProcView::Same(dir) => dir,
        crate::identity::ProcView::Diverged => {
            return Err(Unreadable::View(
                "this process's /proc is an outer pid namespace's, so no process's cgroup can be read by its pid"
                    .into(),
            ))
        }
        crate::identity::ProcView::Unassessable(why) => {
            return Err(Unreadable::View(format!(
                "this process's /proc view could not be established ({})",
                why.reason
            )))
        }
    };
    let (ready_read, ready_write) = std::io::pipe().map_err(Unreadable::Probe)?;
    let (ready_r, ready_w) = (ready_read.as_raw_fd(), ready_write.as_raw_fd());
    // The fork is under the spawn lock, as every fork of cosca's is, so no other spawn's descriptor
    // is copied into the child mid-handshake.
    let _guard = crate::child::spawn::spawn_lock();
    #[cfg(test)]
    let dumpable = super::fault::probe_kept_dumpable();
    #[cfg(not(test))]
    let dumpable = false;
    // SAFETY: the child makes only async-signal-safe syscalls, then waits for the parent's kill; it
    // never returns into Rust.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: async-signal-safe syscalls in the forked child.
        unsafe {
            libc::close(ready_r);
            if !dumpable {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            }
            // What the parent checks: this child is not dumpable, as a front is not.
            let byte = libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) as u8;
            libc::write(ready_w, (&raw const byte).cast(), 1);
            loop {
                libc::pause();
            }
        }
    }
    if pid < 0 {
        return Err(Unreadable::Probe(io::Error::last_os_error()));
    }
    drop(ready_write);
    let mut ready = [0u8; 1];
    let readied = loop {
        match std::io::Read::read(&mut &ready_read, &mut ready) {
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
        Ok(1) if ready[0] != 0 => Err(Unreadable::Probe(io::Error::other(
            "the probe's child could not make itself non-dumpable",
        ))),
        // The child is this process's own and unreaped, so its `/proc` entry exists: an error that
        // says otherwise, or refuses, is `/proc` hiding it.
        Ok(1) => match hidden {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => proc_dir.read_to_string(&format!("{pid}/cgroup")).map(drop),
        }
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ENOENT | libc::EPERM | libc::EACCES) => Unreadable::Hidden(e),
            _ => Unreadable::Probe(e),
        }),
        Ok(_) => Err(Unreadable::Probe(io::Error::other(
            "the probe's child died before it was ready",
        ))),
        Err(e) => Err(Unreadable::Probe(e)),
    };
    // SAFETY: `pid` is this function's own unreaped child, so the number names it.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status = 0;
    loop {
        // SAFETY: `pid` is this function's own unreaped child.
        if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(Unreadable::Probe(e));
        }
    }
    read
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod reach_tests;
