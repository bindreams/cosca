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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::parse::{is_at_or_under, parse_v2_relative_path};

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
/// (see [`names_leaf`]): `other_id` says the task's pidfd gave a cgroup id other than the leaf's,
/// and `recorded` answers for the leaf's own path with ` (deleted)` after it.
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
    names_leaf(path, leaf_path, other_id, recorded)
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
/// leaf is removed: the leaf's own cgroup id, its directory, its unified-hierarchy path, the ids of
/// the cgroups its sweep removed, its front's place before its removal, and whether a kill through
/// it has landed (the leaf's own record).
#[derive(Debug)]
pub(crate) struct Subtree {
    leaf_id: u64,
    dir: Option<Arc<OwnedFd>>,
    path: Option<String>,
    swept: super::Swept,
    placed: PlacedAtRemoval,
    killed: Arc<AtomicBool>,
}

impl Subtree {
    pub(crate) fn new(
        leaf_id: u64,
        dir: Option<Arc<OwnedFd>>,
        path: Option<String>,
        swept: super::Swept,
        placed: PlacedAtRemoval,
        killed: Arc<AtomicBool>,
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
    /// cgroup id (6.13+), the task is in the subtree if that id is the leaf's, or one the leaf's
    /// sweep removed, or one a walk of the leaf's descendants finds; outside if the walk finds it
    /// nowhere (see [`walk_places`](Self::walk_places)). Otherwise, before 6.13 or when the walk
    /// cannot tell, by `/proc/<pid>/cgroup`'s path. A subtree with no unified-hierarchy path (a
    /// test leaf) holds nothing that read would place.
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
        proc_names(path, pid, || self.placed.of(pid), elsewhere).map_err(|e| {
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
                         cannot be read ({e}), so it is not shown to be outside"
                    );
                    None
                }
            },
            super::Walked::Unknown(e) => {
                log::debug!("the cgroups under a leaf could not all be walked ({e})");
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
/// spawned. Placement is by a pidfd's cgroup id on Linux 6.13 and later, else by `/proc/<pid>/cgroup`
/// of a non-dumpable child, since `hidepid` hides such a process as it hides a root `sudo` front.
/// The leaf's id must be readable: `ENOSYS`, `EOPNOTSUPP` or `EPERM` is `Unsupported` naming the
/// errno, and any other error is `Io`.
///
/// `Err` is the spawn's refusal.
pub(crate) fn front_placement(leaf_id: impl FnOnce() -> io::Result<u64>) -> Result<(), crate::error::Error> {
    use std::os::fd::AsFd;

    if let Err(e) = leaf_id() {
        return Err(match e.raw_os_error() {
            Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM) => unplaceable(format!(
                "this host gives no cgroup's id by name_to_handle_at ({e}), as a kernel without CONFIG_FHANDLE, a \
                 filesystem without export operations or a seccomp filter refuses it"
            )),
            _ => crate::error::Error::Io(crate::error::io_context(
                "the cgroup id of the elevated front's leaf",
                e,
            )),
        });
    }
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

/// The probe child's exit status once its parent sent it the release byte.
const RELEASED: i32 = 0;
/// The probe child's exit status when it was not released: its release socket closed or failed
/// with no byte, its descriptors could not be set up, or its parent was gone.
const ABANDONED: i32 = 1;

/// The probe child's only descriptors once it has closed every other: the write end of its report
/// pipe, and its end of the release socket.
const CHILD_READY_FD: libc::c_int = 3;
const CHILD_RELEASE_FD: libc::c_int = 4;

/// A forked probe child (see [`fork_probe`]).
struct Probe {
    pid: libc::pid_t,
    /// How the child is killed and reaped.
    hold: Hold,
    /// Where the child reports whether it is dumpable and its parent-death signal, a byte each. Its
    /// end closes when it exits.
    ready_read: std::io::PipeReader,
    /// The child exits by itself once it reads a byte from this, or once this closes, so a kill
    /// that was not made or failed leaves it to exit rather than wait forever ([`release_probe`]).
    release: std::os::unix::net::UnixStream,
}

/// Forks the probe child of `parent`, this process's pid as recorded before the fork. The child
/// keeps only its own two descriptors, is made non-dumpable (`dumpable`: left so, for a test),
/// reports `PR_GET_DUMPABLE` and `PR_GET_PDEATHSIG` on `ready_read`, and waits to be killed or
/// released. It dies with its parent: `PR_SET_PDEATHSIG` is set before it reports, and a parent
/// that died before that took effect is no longer `parent`, so the child exits instead. `proc` is
/// this process's `/proc`, through which the child lists its descriptors where `close_range` is
/// refused.
fn fork_probe(proc: &crate::identity::ProcDir, parent: libc::pid_t, dumpable: bool) -> io::Result<Probe> {
    use std::os::fd::AsRawFd;

    // The descriptors are made, and the child's ends closed here, under the spawn lock, as every
    // fork of cosca's is: no other fork of cosca's copies the child's ends. A probe child forked
    // later copies this probe's parent ends, and closes them before anything else.
    let _guard = crate::child::spawn::spawn_lock();
    let (ready_read, ready_write) = std::io::pipe()?;
    let (release, release_end) = std::os::unix::net::UnixStream::pair()?;
    let (ready_w, release_r) = (ready_write.as_raw_fd(), release_end.as_raw_fd());
    // SAFETY: the child makes only async-signal-safe calls and never returns into Rust.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: this is the forked child.
        unsafe { probe_child(proc, parent, dumpable, ready_w, release_r) }
    }
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    drop((ready_write, release_end));
    let hold = match own_child_pidfd(pid) {
        Ok(pidfd) => Hold::Pidfd(pidfd),
        Err(Unpinned::Gone(e)) => return Err(e),
        Err(Unpinned::Failed(e)) => {
            log::warn!(
                "containment::cgroup: no pidfd pins the placement probe's child {pid} ({e}), so it is killed and reaped by its number"
            );
            Hold::Number
        }
    };
    Ok(Probe {
        pid,
        hold,
        ready_read,
        release,
    })
}

/// The probe child's body (see [`fork_probe`]): keeps only `ready_w` and `release_r`
/// ([`keep_only_own`]), reports, and waits for the release byte or the socket's close.
///
/// # Safety
///
/// Called only in a child just forked from this (multithreaded) process: it makes only
/// async-signal-safe calls.
unsafe fn probe_child(
    proc: &crate::identity::ProcDir,
    parent: libc::pid_t,
    dumpable: bool,
    ready_w: libc::c_int,
    release_r: libc::c_int,
) -> ! {
    // SAFETY: async-signal-safe calls in the forked child.
    unsafe {
        if !keep_only_own(proc, ready_w, release_r) {
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
        libc::write(CHILD_READY_FD, report.as_ptr().cast(), report.len());
        let mut byte = 0u8;
        let read = loop {
            let n = libc::read(CHILD_RELEASE_FD, (&raw mut byte).cast(), 1);
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break n;
        };
        libc::_exit(if read == 1 { RELEASED } else { ABANDONED });
    }
}

/// Moves `ready_w` and `release_r` to [`CHILD_READY_FD`] and [`CHILD_RELEASE_FD`] and closes every
/// other descriptor of this forked child: by `close_range` (Linux 5.9), else by a walk of its
/// `/proc/self/fd`. A fork copies every descriptor of the process, another probe's release end
/// included, which would otherwise stay open as long as this child. `false` if it could not.
///
/// # Safety
///
/// As [`probe_child`]'s.
unsafe fn keep_only_own(proc: &crate::identity::ProcDir, ready_w: libc::c_int, release_r: libc::c_int) -> bool {
    use std::os::fd::IntoRawFd;

    let above = CHILD_RELEASE_FD + 1;
    // SAFETY: async-signal-safe calls in the forked child, on descriptors it holds.
    unsafe {
        // Opened before the moves, which may land on `proc`'s descriptor. Each source is first
        // copied above both targets, so no move lands on a source not yet moved.
        let dir = proc
            .open_own_fd_dir()
            .map_or(-1, |dir| libc::fcntl(dir.into_raw_fd(), libc::F_DUPFD, above));
        let ready = libc::fcntl(ready_w, libc::F_DUPFD, above);
        let release = libc::fcntl(release_r, libc::F_DUPFD, above);
        if ready < 0
            || release < 0
            || libc::dup2(ready, CHILD_READY_FD) < 0
            || libc::dup2(release, CHILD_RELEASE_FD) < 0
        {
            return false;
        }
        #[cfg(test)]
        let refused = super::fault::probe_close_range_refused();
        #[cfg(not(test))]
        let refused = false;
        let close_range = |first: libc::c_uint, last: libc::c_uint| {
            libc::syscall(libc::SYS_close_range, first, last, 0 as libc::c_uint) == 0
        };
        if !refused && close_range(0, CHILD_READY_FD as libc::c_uint - 1) && close_range(above as libc::c_uint, !0) {
            return true;
        }
        dir >= 0 && close_by_walk(dir)
    }
}

/// Closes every descriptor `dir` (this child's `/proc/self/fd`) lists but [`CHILD_READY_FD`],
/// [`CHILD_RELEASE_FD`] and `dir`, then `dir`. A pass that closed any starts the listing over, as
/// glibc's `closefrom` fallback does; the walk ends at a pass that closes none. `false` if the
/// listing failed.
///
/// # Safety
///
/// As [`probe_child`]'s.
unsafe fn close_by_walk(dir: libc::c_int) -> bool {
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
                if digits == 0 || fd == dir || fd == CHILD_READY_FD || fd == CHILD_RELEASE_FD {
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

/// How the parent holds a probe's child, to kill and reap it.
enum Hold {
    /// A pidfd shown to name a child of this process ([`own_child_pidfd`]).
    Pidfd(OwnedFd),
    /// Its pid alone, when no pidfd could be opened (`EMFILE`, say): the fallback is main's, a kill
    /// and a reap by the number. The child runs until killed or released, so the number names it
    /// unless something else in the process kills it and another reaper reaps it; the kill and the
    /// reap then reach whoever holds the number: a child of this process, or, for the kill, any
    /// process. A pidfd from the fork itself (#383) removes this case.
    Number,
}

/// Why [`own_child_pidfd`] has no pidfd for the probe's child.
enum Unpinned {
    /// The child was reaped by another reaper in this process: nothing is the probe's to kill.
    Gone(io::Error),
    /// No pidfd could be opened or shown to name a child; as far as this process can tell, the number
    /// still names the probe's child.
    Failed(io::Error),
}

/// A pidfd for `pid`, a child this process just forked, opened by that number and shown to name an
/// unreaped child of this process: a pidfd that can be waited on names one. That child is the probe
/// unless the probe was killed from outside and reaped by another reaper in the process before
/// `pidfd_open`, and another child of this process took its pid; the probe's kill and reap then reach
/// that child. Obtaining the pidfd from the fork itself would close this. A pid that names no process
/// (`ESRCH`), or a pidfd that names no child of this process (`ECHILD`), is [`Unpinned::Gone`].
fn own_child_pidfd(pid: libc::pid_t) -> Result<OwnedFd, Unpinned> {
    use rustix::process::{pidfd_open, waitid, Pid, PidfdFlags, WaitId, WaitIdOptions};
    let Some(raw) = Pid::from_raw(pid) else {
        unreachable!("fork returned pid {pid} to its parent");
    };
    let gone = |e: rustix::io::Errno| {
        Unpinned::Gone(io::Error::other(format!(
            "the placement probe's child {pid} was reaped by another reaper in this process ({e})"
        )))
    };
    #[cfg(test)]
    let opened = match super::fault::run_before_probe_pin(pid) {
        Some(errno) => Err(rustix::io::Errno::from_raw_os_error(errno)),
        None => pidfd_open(raw, PidfdFlags::empty()),
    };
    #[cfg(not(test))]
    let opened = pidfd_open(raw, PidfdFlags::empty());
    let pidfd = match opened {
        Ok(pidfd) => pidfd,
        Err(e @ rustix::io::Errno::SRCH) => return Err(gone(e)),
        Err(e) => return Err(Unpinned::Failed(io::Error::from(e))),
    };
    loop {
        match waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(e @ rustix::io::Errno::CHILD) => return Err(gone(e)),
            Err(e) => return Err(Unpinned::Failed(io::Error::from(e))),
            Ok(_) => return Ok(pidfd),
        }
    }
}

/// Kills the probe's child `pid` through `hold`, releases it ([`release_probe`]), and reaps it.
/// Every exit that returns leaves no probe process, except a reap that itself fails. A kill that
/// answers `ESRCH` finds the child already dead or reaped; any other failure is a `warn`, and the
/// release ends the child. Nothing is sent by the child's number while a pidfd holds it. A reap
/// that answers `ECHILD` finds the child reaped by another reaper: it is gone, and that is no
/// failure.
fn kill_and_reap(pid: libc::pid_t, hold: Hold, release: std::os::unix::net::UnixStream) -> io::Result<()> {
    #[cfg(test)]
    let seam = super::fault::run_before_probe_kill(pid).map(rustix::io::Errno::from_raw_os_error);
    #[cfg(not(test))]
    let seam: Option<rustix::io::Errno> = None;
    let killed = match &hold {
        Hold::Pidfd(pidfd) => kill_probe(ProbeKill::Pidfd(pidfd.as_fd()), seam),
        Hold::Number => kill_probe(ProbeKill::Number(pid), seam),
    };
    match killed {
        Ok(()) => {}
        Err(rustix::io::Errno::SRCH) => log::debug!(
            "containment::cgroup: the placement probe's child {pid} had already exited, or was reaped by another reaper in this process, when it was to be killed"
        ),
        Err(e) => log::warn!(
            "containment::cgroup: the kill of the placement probe's child {pid} failed ({e}); it is released to exit by itself"
        ),
    }
    release_probe(pid, release);
    match hold {
        Hold::Pidfd(pidfd) => reap_through(pid, &pidfd),
        Hold::Number => reap_by_number(pid),
    }
}

/// How [`kill_probe`] names the probe's child.
enum ProbeKill<'a> {
    /// Through its pidfd.
    Pidfd(BorrowedFd<'a>),
    /// By its number, with the residual [`Hold::Number`] documents.
    Number(libc::pid_t),
}

/// Sends the probe's child `SIGKILL` as `kill` names it, and gives the kernel's answer; in a test
/// build `seam` answers in its place. A test build records the step once the syscall answered,
/// with the route of the syscall made.
fn kill_probe(kill: ProbeKill<'_>, seam: Option<rustix::io::Errno>) -> rustix::io::Result<()> {
    use rustix::process::{kill_process, pidfd_send_signal, Pid, Signal};
    let (signal, sent) = match (seam, &kill) {
        (Some(errno), _) => (Signal::KILL, Err(errno)),
        (None, ProbeKill::Pidfd(pidfd)) => {
            let signal = Signal::KILL;
            (signal, pidfd_send_signal(pidfd, signal))
        }
        (None, ProbeKill::Number(pid)) => match Pid::from_raw(*pid) {
            Some(pid) => {
                let signal = Signal::KILL;
                (signal, kill_process(pid, signal))
            }
            None => unreachable!("fork returned pid {pid} to its parent"),
        },
    };
    #[cfg(test)]
    super::fault::record_probe_step(super::fault::ProbeStep::Kill(
        match kill {
            ProbeKill::Pidfd(_) => crate::send_log::Via::Pidfd,
            ProbeKill::Number(_) => crate::send_log::Via::Pid,
        },
        signal.as_raw(),
    ));
    #[cfg(not(test))]
    let _ = signal;
    sent
}

/// Sends the probe's child `pid` its release byte and closes `release`. The child exits once it
/// reads the byte, which no other holder of a copy of `release` (a process forked meanwhile) can
/// hold back as it holds back the close. `MSG_NOSIGNAL`: a child already gone answers `EPIPE`, not
/// `SIGPIPE`.
fn release_probe(pid: libc::pid_t, release: std::os::unix::net::UnixStream) {
    let sent = loop {
        match rustix::net::send(&release, &[0], rustix::net::SendFlags::NOSIGNAL) {
            Err(rustix::io::Errno::INTR) => continue,
            other => break other,
        }
    };
    match sent {
        Ok(_) | Err(rustix::io::Errno::PIPE | rustix::io::Errno::CONNRESET) => {}
        Err(e) => log::warn!(
            "containment::cgroup: the placement probe's child {pid} could not be released ({e}); it exits once every copy of its release socket closes"
        ),
    }
}

/// Reaps the probe's child `pid`, which `pidfd` names, waiting for it to exit.
fn reap_through(pid: libc::pid_t, pidfd: &OwnedFd) -> io::Result<()> {
    loop {
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED,
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::CHILD) => {
                reaped_elsewhere(pid);
                #[cfg(test)]
                super::fault::record_probe_step(super::fault::ProbeStep::Reap(
                    crate::send_log::Via::Pidfd,
                    super::fault::ProbeEnd::Elsewhere,
                ));
                return Ok(());
            }
            Err(e) => return Err(io::Error::from(e)),
            Ok(status) => {
                #[cfg(test)]
                super::fault::record_probe_step(super::fault::ProbeStep::Reap(
                    crate::send_log::Via::Pidfd,
                    match status {
                        Some(status) => match status.terminating_signal() {
                            Some(signo) => super::fault::ProbeEnd::Signal(signo),
                            None => super::fault::ProbeEnd::Exit(status.exit_status().unwrap_or(-1)),
                        },
                        None => unreachable!("a waitid without WNOHANG returns a status"),
                    },
                ));
                #[cfg(not(test))]
                let _ = status;
                return Ok(());
            }
        }
    }
}

/// Reaps the probe's child `pid` by its number, with the residual [`Hold::Number`] documents.
fn reap_by_number(pid: libc::pid_t) -> io::Result<()> {
    let mut status = 0;
    loop {
        // SAFETY: a plain syscall on `pid`, this process's own child, with that residual.
        if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
            #[cfg(test)]
            super::fault::record_probe_step(super::fault::ProbeStep::Reap(
                crate::send_log::Via::Pid,
                if libc::WIFSIGNALED(status) {
                    super::fault::ProbeEnd::Signal(libc::WTERMSIG(status))
                } else {
                    super::fault::ProbeEnd::Exit(libc::WEXITSTATUS(status))
                },
            ));
            return Ok(());
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => {}
            Some(libc::ECHILD) => {
                reaped_elsewhere(pid);
                #[cfg(test)]
                super::fault::record_probe_step(super::fault::ProbeStep::Reap(
                    crate::send_log::Via::Pid,
                    super::fault::ProbeEnd::Elsewhere,
                ));
                return Ok(());
            }
            _ => return Err(e),
        }
    }
}

/// Notes that the probe's child `pid` was reaped by another reaper (`SIGCHLD` ignored, or a
/// `waitpid(-1)` elsewhere): it is gone, so nothing of the probe is left.
fn reaped_elsewhere(pid: libc::pid_t) {
    log::debug!("containment::cgroup: the placement probe's child {pid} was reaped by another reaper in this process");
}

/// Reads the cgroup of a non-dumpable child of this process (see [`front_placement`]).
fn untraceable_cgroup_readable() -> Result<(), Unreadable> {
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
    #[cfg(test)]
    let dumpable = super::fault::probe_kept_dumpable();
    #[cfg(not(test))]
    let dumpable = false;
    let Probe {
        pid,
        hold,
        ready_read,
        release,
    } = fork_probe(&proc_dir, rustix::process::getpid().as_raw_nonzero().get(), dumpable).map_err(Unreadable::Probe)?;
    let mut ready = [0u8; 2];
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
        Ok(2) if ready[0] != 0 => Err(Unreadable::Probe(io::Error::other(
            "the probe's child could not make itself non-dumpable",
        ))),
        Ok(2) if i32::from(ready[1]) != libc::SIGKILL => Err(Unreadable::Probe(io::Error::other(
            "the probe's child could not ask to die with its parent",
        ))),
        // The child is this process's own and unreaped, so its `/proc` entry exists: an error that
        // says otherwise, or refuses, is `/proc` hiding it.
        Ok(2) => match hidden {
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
    kill_and_reap(pid, hold, release).map_err(Unreadable::Probe)?;
    read
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod reach_tests;
