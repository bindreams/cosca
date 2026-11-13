//! The first half of making a leaf: finding the supervisor's own cgroup, and asking whether the host
//! offers it for a leaf. [`ContainMode::Strongest`](crate::ContainMode::Strongest) decides on this
//! answer, and on `cgroup.kill` as the new leaf shows it: the own directory cannot say whether the
//! kernel has it, because the hierarchy's true root never shows `cgroup.kill`, and a leaf never is
//! the root.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::{accessat, Access, AtFlags, CWD};
use rustix::io::Errno;

use super::*;

/// The supervisor's cgroup in the unified hierarchy, as the kernel prints it for this process.
const PROC_SELF_CGROUP: &str = "/proc/self/cgroup";

/// Where the cgroup v2 filesystem is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The supervisor's own cgroup: the directory a leaf is made under.
#[derive(Debug)]
pub(crate) struct OwnCgroup {
    /// Its path in the unified hierarchy, as `/proc/self/cgroup` prints it.
    rel_path: String,
    /// Its directory under the cgroup filesystem.
    dir: PathBuf,
}

impl OwnCgroup {
    pub(super) fn rel_path(&self) -> &str {
        &self.rel_path
    }

    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }

    /// What a leaf needs of this cgroup, by this process's effective ids: write and search on the
    /// directory, for the leaf's `mkdir`, and write on its `cgroup.procs`, which moving the child
    /// into the leaf writes too (this cgroup is the common ancestor of the child's cgroup and the
    /// leaf).
    fn needs(&self) -> [(PathBuf, Access); 2] {
        [
            (self.dir.clone(), Access::WRITE_OK | Access::EXEC_OK),
            (self.dir.join("cgroup.procs"), Access::WRITE_OK),
        ]
    }
}

/// The supervisor's own cgroup, from the contents of `/proc/self/cgroup` (`file`, or why it could
/// not be read) and the cgroup filesystem mounted at `root`.
fn find_in(file: io::Result<String>, root: &Path) -> Result<OwnCgroup, LeafError> {
    let file = file.map_err(LeafError::ReadProcSelfCgroup)?;
    let rel_path = parse_v2_relative_path(&file).ok_or_else(|| {
        let (line_count, controllers) = summarize_cgroup_controllers(&file);
        LeafError::NoUnifiedLine {
            line_count,
            controllers,
        }
    })?;
    Ok(OwnCgroup {
        dir: root.join(rel_path.trim_start_matches('/')),
        rel_path: rel_path.to_owned(),
    })
}

/// The supervisor's own cgroup, found for a leaf: the one read of `/proc/self/cgroup`. Errs where
/// it cannot be read or has no `0::` line; whether the cgroup can be written is not asked.
pub(super) fn find_own_cgroup() -> Result<OwnCgroup, LeafError> {
    find_in(fs::read_to_string(PROC_SELF_CGROUP), Path::new(CGROUP_ROOT))
}

/// Whether the host offers a cgroup for a leaf: the supervisor's own cgroup, with what a leaf needs
/// of it granted to this process (see [`OwnCgroup::needs`]). `Ok(None)` is a host that does not:
/// no `/proc/self/cgroup`, no `0::` line in it, or an own cgroup this process may not use (an
/// undelegated slice, a read-only cgroup filesystem, a path the filesystem does not show). Any
/// other failure, to read `/proc/self/cgroup` or to check the access, is an error.
///
/// It reads state per call and keeps none: a delegation can change between spawns.
pub(crate) fn offered_cgroup() -> Result<Option<OwnCgroup>, LeafError> {
    offered_from(find_own_cgroup())
}

/// [`offered_cgroup`] over the own cgroup as [`find_in`] answered it.
fn offered_from(found: Result<OwnCgroup, LeafError>) -> Result<Option<OwnCgroup>, LeafError> {
    let own = match found {
        Ok(own) => own,
        Err(LeafError::ReadProcSelfCgroup(e)) if e.kind() == io::ErrorKind::NotFound => {
            log::debug!("cgroup v2: no /proc/self/cgroup, so no cgroup is offered");
            return Ok(None);
        }
        Err(e @ LeafError::NoUnifiedLine { .. }) => {
            log::debug!(
                "cgroup v2: no cgroup is offered: {report}",
                report = crate::error::Report(&e)
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    for (path, access) in own.needs() {
        let answer = accessat(CWD, path.as_path(), access, AtFlags::EACCESS);
        if !grants(answer, &path)? {
            log::debug!("cgroup v2: no cgroup is offered: {} is not {access:?}", path.display());
            return Ok(None);
        }
    }
    Ok(Some(own))
}

/// What the answer of `faccessat(AT_EACCESS)` for `path` says of whether the access is granted:
/// `Ok(false)` for a refusal (`EACCES`, `EPERM`, `EROFS`) or a path that is not there (`ENOENT`),
/// and an error for any other answer, which says nothing of what is granted.
///
/// `ENOSYS` is the kernel having no `faccessat2` (before Linux 5.8). `rustix` then checks with the
/// plain `faccessat`, which is exact for a process whose effective ids are its real ones, so the
/// answer reaches this function only for one whose ids differ.
fn grants(answer: Result<(), Errno>, path: &Path) -> Result<bool, LeafError> {
    let path = || path.to_path_buf();
    match answer {
        Ok(()) => Ok(true),
        Err(Errno::ACCESS | Errno::PERM | Errno::ROFS | Errno::NOENT) => Ok(false),
        Err(source @ Errno::NOSYS) => Err(LeafError::CheckAccessUnavailable {
            path: path(),
            source: source.into(),
        }),
        Err(source) => Err(LeafError::CheckAccess {
            path: path(),
            source: source.into(),
        }),
    }
}

/// The leaf a `Strongest` spawn gets from what the host offers (`offered`, as [`offered_cgroup`]
/// answers): `None` is a process group, `Some` a leaf that is made, and an error fails the spawn.
///
/// A leaf with no `cgroup.kill` (a kernel before 5.14) is the kernel saying it has no cgroup that
/// can kill a tree, so the host offers none: a process group, with the leaf removed. It is read on
/// the new leaf and not on the own directory, because the hierarchy's root never shows
/// `cgroup.kill`. Every other failure to set up a cgroup the host offers is an error.
pub(crate) fn leaf_if_offered(
    offered: Result<Option<OwnCgroup>, LeafError>,
    teardown_warn_after: Option<std::time::Duration>,
) -> Result<Option<CgroupLeaf>, crate::error::Error> {
    let Some(own) = offered.map_err(LeafError::into_containment)? else {
        return Ok(None);
    };
    match create_leaf_in(&own, teardown_warn_after) {
        Ok(leaf) => Ok(Some(leaf)),
        Err(e @ LeafError::KillUnsupported { .. }) => {
            log::debug!(
                "cgroup v2: no cgroup is offered: {report}",
                report = crate::error::Report(&e)
            );
            Ok(None)
        }
        Err(e) => Err(e.into_containment()),
    }
}

#[cfg(test)]
#[path = "own_tests.rs"]
mod own_tests;
