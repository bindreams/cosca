//! The first half of making a leaf: finding the supervisor's own cgroup, and asking whether the host
//! offers it for a leaf. [`ContainMode::Strongest`](crate::ContainMode::Strongest) decides on this
//! answer, and on `cgroup.kill` as the new leaf shows it: the own directory cannot say whether the
//! kernel has it, because the hierarchy's true root never shows `cgroup.kill`, and a leaf never is
//! the root.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::*;

/// Where the cgroup v2 filesystem is mounted.
#[cfg(target_os = "linux")]
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The supervisor's own cgroup: the directory a leaf is made under.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct OwnCgroup {
    /// Its path in the unified hierarchy, as `/proc/self/cgroup` prints it.
    rel_path: String,
    /// Its directory under the cgroup filesystem.
    dir: PathBuf,
}

#[cfg(target_os = "linux")]
impl OwnCgroup {
    pub(super) fn rel_path(&self) -> &str {
        &self.rel_path
    }

    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether this process, by its effective ids, may write the directory: the delegation a leaf's
    /// `mkdir` needs.
    fn writable(&self) -> io::Result<()> {
        use rustix::fs::{accessat, Access, AtFlags, CWD};
        Ok(accessat(CWD, self.dir.as_path(), Access::WRITE_OK, AtFlags::EACCESS)?)
    }
}

/// The supervisor's own cgroup, from the contents of `/proc/self/cgroup` (`file`, or why it could
/// not be read) and the cgroup filesystem mounted at `root`.
#[cfg(target_os = "linux")]
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

/// The supervisor's own cgroup, found for a leaf. Errs where `/proc/self/cgroup` cannot be read or
/// has no `0::` line; whether the cgroup can be written is not asked.
#[cfg(target_os = "linux")]
pub(super) fn find_own_cgroup() -> Result<OwnCgroup, LeafError> {
    find_in(fs::read_to_string("/proc/self/cgroup"), Path::new(CGROUP_ROOT))
}

/// Whether the host offers a cgroup for a leaf: the supervisor's own cgroup, writable by this
/// process. `Ok(None)` is a host that does not: no `/proc/self/cgroup`, no `0::` line in it, or an
/// own cgroup this process may not write (an undelegated slice, a read-only cgroup filesystem, a
/// path the filesystem does not show). Any other failure to read `/proc/self/cgroup` is an error.
///
/// It reads two files' worth of state per call and keeps none: a delegation can change between
/// spawns.
#[cfg(target_os = "linux")]
pub(crate) fn offered_cgroup() -> Result<Option<OwnCgroup>, LeafError> {
    offered_in(fs::read_to_string("/proc/self/cgroup"), Path::new(CGROUP_ROOT))
}

/// [`offered_cgroup`] over an explicit `/proc/self/cgroup` read and cgroup filesystem mount.
#[cfg(target_os = "linux")]
fn offered_in(file: io::Result<String>, root: &Path) -> Result<Option<OwnCgroup>, LeafError> {
    let own = match find_in(file, root) {
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
    match own.writable() {
        Ok(()) => Ok(Some(own)),
        Err(e) => {
            log::debug!(
                "cgroup v2: no cgroup is offered: {} is not writable ({})",
                own.dir.display(),
                crate::error::Report(&e)
            );
            Ok(None)
        }
    }
}

/// The leaf a `Strongest` spawn gets from what the host offers (`offered`, as [`offered_cgroup`]
/// answers): `None` is a process group, `Some` a leaf that is made, and an error fails the spawn.
///
/// A leaf with no `cgroup.kill` (a kernel before 5.14) is the kernel saying it has no cgroup that
/// can kill a tree, so the host offers none: a process group, with the leaf removed. It is read on
/// the new leaf and not on the own directory, because the hierarchy's root never shows
/// `cgroup.kill`. Every other failure to set up a cgroup the host offers is an error.
#[cfg(target_os = "linux")]
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

#[cfg(all(test, target_os = "linux"))]
#[path = "own_tests.rs"]
mod own_tests;
