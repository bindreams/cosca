//! The first half of making a leaf: finding the supervisor's own cgroup, and deciding whether the
//! host offers it for a leaf. [`ContainMode::Strongest`](crate::ContainMode::Strongest) decides by
//! acting: the setup calls say what the host lets this process do ([`leaf_if_offered`]), because
//! `access(2)` does not consult the path hooks of Landlock or AppArmor. It decides on `cgroup.kill`
//! as the new leaf shows it, since the hierarchy's root never shows it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
    #[cfg(test)]
    if let Some((file, root)) = fault::take_force_own_cgroup() {
        return find_in(Ok(file), &root);
    }
    find_in(fs::read_to_string(PROC_SELF_CGROUP), Path::new(CGROUP_ROOT))
}

/// The supervisor's own cgroup, if the host names one: `Ok(None)` is a host that does not (no
/// `/proc/self/cgroup`, or no `0::` line). Any other failure to read it is an error. Whether this
/// process may use that cgroup is [`leaf_if_offered`]'s to decide, by acting.
///
/// It reads state per call and keeps none.
pub(crate) fn offered_cgroup() -> Result<Option<OwnCgroup>, LeafError> {
    offered_from(find_own_cgroup())
}

/// [`offered_cgroup`] over the own cgroup as [`find_in`] answered it.
fn offered_from(found: Result<OwnCgroup, LeafError>) -> Result<Option<OwnCgroup>, LeafError> {
    match found {
        Ok(own) => Ok(Some(own)),
        Err(LeafError::ReadProcSelfCgroup(e)) if e.kind() == io::ErrorKind::NotFound => {
            log::debug!("cgroup v2: no /proc/self/cgroup, so no cgroup is offered");
            Ok(None)
        }
        Err(e @ LeafError::NoUnifiedLine { .. }) => {
            log::debug!(
                "cgroup v2: no cgroup is offered: {report}",
                report = crate::error::Report(&e)
            );
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The leaf a `Strongest` spawn gets from the own cgroup the host names (`offered`, as
/// [`offered_cgroup`] answers): `None` is a process group, `Some` a leaf that is made, and an error
/// fails the spawn. The setup calls decide, in order, before anything is forked:
///
/// 1. The own directory (held `O_PATH`) and its `cgroup.procs` (`O_WRONLY`, which moving the child
///    writes too): `EACCES`, `EPERM`, `EROFS` or `ENOENT` (the own cgroup is not visible in this
///    mount) mean the host offers no cgroup. Nothing is made yet.
/// 2. `mkdir` of the leaf: `EACCES`, `EPERM` or `EROFS` mean none; `ENOENT` is an error.
/// 3. `cgroup.procs` of the new leaf, `O_WRONLY`: `EACCES`, `EPERM` or `EROFS` mean none (a policy
///    such as Landlock or AppArmor refuses what the mode bits grant the owner); `ENOENT` is an
///    error. The leaf is removed.
/// 4. A new leaf with no `cgroup.kill` (a kernel before 5.14) is a kernel with no cgroup that can
///    kill a tree: none offered, the leaf removed. It is read on the leaf, as the hierarchy's root
///    never shows it.
///
/// Every other failure is an error: `EAGAIN` (`cgroup.max.depth`, `cgroup.max.descendants`),
/// `ENODEV`, `ENOMEM`, `EMFILE`, a `cgroup.kill` lookup that fails otherwise, the report channel,
/// the drain watch, `getrandom`, and the child's own placement. A refusal is the host stating what
/// it lets this process do, as for `cgroup.kill`; it is no hidden failure. A policy's `EPERM`
/// (seccomp) or a `/sys/fs/cgroup` that is not cgroup2 reads the same, since `mkdir` there answers
/// `EPERM`.
pub(crate) fn leaf_if_offered(
    offered: Result<Option<OwnCgroup>, LeafError>,
    teardown_warn_after: Option<std::time::Duration>,
) -> Result<Option<CgroupLeaf>, crate::error::Error> {
    let Some(own) = offered.map_err(LeafError::into_containment)? else {
        return Ok(None);
    };
    let e = match create_leaf_in(&own, teardown_warn_after) {
        Ok(leaf) => return Ok(Some(leaf)),
        Err(e) => e,
    };
    let refused = |source: &io::Error, missing_too: bool| {
        matches!(source.raw_os_error(), Some(libc::EACCES | libc::EPERM | libc::EROFS))
            || (missing_too && source.raw_os_error() == Some(libc::ENOENT))
    };
    let not_offered = match &e {
        LeafError::KillUnsupported { .. } => true,
        LeafError::OpenOwnCgroup { source, .. } => refused(source, true),
        LeafError::CreateLeafDir { source, .. } | LeafError::OpenProcs { source, .. } => refused(source, false),
        _ => false,
    };
    if not_offered {
        log::debug!(
            "cgroup v2: no cgroup is offered: {report}",
            report = crate::error::Report(&e)
        );
        return Ok(None);
    }
    Err(e.into_containment())
}

#[cfg(test)]
#[path = "own_tests.rs"]
mod own_tests;
