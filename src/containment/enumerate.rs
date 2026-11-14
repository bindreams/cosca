//! A `(pid, ppid)` snapshot of every process on the host — the raw material the
//! tree-walk mechanism filters by identity. Per-OS backends reuse the same
//! infrastructure as `identity`: ToolHelp on Windows, `/proc` on Linux,
//! `proc_listallpids` on macOS. `sysinfo` is deliberately NOT used: its
//! 1-second start-time granularity is useless as an ordering key, and it pulls a
//! second major `windows` version.

#[cfg(not(target_os = "linux"))]
use crate::error::Error;
use crate::identity::{Kernel, RawPid};

#[cfg_attr(windows, path = "enumerate/windows.rs")]
#[cfg_attr(target_os = "linux", path = "enumerate/linux.rs")]
#[cfg_attr(target_os = "macos", path = "enumerate/macos.rs")]
mod backend;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("cosca::containment::enumerate is implemented only for Windows, Linux, and macOS");

/// A `(pid, ppid)` pair for every currently-listable process. Best-effort: a
/// process that vanishes mid-snapshot is simply absent. Only pid/ppid are read;
/// each candidate's high-res start token is resolved later via `ProcessId::of`.
///
/// # Errors
///
/// [`Error::Unassessable`](crate::error::Error::Unassessable) naming the cause when no trustworthy
/// snapshot can be taken ([`Error::Unsupported`](crate::error::Error::Unsupported) on Linux without
/// `openat2`). An empty `Ok` means the host has no processes: a walk over a failed snapshot would
/// find no descendants and skip every kill and wait.
pub(crate) use backend::process_parents;

/// The `(pid, ppid)` snapshot of a walk ([`process_table`]), and on Linux the checked `/proc` it was read
/// through, which the walk's other reads about the same tree share: the snapshot and the root's exit
/// flag are read from one view.
pub(crate) struct Table {
    pub(crate) parents: Vec<(RawPid, RawPid)>,
    #[cfg(target_os = "linux")]
    view: crate::identity::ProcDir,
}

/// [`process_parents`], kept with the view it was read through. The errors are those of `process_parents`.
#[cfg(target_os = "linux")]
pub(crate) use backend::process_table;

/// [`process_parents`], in a [`Table`]. The errors are those of `process_parents`.
#[cfg(not(target_os = "linux"))]
pub(crate) fn process_table(kernel: &dyn Kernel) -> Result<Table, Error> {
    Ok(Table {
        parents: backend::process_parents(kernel)?,
    })
}

#[cfg(unix)]
impl Table {
    /// [`ProcessId::exit_begun_with`](crate::identity::ProcessId::exit_begun_with) of `root`, read
    /// through the `/proc` of this table on Linux.
    pub(crate) fn exit_begun(
        &self,
        kernel: &dyn Kernel,
        root: crate::identity::ProcessId,
    ) -> (crate::identity::Resolved<bool>, crate::identity::UnknownCause) {
        #[cfg(target_os = "linux")]
        {
            root.exit_begun_in(kernel, &self.view)
        }
        #[cfg(not(target_os = "linux"))]
        {
            root.exit_begun_with(kernel)
        }
    }
}

/// Every listable pid plus the `(pid, ppid)` edges plus the denied-ppid-read count, from one
/// enumeration (macOS only — the fd-marker sweep needs all three, consistently, so it cannot
/// disagree with the ppid-walk channel about the host).
#[cfg(target_os = "macos")]
pub(crate) fn snapshot() -> (Vec<RawPid>, Vec<(RawPid, RawPid)>, usize) {
    backend::snapshot()
}

/// Test-only re-export of the macOS backend's blind-snapshot fault seam — `fdmarker_tests.rs`
/// (a different module) needs it to exercise `Marker::sweep`'s `incomplete`/`Err` path
/// end-to-end, and `backend` is private to this file.
#[cfg(all(test, target_os = "macos"))]
pub(crate) fn force_blind_snapshots(count: usize) {
    backend::force_blind_snapshots(count)
}

/// Test-only re-export of the backend's fault seams, for the tree-walk propagation tests.
#[cfg(all(test, any(target_os = "macos", windows)))]
pub(crate) use backend::fault as backend_fault;
