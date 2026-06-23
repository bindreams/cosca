//! A `(pid, ppid)` snapshot of every process on the host — the raw material the
//! tree-walk mechanism filters by identity. Per-OS backends reuse the same
//! infrastructure as `identity`: ToolHelp on Windows, `/proc` on Linux,
//! `proc_listallpids` on macOS. We deliberately do NOT use `sysinfo` (its
//! 1-second start-time granularity is useless as an ordering key, and it pulls a
//! second major `windows` version).

use crate::identity::RawPid;

#[cfg_attr(windows, path = "enumerate/windows.rs")]
#[cfg_attr(target_os = "linux", path = "enumerate/linux.rs")]
#[cfg_attr(target_os = "macos", path = "enumerate/macos.rs")]
mod backend;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("subprocess::containment::enumerate is implemented only for Windows, Linux, and macOS");

/// A `(pid, ppid)` pair for every currently-listable process. Best-effort: a
/// process that vanishes mid-snapshot is simply absent. Only pid/ppid are read;
/// each candidate's high-res start token is resolved later via `ProcessId::of`.
pub(crate) fn process_parents() -> Vec<(RawPid, RawPid)> {
    backend::process_parents()
}
