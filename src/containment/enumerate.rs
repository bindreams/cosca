//! A `(pid, ppid)` snapshot of every process on the host — the raw material the
//! tree-walk mechanism filters by identity. Per-OS backends reuse the same
//! infrastructure as `identity`: ToolHelp on Windows, `/proc` on Linux,
//! `proc_listallpids` on macOS. `sysinfo` is deliberately NOT used: its
//! 1-second start-time granularity is useless as an ordering key, and it pulls a
//! second major `windows` version.

use crate::identity::RawPid;

#[cfg_attr(windows, path = "enumerate/windows.rs")]
#[cfg_attr(target_os = "linux", path = "enumerate/linux.rs")]
#[cfg_attr(target_os = "macos", path = "enumerate/macos.rs")]
mod backend;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("cosca::containment::enumerate is implemented only for Windows, Linux, and macOS");

/// A `(pid, ppid)` pair for every currently-listable process. Best-effort: a
/// process that vanishes mid-snapshot is simply absent. Only pid/ppid are read;
/// each candidate's high-res start token is resolved later via `ProcessId::of`.
pub(crate) fn process_parents() -> Vec<(RawPid, RawPid)> {
    backend::process_parents()
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
pub(crate) fn force_blind_snapshot_for_next_call(force: bool) {
    backend::force_blind_snapshot_for_next_call(force)
}
