//! Shared helpers for the Windows `ShellExecuteExW`/elevation probe suite: `tests/windows_shell_execute.rs`,
//! `tests/windows_shell_resolution/` and `tests/windows_elevation_routes/`. The same sharing
//! mechanism `tests/common/mod.rs` documents for cross-file test helpers — `#[path =
//! "common/windows_probe.rs"] mod windows_probe;` — applied to this Windows-only subset so the
//! marker-write, file-name-comparison and COM-apartment-wrapper patterns are defined once instead
//! of hand-copied into each probe file.
#![cfg(windows)]
#![allow(dead_code)] // each consumer uses only the subset it needs

use std::path::Path;

use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};

/// Record that the current test ran to a real conclusion, as a file named after the test's thread
/// in the directory `env_var` names, when that variable is set — a no-op otherwise. Each probe
/// file's own CI job requires this marker to fail a run whose test filter matched nothing.
/// `windows_shell_execute.rs` uses `COSCA_CANARY_MARKERS`; `windows_elevation_routes.rs` and
/// `windows_shell_resolution.rs` use `COSCA_PROBE_MARKERS` — two different marker directories for
/// two different CI jobs, so the variable name is a parameter here, not baked in.
pub(crate) fn mark_test_passed(env_var: &str) {
    let Some(dir) = std::env::var_os(env_var) else {
        return;
    };
    let name = std::thread::current()
        .name()
        .expect("libtest names each test's thread")
        .replace("::", ".");
    std::fs::write(Path::new(&dir).join(name), b"")
        .unwrap_or_else(|e| panic!("could not write the {env_var} marker: {e}"));
}

/// Whether `reported` names the same file as `want`, by file name only: a self-report's directory
/// component may come back short-named (`RUNNER~1`) even though the file name itself never does.
pub(crate) fn same_file(reported: &Path, want: &Path) -> bool {
    let want = want
        .file_name()
        .expect("a planted path has a file name")
        .to_string_lossy();
    reported
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(&want))
}

/// Initialise a single-threaded COM apartment on this thread, run `f`, then uninitialise it — the
/// sequence Microsoft documents as required before `ShellExecuteExW`. `on_com_failure` builds the
/// caller's own error type from the `CoInitializeEx` failure message, since each caller here
/// reports it through a different error type. The init, the call and the uninit all run on THIS
/// thread: a COM apartment is thread-local, so `f` must not hand the actual `ShellExecuteExW` call
/// off to another thread.
pub(crate) fn in_com_apartment<T, E>(
    on_com_failure: impl FnOnce(String) -> E,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    // SAFETY: paired with the CoUninitialize below, on this same thread.
    let com = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    if com.is_err() {
        return Err(on_com_failure(format!("CoInitializeEx: {com:?}")));
    }
    let result = f();
    // SAFETY: balances the successful CoInitializeEx above, still on this thread.
    unsafe { CoUninitialize() };
    result
}
