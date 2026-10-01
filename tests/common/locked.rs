//! The ONLY place `tests/` forks a RAW `std::process::Command` (or tokio's) — one not going
//! through `cosca::Command`, which takes the same lock internally.
//!
//! Cargo runs `#[test]` fns in one binary concurrently, alongside cosca spawns and (on macOS)
//! `FdMarker` sweeps. A raw fork without the lock can inherit another spawn's transient
//! descriptors, or a live marker before it `exec`s, and a concurrent sweep can then SIGKILL it.
//! Every wrapper takes `cosca::test_spawn_lock()` around the fork only; the wait runs unlocked.
//!
//! The lock is not reentrant: never call these while holding `cosca::test_spawn_lock()` or from
//! inside a `cosca::Command` spawn; re-entry panics under `debug_assertions`. A test that must
//! hold the guard for its whole body cannot use them and calls the raw method under its own guard
//! with an `#[allow]` that says so.
//!
//! This file is also compiled into the library's tests (`src/test_spawn_tests`), which run the
//! spawn-window scenario against these exact wrappers.

use std::process::{Child, Command, ExitStatus, Output, Stdio};

/// [`Command::spawn`] under `cosca::test_spawn_lock()`.
pub fn spawn_locked(cmd: &mut Command) -> std::io::Result<Child> {
    let _guard = cosca::test_spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "`_guard` is spawn_lock")]
    cmd.spawn()
}

/// [`Command::output`] with the lock held for the spawn only. Like `output`, it overrides stdin
/// (null) and stdout/stderr (piped), discarding any caller setting.
pub fn output_locked(cmd: &mut Command) -> std::io::Result<Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    spawn_locked(cmd)?.wait_with_output()
}

/// [`Command::status`] with the lock held for the spawn only.
pub fn status_locked(cmd: &mut Command) -> std::io::Result<ExitStatus> {
    spawn_locked(cmd)?.wait()
}

/// `tokio::process::Command::spawn` under `cosca::test_spawn_lock()`.
#[cfg(feature = "tokio")]
pub fn spawn_locked_tokio(cmd: &mut ::tokio::process::Command) -> std::io::Result<::tokio::process::Child> {
    let _guard = cosca::test_spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "`_guard` is spawn_lock")]
    cmd.spawn()
}

/// The tokio twin of [`output_locked`], with the same stdio override.
#[cfg(feature = "tokio")]
pub async fn output_locked_tokio(cmd: &mut ::tokio::process::Command) -> std::io::Result<Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    spawn_locked_tokio(cmd)?.wait_with_output().await
}

/// The tokio twin of [`status_locked`].
#[cfg(feature = "tokio")]
pub async fn status_locked_tokio(cmd: &mut ::tokio::process::Command) -> std::io::Result<ExitStatus> {
    spawn_locked_tokio(cmd)?.wait().await
}

/// Creates `path` with `mode` (truncating any file there), lets `fill` write its contents and
/// closes it, all under `cosca::test_spawn_lock()`. Every file a test execs is written here or by
/// [`write_opened_executable_locked`].
///
/// A fork while the file is open for writing leaves the forked child a copy of the descriptor
/// until it execs or exits, and `execve` of the file fails with `ETXTBSY` until then. Every fork in
/// a process that runs other tests takes this lock, so none lands inside the write. Renaming a
/// finished file into place would not help: the rename keeps the inode that the copy refers to.
///
/// `fill` runs under the lock, so it must not spawn.
#[cfg(unix)]
pub fn write_executable_locked(
    path: &std::path::Path,
    mode: u32,
    fill: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let open = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
    };
    write_opened_executable_locked(open, mode, fill)
}

/// [`write_executable_locked`] for a caller that opens the file itself, relative to a directory
/// descriptor, say. `open` runs under the lock too.
#[cfg(unix)]
pub fn write_opened_executable_locked(
    open: impl FnOnce() -> std::io::Result<std::fs::File>,
    mode: u32,
    fill: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let _guard = cosca::test_spawn_lock();
    let mut file = open()?;
    fill(&mut file)?;
    // The umask may have narrowed the create mode.
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    drop(file);
    Ok(())
}
