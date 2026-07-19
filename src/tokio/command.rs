//! Async `Command` builder — wraps the sync `crate::command::Command`, adding async run methods.
//! The config methods hand-mirror the sync builder (no compiler-enforced parity): mirror any new
//! sync builder method here too.

use crate::command::Command as SyncCommand;
use crate::error::Error;
use crate::stdio::Stdio;

use super::child::Child;

/// An async (tokio) process to configure and spawn — mirrors [`subprocess::Command`](crate::Command).
///
/// # Limitations
///
/// Mirror the sync API: arbitrary descriptors (fd ≥ 3) work on every platform — parent pipe ends
/// via `Child::fd_read_end`/`Child::fd_write_end` (Unix wires them through `command-fds`; Windows
/// through the raw `CreateProcessW` backend's MSVCRT fd-table). Merging into a *piped* target works
/// on all platforms, in both directions; a merge whose target is itself a merge is rejected.
#[derive(Debug, Default)]
pub struct Command {
    inner: SyncCommand,
}

impl Command {
    pub fn new() -> Command {
        Command {
            inner: SyncCommand::new(),
        }
    }
    pub fn arg<S: Into<std::ffi::OsString>>(&mut self, a: S) -> &mut Command {
        self.inner.arg(a);
        self
    }
    pub fn args<I, S>(&mut self, args: I) -> &mut Command
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        self.inner.args(args);
        self
    }
    pub fn commandline<S: Into<std::ffi::OsString>>(&mut self, line: S) -> &mut Command {
        self.inner.commandline(line);
        self
    }
    pub fn executable<P: Into<std::path::PathBuf>>(&mut self, p: P) -> &mut Command {
        self.inner.executable(p);
        self
    }
    pub fn stdin(&mut self, t: Stdio) -> Result<&mut Command, Error> {
        self.inner.stdin(t)?;
        Ok(self)
    }
    pub fn stdout(&mut self, t: Stdio) -> Result<&mut Command, Error> {
        self.inner.stdout(t)?;
        Ok(self)
    }
    pub fn stderr(&mut self, t: Stdio) -> Result<&mut Command, Error> {
        self.inner.stderr(t)?;
        Ok(self)
    }
    pub fn fd(&mut self, slot: impl Into<crate::stdio::Fd>, t: Stdio) -> Result<&mut Command, Error> {
        self.inner.fd(slot, t)?;
        Ok(self)
    }
    pub fn env(&mut self, k: impl Into<std::ffi::OsString>, v: impl Into<std::ffi::OsString>) -> &mut Command {
        self.inner.env(k, v);
        self
    }
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Command
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<std::ffi::OsString>,
        V: Into<std::ffi::OsString>,
    {
        self.inner.envs(vars);
        self
    }
    pub fn env_remove(&mut self, k: impl Into<std::ffi::OsString>) -> &mut Command {
        self.inner.env_remove(k);
        self
    }
    pub fn env_clear(&mut self) -> &mut Command {
        self.inner.env_clear();
        self
    }
    pub fn current_dir(&mut self, dir: impl Into<std::path::PathBuf>) -> &mut Command {
        self.inner.current_dir(dir);
        self
    }
    pub fn kill_on_drop(&mut self, yes: bool) -> &mut Command {
        self.inner.kill_on_drop(yes);
        self
    }
    /// Contain the child's tree with the strongest available mechanism.
    pub fn contain(&mut self) -> &mut Command {
        self.inner.contain();
        self
    }

    /// Contain with a specific [`ContainMode`](crate::ContainMode).
    pub fn contain_with(&mut self, mode: crate::ContainMode) -> &mut Command {
        self.inner.contain_with(mode);
        self
    }

    /// Set how this contained spawn marks its descendants (default
    /// [`Nesting::Mark`](crate::containment::Nesting::Mark)).
    pub fn nesting(&mut self, nesting: crate::containment::Nesting) -> &mut Command {
        self.inner.nesting(nesting);
        self
    }

    /// Spawn the child. Spawn is synchronous; the returned `Child`'s waits are async.
    ///
    /// # Runtime
    ///
    /// Must be called from within an IO-enabled Tokio runtime (the default `#[tokio::main]` /
    /// `#[tokio::test]`, or a builder with `enable_io()`/`enable_all()`), which the async waits need.
    /// Called outside any runtime, `spawn` returns [`Error::Io`](crate::error::Error::Io). On a
    /// runtime built *without* it, tokio's behavior applies and is platform-specific — on Unix `spawn`
    /// panics (child reaping needs the runtime driver: IO on Linux, signal on macOS), on Windows it
    /// currently succeeds — and tokio exposes no way to preflight it, so neither can be turned into a
    /// typed error.
    /// `status`/`output`/`read` and the [`run`](crate::tokio::run)/[`run_line`](crate::tokio::run_line)
    /// free functions spawn eagerly, so the same applies to them.
    pub fn spawn(&mut self) -> Result<Child, Error> {
        super::spawn::spawn(&mut self.inner)
    }

    /// Run to completion with inherited stdio, returning the exit status.
    pub async fn status(&mut self) -> Result<std::process::ExitStatus, Error> {
        self.inner.stdin(Stdio::inherit())?;
        self.inner.stdout(Stdio::inherit())?;
        self.inner.stderr(Stdio::inherit())?;
        let mut child = self.spawn()?;
        child.wait().await
    }

    /// Run to completion, capturing stdout and stderr (stdin is `/dev/null`).
    pub async fn output(&mut self) -> Result<crate::Output, Error> {
        self.inner.stdin(Stdio::null())?;
        self.inner.stdout(Stdio::pipe())?;
        self.inner.stderr(Stdio::pipe())?;
        let mut child = self.spawn()?;
        child.communicate(None).await
    }

    /// Run to completion, capturing stdout as a UTF-8 string (stdin is `/dev/null`).
    pub async fn read(&mut self) -> Result<String, Error> {
        self.inner.stdin(Stdio::null())?;
        self.inner.stdout(Stdio::pipe())?;
        let mut child = self.spawn()?;
        let out = child.communicate(None).await?;
        String::from_utf8(out.stdout).map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }

    /// Test-only spawn variant that installs a per-instance wait observer on the resulting raw
    /// child, so a cancellation test observes exactly THIS child's blocking wait (see the raw
    /// backend's `WaitObserver`) rather than racing a parallel test. Routes through the normal
    /// spawn, so the config must reach the raw backend (executable, uncontained, no fd >= 3).
    #[cfg(all(test, windows))]
    pub(crate) fn spawn_with_wait_observer(
        &mut self,
        started: ::tokio::sync::oneshot::Sender<()>,
        outcome: ::tokio::sync::oneshot::Sender<crate::child::spawn::windows_raw::WaitOutcome>,
    ) -> Result<Child, Error> {
        let mut child = self.spawn()?;
        child.install_wait_observer(started, outcome);
        Ok(child)
    }
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod command_tests;
