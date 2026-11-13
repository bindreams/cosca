//! Async `Command` builder — wraps the sync `crate::command::Command`, adding async run methods.
//! The config methods hand-mirror the sync builder; parity is not compiler-enforced.

use crate::command::Command as SyncCommand;
use crate::error::Error;
use crate::stdio::Stdio;

use super::child::Child;

/// An async (tokio) process to configure and spawn — mirrors [`cosca::Command`](crate::Command).
///
/// # Limitations
///
/// Mirror the sync API: arbitrary descriptors (fd ≥ 3) work on every platform — parent pipe ends
/// via `Child::fd_read_end`/`Child::fd_write_end` (Unix wires them through `fd_map`; Windows
/// through the raw `CreateProcessW` backend's MSVCRT fd-table). Merging into a *piped* target works
/// on all platforms, in both directions; a merge whose target is itself a merge is rejected.
#[derive(Debug, Default)]
pub struct Command {
    inner: SyncCommand,
}

impl Command {
    /// The sync builder this one wraps, for the frozen spawn, which shares its core.
    pub(crate) fn as_sync_mut(&mut self) -> &mut SyncCommand {
        &mut self.inner
    }

    /// The sync builder this one wraps, to read what a spawn did to it.
    #[cfg(test)]
    pub(crate) fn sync(&self) -> &SyncCommand {
        &self.inner
    }

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
    /// Mirrors [`cosca::Command::raw_executable`](crate::Command::raw_executable) — see there for
    /// the contract.
    pub fn raw_executable<P: Into<std::path::PathBuf>>(&mut self, p: P) -> &mut Command {
        self.inner.raw_executable(p);
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
    /// Async mirror of [`Command::kill_on_drop`](crate::Command::kill_on_drop) — see there for
    /// what the teardown does. The per-child opt-out is
    /// [`Child::detach`](crate::tokio::Child::detach).
    pub fn kill_on_drop(&mut self, yes: bool) -> &mut Command {
        self.inner.kill_on_drop(yes);
        self
    }
    /// Contain the child's tree with the strongest available mechanism. See
    /// [`Command::contain`](crate::Command::contain) for a child reaped by something else.
    ///
    /// A spawn that fails after forking the child tears it down, as the sync
    /// [`Command::spawn`](SyncCommand::spawn) does. On Linux the spawn's pidfd kills and reaps the
    /// root, and a child contained in a cgroup leaf ([`Containment::CgroupV2`](crate::Containment::CgroupV2))
    /// is killed with its leaf. On Linux 6.9+ a process-group or session root's whole group is
    /// killed too, through the root's pidfd, while the group has a member, whoever reaped the root.
    /// Below 6.9 the root alone is killed, and a `warn` says the group's members may be left
    /// running. An elevation front is the exception: it is sent no signal of its own and no group
    /// kill, and is reaped only if it had exited, as its error says; a cgroup leaf's kill still ends
    /// what is in the leaf. Elsewhere this failure leaves the child running.
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

    /// Do not put a console window on the user's screen — mirrors
    /// [`no_window`](crate::Command::no_window), including the per-path lowering and the
    /// one-directional console consequence documented there.
    pub fn no_window(&mut self) -> &mut Command {
        self.inner.no_window();
        self
    }

    /// Spawn with `DETACHED_PROCESS` — mirrors [`detached`](crate::Command::detached).
    #[cfg(windows)]
    pub fn detached(&mut self) -> &mut Command {
        self.inner.detached();
        self
    }

    /// Spawn outside this process's job object — mirrors
    /// [`breakaway_from_job`](crate::Command::breakaway_from_job), including everything it does
    /// not promise.
    #[cfg(windows)]
    pub fn breakaway_from_job(&mut self) -> &mut Command {
        self.inner.breakaway_from_job();
        self
    }

    /// Add arbitrary `dwCreationFlags` bits — mirrors
    /// [`creation_flags`](crate::Command::creation_flags), including its reserved-bit table and
    /// its replace-not-accumulate semantics.
    #[cfg(windows)]
    pub fn creation_flags(&mut self, flags: u32) -> &mut Command {
        self.inner.creation_flags(flags);
        self
    }

    /// Run the child elevated — mirrors [`cosca::Command::elevate`](crate::Command::elevate).
    pub fn elevate(&mut self) -> &mut Command {
        self.inner.elevate();
        self
    }
    /// Select the elevation backend — mirrors
    /// [`elevation_backend`](crate::Command::elevation_backend).
    pub fn elevation_backend(&mut self, backend: crate::elevation::Backend) -> &mut Command {
        self.inner.elevation_backend(backend);
        self
    }
    /// Select how the backend authenticates — mirrors
    /// [`elevation_auth`](crate::Command::elevation_auth).
    pub fn elevation_auth(&mut self, auth: crate::elevation::Auth) -> &mut Command {
        self.inner.elevation_auth(auth);
        self
    }
    /// Set the env sanitizer applied before forwarding to the backend — mirrors
    /// [`sanitize_env`](crate::Command::sanitize_env).
    pub fn sanitize_env(&mut self, sanitizer: crate::elevation::EnvSanitizer) -> &mut Command {
        self.inner.sanitize_env(sanitizer);
        self
    }

    /// Spawn the child. The returned `Child`'s waits are async.
    ///
    /// The whole sync spawn runs on tokio's blocking pool, so nothing in it blocks the runtime: not
    /// an elevation backend's setup (`pkexec --version`, the UAC consent prompt, the password
    /// delivered to `sudo -S`), not the wait for `exec`, and not the teardown of a spawn that fails
    /// after its child exists (a cgroup leaf's drain among it).
    ///
    /// # Runtime
    ///
    /// Must be called from within a Tokio runtime, and one with the IO driver enabled (the default
    /// `#[tokio::main]` / `#[tokio::test]`, or a builder with `enable_io()`/`enable_all()`) for the
    /// child's waits and pipes. Called outside any runtime, `spawn` returns
    /// [`Error::Io`](crate::error::Error::Io). `spawn` itself does not need the IO driver: on a
    /// runtime built without it, the child starts, and on Unix its first wait panics if the child
    /// is still running (the wait registers it with the reactor: IO on Linux, signal on macOS), as
    /// taking a pipe does on any platform. tokio exposes no way to preflight
    /// the driver, so the panic cannot be turned into a typed error.
    /// `status`/`output`/`read` and the [`run`](crate::tokio::run)/[`run_line`](crate::tokio::run_line)
    /// free functions spawn eagerly, so the same applies to them.
    ///
    /// # Dropping the future
    ///
    /// A future that is never polled does nothing, and leaves the command as it was. The first poll
    /// moves the command into the blocking task. When the spawn completes, it succeeded or not, the
    /// command is moved back, as the sync spawn leaves it: the fds taken, the arguments, environment
    /// and the rest kept. A future dropped after its first poll leaves the command as
    /// [`Command::new`] makes it: rebuild it before a reuse. So does a spawn that ends without
    /// moving the command back: one that panics (the panic is resumed) and one the runtime's
    /// shutdown cancels. Called with no runtime, `spawn` leaves the command as it was.
    ///
    /// The spawn is not cancelled by the drop: it runs to its end on the pool, and a child it made
    /// (also one finished before the drop, or started by a UAC yes) is dropped there as a dropped
    /// [`Child`] is: killed and reaped with [`kill_on_drop`](Self::kill_on_drop) (the default), left
    /// running without. An elevated child the drop cannot kill is warned about and left. A failed
    /// spawn's teardown finishes on the pool too, and a UAC prompt stays on screen until it is
    /// answered.
    ///
    /// The thread that drops a finished spawn's child depends on where the future is dropped. The
    /// child reaches the future over a channel, so that a runtime thread need not run its
    /// destructor, which may wait. A future dropped before the task finished leaves the child to the
    /// task, which drops it on the pool. One dropped after the task finished hands the child to the
    /// pool when the drop is inside a running runtime, and drops it on the dropping thread outside a
    /// runtime or once the runtime's shutdown began.
    ///
    /// # Runtime shutdown
    ///
    /// Dropping the runtime waits for a spawn that is running on the pool (tokio's blocking pool is
    /// joined; `shutdown_timeout` and `shutdown_background` are the caller's way out). A spawn the
    /// shutdown cancels before it ran started nothing, and fails with
    /// [`Error::Io`](crate::error::Error::Io) saying so. A task that is already queued is dropped,
    /// with what it holds, by the pool's shutdown on a pool or shutdown thread; a spawn made after
    /// the shutdown began is dropped on the calling thread. A panic in the spawn is resumed here.
    ///
    /// # Per-thread state
    ///
    /// The child is forked on a pool thread, so it inherits that thread's per-thread state (signal
    /// mask, seccomp filter, namespaces, capabilities, nice/affinity; on Windows its impersonation
    /// token and COM apartment), not the caller's. Process-wide state is the process's. To use a
    /// thread's own state, spawn with the sync [`Command::spawn`](SyncCommand::spawn) on that
    /// thread.
    ///
    /// # Errors
    ///
    /// The errors are the sync [`Command::spawn`](SyncCommand::spawn)'s: this is the same spawn, and
    /// every error says whether the program could have started.
    pub async fn spawn(&mut self) -> Result<Child, Error> {
        Ok(super::spawn::spawn(&mut self.inner).await?)
    }

    /// Forwards to the sync command's `set_elevation_report`.
    #[cfg(test)]
    pub(crate) fn set_elevation_report(&mut self, report: Option<crate::elevation::ElevationReport>) {
        self.inner.set_elevation_report(report);
    }

    /// Run to completion with inherited stdio, returning the exit status.
    /// Spawns as [`spawn`](Self::spawn) does, on the blocking pool. Fails as `spawn`
    /// does, and with [`Error::MayHaveStarted`] after it.
    pub async fn status(&mut self) -> Result<std::process::ExitStatus, Error> {
        self.inner.stdin(Stdio::inherit())?;
        self.inner.stdout(Stdio::inherit())?;
        self.inner.stderr(Stdio::inherit())?;
        let mut child = self.spawn().await?;
        match child.wait().await {
            Ok(status) => Ok(status),
            Err(e) => Err(after_the_spawn(e, child).await),
        }
    }

    /// Run to completion, capturing stdout and stderr (stdin is `/dev/null`).
    /// Spawns as [`spawn`](Self::spawn) does, on the blocking pool. Fails as `spawn`
    /// does, and with [`Error::MayHaveStarted`] after it.
    pub async fn output(&mut self) -> Result<crate::Output, Error> {
        self.inner.stdin(Stdio::null())?;
        self.inner.stdout(Stdio::pipe())?;
        self.inner.stderr(Stdio::pipe())?;
        let mut child = self.spawn().await?;
        match child.communicate(None).await {
            Ok(output) => Ok(output),
            Err(e) => Err(after_the_spawn(e, child).await),
        }
    }

    /// Run to completion, capturing stdout as a UTF-8 string (stdin is `/dev/null`).
    /// Spawns as [`spawn`](Self::spawn) does, on the blocking pool. Fails as `spawn`
    /// does, and with [`Error::MayHaveStarted`] after it.
    pub async fn read(&mut self) -> Result<String, Error> {
        self.inner.stdin(Stdio::null())?;
        self.inner.stdout(Stdio::pipe())?;
        let mut child = self.spawn().await?;
        let out = match child.communicate(None).await {
            Ok(out) => out,
            Err(e) => return Err(after_the_spawn(e, child).await),
        };
        // `communicate` collected the exit.
        String::from_utf8(out.stdout).map_err(|e| {
            crate::child::spawn::after_the_spawn(
                Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                crate::child::drop_teardown::Torn::left(crate::error::ChildFate::Reaped),
                child.inner.front().is_some(),
            )
        })
    }
}

/// The error of a run-to-completion helper that failed after its spawn: the program may have
/// started, and `child` is torn down now as its drop would, awaiting what the drop would block on.
/// The teardown says what became of the child, and hands it back if it could not end it.
pub(super) async fn after_the_spawn(error: Error, child: Child) -> Error {
    let behind_front = child.inner.front().is_some();
    let torn = child.tear_down_awaiting().await;
    crate::child::spawn::after_the_spawn(error, torn, behind_front)
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod command_tests;
