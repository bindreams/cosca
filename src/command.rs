//! The `Command` builder: executable/args/commandline input model (Task 1)
//! extended with stdio, env, cwd, and kill_on_drop (Task 3).
//!
//! Note: `Command` does not implement `Clone` because [`ResolvedStdio`] can
//! hold a [`std::fs::File`], which is not `Clone` by design.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::containment::{ContainMode, ContainRequest, Nesting};
use crate::error::Error;
use crate::stdio::{Fd, ResolvedStdio, Stdio};

/// A process to be configured and (later) spawned.
#[derive(Debug)]
pub struct Command {
    input: CommandInput,
    executable: Option<PathBuf>,
    fds: BTreeMap<Fd, ResolvedStdio>,
    env_ops: Vec<EnvOp>,
    cwd: Option<PathBuf>,
    kill_on_drop: bool,
    contain: ContainRequest,
}

/// An environment variable operation, recorded in order.
#[derive(Debug, Clone)]
pub(crate) enum EnvOp {
    Set(OsString, OsString),
    Remove(OsString),
    Clear,
}

impl Default for Command {
    fn default() -> Command {
        Command {
            input: CommandInput::Empty,
            executable: None,
            fds: BTreeMap::new(),
            env_ops: Vec::new(),
            cwd: None,
            kill_on_drop: true,
            contain: ContainRequest::default(),
        }
    }
}

/// The argument source of truth. `Argv` and `CommandLine` are mutually
/// exclusive — the last one set wins.
#[derive(Debug, Clone, Default)]
pub(crate) enum CommandInput {
    #[default]
    Empty,
    Argv(Vec<OsString>),
    CommandLine(OsString),
}

impl Command {
    /// A fresh command with no arguments. argv is not special: set it via
    /// [`Command::args`]/[`Command::arg`] or [`Command::commandline`].
    pub fn new() -> Command {
        Command::default()
    }

    /// Append one argument, switching to argv mode if a command line was set.
    pub fn arg<S: Into<OsString>>(&mut self, a: S) -> &mut Command {
        match &mut self.input {
            CommandInput::Argv(v) => v.push(a.into()),
            _ => self.input = CommandInput::Argv(vec![a.into()]),
        }
        self
    }

    /// Append several arguments, switching to argv mode if a command line was set.
    pub fn args<I, S>(&mut self, args: I) -> &mut Command
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let items = args.into_iter().map(Into::into);
        match &mut self.input {
            CommandInput::Argv(v) => v.extend(items),
            _ => self.input = CommandInput::Argv(items.collect()),
        }
        self
    }

    /// Set the argument source to a single command-line string (Windows-native
    /// form). Discards any previously set argv.
    ///
    /// # Platform note
    ///
    /// Combining `commandline` with [`executable`](Self::executable) is
    /// unsupported on Windows in this plan (returns
    /// [`Error::Unsupported`](crate::error::Error::Unsupported)); POSIX
    /// supports it.
    pub fn commandline<S: Into<OsString>>(&mut self, line: S) -> &mut Command {
        self.input = CommandInput::CommandLine(line.into());
        self
    }

    /// Override the executable file that the OS loads, independently of argv[0]
    /// (e.g. load `/bin/busybox` while argv[0] is `sh`).
    ///
    /// # Platform note
    ///
    /// On POSIX, the user's argv[0] is preserved via `CommandExt::arg0`, so
    /// `executable("/bin/busybox").args(["sh", "-c", "..."])` correctly loads
    /// busybox while the child sees `"sh"` as its argv[0].
    ///
    /// On Windows, `std::process` has no stable API to set argv[0] independently
    /// of the executable, so argv[0] will be the executable path instead of the
    /// user-supplied value. This limitation is lifted in Plan 4's raw backend.
    /// Combining `executable` with [`commandline`](Self::commandline) is
    /// unsupported on Windows (returns
    /// [`Error::Unsupported`](crate::error::Error::Unsupported)).
    pub fn executable<P: Into<PathBuf>>(&mut self, path: P) -> &mut Command {
        self.executable = Some(path.into());
        self
    }

    pub(crate) fn input(&self) -> &CommandInput {
        &self.input
    }

    pub(crate) fn executable_path(&self) -> Option<&Path> {
        self.executable.as_deref()
    }

    /// Wire descriptor `slot` to `target`. Errors now if the target's direction
    /// is ambiguous for `slot` (a bare `pipe()` on a descriptor >= 3).
    pub fn fd(&mut self, slot: impl Into<Fd>, target: Stdio) -> Result<&mut Command, Error> {
        let slot = slot.into();
        let resolved = target.resolve(slot)?;
        self.fds.insert(slot, resolved);
        Ok(self)
    }

    pub fn stdin(&mut self, target: Stdio) -> Result<&mut Command, Error> {
        self.fd(Fd::STDIN, target)
    }

    pub fn stdout(&mut self, target: Stdio) -> Result<&mut Command, Error> {
        self.fd(Fd::STDOUT, target)
    }

    pub fn stderr(&mut self, target: Stdio) -> Result<&mut Command, Error> {
        self.fd(Fd::STDERR, target)
    }

    pub fn env(&mut self, k: impl Into<OsString>, v: impl Into<OsString>) -> &mut Command {
        self.env_ops.push(EnvOp::Set(k.into(), v.into()));
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Command
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        for (k, v) in vars {
            self.env_ops.push(EnvOp::Set(k.into(), v.into()));
        }
        self
    }

    pub fn env_remove(&mut self, k: impl Into<OsString>) -> &mut Command {
        self.env_ops.push(EnvOp::Remove(k.into()));
        self
    }

    pub fn env_clear(&mut self) -> &mut Command {
        self.env_ops.push(EnvOp::Clear);
        self
    }

    pub fn current_dir(&mut self, dir: impl Into<PathBuf>) -> &mut Command {
        self.cwd = Some(dir.into());
        self
    }

    pub fn kill_on_drop(&mut self, yes: bool) -> &mut Command {
        self.kill_on_drop = yes;
        self
    }

    /// Contain the child's whole process tree using the strongest mechanism
    /// available, so dropping or `kill_tree`-ing the child tears down every
    /// descendant. See [`crate::Containment`] for the per-OS mechanisms.
    pub fn contain(&mut self) -> &mut Command {
        self.contain_with(ContainMode::Strongest)
    }

    /// Contain with a specific [`ContainMode`].
    pub fn contain_with(&mut self, mode: ContainMode) -> &mut Command {
        self.contain.mode = Some(mode);
        self
    }

    /// Set how this contained spawn marks its descendants (default [`Nesting::Mark`]).
    pub fn nesting(&mut self, nesting: Nesting) -> &mut Command {
        self.contain.nesting = nesting;
        self
    }

    #[allow(dead_code)]
    pub(crate) fn contain_request(&self) -> ContainRequest {
        self.contain
    }

    // ---- crate-internal accessors for the spawn engine (Task 4) -------------
    // `fds` is read only by command_tests; spawn uses `fds_mut` (std::mem::take).
    #[allow(dead_code)]
    pub(crate) fn fds(&self) -> &BTreeMap<Fd, ResolvedStdio> {
        &self.fds
    }

    pub(crate) fn fds_mut(&mut self) -> &mut BTreeMap<Fd, ResolvedStdio> {
        &mut self.fds
    }

    pub(crate) fn env_ops(&self) -> &[EnvOp] {
        &self.env_ops
    }

    pub(crate) fn cwd(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    pub(crate) fn kill_on_drop_flag(&self) -> bool {
        self.kill_on_drop
    }
}

impl Command {
    /// Run to completion capturing stdout+stderr (stdin is connected to null).
    pub fn output(&mut self) -> Result<crate::Output, Error> {
        self.stdin(crate::Stdio::null())?;
        self.stdout(crate::Stdio::pipe())?;
        self.stderr(crate::Stdio::pipe())?;
        let mut child = self.spawn()?;
        child.communicate(None)
    }

    /// Run to completion with inherited stdio, returning the exit status.
    pub fn status(&mut self) -> Result<crate::ExitStatus, Error> {
        // Force inherit so a caller who previously called .stdout(pipe()) does
        // not get a pump-free wait() that deadlocks once the pipe buffer fills.
        self.stdin(crate::Stdio::inherit())?;
        self.stdout(crate::Stdio::inherit())?;
        self.stderr(crate::Stdio::inherit())?;
        let child = self.spawn()?;
        child.wait()
    }

    /// Run to completion capturing stdout as a UTF-8 String (stdin=null,
    /// stderr inherited). Errors on invalid UTF-8; output is verbatim (no trim).
    pub fn read(&mut self) -> Result<String, Error> {
        self.stdin(crate::Stdio::null())?;
        self.stdout(crate::Stdio::pipe())?;
        // stderr left at its default (inherit).
        let mut child = self.spawn()?;
        let out = child.communicate(None)?;
        String::from_utf8(out.stdout).map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod command_tests;
