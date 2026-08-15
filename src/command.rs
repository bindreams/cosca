//! The `Command` builder: executable/args/commandline input model plus stdio,
//! env, cwd, and kill_on_drop.
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
    elevation: crate::elevation::ElevationRequest,
    fd_marker_suppressed: bool,
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
            elevation: crate::elevation::ElevationRequest::default(),
            fd_marker_suppressed: false,
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
    /// Combining `commandline` with [`executable`](Self::executable) is supported
    /// on both POSIX and Windows. On Windows the raw `CreateProcessW` backend sets
    /// the loaded image (`lpApplicationName`) independently of the command line
    /// (`lpCommandLine`), so `executable` selects the file that runs while the
    /// child's `argv[0]` is the command line's first token.
    pub fn commandline<S: Into<OsString>>(&mut self, line: S) -> &mut Command {
        self.input = CommandInput::CommandLine(line.into());
        self
    }

    /// Override the executable file that the OS loads, independently of `argv[0]`
    /// (e.g. load `/bin/busybox` while `argv[0]` is `sh`).
    ///
    /// # Platform note
    ///
    /// On POSIX, the user's `argv[0]` is preserved via `CommandExt::arg0`, so
    /// `executable("/bin/busybox").args(["sh", "-c", "..."])` correctly loads
    /// busybox while the child sees `"sh"` as its `argv[0]`.
    ///
    /// On Windows, a set `executable` spawns through the raw `CreateProcessW`
    /// backend, which sets `lpApplicationName` independently of `lpCommandLine` —
    /// so `argv[0]` is preserved (it no longer degrades to the executable path), and
    /// combining `executable` with [`commandline`](Self::commandline) is supported.
    /// A bare or relative `executable` is resolved with a deliberate rule (not full
    /// `CreateProcessW` search parity): the current directory first, then each
    /// `PATH` directory, appending `.exe` when the name has no extension.
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
    ///
    /// # Platform note
    ///
    /// A descriptor `slot >= 3` is delivered on Windows through the raw
    /// `CreateProcessW` backend's MSVCRT `lpReserved2` fd-table, so only a child
    /// linked against the MSVC/UCRT runtime sees it as a numbered fd; a non-MSVCRT
    /// child (foreign or no CRT) cannot recover it — inherent to the CRT-private
    /// table, not a bug. `Stdio::inherit()` on a `slot >= 3` (no defined parent
    /// stream) and a chained merge (a merge whose target is itself a merge) remain
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) on every platform.
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

    pub(crate) fn contain_request(&self) -> ContainRequest {
        self.contain
    }

    /// Run this child elevated (admin/root). Sugar for `Backend::Auto` +
    /// `Auth::Interactive` + the default `EnvSanitizer`. Elevation wraps the
    /// CHILD, never this process.
    pub fn elevate(&mut self) -> &mut Command {
        self.elevation.enabled = true;
        self
    }

    /// Force a specific elevation backend (implies `.elevate()`).
    pub fn elevation_backend(&mut self, backend: crate::elevation::Backend) -> &mut Command {
        self.elevation.enabled = true;
        self.elevation.backend = backend;
        self
    }

    /// Choose the elevation auth strategy (implies `.elevate()`).
    pub fn elevation_auth(&mut self, auth: crate::elevation::Auth) -> &mut Command {
        self.elevation.enabled = true;
        self.elevation.auth = auth;
        self
    }

    /// Replace the env sanitizer applied to explicitly-forwarded vars (implies `.elevate()`).
    pub fn sanitize_env(&mut self, sanitizer: crate::elevation::EnvSanitizer) -> &mut Command {
        self.elevation.enabled = true;
        self.elevation.sanitizer = sanitizer;
        self
    }

    // Consumed by the elevation paths: `elevation_request`/`fds` read the request;
    // `set_input_argv`/`set_env_ops`/`set_contain` build the POSIX DERIVED command
    // (hence the non-unix dead_code allows on the setters).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn elevation_request(&self) -> &crate::elevation::ElevationRequest {
        &self.elevation
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn set_input_argv(&mut self, argv: Vec<OsString>) {
        self.input = CommandInput::Argv(argv);
        self.executable = None;
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn set_env_ops(&mut self, ops: Vec<EnvOp>) {
        self.env_ops = ops;
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn set_contain(&mut self, req: ContainRequest) {
        self.contain = req;
    }

    /// Suppress the macOS fd marker for this spawn. Set on a REAL wrapper-spawn command
    /// (`ElevatePosix`'s derived `sudo`/`doas`/`pkexec …`), whose wrapper closes every
    /// descriptor >= 3 before exec, so a marker installed here could never reach the tree.
    /// Not set on `RunAsIs`'s derived command (already elevated): that one spawns the
    /// original program directly, with no wrapper to destroy anything.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn suppress_fd_marker(&mut self) {
        self.fd_marker_suppressed = true;
    }

    pub(crate) fn fd_marker_suppressed(&self) -> bool {
        self.fd_marker_suppressed
    }

    // ---- crate-internal accessors for the spawn engine -------------
    #[cfg_attr(not(unix), allow(dead_code))]
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
    /// Set `default` on fd0 UNLESS `Auth::Stdin` already claims it. The three convenience
    /// methods below each force their own stdin default; `Auth::Stdin` needs sole,
    /// unconflicting ownership of fd0 to feed the backend the password, and the elevation
    /// rewrite rejects ANY caller-configured fd0 as ambiguous (real content could be lost).
    /// A convenience method's own default is not a real caller intent to preserve, so it is
    /// skipped here rather than tripping that same rejection.
    fn apply_default_stdin(&mut self, default: crate::Stdio) -> Result<&mut Command, Error> {
        if !matches!(self.elevation.auth, crate::elevation::Auth::Stdin(_)) {
            self.stdin(default)?;
        }
        Ok(self)
    }

    /// Run to completion capturing stdout+stderr (stdin is connected to null).
    pub fn output(&mut self) -> Result<crate::Output, Error> {
        self.apply_default_stdin(crate::Stdio::null())?;
        self.stdout(crate::Stdio::pipe())?;
        self.stderr(crate::Stdio::pipe())?;
        let mut child = self.spawn()?;
        child.communicate(None)
    }

    /// Run to completion with inherited stdio, returning the exit status.
    pub fn status(&mut self) -> Result<crate::ExitStatus, Error> {
        // Force inherit so a caller who previously called .stdout(pipe()) does
        // not get a pump-free wait() that deadlocks once the pipe buffer fills.
        self.apply_default_stdin(crate::Stdio::inherit())?;
        self.stdout(crate::Stdio::inherit())?;
        self.stderr(crate::Stdio::inherit())?;
        let child = self.spawn()?;
        child.wait()
    }

    /// Run to completion capturing stdout as a UTF-8 String (stdin=null,
    /// stderr inherited). Errors on invalid UTF-8; output is verbatim (no trim).
    pub fn read(&mut self) -> Result<String, Error> {
        self.apply_default_stdin(crate::Stdio::null())?;
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
