//! The `Command` builder: executable/args/commandline input model plus stdio,
//! env, cwd, and kill_on_drop.
//!
//! Note: `Command` does not implement `Clone` because [`ResolvedStdio`] can
//! hold a [`std::fs::File`], which is not `Clone` by design.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::command::flags::FlagsRequest;
use crate::containment::{ContainMode, ContainRequest, Nesting};
use crate::error::Error;
use crate::stdio::{Fd, ResolvedStdio, Stdio};

pub(crate) mod flags;

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
    flags: FlagsRequest,
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
            flags: FlagsRequest::default(),
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

    /// Tear the child down when its handle drops. **On by default**; pass `false` to opt out for
    /// every child of this command, or [`Child::detach`](crate::Child::detach) to opt one out
    /// after the fact.
    ///
    /// What "tear down" means, on both handles: hard-kill the contained tree (a no-op for an
    /// uncontained child — see [`contain`](Command::contain)), then block until the ROOT has
    /// exited. There is no cooperative signal first; use
    /// [`graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree) before dropping if the
    /// child needs one. Descendants are killed, not waited for.
    ///
    /// An elevated child this process cannot signal is the one case that does not block: the
    /// teardown gives up rather than wait forever, and the child is left running.
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

    // ---- creation-flag intents ---------------------------------------

    /// Do not put a console window on the user's screen for this child.
    ///
    /// # The intent sits above the mechanisms
    ///
    /// Windows offers two unrelated launch mechanisms and this request is lowered onto whichever
    /// one a given spawn uses, because a flags-shaped API would honour it on one path and
    /// silently ignore it on the other:
    ///
    /// | Platform / path | Lowered to |
    /// | --- | --- |
    /// | Windows, no [`elevate`](Self::elevate) | `CREATE_NO_WINDOW` in `dwCreationFlags` |
    /// | Windows, `elevate()` from an **already-elevated** caller | `CREATE_NO_WINDOW` — the ordinary backends, unchanged |
    /// | Windows, `elevate()` where a **consent prompt is used** | the launch's show-command becomes `SW_HIDE` |
    /// | Unix | nothing; a documented no-op |
    ///
    /// The request means the same thing everywhere; only how far the closest available mechanism
    /// carries it differs. Where the creation flag carries it, it concerns the child's
    /// **console** and nothing else. Where a consent prompt is used there is no console-only
    /// knob, so the show-command is the shell's initial show state for the whole launched
    /// application — a graphical child's own main window is affected too, and may override it.
    /// Note the condition: an already-elevated caller gets the ordinary creation flag, so
    /// "elevation was requested" is not what selects the wider reach.
    ///
    /// A child that would not have had a console anyway — a windows-subsystem image, for
    /// instance — needs no suppression and is not an error; the request is already satisfied.
    ///
    /// # Consequence for cooperative shutdown
    ///
    /// The child gets a console of its own rather than joining this process's, so a console-group
    /// signal sent from this process cannot reach it. Not requesting this does not establish the
    /// reverse — whether a child shares this process's console also depends on the child image's
    /// subsystem and on what the child does with its own console. What cosca recorded about the
    /// route is reported per child by
    /// [`Child::graceful_mechanism`](crate::Child::graceful_mechanism); it is a statement about
    /// the route, never an authority on whether a signal will arrive.
    ///
    /// This is not "such a child cannot be shut down politely" — a process attached to the child's
    /// own console can deliver the event. Nor does cosca report an error for one: the cooperative
    /// ops ([`terminate`](crate::Child::terminate),
    /// [`terminate_tree`](crate::Child::terminate_tree)) return `Ok` and deliver nothing, which is
    /// the gap this crate documents rather than the behaviour it wants. The forced ops
    /// ([`kill`](crate::Child::kill) / [`kill_tree`](crate::Child::kill_tree)) are unaffected.
    pub fn no_window(&mut self) -> &mut Command {
        self.flags.no_window = true;
        self
    }

    /// Spawn the child with `DETACHED_PROCESS`: it gets no console at all.
    ///
    /// This removes the child's **console**, not its stdio — with [`Stdio::inherit`] a detached
    /// child still writes to the handles it inherited. It also does not leave a job; that is
    /// [`breakaway_from_job`](Self::breakaway_from_job).
    ///
    /// Same one-directional console consequence as [`no_window`](Self::no_window): a
    /// console-group signal sent from this process cannot reach such a child, while *not*
    /// detaching establishes nothing about the reverse — and the cooperative ops return `Ok` and
    /// deliver nothing rather than reporting an error.
    #[cfg(windows)]
    pub fn detached(&mut self) -> &mut Command {
        self.flags.detached = true;
        self
    }

    /// Spawn the child with `CREATE_BREAKAWAY_FROM_JOB`, so it starts outside whatever job object
    /// this process belongs to.
    ///
    /// The bit is emitted from the request alone — cosca never reads the ambient job first. A
    /// pre-spawn reading could go stale in the gap, and omitting the bit on a "not in a job"
    /// reading would silently leave the child in a job the caller asked it to escape. Where the
    /// ambient job forbids breakaway the OS refuses the spawn, and that refusal is classified
    /// afterwards as [`Error::Containment`](crate::error::Error::Containment).
    ///
    /// # What it does not promise
    ///
    /// - Breakaway leaves the immediate job and each job up the parent chain **until one forbids
    ///   it**, so under nesting the child can still end up inside an ancestor job. cosca does not
    ///   promise the child ends up in no job at all.
    /// - **It cannot succeed from inside a cosca-contained tree.** cosca's own containment job
    ///   sets neither breakaway limit, and a member process cannot relax the limits of the job
    ///   that holds it — so for a child that was itself spawned by cosca with
    ///   [`contain`](Self::contain), this request can only fail.
    /// - The resulting error names the **first** thing the OS refused. The breakaway denial is
    ///   evaluated before the image is resolved, so removing the request may reveal a different
    ///   failure rather than making the spawn work.
    ///
    /// Combining it with any `contain*()` is [`Error::Unsupported`](crate::error::Error::Unsupported):
    /// a nested contained spawn's containment IS "the child inherits the ancestor's job", and
    /// breaking away from it would leave cosca reporting a teardown owner that no longer owns
    /// anything.
    #[cfg(windows)]
    pub fn breakaway_from_job(&mut self) -> &mut Command {
        self.flags.breakaway_from_job = true;
        self
    }

    /// Add arbitrary bits to this spawn's `dwCreationFlags`, for flags cosca does not name.
    ///
    /// **Replaces, it does not accumulate** — matching
    /// [`std::os::windows::process::CommandExt::creation_flags`]. Calling it twice leaves the
    /// second word, and `creation_flags(0)` is how a word set earlier is cleared. Or-in would
    /// make a bit unclearable, which is the one thing a raw hatch must never do.
    ///
    /// # Reserved bits
    ///
    /// Bits whose consequences cosca must manage are refused at spawn with
    /// [`Error::Unsupported`], naming every offending flag and its replacement. Validation is at
    /// spawn rather than here because a pairwise rule enforced in a setter would give a verdict
    /// that depends on builder call order.
    ///
    /// | Flag | Why reserved | Instead |
    /// | --- | --- | --- |
    /// | `CREATE_SUSPENDED` | cosca suspends and resumes a contained root itself | none; a suspended-spawn window is being designed in [cosca#49](https://github.com/bindreams/cosca/issues/49) |
    /// | `CREATE_NEW_PROCESS_GROUP` | load-bearing for `CTRL_BREAK` delivery to the contained root | [`contain`](Self::contain) |
    /// | `CREATE_NEW_CONSOLE` | measured: the child gets its own *visible* console window, overriding a requested window suppression | none |
    /// | `CREATE_UNICODE_ENVIRONMENT` | both backends supply it structurally, so a caller can neither set nor clear it meaningfully | none |
    /// | `EXTENDED_STARTUPINFO_PRESENT` | it announces a structure only the spawn backend can supply | none |
    /// | `DETACHED_PROCESS` | carries a console consequence cosca must record | [`detached`](Self::detached) |
    /// | `CREATE_NO_WINDOW` | same | [`no_window`](Self::no_window) |
    /// | `CREATE_BREAKAWAY_FROM_JOB` | same, plus the failure classification the raw bit would lose | [`breakaway_from_job`](Self::breakaway_from_job) |
    /// | `DEBUG_PROCESS` | makes the spawner a debugger; the child stops on debug events nothing services, so `wait`/`wait_tree` would hang | none |
    /// | `DEBUG_ONLY_THIS_PROCESS` | same | none |
    #[cfg(windows)]
    pub fn creation_flags(&mut self, flags: u32) -> &mut Command {
        self.flags.raw = flags;
        self
    }

    pub(crate) fn flags_request(&self) -> &FlagsRequest {
        &self.flags
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
