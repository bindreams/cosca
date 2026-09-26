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
    executable: Option<ExecutableSpec>,
    fds: BTreeMap<Fd, ResolvedStdio>,
    env_ops: Vec<EnvOp>,
    cwd: Option<PathBuf>,
    kill_on_drop: bool,
    contain: ContainRequest,
    elevation: crate::elevation::ElevationRequest,
    fd_marker_suppressed: bool,
    flags: FlagsRequest,
    /// Files the spawn needs open until it runs: a pinned elevation backend exec'd through
    /// `/proc/self/fd/N`.
    held: Vec<std::sync::Arc<std::fs::File>>,
}

/// [`explain_cwd_read`]'s error when this process's cwd cannot be read: says why a path was
/// needed, and keeps the read's own error — errno included — as its source.
#[derive(Debug)]
struct CwdUnreadable(std::io::Error);

impl std::fmt::Display for CwdUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "elevating raw_executable() needs this process's working directory as a path, and it \
             cannot be read: {}",
            self.0
        )
    }
}

impl std::error::Error for CwdUnreadable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// `process_cwd`, with a failure explained as [`CwdUnreadable`] and its own error kept as the
/// source — for the macOS graphical elevation, the one sink that needs this process's cwd as a
/// path.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn explain_cwd_read(
    process_cwd: impl FnOnce() -> std::io::Result<PathBuf>,
) -> impl FnOnce() -> std::io::Result<PathBuf> {
    move || process_cwd().map_err(|e| std::io::Error::new(e.kind(), CwdUnreadable(e)))
}

/// Which setter recorded the executable path, and therefore whether cosca resolves it before
/// the OS sees it.
///
/// The variants are alternatives on ONE field: [`Command::executable`] and
/// [`Command::raw_executable`] overwrite each other, last call wins. Downstream, only the sites
/// that would otherwise resolve need the discriminant — everything that merely wants the path
/// uses [`Command::executable_path`], which is variant-agnostic.
#[derive(Debug, Clone)]
pub(crate) enum ExecutableSpec {
    /// From [`Command::executable`]: cosca resolves it (`PATH`, `.exe`) before the OS sees it.
    Search(PathBuf),
    /// From [`Command::raw_executable`]: never searched — at most completed to an absolute path,
    /// where a sink would otherwise search a relative one.
    Exact(PathBuf),
}

impl ExecutableSpec {
    /// The path as written, whichever setter recorded it.
    pub(crate) fn path(&self) -> &Path {
        match self {
            ExecutableSpec::Search(p) | ExecutableSpec::Exact(p) => p,
        }
    }
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
            held: Vec::new(),
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
    ///
    /// Without `executable`, the loaded image comes from `line`'s own first token instead (see
    /// [`crate::quote::windows::first_token_and_rest_wide`]'s doc for exactly how that token is
    /// extracted). An UNQUOTED path containing a space fails closed with `NotFound` there rather
    /// than being found via successive whitespace-delimited prefixes the way a NULL
    /// `lpApplicationName` would be by `CreateProcessW` itself — see that doc for why (it is the
    /// classic unquoted-service-path hijack vector, deliberately not replicated). Quote such a
    /// path.
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
    /// On Windows, for an UNELEVATED spawn, a set `executable` routes through the raw
    /// `CreateProcessW` backend, which sets `lpApplicationName` independently of
    /// `lpCommandLine` — so `argv[0]` is preserved (it no longer degrades to the
    /// executable path), and combining `executable` with
    /// [`commandline`](Self::commandline) is supported. A bare or relative
    /// `executable` is resolved with a deliberate rule (not full `CreateProcessW`
    /// search parity): a name containing a path separator resolves against the
    /// working directory with no search, while a true bare name is looked up in the
    /// system directories (`System32`, then the Windows directory) and then `PATH` —
    /// **never the app directory (the directory this process's own image loaded
    /// from), and never the current directory**. That order, system directories
    /// before `PATH`, is deliberate: it is `CreateProcessW`'s own documented search
    /// order minus the app directory and the current directory (and the 16-bit
    /// system directory — Microsoft's own reference says "There is no function
    /// that obtains the path of this directory", so this crate cannot query it
    /// either), not a fresh rule, so a directory placed early on `PATH` (a dev toolchain install, a
    /// per-user app shim) still cannot shadow e.g. `System32\find.exe`. Searching the
    /// app directory or the current directory is a binary-planting hazard:
    /// `executable("helper")` would load a `helper.exe` dropped next to the running
    /// program's own `.exe`, or in whatever directory the process is running in, or
    /// the child is about to run in ([`current_dir`](Self::current_dir) when set) —
    /// either way, a directory this crate's caller does not necessarily
    /// control. This is a deliberate difference from `CreateProcessW`'s own
    /// NULL-`lpApplicationName` search and from `std::process::Command`, both of
    /// which search the app directory. Write `./helper` to reach the working directory
    /// explicitly (the child's, via [`current_dir`](Self::current_dir) when set — see below), or
    /// `std::env::current_exe()?.with_file_name("helper.exe")` to reach the app directory
    /// explicitly.
    ///
    /// **The rule follows the BACKEND, not this setter.** A [`fd`](Self::fd) mapping a descriptor >= 3, or
    /// [`raw_executable`](Self::raw_executable), also routes an unelevated Windows spawn through the raw
    /// backend, so `Command::new().arg("sub/helper").fd(3, ..)` is resolved by everything described here —
    /// against the CHILD's working directory ([`current_dir`](Self::current_dir) when set) — even with no
    /// `executable` set at all. (`raw_executable` itself does not add a second bare-name search: its image is
    /// completed rather than searched — see its own doc — so this rule has nothing to resolve for it; it
    /// matters here only as a second way to land on the raw backend.) This is specific
    /// to the raw backend: on Windows, [`elevate`](Self::elevate) ordinarily takes a different route
    /// (`ShellExecuteEx`, not `CreateProcessW`) — except when the calling process is already elevated, where it
    /// falls back to the same unelevated backends this doc otherwise describes: the raw `CreateProcessW`
    /// backend when `executable` or `raw_executable` is set (an elevated spawn cannot map fd >= 3, so that
    /// trigger is unavailable here), `std::process::Command` otherwise. Either way — `ShellExecuteEx`, or either
    /// already-elevated fallback — `elevate()` refuses anything but a fully qualified `.exe`/`.com` before that
    /// matters, so a bare or relative `executable` never reaches a search on the `elevate()` path at all. (On
    /// POSIX, `elevate` goes through one of the POSIX elevation backends — `sudo`, `doas`, `run0`, `pkexec`,
    /// `osascript` — none of which is `CreateProcessW`, so this rule, specific to Windows's raw backend, has
    /// nothing to resolve there either.)
    ///
    /// **An UNELEVATED spawn that reaches neither trigger — no `executable`/`raw_executable`, no `fd` mapping a
    /// descriptor >= 3 — stays on the DEFAULT Windows backend, `std::process::Command`, and none
    /// of this applies.** `Command::new().arg("helper").spawn()` alone does not route through the
    /// raw backend, so it is resolved by `std::process::Command` itself, which — unlike the rule
    /// above — DOES search the app directory.
    ///
    /// The directory resolved against is the one the child runs in. `current_dir`, or this
    /// process's cwd when none is set, is read once and handed to `CreateProcessW` completed, so a
    /// concurrent `set_current_dir` cannot load one directory's file and run the child in another.
    /// A `current_dir` that is empty is [`std::io::ErrorKind::NotFound`]; one starting with two
    /// separators that names no share (`\\server`) is [`std::io::ErrorKind::InvalidInput`].
    ///
    /// The `.exe` rule is a property of names that get SEARCHED, not of files that get
    /// LOADED, so it differs by shape. If the name's final path component already ends
    /// in `.exe` or `.com` (case-insensitively — `TOOL.EXE` is left alone, never doubled
    /// into `TOOL.EXE.exe`), it is used as-is either way. Otherwise:
    ///
    /// - a **bare name** is checked against `name.exe` and nothing else. There is no
    ///   extensionless fallback candidate — a directory holding only an extensionless
    ///   `tool` will not resolve, matching `CreateProcessW`, `cmd.exe`, and both
    ///   PowerShell editions, all of which refuse to run an extensionless image by bare
    ///   name (measured on real Windows CI). `PATHEXT` cannot express "no extension", so
    ///   there is nothing to be compatible with.
    /// - a **pathed name** is checked against the exact name the caller wrote, first and
    ///   always. `CreateProcessW` documents "no default extension is assumed" for the
    ///   `lpApplicationName` this backend sets, and the PE format makes no extension
    ///   normative, so `executable(r"C:\tools\payload.tmp")` names exactly that file.
    ///   A second `name.exe` candidate follows only when the name carries no extension at
    ///   all, so `tools\thing.bin` has exactly one candidate. Where both `bin\tool` and
    ///   `bin\tool.exe` exist, the extensionless one wins. A name that names no file —
    ///   `tools\thing.bin\`, a root, a bare `\\server\share` — has none: it is refused
    ///   before any candidate is built (see the error kinds below).
    ///
    /// Both bullets read the name AS WRITTEN. Windows trims a path component's trailing
    /// dots and spaces on the way into an API, but that describes the string rather than
    /// what may exist on disk, and this resolver does not reproduce it — so a trailing dot
    /// or space is an ordinary part of a name. A bare `tool.` is therefore searched for as
    /// `tool..exe`, while a pathed `bin\tool.` carries an extension (an empty one) and so
    /// gets no second candidate at all.
    ///
    /// A bare name with a non-`.exe`/`.com` dot, such as `python3.11`, resolves to
    /// `python3.11.exe` — matching how `cmd.exe` and both PowerShell editions use PATHEXT
    /// to resolve it, which `CreateProcessW` itself does not do. `.bat`/`.cmd` are
    /// deliberately excluded from the exact-match allowlist: resolving to a script is a
    /// separate, not-yet-implemented feature (planned as its own follow-up), not a
    /// judgement that scripts are unsafe — this crate's existing, separate batch-path
    /// rejection (CVE-2024-24576) is unaffected either way.
    ///
    /// # Error kinds
    ///
    /// The two kinds answer different questions:
    ///
    /// - [`std::io::ErrorKind::InvalidInput`] — the name was NOT ACCEPTED. It was refused on
    ///   its shape and nothing was searched for, so no filesystem result is being reported.
    ///   A drive-relative name such as `C:tool` is refused this way rather than loaded from
    ///   the working directory: resolving it would need drive C's own current directory,
    ///   which cosca does not track. As in Win32, any one character before the `:` is a drive,
    ///   so `1:tool` is refused too. So is a name that names no file at all (`C:\`, `.`,
    ///   `tools\dir\`, `\\server\share`), and one starting with two separators that names no
    ///   share (`\\tool.exe`), which Win32 reads as a UNC path rather than a file on this drive.
    ///   On Windows, a rooted name (`\bin\tool.exe`) resolved against a verbatim (`\\?\`)
    ///   working directory is refused too: Win32 completes it to `\\bin\tool.exe`, off that
    ///   directory's volume (measured). So is a relative one whose `..` Win32 completes past a
    ///   verbatim share, to a share root or no share at all. The `std` backend and cosca before
    ///   this rule resolved such a rooted name onto the directory's own volume.
    /// - [`std::io::ErrorKind::NotFound`] — the name was acceptable, the search above ran,
    ///   and nothing matched.
    ///
    /// The dividing line is whether a different filesystem could make the name succeed: if
    /// no disk ever could, the refusal is a property of the string, and it is `InvalidInput`.
    ///
    /// This resolution rule does NOT apply to an ELEVATED spawn: that path goes through
    /// `ShellExecuteEx` instead of `CreateProcessW`, entirely bypassing the raw
    /// backend (and this resolver) described above, and nothing resolves the name there. So
    /// [`elevate`](Self::elevate) on Windows takes only a fully qualified path to an image.
    /// `ShellExecuteEx` can apply `PATHEXT` and file associations even to an absolute name
    /// (measured without a class; for cosca's `exefile` launch on the consent route it is
    /// unmeasured), so a name not ending in `.exe` or `.com` is refused with
    /// [`std::io::ErrorKind::InvalidInput`] — both `executable(r"C:\tools\setup")` and
    /// `executable("whoami")` — and a bare or relative one such as `whoami.exe` is refused with
    /// [`Error::Unsupported`]. A `%` in the name or in [`current_dir`](Self::current_dir) is refused
    /// with [`std::io::ErrorKind::InvalidInput`], since whether the launch expands it is unmeasured.
    /// All of these hold whether or not the caller is already elevated.
    ///
    /// Every Windows spawn, elevated or not, refuses a `.bat`/`.cmd` that only Win32's
    /// normalisation exposes, such as `C:\t\setup.bat.` (trailing dot), `C:\t\setup.bat ` (one
    /// trailing space) and `C:\t\.bat`, with [`Error::Unsupported`] (CVE-2024-24576).
    ///
    /// [`raw_executable`](Self::raw_executable) is the unresolved alternative; calling either
    /// replaces the other.
    pub fn executable<P: Into<PathBuf>>(&mut self, path: P) -> &mut Command {
        self.executable = Some(ExecutableSpec::Search(path.into()));
        self
    }

    /// Load exactly this file, with **no resolution of any kind** — no `PATH` search, no `.exe`
    /// appending, no existence check.
    ///
    /// This is the underlying primitive that [`executable`](Self::executable) layers a search
    /// over. A relative value keeps the platform primitive's own meaning — but **which directory
    /// that is differs by platform, and it is not the same one `executable()` uses**:
    ///
    /// - **Windows:** the **calling process's** current directory. `CreateProcessW` completes a
    ///   partial `lpApplicationName` "using the current drive and current directory", and
    ///   `lpCurrentDirectory` (what [`current_dir`](Self::current_dir) sets) does not affect
    ///   image lookup at all. So `raw_executable("helper.exe").current_dir(r"D:\work")` loads
    ///   `helper.exe` from wherever THIS process happens to sit, not from `D:\work`. cosca
    ///   completes the name itself, as `CreateProcessW` would, from the same one read of this
    ///   process's cwd that `current_dir` is completed against, so the two cannot come from
    ///   different directories. Pass an absolute path if that distinction could ever matter — and
    ///   note that a directory this process sits in may be writable by someone else, which is the
    ///   binary-planting shape [`executable`](Self::executable) deliberately refuses to walk into.
    /// - **POSIX:** the **child's** working directory — [`current_dir`](Self::current_dir) when
    ///   set (itself read against this process's directory if relative), else this process's. The
    ///   `chdir` happens before the exec, so that is where a relative path lands. A bare `tool`
    ///   is run as `./tool`, never looked up on `PATH`: the child enters its directory and reads
    ///   the name there, both from the cwd it inherits, so no path to this process's cwd is ever
    ///   needed and the file loaded and the directory run in are always the same.
    ///
    ///   Under [`elevate`](Self::elevate), see that method's doc for which directory each
    ///   backend runs in; the file loaded here is always the one the directory it names holds.
    ///
    /// [`executable`](Self::executable) resolves against the child's working directory on both.
    /// The divergence is inherited from the platform primitives, not chosen here.
    ///
    /// A drive-relative name (`C:tool`) is honoured rather than refused: it names a file relative
    /// to drive C's own current directory, which Windows tracks and this crate does not.
    /// [`executable`](Self::executable) fails such a name closed for exactly that reason; here
    /// the platform answers it.
    ///
    /// A name that names no file — empty, separator-terminated, or a final `.`/`..` — is refused
    /// with [`std::io::ErrorKind::InvalidInput`] on every platform. On Windows so is a rooted name
    /// (`\bin\tool.exe`) when this process's cwd is verbatim (`\\?\`), which Win32 completes to
    /// `\\bin\tool.exe`, off that cwd's volume (measured), and a relative one whose `..` Win32
    /// completes past a verbatim share.
    ///
    /// On Windows a `.bat`/`.cmd` is refused with [`Error::Unsupported`] (CVE-2024-24576), judged
    /// on the name Win32 loads, so `setup.bat.` and `C:\t\.bat` are refused too.
    ///
    /// # Elevation
    ///
    /// On Windows the elevated path goes through `ShellExecuteEx`, which can search a path-less
    /// `lpFile` and apply `PATHEXT` even to an absolute one (measured without a class; for cosca's
    /// `exefile` launch on the consent route it is unmeasured). cosca completes the name to an
    /// absolute path first, by the same rules as above, and refuses it with
    /// [`std::io::ErrorKind::InvalidInput`] unless it ends in `.exe` or `.com` — so
    /// `raw_executable(r"C:\tools\setup").elevate()` is refused where the unelevated spawn loads
    /// `C:\tools\setup`.
    ///
    /// Every elevation backend derives the child's `argv[0]` from the program it is handed
    /// (`ShellExecuteEx`'s `lpFile`, the POSIX backends' and `osascript`'s exec): `./tool` under
    /// `sudo`, `doas` and `osascript`; the path run0 completes `./tool` to (`/dir/tool`, measured on
    /// 257–259); and the completed absolute path under `ShellExecuteEx`. `pkexec` refuses a relative
    /// `raw_executable()` (see [`elevate`](Self::elevate)), and an absolute one is its `argv[0]` as
    /// given. So `raw_executable("tool").args(["tool"])` yields `argv[0] == "tool"`
    /// only unelevated, or from an already-elevated caller, which runs no backend and spawns
    /// with argv verbatim. Handing a backend the bare name instead would let it search for the
    /// image.
    pub fn raw_executable<P: Into<PathBuf>>(&mut self, path: P) -> &mut Command {
        self.executable = Some(ExecutableSpec::Exact(path.into()));
        self
    }

    pub(crate) fn input(&self) -> &CommandInput {
        &self.input
    }

    /// The executable path as written, whichever setter recorded it.
    ///
    /// Deliberately variant-agnostic: most readers — the elevation `argv[0]` guards, backend
    /// routing, the argv and command-line builders — want the path and nothing else. Only a
    /// caller that must not resolve an `Exact` path should reach for
    /// [`executable_spec`](Self::executable_spec).
    pub(crate) fn executable_path(&self) -> Option<&Path> {
        self.executable.as_ref().map(ExecutableSpec::path)
    }

    /// The path together with which setter recorded it.
    pub(crate) fn executable_spec(&self) -> Option<&ExecutableSpec> {
        self.executable.as_ref()
    }

    /// Carry another command's executable over whole, setter included.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn set_executable_spec(&mut self, spec: Option<ExecutableSpec>) {
        self.executable = spec;
    }

    /// Keep `file` open for as long as this command, so a path through it stays valid until the
    /// spawn.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn hold(&mut self, file: std::sync::Arc<std::fs::File>) {
        self.held.push(file);
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
    ///
    /// Routing to that backend also applies [`executable`](Self::executable)'s Windows
    /// resolution policy — and its error kinds — to the program name, whether or not
    /// `executable` is set.
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
    /// uncontained child — see [`contain`](Command::contain)), then kill the ROOT. There is no
    /// cooperative signal first; use
    /// [`graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree) before dropping if the
    /// child needs one.
    ///
    /// **Under [`CgroupV2`](crate::Containment::CgroupV2) the drop waits for the tree to be gone**
    /// before it removes the tree's leaf: it waits while any process remains in the leaf. That is
    /// almost always instant, since every member was just sent `SIGKILL`. It lasts as long as a
    /// member stuck in uninterruptible I/O (D state) stays stuck, and as long as any process
    /// another party (the same uid, or root) moves into the leaf after the kill keeps running:
    /// the kill reaches only the processes in the leaf when it is written. On kernels before
    /// 6.14 (without commit b69bb476dee9, "cgroup: fix race between fork and cgroup.kill"), a
    /// child a member forks at the moment of the kill can escape it too, and the drop waits for
    /// that child's whole life. Neither case raises an event cosca could re-kill on: `populated`
    /// does not change, and a fork writes no file. Under every other
    /// mechanism descendants are killed, not waited for. To wait explicitly, call
    /// [`kill_tree`](crate::Child::kill_tree) then [`wait_tree`](crate::Child::wait_tree).
    ///
    /// **Where the two handles differ is the wait.** The sync [`Child`](crate::Child) blocks
    /// until the root has exited, so after `drop` returns the child is gone. The async
    /// [`Child`](crate::tokio::Child) signals and returns — parking a runtime worker in a
    /// destructor is not something the caller can await or cancel — and hands the wait to reaper
    /// threads of its own, so the reap happens later and off this thread. Its cgroup leaf's wait
    /// happens there too, unless the drop releases the handle on the dropping thread: for a root
    /// already reaped, one it could not signal, or when no reaper thread could be started.
    ///
    /// The async reap is **not** unconditional: a host too thread-starved to start the pool falls
    /// back to the runtime's orphan handling, and a process that forks without `exec` loses it
    /// entirely in the forked child. Code that must know the child is gone should `kill` and
    /// `await` [`wait`](crate::tokio::Child::wait) rather than rely on the drop. See that `Drop`'s
    /// rustdoc for both paths.
    ///
    /// An elevated child this process cannot signal is the one case the sync handle does not
    /// block on: the teardown gives up rather than wait forever, and the child is left running.
    ///
    /// **Under [`CgroupV2`](crate::Containment::CgroupV2), opting out can leave the tree's cgroup
    /// leaf behind.** Dropping the handle still removes the leaf if the whole tree has exited,
    /// but never kills to empty it itself. A tree still running keeps it, and so does one torn
    /// down with [`terminate_tree`](crate::Child::terminate_tree) that has not finished exiting —
    /// a `SIGTERM` is catchable, so the tree may outlive it — which
    /// [`wait_tree`](crate::Child::wait_tree) before the drop is what proves either case is done.
    /// [`kill_tree`](crate::Child::kill_tree) is different: that kill is atomic, so a drop after
    /// it waits for that kill's drain before giving up the leaf, the same as it would with
    /// `kill_on_drop` left on. cosca does not come back
    /// for a leaf it left: the empty `cosca-*` directory stays until something else removes it,
    /// such as systemd removing a stopped unit's cgroup subtree.
    pub fn kill_on_drop(&mut self, yes: bool) -> &mut Command {
        self.kill_on_drop = yes;
        self
    }

    /// Contain the child's whole process tree using the strongest mechanism
    /// available, so dropping or `kill_tree`-ing the child tears down every
    /// descendant. See [`crate::Containment`] for the per-OS mechanisms.
    ///
    /// # Linux: the child must stay this process's to reap
    /// Until `spawn` returns, cosca tells by the child's pid whether it entered its cgroup, and may
    /// have to kill it. So nothing else in the process may reap it first: do not set `SIGCHLD` to
    /// `SIG_IGN`, and do not run a reaper that calls `waitpid(-1, …)` or `wait()`. Either can free
    /// the pid for reuse by an unrelated process. Debug builds assert this; release builds
    /// degrade, or fail the spawn, without signalling the pid when they see it.
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
    /// | `CREATE_SUSPENDED` | cosca suspends and resumes a contained root itself | none |
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
    ///
    /// On POSIX the backend is started in [`current_dir`](Self::current_dir), or this process's
    /// cwd, and told to run the child there:
    ///
    /// - `sudo` and `doas` keep it by default; a sudoers `runcwd` moves `sudo`'s child —
    ///   measured, sudo 1.9.5–1.9.17 with `runcwd=~` ran it in `/root`.
    /// - `run0` is passed `-D .`, its working-directory option (measured, systemd 257 and 259).
    /// - `pkexec` is passed `--keep-cwd`, and so requires Linux and polkit 121 or later; see
    ///   [`Backend::Pkexec`](crate::elevation::Backend::Pkexec).
    ///
    /// A relative [`raw_executable`](Self::raw_executable) reaches each backend but pkexec in a form
    /// it does not search:
    ///
    /// - `sudo` and `doas` are handed `./tool`, and read it against the directory they inherited,
    ///   after authenticating, so a rename of an ancestor during authentication cannot swap the
    ///   file; under a sudoers `runcwd`, `./tool` is not found.
    /// - `run0` is handed `./tool` and completes it against its cwd's path before authenticating,
    ///   so such a rename can redirect it.
    /// - `osascript`'s trampoline carries no cwd, so its shell `cd -P`s to the directory as an
    ///   absolute path completed against this process's cwd (read once), and runs `./tool` there.
    ///   A cwd with no usable path fails the spawn: an unlinked directory with `NotFound`, an
    ///   unsearchable ancestor with `PermissionDenied`, each with an error saying why a path was
    ///   needed.
    ///
    /// `pkexec` runs a relative program only if the caller itself can execute it, so under
    /// `Backend::Pkexec` a relative `raw_executable()` is refused with [`Error::Unsupported`],
    /// root or not: pass an absolute path. A program named by [`executable`](Self::executable) or
    /// `argv[0]` reaches pkexec as written, and pkexec's own lookup resolves it.
    ///
    /// An already-root caller runs no backend and spawns as it would unelevated.
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
