//! The consent launch's own phase: completing the program and working directory into the
//! `lpFile` and `lpDirectory` a `ShellExecuteEx(runas)` is handed, from one read of this process's
//! cwd and environment.
//!
//! No resolution and no consent-launch check here may run for a caller that is already elevated,
//! whose request re-spawns through the ordinary backend instead. That is enforced by type, not by
//! call order: every such step is private to this module and reachable only through
//! [`Validated::launch`], which takes a [`ConsentCertain`] that only the planner's `ElevateWindows`
//! transition yields. [`ProcessOnce`] is the exception, by design: `validate` completes an `Exact`
//! token above the short-circuit through the same one cwd read, so the launch cannot read it twice.

use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::{runas_show_command, wide_nul, RunasLaunch};
use crate::child::spawn::windows_raw::env_snapshot::EnvSnapshot;
use crate::command::{Command, ExecutableSpec};
use crate::elevation::plan::Transition;
use crate::elevation::shell_file;
use crate::error::Error;

/// Proof that the planner chose a consent launch. Its field is private, so the only way to get one
/// is [`ConsentCertain::from_plan`] on an `ElevateWindows` transition.
pub(super) struct ConsentCertain(());

impl ConsentCertain {
    /// `Some` for a consent launch, `None` for an already-elevated caller, the planner's error for
    /// a refusal.
    pub(super) fn from_plan(transition: Transition) -> Result<Option<Self>, Error> {
        match transition {
            Transition::RunAsIs => Ok(None),
            Transition::Reject { error } => Err(error),
            Transition::ElevatePosix { .. } => unreachable!("planner never yields ElevatePosix on a windows host"),
            Transition::ElevateMacosGui { .. } => {
                unreachable!("planner never yields ElevateMacosGui on a windows host")
            }
            Transition::ElevateWindows { .. } => Ok(Some(ConsentCertain(()))),
        }
    }
}

/// A request that passed every privilege-independent check, carried to the consent launch.
pub(super) struct Validated<'a> {
    cmd: &'a Command,
    program: OsString,
    exact_used_cwd: bool,
    params_w: Vec<u16>,
    verb_w: Vec<u16>,
}

impl<'a> Validated<'a> {
    pub(super) fn new(
        cmd: &'a Command,
        program: OsString,
        exact_used_cwd: bool,
        params_w: Vec<u16>,
        verb_w: Vec<u16>,
    ) -> Self {
        Validated {
            cmd,
            program,
            exact_used_cwd,
            params_w,
            verb_w,
        }
    }

    /// The consent launch's payload: the program resolved and completed into `lpFile`, the working
    /// directory into `lpDirectory`, and the checks only a consent launch needs.
    pub(super) fn launch(self, _proof: ConsentCertain, state: &ProcessOnce<'_>) -> Result<RunasLaunch, Error> {
        let Validated {
            cmd,
            program,
            exact_used_cwd,
            params_w,
            verb_w,
        } = self;
        // The shape refusals on what the caller WROTE, before anything is searched, so their
        // verdict does not depend on what is on disk. The checks after resolution below repeat
        // them on what resolution added: a `PATH` entry, this process's cwd.
        shell_file::reject_quote(Path::new(&program))?;
        shell_file::reject_percent("program", Path::new(&program))?;
        if let Some(dir) = cmd.cwd() {
            shell_file::reject_percent_in_directory(dir)?;
        }
        let base = consent_base(cmd, &program, exact_used_cwd, state)?;
        let program = lp_file_for(cmd, &program, base.as_deref(), state)?;
        // On the exact bytes `ShellExecuteEx` will see: a fully qualified `.exe`/`.com` path with
        // no `"` or `%` (see `shell_file`). The `.exe`/`.com` rule is the `Exact` arm's gate, since
        // `absolutise_exact` searches nothing; the `Search` arm's resolver kept only loadable
        // candidates. An already-elevated caller never gets here: it re-spawns through
        // `CreateProcessW`, which neither extends a name nor expands `%`.
        shell_file::reject_elevated_program(Path::new(&program))?;
        if let Some(base) = &base {
            shell_file::reject_percent_in_directory(base)?;
        }
        let file_w = wide_nul("program path", program.as_os_str())?;
        let dir_w = lp_directory(cmd.cwd(), base)?;
        Ok(RunasLaunch {
            file_w,
            class_w: wide_nul("class", OsStr::new("exefile"))?,
            params_w,
            dir_w,
            verb_w,
            show: runas_show_command(cmd.flags_request()),
        })
    }
}

/// `lpDirectory`: the completed base, not `current_dir()` as written (see [`consent_base`]). A set
/// `current_dir` always yields a base; `None` without one leaves the child in this process's cwd.
fn lp_directory(cmd_cwd: Option<&Path>, base: Option<PathBuf>) -> Result<Option<Vec<u16>>, Error> {
    debug_assert!(
        base.is_some() || cmd_cwd.is_none(),
        "a current_dir always yields a base: {cmd_cwd:?}"
    );
    base.map(|base| wide_nul("working directory", base.as_os_str()))
        .transpose()
}

/// Where the consent launch reads this process's state from: its cwd and its environment. The
/// tests inject both.
pub(crate) struct ProcessDirs<'a> {
    pub(crate) cwd: &'a dyn Fn() -> std::io::Result<PathBuf>,
    pub(crate) env: &'a dyn Fn() -> Result<EnvSnapshot, Error>,
}

impl ProcessDirs<'static> {
    pub(crate) fn real() -> Self {
        ProcessDirs {
            cwd: &std::env::current_dir,
            env: &EnvSnapshot::read,
        }
    }
}

/// This process's cwd and environment, each read at most once and shared by every step of one
/// consent launch: the cwd by the `Exact` token, `current_dir` and the resolver's base; the
/// environment by `PATH` and a drive's own current directory (`=Q:`).
pub(crate) struct ProcessOnce<'a> {
    dirs: &'a ProcessDirs<'a>,
    // Each read's outcome, failure included, handed out again by `Error::replay` rather than
    // retried.
    cwd: RefCell<Option<Result<PathBuf, Error>>>,
    env: RefCell<Option<Result<EnvSnapshot, Error>>>,
}

impl<'a> ProcessOnce<'a> {
    pub(crate) fn new(dirs: &'a ProcessDirs<'a>) -> Self {
        ProcessOnce {
            dirs,
            cwd: RefCell::new(None),
            env: RefCell::new(None),
        }
    }

    pub(super) fn cwd(&self) -> Result<PathBuf, Error> {
        let mut cwd = self.cwd.borrow_mut();
        match cwd.get_or_insert_with(|| (self.dirs.cwd)().map_err(Error::Io)) {
            Ok(cwd) => Ok(cwd.clone()),
            Err(e) => Err(e.replay()),
        }
    }

    fn env_var(&self, name: &OsStr) -> Result<Option<OsString>, Error> {
        let mut env = self.env.borrow_mut();
        match env.get_or_insert_with(|| (self.dirs.env)()) {
            Ok(env) => Ok(env.var(name)),
            Err(e) => Err(e.replay()),
        }
    }

    pub(super) fn drive_cwd(&self, drive: &OsStr) -> Result<Option<OsString>, Error> {
        self.env_var(&crate::child::spawn::windows_raw::resolve::drive_cwd_var(drive))
    }

    fn path_var(&self) -> Result<Option<OsString>, Error> {
        self.env_var(OsStr::new("PATH"))
    }
}

/// The ABSOLUTE directory the consent launch resolves a relative name against and runs the child
/// in, from `cwd`'s one read of this process's cwd.
///
/// - A `current_dir` is completed as Win32 completes any path
///   ([`complete_on`](crate::child::spawn::windows_raw::resolve::complete_on)): as written when
///   absolute or UNC-shaped, on the read when relative or rooted or relative to the current drive,
///   and on that drive's own directory when relative to another drive. It must then be fully
///   qualified, so `current_dir(r"\\server")` is refused.
/// - With none, the read is used when a relative `Exact` token went into `lpFile`
///   (`exact_used_cwd`), or when a `Search` token needs a base
///   ([`needs_base`](crate::resolve::needs_base)). The child then runs there too.
/// - Otherwise `None`: `lpDirectory` stays null, as the caller asked. A cwd fetched only to learn
///   the current drive, and not used, does not pin it.
///
/// One value serves every field because two reads can disagree: a `set_current_dir` between the
/// read that picks the file and `ShellExecuteEx`'s own read of a relative or null `lpDirectory`
/// would load one directory's file and run the child in another.
/// `crate::resolve::exact::complete_posix` does the same on the POSIX elevation path.
fn consent_base(
    cmd: &Command,
    program: &OsStr,
    exact_used_cwd: bool,
    cwd: &ProcessOnce<'_>,
) -> Result<Option<PathBuf>, Error> {
    Ok(match cmd.cwd() {
        Some(dir) => {
            crate::child::spawn::windows_raw::resolve::check_current_dir(dir)?;
            let done = crate::child::spawn::windows_raw::resolve::complete_on(dir, || cwd.cwd(), |d| cwd.drive_cwd(d))?;
            crate::child::spawn::windows_raw::resolve::reject_not_fully_qualified(
                "elevated working directory",
                &done.path,
            )?;
            Some(done.path)
        }
        None if exact_used_cwd || crate::resolve::needs_base(program, true) => Some(cwd.cwd()?),
        None => None,
    })
}

/// The ABSOLUTE `lpFile` handed to `ShellExecuteEx`, from
/// [`elevated_program`](super::elevated_program)'s `program`.
///
/// Called by [`Validated::launch`] only, so only once a consent launch is certain. Resolving
/// earlier would make cosca's policy a precondition on a spawn that never uses it: an already-elevated caller
/// short-circuits to `AlreadyElevated` and re-spawns the original command through the ordinary
/// backend, so a program that backend finds but this resolver does not would fail with `NotFound`
/// only because `.elevate()` was called.
///
/// `Exact` (`raw_executable()`) arrives already completed by `absolutise_exact`, which searches
/// nothing, and is returned as is.
///
/// `Search` (`executable()`, or the argv[0] fallback) gets cosca's resolver, seeded with `base`
/// ([`consent_base`]: the CHILD's directory, absolute) and this process's `PATH`, from `state`'s
/// one environment snapshot: [`reject_unsupported_config`](super::reject_unsupported_config)
/// refuses every env op, so there is no other `PATH` the request could mean.
///
/// A bare name is searched in [`consent_system_dirs`] and then `PATH`, never the app directory.
///
/// [`consent_system_dirs`]: crate::child::spawn::windows_raw::resolve::consent_system_dirs
///
/// The resolver is restricted to `.exe`/`.com` candidates
/// ([`crate::resolve::ResolveInput::loadable_only`]): a non-loadable candidate is skipped, not
/// chosen and then refused, so `bin\tool` beside `bin\tool.exe` launches `bin\tool.exe`.
///
/// Either way `lpDirectory` still sets the child's working directory; only which file loads is
/// decided here. A path-less `lpFile` is searched by `ShellExecuteEx` — `PATHEXT` applied,
/// `lpDirectory` consulted (measured) — and an absolute one is taken verbatim, so resolving first
/// puts that search under cosca's policy.
fn lp_file_for(
    cmd: &Command,
    program: &OsStr,
    base: Option<&Path>,
    state: &ProcessOnce<'_>,
) -> Result<OsString, Error> {
    use crate::child::spawn::windows_raw::resolve::resolve_consent_image;
    let resolved = match cmd.executable_spec() {
        Some(ExecutableSpec::Exact(_)) => program.to_os_string(),
        // Spelled out rather than `_ =>`: the discriminant IS the feature, and this is the
        // security sink. A future `ExecutableSpec` variant must not compile silently into the
        // SEARCHING branch.
        Some(ExecutableSpec::Search(_)) | None => {
            debug_assert!(
                cmd.env_ops().is_empty(),
                "reject_unsupported_config refuses env ops before the planner"
            );
            let path = state.path_var()?;
            resolve_consent_image(Path::new(program), base, path.as_deref())?.into_os_string()
        }
    };
    debug_assert!(
        crate::resolve::is_absolute_name(&resolved, true),
        "lpFile must reach ShellExecuteEx absolute: {resolved:?}"
    );
    Ok(resolved)
}

#[cfg(test)]
#[path = "windows_consent_tests.rs"]
mod windows_consent_tests;
