//! `raw_executable()` on POSIX: making an `Exact` program unsearchable, which is the opposite of
//! searching for it. The unelevated spawn anchors it to the child's inherited cwd
//! ([`anchor_posix`]); the elevation backends, which run in another process, need it completed to
//! an absolute path ([`complete_posix`]).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::Error;

/// The unelevated spawn's form of an `Exact` program: one no `exec` will search, resolved by the
/// child against the working directory it inherits at `fork` — **without reading this process's
/// cwd, searching, appending anything, or touching the filesystem**.
///
/// An absolute program is left as is, and `child_cwd` goes to std as given. A relative one is
/// prefixed with `./` unless it already contains a `/` (`execvp` searches only a name without
/// one), and [`Anchored::enter`] is set: the sink must `chdir` to `child_cwd` in the child
/// itself, just before the exec, rather than hand it to std, whose handling of a relative program
/// with a `current_dir` its docs call "platform specific and unstable". The child then reads the
/// name against the directory it is about to run in, both relative to the cwd it inherited, so
/// the file loaded and the directory run in cannot come from two readings — and a cwd with no
/// usable path (an unsearchable ancestor, an unlinked directory, one outside a chroot) works,
/// as it does for `./tool` under std.
///
/// Refused with `InvalidInput` as [`complete_posix`] refuses.
// Off unix the std spawn never has an `Exact` program: it routes to the raw backend.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn anchor_posix(program: &OsStr, child_cwd: Option<&Path>) -> Result<Anchored, Error> {
    refuse_unnameable(program)?;
    let cwd = child_cwd.map(Path::to_path_buf);
    if is_absolute(program) {
        return Ok(Anchored {
            program: PathBuf::from(program),
            cwd,
            enter: false,
        });
    }
    let program = if program.as_encoded_bytes().contains(&b'/') {
        program.to_os_string()
    } else {
        join(OsStr::new("."), program)
    };
    Ok(Anchored {
        program: PathBuf::from(program),
        cwd,
        enter: true,
    })
}

/// [`anchor_posix`]'s answer.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Anchored {
    pub(crate) program: PathBuf,
    /// `current_dir()` as given.
    pub(crate) cwd: Option<PathBuf>,
    /// Whether the child must `chdir` to `cwd` itself, right before the exec, instead of std.
    pub(crate) enter: bool,
}

/// Complete an `Exact` program to an absolute path against the CHILD's working directory —
/// **without searching, appending anything, or touching the filesystem**. For the elevation
/// backends, which run the program in another process and so need a path.
///
/// Needs this process's cwd as a PATH when the program is relative and `child_cwd` is not
/// absolute, so a cwd with no usable path fails where the unelevated [`anchor_posix`] would
/// succeed. An unlinked directory fails `process_cwd` on every OS (`ENOENT`), so this does. An
/// unsearchable ancestor fails it on macOS (`EACCES`); Linux's `getcwd` succeeds regardless of
/// ancestors' permissions, so the path is returned and entering it fails later, at spawn.
///
/// The base is `child_cwd` (what `Command::current_dir` set; joined onto `process_cwd()` when
/// itself relative), or `process_cwd()` when unset. That is the directory the child's own exec
/// would read a relative path against.
///
/// Returns the base alongside the program as [`Completed::child_cwd`], for the sink to run the
/// child in. A base built from `process_cwd()` replaces `child_cwd`: left relative or unset, the
/// child would read this process's cwd again at `fork`, and a `set_current_dir` in between would
/// load one directory's file while running in another.
///
/// Absolute is the point: `sudo`, `doas`, `pkexec`, `run0` and root's `/bin/sh` each look up a
/// name they are handed bare, and none of them searches an absolute path. A `./` prefix would not
/// do there — the backend reads it against a directory of its own choosing.
///
/// POSIX grammar, byte-level, on every host: `/` is the only separator and a leading `/` the only
/// absolute form, so the macOS elevation path — compiled and tested everywhere — gets one answer.
/// The join does not normalise: `..` is left for the kernel, which reads it against the same base.
///
/// Refused with `InvalidInput` before any cwd is read: an interior NUL, which no exec argument can
/// carry, and a name that [names no file](super::names_no_file) — empty, `/`-terminated, or a
/// final `.`/`..`. An empty `child_cwd` under a relative program is `NotFound`, as the `chdir("")`
/// it would otherwise reach reports. `process_cwd` is called at most once, and only when the base
/// needs it, so an absolute program or child cwd cannot fail on an unreadable process cwd.
pub(crate) fn complete_posix(
    program: &OsStr,
    child_cwd: Option<&Path>,
    process_cwd: impl FnOnce() -> std::io::Result<PathBuf>,
) -> Result<Completed, Error> {
    refuse_unnameable(program)?;
    let as_given = || child_cwd.map(Path::to_path_buf);
    if is_absolute(program) {
        return Ok(Completed {
            program: PathBuf::from(program),
            child_cwd: as_given(),
        });
    }
    let base = match child_cwd {
        // Joined, it would name the process cwd, where the `chdir` it stands for fails.
        Some(dir) if dir.as_os_str().is_empty() => {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "current_dir(\"\") names no directory",
            )))
        }
        Some(dir) if is_absolute(dir.as_os_str()) => {
            return Ok(Completed {
                program: PathBuf::from(join(dir.as_os_str(), program)),
                child_cwd: as_given(),
            })
        }
        Some(dir) => join(process_cwd()?.as_os_str(), dir.as_os_str()),
        None => process_cwd()?.into_os_string(),
    };
    Ok(Completed {
        program: PathBuf::from(join(&base, program)),
        child_cwd: Some(PathBuf::from(base)),
    })
}

/// An `Exact` program for a shell that enters a directory by path and then execs — root's shell
/// under `osascript`: the absolute directory to `cd` to, and the name to exec there.
///
/// The directory is [`complete_posix`]'s — `child_cwd` if absolute, else completed against one
/// reading of `process_cwd` — and the name is the program as written, `./`-prefixed when
/// relative: exec reads it against the directory the `cd` entered, and a `./` keeps any shell
/// from searching `PATH` for it or reading `-x/tool` as an option. An absolute program is left
/// as is, with `child_cwd` as given.
pub(crate) fn enter_posix(
    program: &OsStr,
    child_cwd: Option<&Path>,
    process_cwd: impl FnOnce() -> std::io::Result<PathBuf>,
) -> Result<Entered, Error> {
    let completed = complete_posix(program, child_cwd, process_cwd)?;
    if is_absolute(program) {
        return Ok(Entered {
            program: completed.program,
            dir: completed.child_cwd,
        });
    }
    let bytes = program.as_encoded_bytes();
    let program = if bytes.starts_with(b"./") {
        program.to_os_string()
    } else {
        join(OsStr::new("."), program)
    };
    Ok(Entered {
        program: PathBuf::from(program),
        dir: completed.child_cwd,
    })
}

/// [`enter_posix`]'s answer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Entered {
    /// Absolute, or `./`-prefixed and read against `dir`.
    pub(crate) program: PathBuf,
    /// Absolute whenever `program` is relative.
    pub(crate) dir: Option<PathBuf>,
}

/// The refusals both forms share: an interior NUL, which no exec argument can carry, and a name
/// that [names no file](super::names_no_file).
pub(crate) fn refuse_unnameable(program: &OsStr) -> Result<(), Error> {
    if program.as_encoded_bytes().contains(&0) {
        // A literal: interpolating the token would put a raw U+0000 into logs and terminals.
        return Err(invalid_input(
            "raw_executable() was given a path containing an embedded NUL, so it names no file".into(),
        ));
    }
    if super::names_no_file(program, false) {
        return Err(invalid_input(format!(
            "raw_executable() was given a path that names no file: {program:?}"
        )));
    }
    Ok(())
}

/// [`complete_posix`]'s answer: the program to exec and the directory to run it in.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Completed {
    pub(crate) program: PathBuf,
    /// The base `program` was joined onto when that base came from `process_cwd()`; otherwise
    /// `child_cwd` as given.
    pub(crate) child_cwd: Option<PathBuf>,
}

fn is_absolute(p: &OsStr) -> bool {
    p.as_encoded_bytes().first() == Some(&b'/')
}

fn join(base: &OsStr, rel: &OsStr) -> OsString {
    let mut out = base.to_os_string();
    if !base.as_encoded_bytes().ends_with(b"/") {
        out.push("/");
    }
    out.push(rel);
    out
}

fn invalid_input(msg: String) -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

#[cfg(test)]
#[path = "exact_tests.rs"]
mod exact_tests;
