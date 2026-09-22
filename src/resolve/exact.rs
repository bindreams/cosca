//! `raw_executable()` on POSIX: completing an `Exact` program to an absolute path, which is the
//! opposite of searching for it.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::Error;

/// Complete an `Exact` program to an absolute path against the CHILD's working directory —
/// **without searching, appending anything, or touching the filesystem**.
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
/// Absolute is the point. Every POSIX sink searches a name it is handed bare — `execvp` walks
/// `PATH` for a name with no `/`, and `sudo`, `doas`, `pkexec`, `run0` and root's `/bin/sh` each
/// do their own lookup — and none of them searches an absolute path. Completing first also takes
/// std's own relative-program-plus-`current_dir` behaviour, which its docs call "platform
/// specific and unstable", out of the question.
///
/// POSIX grammar, byte-level, on every host: `/` is the only separator and a leading `/` the only
/// absolute form, so the macOS elevation path — compiled and tested everywhere — gets one answer.
/// The join does not normalise: `..` is left for the kernel, which reads it against the same base.
///
/// Refused with `InvalidInput` before any cwd is read: an interior NUL, which no exec argument can
/// carry, and a name that [names no file](super::names_no_file) — empty, `/`-terminated, or a
/// final `.`/`..`. `process_cwd` is called at most once, and only when the base needs it, so an
/// absolute program or child cwd cannot fail on an unreadable process cwd.
pub(crate) fn complete_posix(
    program: &OsStr,
    child_cwd: Option<&Path>,
    process_cwd: impl FnOnce() -> std::io::Result<PathBuf>,
) -> Result<Completed, Error> {
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
    let as_given = || child_cwd.map(Path::to_path_buf);
    if is_absolute(program) {
        return Ok(Completed {
            program: PathBuf::from(program),
            child_cwd: as_given(),
        });
    }
    let base = match child_cwd {
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
