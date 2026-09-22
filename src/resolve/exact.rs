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
/// reads a relative path against: std `chdir`s in the child before it execs, and a relative
/// `current_dir` is read against this process's cwd at that `chdir`.
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
) -> Result<PathBuf, Error> {
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
    if is_absolute(program) {
        return Ok(PathBuf::from(program));
    }
    let base = match child_cwd {
        Some(dir) if is_absolute(dir.as_os_str()) => dir.as_os_str().to_os_string(),
        Some(dir) => join(process_cwd()?.as_os_str(), dir.as_os_str()),
        None => process_cwd()?.into_os_string(),
    };
    Ok(PathBuf::from(join(&base, program)))
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
