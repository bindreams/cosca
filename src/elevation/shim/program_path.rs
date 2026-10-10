//! Resolving the program the shim executes, before the child exists, so that the child's only calls
//! are `execve`.
//!
//! - A program containing `/` is used as given. An empty program is `ENOENT`.
//! - A bare name is searched in `PATH`, element by element, as glibc's `execvp` does. A candidate
//!   `<element>/<name>` is skipped when it is absent (`ENOENT`, `ENOTDIR`, `ESTALE`, `ENODEV`,
//!   `ETIMEDOUT`), and skipped and remembered when it is a directory, is not executable for the
//!   effective ids or sits in a directory this process cannot search (`EACCES`). Any other error
//!   ends the search with that errno, as `execve` ends `execvp`'s. If nothing wins, the result is
//!   `EACCES` when one was remembered, else `ENOENT`.
//! - Never the working directory: empty, `.` and every other relative element is skipped, so every
//!   candidate is absolute and `execve` never sees a name without a slash. (`Direct` mode searches
//!   them under sudo without `secure_path` and `ignore_dot`, and under pkexec.)
//! - The search only decides whether to start. It returns every candidate, in order, and the child
//!   tries `execve` on each with `execvp`'s rules: a candidate that vanishes between the search and
//!   the exec does not stop a later one from running.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use super::protocol::Errno;

/// What one candidate path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Candidate {
    Missing,
    Directory,
    NotExecutable,
    Executable,
    /// `execve` would fail with this errno and stop `execvp`'s search.
    Failed(i32),
}

/// The search over `path`, asking `probe` about each candidate: every candidate, in order, if the
/// program can start. `None` for an unset `PATH`, which means the system default
/// (`confstr(_CS_PATH)`).
pub(crate) fn resolve(program: &OsStr, path: Option<&OsStr>) -> Result<Vec<OsString>, Errno> {
    resolve_with(program, path, probe_fs)
}

/// [`resolve`] with the file system behind `probe`. `probe` is asked about candidates in order, and
/// no further once one is executable or fails.
pub(crate) fn resolve_with(
    program: &OsStr,
    path: Option<&OsStr>,
    mut probe: impl FnMut(&Path) -> Candidate,
) -> Result<Vec<OsString>, Errno> {
    let name = program.as_bytes();
    if name.contains(&b'/') {
        return Ok(vec![program.to_owned()]);
    }
    if name.is_empty() {
        return Err(Errno(libc::ENOENT));
    }
    let default;
    let path = match path {
        Some(path) => path,
        None => {
            default = default_path();
            &default
        }
    };
    let mut candidates = Vec::new();
    let mut remembered = false;
    let mut decided = None;
    for element in path.as_bytes().split(|&b| b == b':') {
        if !element.starts_with(b"/") {
            continue;
        }
        let mut candidate = element.to_vec();
        candidate.push(b'/');
        candidate.extend_from_slice(name);
        let candidate = OsString::from_vec(candidate);
        if decided.is_none() {
            match probe(Path::new(&candidate)) {
                Candidate::Executable => decided = Some(Ok(())),
                Candidate::Failed(errno) => decided = Some(Err(Errno(errno))),
                Candidate::Directory | Candidate::NotExecutable => remembered = true,
                Candidate::Missing => {}
            }
        }
        candidates.push(candidate);
    }
    match decided {
        Some(Ok(())) => Ok(candidates),
        Some(Err(errno)) => Err(errno),
        None => Err(Errno(if remembered { libc::EACCES } else { libc::ENOENT })),
    }
}

/// `confstr(_CS_PATH)`: the system's default search path.
fn default_path() -> OsString {
    // SAFETY: a null buffer of length 0 asks only for the size.
    let size = unsafe { libc::confstr(libc::_CS_PATH, std::ptr::null_mut(), 0) };
    if size == 0 {
        return OsString::new();
    }
    let mut buf = vec![0u8; size];
    // SAFETY: `buf` is `size` writable bytes.
    let written = unsafe { libc::confstr(libc::_CS_PATH, buf.as_mut_ptr().cast(), buf.len()) };
    debug_assert_eq!(written, size, "confstr gave a different size the second time");
    buf.truncate(size.saturating_sub(1));
    OsString::from_vec(buf)
}

/// The real file system: `stat` follows symlinks, and the access check uses the effective ids.
fn probe_fs(path: &Path) -> Candidate {
    use rustix::fs::{accessat, stat, Access, AtFlags, FileType, CWD};
    let stat = match stat(path) {
        Ok(stat) => stat,
        Err(e) => return classify(path, e.raw_os_error()),
    };
    if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
        return Candidate::Directory;
    }
    match accessat(CWD, path, Access::EXEC_OK, AtFlags::EACCESS) {
        Ok(()) => Candidate::Executable,
        Err(e) => classify(path, e.raw_os_error()),
    }
}

/// What a failed check of `path` means to the search, by `errno`, as glibc's `execvp` reads the
/// errno of `execve`.
fn classify(path: &Path, errno: i32) -> Candidate {
    match errno {
        libc::ENOENT | libc::ENOTDIR | libc::ESTALE | libc::ENODEV | libc::ETIMEDOUT => Candidate::Missing,
        libc::EACCES => Candidate::NotExecutable,
        libc::ELOOP | libc::ENAMETOOLONG | libc::EIO => Candidate::Failed(errno),
        other => {
            log::warn!(
                "the shim's search of {}: unexpected errno {other}; it ends the search",
                path.display()
            );
            Candidate::Failed(other)
        }
    }
}

#[cfg(test)]
#[path = "program_path_tests.rs"]
mod program_path_tests;
