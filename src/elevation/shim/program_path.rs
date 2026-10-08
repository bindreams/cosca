//! Resolving the program the shim executes (plan F, D11), before the child exists, so that the
//! child's only call is `execve`.
//!
//! - A program containing `/` is used as given. An empty program is `ENOENT`.
//! - A bare name is searched in `PATH`, element by element, as `execvp` does: the first candidate
//!   `<element>/<name>` that is not a directory and is executable for the effective ids wins. One
//!   that exists but fails either check is skipped and remembered: if nothing wins, the result is
//!   `EACCES` when one was remembered, else `ENOENT`.
//! - Never the working directory: empty, `.` and every other relative element is skipped, so the
//!   result for a bare name is absolute and `execve` never sees a name without a slash. (`Direct`
//!   mode searches them under sudo without `secure_path` and `ignore_dot`, and under pkexec.)

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
}

/// The search over `path`, asking `probe` about each candidate. `None` for an unset `PATH`, which
/// means the system default (`confstr(_CS_PATH)`).
pub(crate) fn resolve(program: &OsStr, path: Option<&OsStr>) -> Result<OsString, Errno> {
    resolve_with(program, path, probe_fs)
}

/// [`resolve`] with the file system behind `probe`.
pub(crate) fn resolve_with(
    program: &OsStr,
    path: Option<&OsStr>,
    mut probe: impl FnMut(&Path) -> Candidate,
) -> Result<OsString, Errno> {
    let name = program.as_bytes();
    if name.contains(&b'/') {
        return Ok(program.to_owned());
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
    let mut remembered = false;
    for element in path.as_bytes().split(|&b| b == b':') {
        if !element.starts_with(b"/") {
            continue;
        }
        let mut candidate = element.to_vec();
        candidate.push(b'/');
        candidate.extend_from_slice(name);
        let candidate = OsString::from_vec(candidate);
        match probe(Path::new(&candidate)) {
            Candidate::Executable => return Ok(candidate),
            Candidate::Directory | Candidate::NotExecutable => remembered = true,
            Candidate::Missing => {}
        }
    }
    Err(Errno(if remembered { libc::EACCES } else { libc::ENOENT }))
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
    let Ok(stat) = stat(path) else {
        return Candidate::Missing;
    };
    if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
        return Candidate::Directory;
    }
    match accessat(CWD, path, Access::EXEC_OK, AtFlags::EACCESS) {
        Ok(()) => Candidate::Executable,
        Err(_) => Candidate::NotExecutable,
    }
}

#[cfg(test)]
#[path = "program_path_tests.rs"]
mod program_path_tests;
