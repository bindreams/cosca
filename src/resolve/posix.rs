//! The POSIX program lookup: [`super::resolve`] on the POSIX grammar, the one search every unix spawn
//! makes in the parent (the Linux ordinary spawn, the Linux elevation shim, the macOS spawn).
//!
//! The rules:
//!
//! - A bare name is searched in the child's `PATH` and nowhere else. A child with no `PATH` searches
//!   nothing (no system default path), an empty or relative element is skipped (never the working
//!   directory), and the result is absolute.
//! - The first candidate that exists as a file is the match, whatever its mode. The execute bit is
//!   not part of the search: starting it is, and its failure (`EACCES`, `ENOEXEC`) is the launch's
//!   own error, not `NotFound` and not a reason to search on.
//! - A candidate that cannot be examined (`EACCES` on a locked entry, `ELOOP`, `EIO`, an unreachable
//!   mount) stops the search with an error of the cause's kind that names the entry and the
//!   candidate and holds the OS code down its `source()` chain (where
//!   [`first_os_code`](crate::error::first_os_code) reads it), so `PATH=/locked:/usr/bin` is
//!   `PermissionDenied` even when `/usr/bin` holds the program. Only a definite absence (`ENOENT`,
//!   `ENOTDIR`) goes on.
//! - A name with a `/` is not searched: it is the one entry it names, read against the child's
//!   directory, whatever the entry is (a directory or a device is the match too, and starting it is
//!   the launch's own error). It is answered as written, for the child to read against that
//!   directory itself (the child enters it first), so that no path of any directory is read here: a
//!   process whose own directory has no path (removed, outside a chroot) spawns `../tool`. A
//!   `current_dir` that is missing or not a directory is the answer for such a name, as the
//!   child's `chdir` would have said.
//! - A name that names no file, or holds a NUL, is refused before the directory is looked at.
//! - A bare name's match comes with the candidates after it ([`Found::later`]): the launch goes on to
//!   them only if the file found is gone when it starts it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::{names_no_file, names_no_file_refusal, needs_base, search, Candidate, ResolveInput};
use crate::error::Error;

/// What [`lookup`] found.
#[derive(Debug)]
pub(crate) struct Found {
    /// The file: for a bare name the absolute path of the file found, for a located name the name as
    /// written (see the module doc), which the child must read after entering `cwd`.
    pub(crate) path: PathBuf,
    /// The `PATH` element, as written, the file was found in ([`Candidate::entry`]).
    pub(crate) entry: Option<PathBuf>,
    /// For a bare name, the paths a `PATH` element after the match's would give, in order, each with its
    /// element: for a launch that finds `path` gone between the search and its `execve` and goes on to
    /// these, not probed. Empty for a located name.
    pub(crate) later: Vec<Candidate>,
}

impl Found {
    /// The candidates in the order the child walks them: the match, then `later`, each with its element
    /// as the search wrote it. Moves them out; clones nothing.
    pub(crate) fn into_candidates(self) -> Vec<Candidate> {
        let mut candidates = Vec::with_capacity(1 + self.later.len());
        candidates.push(Candidate {
            path: self.path,
            entry: self.entry,
        });
        candidates.extend(self.later);
        candidates
    }
}

/// The file `program` names, for a child that runs in `cwd` (the directory this process inherited
/// when `None`) with the `PATH` `path_var` (`None`: it has none).
///
/// `InvalidInput` for a name that carries a NUL or names no file; `ENOENT` for a miss; the
/// candidate's error, naming the entry and the candidate, with the OS code readable by
/// [`first_os_code`](crate::error::first_os_code), for one that cannot be examined (see the module
/// doc); for a located name, the OS's own error, bare, whether its `cwd` cannot be entered or its file
/// cannot be examined.
pub(crate) fn lookup(program: &Path, cwd: Option<&Path>, path_var: Option<&OsStr>) -> Result<Found, Error> {
    if program.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "nul byte found in provided data",
        )));
    }
    // Before the directory is looked at: a name that names no file is no file's, whatever the directory.
    if names_no_file(program.as_os_str(), false) {
        return Err(names_no_file_refusal(program));
    }
    let located = needs_base(program.as_os_str(), false);
    if let Some(dir) = cwd.filter(|_| located) {
        if !std::fs::metadata(dir).map_err(Error::Io)?.is_dir() {
            return Err(Error::Io(std::io::Error::from_raw_os_error(libc::ENOTDIR)));
        }
    }
    let (found, later) = search(ResolveInput {
        program,
        cwd,
        system_dirs: &|| Ok(Vec::new()),
        path_var,
        windows: false,
        loadable_only: false,
        normalise: &|path| Ok(path.to_path_buf()),
        child_drive_dir: &|_| None,
        same_drive: &|_, _| false,
    })
    .map_err(miss_as_enoent)?;
    Ok(Found {
        path: if located { program.to_path_buf() } else { found.path },
        entry: found.entry,
        later,
    })
}

/// Whether `error` is a miss, as [`search`] gives it or as [`lookup`] does (`ENOENT`): the one
/// `NotFound` that has no cause. A stop (an entry that cannot be examined) wraps its cause, so it has
/// a `source()`, whatever kind it has.
pub(crate) fn is_miss(error: &Error) -> bool {
    matches!(error, Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound && std::error::Error::source(e).is_none())
}

/// [`search`]'s miss as `ENOENT` itself: a caller of a spawn branches on the errno.
fn miss_as_enoent(error: Error) -> Error {
    if is_miss(&error) {
        Error::Io(std::io::Error::from_raw_os_error(libc::ENOENT))
    } else {
        error
    }
}

/// The error for a walk of `candidates` that stopped at index `at` (`None`: not reported) on `errno`:
/// worded as [`search`] words a stop, with the OS code readable by
/// [`first_os_code`](crate::error::first_os_code). A candidate with no element (a located name) gets the
/// bare OS error, as [`lookup`] gives.
#[cfg(target_os = "linux")]
pub(crate) fn walk_stop(candidates: &[Candidate], at: Option<u64>, errno: i32) -> std::io::Error {
    let cause = std::io::Error::from_raw_os_error(errno);
    let named = at.and_then(|index| {
        let candidate = usize::try_from(index).ok().and_then(|index| candidates.get(index));
        debug_assert!(candidate.is_some(), "the child named the candidate {index} of no path");
        candidate
    });
    match named {
        Some(Candidate { entry: None, .. }) => cause,
        Some(Candidate {
            path,
            entry: Some(entry),
        }) => crate::error::io_context(super::unexamined_context(Some(path), Some(entry)), cause),
        None => crate::error::io_context(super::unexamined_context(None, None), cause),
    }
}

/// The errno that stands for an error of [`lookup`], for a caller that can only say a number (the
/// elevation shim's wire): the error's own OS code, else `EINVAL` for the name that names no file
/// (`InvalidInput` is what an unelevated spawn answers, and what `EINVAL` reads back as).
#[cfg(target_os = "linux")]
pub(crate) fn errno_of(error: &Error) -> i32 {
    crate::error::first_os_code(error).unwrap_or_else(|| {
        debug_assert!(
            matches!(error, Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput),
            "a lookup error is an OS answer or a refusal of the name: {error:?}"
        );
        libc::EINVAL
    })
}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
