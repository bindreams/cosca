//! The program a unix spawn runs, found in the parent: the one search, [`crate::resolve::posix`], over the
//! `PATH` the child will have. The Linux child then only `execve`s the path, and macOS hands std the path
//! (which contains a `/`, so std searches nothing).
//!
//! A failed search is the spawn's error, before any clone or child.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::Invocation;
use crate::error::Error;
use crate::resolve::Candidate;

impl Invocation {
    /// Replaces the program with the file the search finds, for a child whose environment is `env`, and
    /// returns the candidates the launch walks, in order (see [`crate::resolve::posix::Found::into_candidates`]):
    /// the file and then, for a bare name, those after it, each with its `PATH` element. `argv[0]` stays the
    /// name the caller wrote: `arg0` is set to it unless `executable()` set it.
    ///
    /// A relative located name stays as written and is read after the child enters its directory, so
    /// no path of this process's own directory is needed: `enter` is set for a child that has one.
    ///
    /// For an exactly named program, does nothing else: the one candidate is the program, with no element.
    /// `NotFound` for a miss, `InvalidInput` for a name that cannot name a file, the candidate's error
    /// (naming the entry, with the OS code down its `source()` chain) for one that could not be examined,
    /// the directory's own for a located name whose directory cannot be entered; see
    /// [`crate::resolve::posix`].
    pub(crate) fn find(&mut self, env: &[(OsString, OsString)]) -> Result<Vec<Candidate>, Error> {
        if !self.searched {
            return Ok(vec![Candidate {
                path: PathBuf::from(&self.program),
                entry: None,
            }]);
        }
        let path = super::child_env::path_of(env);
        let found = crate::resolve::posix::lookup(Path::new(&self.program), self.cwd.as_deref(), path)?;
        self.enter |= !found.path.is_absolute() && self.cwd.is_some();
        let written = std::mem::replace(&mut self.program, found.path.clone().into_os_string());
        self.arg0.get_or_insert(written);
        Ok(found.into_candidates())
    }
}
