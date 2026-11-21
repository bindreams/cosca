//! Linux: a [`Program`] and the candidates its paths came from, which are never apart: a stop in the
//! child's walk of the later paths ([`Failure::Unexamined`](super::fork_exec::Failure::Unexamined)) names a
//! path by its index, and only the candidates can word it (the core holds no entries).

use std::ffi::{NulError, OsStr, OsString};

use super::fork_exec::Program;
use crate::resolve::Candidate;

/// What a launch runs: the candidates a search returned ([`crate::resolve::posix::Found::into_candidates`])
/// and the [`Program`] that `execve`s their paths in order.
pub(crate) struct Launch {
    program: Program,
    candidates: Vec<Candidate>,
}

impl Launch {
    /// The launch of `candidates` (not empty), which `execve`s each path in order (see [`Program::new`]),
    /// with `argv` and exactly the environment `env` names. `Err` if any of them holds a NUL.
    pub(crate) fn new(
        candidates: Vec<Candidate>,
        argv: &[&OsStr],
        env: impl Iterator<Item = (OsString, OsString)>,
    ) -> Result<Launch, NulError> {
        let paths: Vec<&OsStr> = candidates.iter().map(|c| c.path.as_os_str()).collect();
        let program = Program::new(&paths, argv, env)?;
        Ok(Launch { program, candidates })
    }

    /// The program the child runs.
    pub(crate) fn program(&self) -> &Program {
        &self.program
    }

    /// The candidates [`program`](Self::program)'s paths are, in the same order: a path's index in the
    /// child's report is its index here.
    pub(crate) fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }
}
