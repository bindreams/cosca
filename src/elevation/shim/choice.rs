use std::path::PathBuf;

/// Which executable a front elevates in place of the program.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum ShimChoice {
    /// No shim: the front runs the program itself.
    #[default]
    Direct,
    /// The host binary, re-executed as the shim.
    HostExecutable,
    /// A binary whose `main` calls `cosca::init()`.
    Executable(PathBuf),
}

#[cfg(test)]
#[path = "choice_tests.rs"]
mod choice_tests;
