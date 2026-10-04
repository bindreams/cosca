//! The elevation shim: a small cosca-controlled executable that an elevation front runs in place of
//! the elevated program, so that cosca can reach the program through a socket.
//!
//! [`protocol`] is the wire format between the two: the shim's argv, its frames to cosca, and
//! cosca's commands to it.

pub(crate) mod protocol;

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
