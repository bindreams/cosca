//! Test fixtures shared by the tests of everything that consumes a [`ShimArgs`].

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use super::protocol::{ShimArgs, ShimIdentity, IDENTITY_PRESENT};

/// A `ShimArgs` for `program` and `rest`, whose identity follows the platform.
pub(crate) fn shim_args(program: &[u8], rest: &[&[u8]]) -> ShimArgs {
    ShimArgs {
        dir: PathBuf::from("/tmp/cosca-x1"),
        cosca_pid: 4242,
        cosca_identity: IDENTITY_PRESENT.then_some(ShimIdentity {
            unique_id: 7,
            id_version: 9,
        }),
        cosca_euid: 1000,
        search_path: None,
        program: OsString::from_vec(program.to_vec()),
        args: rest.iter().map(|a| OsString::from_vec(a.to_vec())).collect(),
    }
}
