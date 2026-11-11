//! Test fixtures shared by the shim's tests.

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

/// The first OS code down `error`'s `source()` chain.
pub(crate) fn os_code(error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    crate::error::chain(error)
        .filter_map(|layer| layer.downcast_ref::<std::io::Error>())
        .find_map(std::io::Error::raw_os_error)
}
