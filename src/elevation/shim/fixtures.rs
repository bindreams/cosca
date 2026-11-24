//! Test fixtures shared by the shim's tests.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::protocol::{ShimArgs, ShimIdentity, IDENTITY_PRESENT};

/// A temp directory a private directory or a shim link may be made in: mode 0700 whatever the umask,
/// since the path check refuses a directory others can write that is not sticky. The directory's ancestors are the
/// environment's: a `TMPDIR` that is itself group-writable and not sticky is still refused.
pub(crate) fn private_tmp() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("a temp directory");
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod the temp directory");
    tmp
}

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
